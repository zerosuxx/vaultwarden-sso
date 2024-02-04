use chrono::{NaiveDateTime, Utc};
use num_traits::FromPrimitive;
use rocket::{
    form::{Form, FromForm},
    http::{Cookie, CookieJar, Status},
    response::Redirect,
    serde::json::Json,
    Route,
};
use serde_json::Value;

use crate::{
    api::{
        admin,
        core::{
            accounts::{PreloginData, RegisterData, _prelogin, _register, kdf_upgrade},
            log_user_event,
            two_factor::{authenticator, duo, email, enforce_2fa_policy, webauthn, yubikey},
        },
        ApiResult, EmptyResult, JsonResult, JsonUpcase,
    },
    auth,
    auth::{AuthMethod, AuthMethodScope, ClientHeaders, ClientIp},
    db::{models::*, DbConn},
    error::MapResult,
    mail, sso, util, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![login, prelogin, identity_register, _prevalidate, prevalidate, authorize, oidcsignin, oidcsignin_error]
}

#[post("/connect/token", data = "<data>")]
async fn login(
    data: Form<ConnectData>,
    client_header: ClientHeaders,
    cookies: &CookieJar<'_>,
    mut conn: DbConn,
) -> JsonResult {
    let data: ConnectData = data.into_inner();

    let mut user_uuid: Option<String> = None;

    let login_result = match data.grant_type.as_ref() {
        "refresh_token" => {
            _check_is_some(&data.refresh_token, "refresh_token cannot be blank")?;
            _refresh_login(data, &mut conn).await
        }
        "password" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.password, "password cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;
            _check_is_some(&data.username, "username cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _password_login(data, &mut user_uuid, &mut conn, &client_header.ip).await
        }
        "client_credentials" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.client_secret, "client_secret cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _api_key_login(data, &mut user_uuid, &mut conn, &client_header.ip).await
        }
        "authorization_code" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.code, "code cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _sso_login(data, &mut user_uuid, &mut conn, cookies, &client_header.ip).await
        }
        t => err!("Invalid type", t),
    };

    if let Some(user_uuid) = user_uuid {
        match &login_result {
            Ok(_) => {
                log_user_event(
                    EventType::UserLoggedIn as i32,
                    &user_uuid,
                    client_header.device_type,
                    &client_header.ip.ip,
                    &mut conn,
                )
                .await;
            }
            Err(e) => {
                if let Some(ev) = e.get_event() {
                    log_user_event(
                        ev.event as i32,
                        &user_uuid,
                        client_header.device_type,
                        &client_header.ip.ip,
                        &mut conn,
                    )
                    .await
                }
            }
        }
    }

    login_result
}

// Return Status::Unauthorized to trigger logout
async fn _refresh_login(data: ConnectData, conn: &mut DbConn) -> JsonResult {
    // Extract token
    let refresh_token = match data.refresh_token {
        Some(token) => token,
        None => err_code!("Missing refresh_token", Status::Unauthorized.code),
    };

    // ---
    // Disabled this variable, it was used to generate the JWT
    // Because this might get used in the future, and is add by the Bitwarden Server, lets keep it, but then commented out
    // See: https://github.com/dani-garcia/vaultwarden/issues/4156
    // ---
    // let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, conn).await;
    match auth::refresh_tokens(&refresh_token, conn).await {
        Err(err) => err_code!(err.to_string(), Status::Unauthorized.code),
        Ok((mut device, user, auth_tokens)) => {
            // Save to update `device.updated_at` to track usage
            device.save(conn).await?;

            let result = json!({
                "refresh_token": auth_tokens.refresh_token(),
                "access_token": auth_tokens.access_token(),
                "expires_in": auth_tokens.expires_in(),
                "token_type": "Bearer",
                "Key": user.akey,
                "PrivateKey": user.private_key,

                "Kdf": user.client_kdf_type,
                "KdfIterations": user.client_kdf_iter,
                "KdfMemory": user.client_kdf_memory,
                "KdfParallelism": user.client_kdf_parallelism,
                "ResetMasterPassword": false, // TODO: according to official server seems something like: user.password_hash.is_empty(), but would need testing
                "scope": auth_tokens.scope(),
                "unofficialServer": true,
            });

            Ok(Json(result))
        }
    }
}

// After exchanging the code we need to check first if 2FA is needed before continuing
async fn _sso_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    cookies: &CookieJar<'_>,
    ip: &ClientIp,
) -> JsonResult {
    AuthMethod::Sso.check_scope(data.scope.as_ref())?;

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    let code = match data.code.as_ref() {
        None => err!("Got no code in OIDC data"),
        Some(code) => code,
    };

    let user_infos = sso::exchange_code(code).await?;

    // Will trigger 2FA flow if needed
    let user_data = match User::find_by_mail(user_infos.email.as_str(), conn).await {
        None => None,
        Some(user) => {
            let (mut device, new_device) = get_device(&data, conn, &user).await?;
            let twofactor_token = twofactor_auth(&user, &data, &mut device, ip, conn).await?;

            Some((user, device, new_device, twofactor_token))
        }
    };

    // We passed 2FA get full user informations
    let auth_user = sso::redeem(code, conn).await?;

    let now = Utc::now().naive_utc();
    let (user, mut device, new_device, twofactor_token) = match user_data {
        None => {
            let mut user = User::new(user_infos.email, user_infos.user_name);
            user.verified_at = Some(now);
            user.save(conn).await?;

            let (device, new_device) = get_device(&data, conn, &user).await?;

            (user, device, new_device, None)
        }
        Some((mut user, device, new_device, twofactor_token)) if user.public_key.is_none() => {
            user.verified_at = Some(now);
            if let Some(user_name) = user_infos.user_name {
                user.name = user_name;
            }
            user.save(conn).await?;
            (user, device, new_device, twofactor_token)
        }
        Some(data) => data,
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid.clone());

    sso::sync_groups(&user, &device, ip, &auth_user.groups, conn).await?;

    if auth_user.is_admin() {
        info!("User {} logged with admin cookie", user.email);
        cookies.add(admin::create_admin_cookie());
    }

    let auth_tokens = sso::create_auth_tokens(
        &device,
        &user,
        auth_user.refresh_token,
        &auth_user.access_token,
        auth_user.expires_in,
    ).await?;

    authenticated_response(&user, &mut device, new_device, auth_tokens, twofactor_token, &now, conn, ip).await
}

async fn _password_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("SSO sign-in is required");
    }

    // Validate scope
    AuthMethod::Password.check_scope(data.scope.as_ref())?;

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Get the user
    let username = data.username.as_ref().unwrap().trim();
    let mut user = match User::find_by_mail(username, conn).await {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username)),
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid.clone());

    // Check password
    let password = data.password.as_ref().unwrap();
    if let Some(auth_request_uuid) = data.auth_request.clone() {
        if let Some(auth_request) = AuthRequest::find_by_uuid(auth_request_uuid.as_str(), conn).await {
            if !auth_request.check_access_code(password) {
                err!(
                    "Username or access code is incorrect. Try again",
                    format!("IP: {}. Username: {}.", ip.ip, username),
                    ErrorEvent {
                        event: EventType::UserFailedLogIn,
                    }
                )
            }
        } else {
            err!(
                "Auth request not found. Try again.",
                format!("IP: {}. Username: {}.", ip.ip, username),
                ErrorEvent {
                    event: EventType::UserFailedLogIn,
                }
            )
        }
    } else if !user.check_valid_password(password) {
        err!(
            "Username or password is incorrect. Try again",
            format!("IP: {}. Username: {}.", ip.ip, username),
            ErrorEvent {
                event: EventType::UserFailedLogIn,
            }
        )
    }

    kdf_upgrade(&mut user, password, conn).await?;

    // Check if the user is disabled
    if !user.enabled {
        err!(
            "This user has been disabled",
            format!("IP: {}. Username: {}.", ip.ip, username),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let now = Utc::now().naive_utc();

    if user.verified_at.is_none() && CONFIG.mail_enabled() && CONFIG.signups_verify() {
        if user.last_verifying_at.is_none()
            || now.signed_duration_since(user.last_verifying_at.unwrap()).num_seconds()
                > CONFIG.signups_verify_resend_time() as i64
        {
            let resend_limit = CONFIG.signups_verify_resend_limit() as i32;
            if resend_limit == 0 || user.login_verify_count < resend_limit {
                // We want to send another email verification if we require signups to verify
                // their email address, and we haven't sent them a reminder in a while...
                user.last_verifying_at = Some(now);
                user.login_verify_count += 1;

                if let Err(e) = user.save(conn).await {
                    error!("Error updating user: {:#?}", e);
                }

                if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
                    error!("Error auto-sending email verification email: {:#?}", e);
                }
            }
        }

        // We still want the login to fail until they actually verified the email address
        err!(
            "Please verify your email before trying again.",
            format!("IP: {}. Username: {}.", ip.ip, username),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let (mut device, new_device) = get_device(&data, conn, &user).await?;

    let twofactor_token = twofactor_auth(&user, &data, &mut device, ip, conn).await?;

    let auth_tokens = auth::AuthTokens::new(&device, &user, AuthMethod::Password);

    authenticated_response(&user, &mut device, new_device, auth_tokens, twofactor_token, &now, conn, ip).await
}

#[allow(clippy::too_many_arguments)]
async fn authenticated_response(
    user: &User,
    device: &mut Device,
    new_device: bool,
    auth_tokens: auth::AuthTokens,
    twofactor_token: Option<String>,
    now: &NaiveDateTime,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    if CONFIG.mail_enabled() && new_device {
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.require_device_email() {
                err!(
                    "Could not send login notification email. Please contact your administrator.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
        }
    }

    if CONFIG.sso_enabled() && CONFIG.sso_acceptall_invites() {
        for user_org in UserOrganization::find_invited_by_user(&user.uuid, conn).await.iter_mut() {
            user_org.status = UserOrgStatus::Accepted as i32;
            user_org.save(conn).await?;

            if CONFIG.mail_enabled() {
                if let Some(org) = Organization::find_by_uuid(&user_org.org_uuid, conn).await {
                    if let Some(invited_by) = &user_org.invited_by_email {
                        mail::send_invite_accepted(&user.email, invited_by, &org.name).await?;
                    }
                }
            }
        }
    }

    // Save to update `device.updated_at` to track usage
    device.save(conn).await?;

    let mut result = json!({
        "access_token": auth_tokens.access_token(),
        "expires_in": auth_tokens.expires_in(),
        "token_type": "Bearer",
        "refresh_token": auth_tokens.refresh_token(),
        "Key": user.akey,
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false,// TODO: Same as above
        "scope": auth_tokens.scope(),
        "unofficialServer": true,
        "UserDecryptionOptions": {
            "HasMasterPassword": user.public_key.is_some(),
            "Object": "userDecryptionOptions"
        },
    });

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", user.email, ip.ip);
    Ok(Json(result))
}

async fn _api_key_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Validate scope
    match data.scope.as_ref() {
        Some(scope) if scope == &AuthMethod::UserApiKey.scope() => _user_api_key_login(data, user_uuid, conn, ip).await,
        Some(scope) if scope == &AuthMethod::OrgApiKey.scope() => _organization_api_key_login(data, conn, ip).await,
        _ => err!("Scope not supported"),
    }
}

async fn _user_api_key_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    // Get the user via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let client_user_uuid = match client_id.strip_prefix("user.") {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let user = match User::find_by_uuid(client_user_uuid, conn).await {
        Some(user) => user,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid.clone());

    // Check if the user is disabled
    if !user.enabled {
        err!(
            "This user has been disabled (API key login)",
            format!("IP: {}. Username: {}.", ip.ip, user.email),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    // Check API key. Note that API key logins bypass 2FA.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !user.check_valid_api_key(client_secret) {
        err!(
            "Incorrect client_secret",
            format!("IP: {}. Username: {}.", ip.ip, user.email),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let (mut device, new_device) = get_device(&data, conn, &user).await?;

    if CONFIG.mail_enabled() && new_device {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.require_device_email() {
                err!(
                    "Could not send login notification email. Please contact your administrator.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
        }
    }

    // ---
    // Disabled this variable, it was used to generate the JWT
    // Because this might get used in the future, and is add by the Bitwarden Server, lets keep it, but then commented out
    // See: https://github.com/dani-garcia/vaultwarden/issues/4156
    // ---
    // let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, conn).await;
    let access_claims = auth::LoginJwtClaims::default(&device, &user, &auth::AuthMethod::UserApiKey);

    // Save to update `device.updated_at` to track usage
    device.save(conn).await?;

    info!("User {} logged in successfully via API key. IP: {}", user.email, ip.ip);

    // Note: No refresh_token is returned. The CLI just repeats the
    // client_credentials login flow when the existing token expires.
    let result = json!({
        "access_token": access_claims.token(),
        "expires_in": access_claims.expires_in(),
        "token_type": "Bearer",
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: Same as above
        "scope": auth::AuthMethod::UserApiKey.scope(),
        "unofficialServer": true,
    });

    Ok(Json(result))
}

async fn _organization_api_key_login(data: ConnectData, conn: &mut DbConn, ip: &ClientIp) -> JsonResult {
    // Get the org via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let org_uuid = match client_id.strip_prefix("organization.") {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let org_api_key = match OrganizationApiKey::find_by_org_uuid(org_uuid, conn).await {
        Some(org_api_key) => org_api_key,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Check API key.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !org_api_key.check_valid_api_key(client_secret) {
        err!("Incorrect client_secret", format!("IP: {}. Organization: {}.", ip.ip, org_api_key.org_uuid))
    }

    let claim = auth::generate_organization_api_key_login_claims(org_api_key.uuid, org_api_key.org_uuid);
    let access_token = auth::encode_jwt(&claim);

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": auth::AuthMethod::OrgApiKey.scope(),
        "unofficialServer": true,
    })))
}

/// Retrieves an existing device or creates a new device from ConnectData and the User
async fn get_device(data: &ConnectData, conn: &mut DbConn, user: &User) -> ApiResult<(Device, bool)> {
    // On iOS, device_type sends "iOS", on others it sends a number
    // When unknown or unable to parse, return 14, which is 'Unknown Browser'
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(14);
    let device_id = data.device_identifier.clone().expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    let mut new_device = false;
    // Find device or create new
    let device = match Device::find_by_uuid_and_user(&device_id, &user.uuid, conn).await {
        Some(device) => device,
        None => {
            let device = Device::new(device_id, user.uuid.clone(), device_name, device_type);
            new_device = true;
            device
        }
    };

    Ok((device, new_device))
}

async fn twofactor_auth(
    user: &User,
    data: &ConnectData,
    device: &mut Device,
    ip: &ClientIp,
    conn: &mut DbConn,
) -> ApiResult<Option<String>> {
    let twofactors = TwoFactor::find_by_user(&user.uuid, conn).await;

    // No twofactor token if twofactor is disabled
    if twofactors.is_empty() {
        enforce_2fa_policy(user, &user.uuid, device.atype, &ip.ip, conn).await?;
        return Ok(None);
    }

    TwoFactorIncomplete::mark_incomplete(&user.uuid, &device.uuid, &device.name, ip, conn).await?;

    let twofactor_ids: Vec<_> = twofactors.iter().map(|tf| tf.atype).collect();
    let selected_id = data.two_factor_provider.unwrap_or(twofactor_ids[0]); // If we aren't given a two factor provider, assume the first one

    let twofactor_code = match data.two_factor_token {
        Some(ref code) => code,
        None => err_json!(_json_err_twofactor(&twofactor_ids, &user.uuid, conn).await?, "2FA token not provided"),
    };

    let selected_twofactor = twofactors.into_iter().find(|tf| tf.atype == selected_id && tf.enabled);

    use crate::crypto::ct_eq;

    let selected_data = _selected_data(selected_twofactor);
    let mut remember = data.two_factor_remember.unwrap_or(0);

    match TwoFactorType::from_i32(selected_id) {
        Some(TwoFactorType::Authenticator) => {
            authenticator::validate_totp_code_str(&user.uuid, twofactor_code, &selected_data?, ip, conn).await?
        }
        Some(TwoFactorType::Webauthn) => webauthn::validate_webauthn_login(&user.uuid, twofactor_code, conn).await?,
        Some(TwoFactorType::YubiKey) => yubikey::validate_yubikey_login(twofactor_code, &selected_data?).await?,
        Some(TwoFactorType::Duo) => duo::validate_duo_login(&user.email, twofactor_code, conn).await?,
        Some(TwoFactorType::Email) => {
            email::validate_email_code_str(&user.uuid, twofactor_code, &selected_data?, conn).await?
        }

        Some(TwoFactorType::Remember) => {
            match device.twofactor_remember {
                Some(ref code) if !CONFIG.disable_2fa_remember() && ct_eq(code, twofactor_code) => {
                    remember = 1; // Make sure we also return the token here, otherwise it will only remember the first time
                }
                _ => {
                    err_json!(
                        _json_err_twofactor(&twofactor_ids, &user.uuid, conn).await?,
                        "2FA Remember token not provided"
                    )
                }
            }
        }
        _ => err!(
            "Invalid two factor provider",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        ),
    }

    TwoFactorIncomplete::mark_complete(&user.uuid, &device.uuid, conn).await?;

    let two_factor = if !CONFIG.disable_2fa_remember() && remember == 1 {
        Some(device.refresh_twofactor_remember())
    } else {
        device.delete_twofactor_remember();
        None
    };
    Ok(two_factor)
}

fn _selected_data(tf: Option<TwoFactor>) -> ApiResult<String> {
    tf.map(|t| t.data).map_res("Two factor doesn't exist")
}

async fn _json_err_twofactor(providers: &[i32], user_uuid: &str, conn: &mut DbConn) -> ApiResult<Value> {
    let mut result = json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : providers,
        "TwoFactorProviders2" : {} // { "0" : null }
    });

    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;

        match TwoFactorType::from_i32(*provider) {
            Some(TwoFactorType::Authenticator) => { /* Nothing to do for TOTP */ }

            Some(TwoFactorType::Webauthn) if CONFIG.domain_set() => {
                let request = webauthn::generate_webauthn_login(user_uuid, conn).await?;
                result["TwoFactorProviders2"][provider.to_string()] = request.0;
            }

            Some(TwoFactorType::Duo) => {
                let email = match User::find_by_uuid(user_uuid, conn).await {
                    Some(u) => u.email,
                    None => err!("User does not exist"),
                };

                let (signature, host) = duo::generate_duo_signature(&email, conn).await?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Host": host,
                    "Signature": signature,
                });
            }

            Some(tf_type @ TwoFactorType::YubiKey) => {
                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, conn).await {
                    Some(tf) => tf,
                    None => err!("No YubiKey devices registered"),
                };

                let yubikey_metadata: yubikey::YubikeyMetadata = serde_json::from_str(&twofactor.data)?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Nfc": yubikey_metadata.Nfc,
                })
            }

            Some(tf_type @ TwoFactorType::Email) => {
                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, conn).await {
                    Some(tf) => tf,
                    None => err!("No twofactor email registered"),
                };

                // Send email immediately if email is the only 2FA option
                if providers.len() == 1 {
                    email::send_token(user_uuid, conn).await?
                }

                let email_data = email::EmailTokenData::from_json(&twofactor.data)?;
                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Email": email::obscure_email(&email_data.email),
                })
            }

            _ => {}
        }
    }

    Ok(result)
}

#[post("/accounts/prelogin", data = "<data>")]
async fn prelogin(data: JsonUpcase<PreloginData>, conn: DbConn) -> Json<Value> {
    _prelogin(data, conn).await
}

#[post("/accounts/register", data = "<data>")]
async fn identity_register(data: JsonUpcase<RegisterData>, conn: DbConn) -> JsonResult {
    _register(data, conn).await
}

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default, FromForm)]
#[allow(non_snake_case)]
struct ConnectData {
    #[field(name = uncased("grant_type"))]
    #[field(name = uncased("granttype"))]
    grant_type: String, // refresh_token, password, client_credentials (API key)

    // Needed for grant_type="refresh_token"
    #[field(name = uncased("refresh_token"))]
    #[field(name = uncased("refreshtoken"))]
    refresh_token: Option<String>,

    // Needed for grant_type = "password" | "client_credentials"
    #[field(name = uncased("client_id"))]
    #[field(name = uncased("clientid"))]
    client_id: Option<String>, // web, cli, desktop, browser, mobile
    #[field(name = uncased("client_secret"))]
    #[field(name = uncased("clientsecret"))]
    client_secret: Option<String>,
    #[field(name = uncased("password"))]
    password: Option<String>,
    #[field(name = uncased("scope"))]
    scope: Option<String>,
    #[field(name = uncased("username"))]
    username: Option<String>,

    #[field(name = uncased("device_identifier"))]
    #[field(name = uncased("deviceidentifier"))]
    device_identifier: Option<String>,
    #[field(name = uncased("device_name"))]
    #[field(name = uncased("devicename"))]
    device_name: Option<String>,
    #[field(name = uncased("device_type"))]
    #[field(name = uncased("devicetype"))]
    device_type: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("device_push_token"))]
    #[field(name = uncased("devicepushtoken"))]
    _device_push_token: Option<String>, // Unused; mobile device push not yet supported.

    // Needed for two-factor auth
    #[field(name = uncased("two_factor_provider"))]
    #[field(name = uncased("twofactorprovider"))]
    two_factor_provider: Option<i32>,
    #[field(name = uncased("two_factor_token"))]
    #[field(name = uncased("twofactortoken"))]
    two_factor_token: Option<String>,
    #[field(name = uncased("two_factor_remember"))]
    #[field(name = uncased("twofactorremember"))]
    two_factor_remember: Option<i32>,
    #[field(name = uncased("authrequest"))]
    auth_request: Option<String>,
    // Needed for authorization code
    #[form(field = uncased("code"))]
    code: Option<String>,
}
fn _check_is_some<T>(value: &Option<T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}

// Deprecated but still needed for Mobile apps
#[get("/account/prevalidate")]
fn _prevalidate() -> JsonResult {
    prevalidate()
}

#[get("/sso/prevalidate")]
fn prevalidate() -> JsonResult {
    let claims = auth::generate_ssotoken_claims();
    let sso_token = auth::encode_jwt(&claims);
    Ok(Json(json!({
        "token": sso_token,
    })))
}

#[get("/connect/oidc-signin?<code>&<state>", rank = 1)]
fn oidcsignin(code: String, state: String, jar: &CookieJar<'_>) -> ApiResult<Redirect> {
    sso::format_bitwarden_redirect(&code, &state, jar)
}

// To display the error we wrap it as JWT token
#[get("/connect/oidc-signin?<error>&<error_description>&<state>", rank = 2)]
fn oidcsignin_error(
    error: String,
    error_description: Option<String>,
    state: String,
    jar: &CookieJar<'_>,
) -> ApiResult<Redirect> {
    let as_token = sso::wrap_sso_errors(error, error_description);
    sso::format_bitwarden_redirect(&as_token, &state, jar)
}

#[derive(Debug, Clone, Default, FromForm)]
struct AuthorizeData {
    #[allow(unused)]
    client_id: Option<String>,
    #[field(name = uncased("redirect_uri"))]
    #[field(name = uncased("redirecturi"))]
    redirect_uri: String,
    #[allow(unused)]
    response_type: Option<String>,
    #[allow(unused)]
    scope: Option<String>,
    state: String,
    #[allow(unused)]
    code_challenge: Option<String>,
    #[allow(unused)]
    code_challenge_method: Option<String>,
    #[allow(unused)]
    response_mode: Option<String>,
    #[allow(unused)]
    domain_hint: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("ssoToken"))]
    sso_token: Option<String>,
}

// The `redirect_uri` will change depending of the client (web, android, ios ..)
#[get("/connect/authorize?<data..>")]
async fn authorize(data: AuthorizeData, jar: &CookieJar<'_>, conn: DbConn) -> ApiResult<Redirect> {
    let AuthorizeData {
        redirect_uri,
        state,
        ..
    } = data;

    let cookie = Cookie::build((sso::COOKIE_NAME_REDIRECT.to_string(), redirect_uri))
        .max_age(rocket::time::Duration::minutes(5))
        .same_site(rocket::http::SameSite::Lax)
        .http_only(true);

    jar.add(cookie);

    let auth_url = sso::authorize_url(conn, state).await?;

    Ok(Redirect::temporary(String::from(auth_url)))
}
