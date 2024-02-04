use chrono::Utc;
use rocket::{http::CookieJar, response::Redirect};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;
use url::Url;

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

use jsonwebtoken::errors::ErrorKind::InvalidKeyFormat;
use jwt_authorizer::{Authorizer, JwtAuthorizer};
use mini_moka::sync::Cache;
use once_cell::sync::{Lazy, OnceCell};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessToken, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IdToken, Nonce,
    OAuth2TokenResponse, RefreshToken, Scope,
};
use regex::Regex;
use serde::de::DeserializeOwned;

use crate::{api::core::organizations::CollectionData, api::ApiResult, auth, auth::{AuthMethodScope, ClientIp, TokenWrapper, DEFAULT_REFRESH_VALIDITY}, business::organization_logic, db::models::{Device, EventType, Organization, SsoNonce, User, UserOrgType, UserOrganization}, db::DbConn, CONFIG};

pub static COOKIE_NAME_REDIRECT: &str = "sso_redirect_url";
pub static FAKE_IDENTIFIER: &str = "VaultWarden";

static AC_CACHE: Lazy<Cache<String, AuthenticatedUser>> =
    Lazy::new(|| Cache::builder().max_capacity(1000).time_to_live(Duration::from_secs(10 * 60)).build());

static CLIENT_CACHE: RwLock<Option<CoreClient>> = RwLock::new(None);

static SSO_JWT_VALIDATION: Lazy<Decoding> = Lazy::new(prepare_decoding);
static SSO_JWT_AUTHORIZER: OnceCell<Authorizer> = OnceCell::new();
static DEFAULT_BW_EXPIRATION: Lazy<chrono::Duration> = Lazy::new(|| chrono::Duration::minutes(5));
static SSO_ERRORS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^error_(.*)$").unwrap());

// Will Panic if SSO is activated and a key file is present but we can't decode its content
pub fn pre_load_sso_jwt_validation() {
    Lazy::force(&SSO_JWT_VALIDATION);
}

pub async fn pre_load_sso_jwt_authorizer() {
    if !CONFIG.sso_enabled() || !CONFIG.sso_jwt_authorizer_enabled() {
        return;
    }

    let authorizer_result = JwtAuthorizer::from_oidc(CONFIG.sso_authority().as_str())
        .refresh(Default::default())
        .validation(jwt_authorizer::Validation {
            aud: Some(vec![CONFIG.sso_client_id()]),
            ..Default::default()
        })
        .build()
        .await;

    match authorizer_result {
        Ok(r) => {
            let _ = SSO_JWT_AUTHORIZER.set(r);
        },
        Err(e) => {
            panic!("Failed to initialize JWT Authorizer: {:?}", e);
        }
    }
}

#[rocket::async_trait]
trait CoreClientExt {
    async fn _get_client() -> ApiResult<CoreClient>;
    async fn cached() -> ApiResult<CoreClient>;
    async fn user_info_async(&self, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims>;
}

#[rocket::async_trait]
impl CoreClientExt for CoreClient {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn _get_client() -> ApiResult<CoreClient> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
            Err(err) => err!(format!("Failed to discover OpenID provider: {err}")),
            Ok(metadata) => metadata,
        };

        Ok(CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(CONFIG.sso_redirect_url()?))
    }

    // Simple cache to prevent recalling the discovery endpoint each time
    async fn cached() -> ApiResult<CoreClient> {
        let cc_client = CLIENT_CACHE.read().ok().and_then(|rw_lock| rw_lock.clone());
        match cc_client {
            Some(client) => Ok(client),
            None => Self::_get_client().await.map(|client| {
                let mut cached_client = CLIENT_CACHE.write().unwrap();
                *cached_client = Some(client.clone());
                client
            }),
        }
    }

    async fn user_info_async(&self, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims> {
        let endpoint = match self.user_info(access_token, None) {
            Err(err) => err!(format!("No user_info endpoint: {err}")),
            Ok(endpoint) => endpoint,
        };

        match endpoint.request_async(async_http_client).await {
            Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
            Ok(user_info) => Ok(user_info),
        }
    }
}

// The `nonce` allow to protect against replay attacks
pub async fn authorize_url(mut conn: DbConn, state: String) -> ApiResult<Url> {
    let scopes = CONFIG.sso_scopes_vec().into_iter().map(Scope::new);

    let (auth_url, _csrf_state, nonce) = CoreClient::cached()
        .await?
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(state),
            Nonce::new_random,
        )
        .add_scopes(scopes)
        .url();

    let sso_nonce = SsoNonce::new(nonce.secret().to_string());
    sso_nonce.save(&mut conn).await?;

    Ok(auth_url)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IdTokenPayload {
    exp: i64,
    email: Option<String>,
    nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasicTokenPayload {
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: i64,
}

impl BasicTokenPayload {
    fn nbf(&self) -> i64 {
        self.nbf.or(self.iat).unwrap_or_else(|| Utc::now().naive_utc().timestamp())
    }
}

#[derive(Debug)]
struct AccessTokenPayload {
    role: Option<UserRole>,
    groups: Vec<String>,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub nonce: String,
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub expires_in: Option<Duration>,
    pub email: String,
    pub user_name: Option<String>,
    pub role: Option<UserRole>,
    pub groups: Vec<String>,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role.as_ref().is_some_and(|x| x == &UserRole::Admin)
    }
}

struct Decoding {
    key: DecodingKey,
    id_validation: Validation,
    access_validation: Validation,
    debug_key: DecodingKey,
    debug_validation: Validation,
}

impl Decoding {
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        let mut access_validation = validation.clone();
        access_validation.validate_aud = false;

        let mut debug_validation = insecure_validation();
        debug_validation.validate_aud = false;

        Decoding {
            key,
            id_validation: validation,
            access_validation,
            debug_key: DecodingKey::from_secret(&[]),
            debug_validation,
        }
    }

    pub async fn id_token<
        AC: openidconnect::AdditionalClaims,
        GC: openidconnect::GenderClaim,
        JE: openidconnect::JweContentEncryptionAlgorithm<JT>,
        JS: openidconnect::JwsSigningAlgorithm<JT>,
        JT: openidconnect::JsonWebKeyType,
    >(
        &self,
        oic_id_token: Option<&IdToken<AC, GC, JE, JS, JT>>,
    ) -> ApiResult<IdTokenPayload> {
        let id_token_str = match oic_id_token {
            None => err!("Token response did not contain an id_token"),
            Some(token) => token.to_string(),
        };

        match self.decode_token::<IdTokenPayload>(id_token_str.as_str(), &self.id_validation).await {
            Ok(claims) => Ok(claims),
            Err(err) => {
                self.log_debug("identity_token", id_token_str.as_str());
                err!(format!("Could not decode id token: {err}"))
            }
        }
    }

    // Errors are logged but will return None
    fn roles(email: &str, token: &serde_json::Value) -> Option<UserRole> {
        if let Some(json_roles) = token.pointer(&CONFIG.sso_roles_token_path()) {
            match serde_json::from_value::<Vec<UserRole>>(json_roles.clone()) {
                Ok(mut roles) => {
                    roles.sort();
                    roles.into_iter().next()
                }
                Err(err) => {
                    debug!("Failed to parse user ({email}) roles: {err}");
                    None
                }
            }
        } else {
            debug!("No roles in {email} access_token");
            None
        }
    }

    // Errors are logged but will return an empty Vec
    fn groups(email: &str, token: &serde_json::Value) -> Vec<String> {
        if let Some(json_groups) = token.pointer(&CONFIG.sso_organizations_token_path()) {
            match serde_json::from_value::<Vec<String>>(json_groups.clone()) {
                Ok(groups) => groups,
                Err(err) => {
                    error!("Failed to parse user ({email}) groups: {err}");
                    Vec::with_capacity(0)
                }
            }
        } else {
            debug!("No groups in {email} access_token");
            Vec::with_capacity(0)
        }
    }

    async fn access_token(&self, email: &str, access_token: &AccessToken) -> ApiResult<AccessTokenPayload> {
        let mut role = None;
        let mut groups = Vec::new();

        if CONFIG.sso_roles_enabled() || CONFIG.sso_organizations_invite() {
            let access_token_str = access_token.secret();

            self.log_debug("access_token", access_token_str);

            match self.decode_token::<serde_json::Value>(access_token_str, &self.access_validation).await {
                Err(err) => err!(format!("Could not decode access token: {:?}", err)),
                Ok(claims) => {
                    if CONFIG.sso_roles_enabled() {
                        role = Self::roles(email, &claims);
                        if !CONFIG.sso_roles_default_to_user() && role.is_none() {
                            info!("User {email} failed to login due to missing/invalid role");
                            err!(
                                "Invalid user role. Contact your administrator",
                                ErrorEvent {
                                    event: EventType::UserFailedLogIn
                                }
                            )
                        }
                    }

                    if CONFIG.sso_organizations_invite() {
                        groups = Self::groups(email, &claims);
                    }
                }
            }
        }

        Ok(AccessTokenPayload {
            role,
            groups,
        })
    }

    pub async fn basic_token(&self, token_name: &str, token: &str) -> ApiResult<BasicTokenPayload> {
        match self.decode_token::<BasicTokenPayload>(token, &self.access_validation).await {
            Ok(claims) => Ok(claims),
            Err(err) => {
                self.log_debug(token_name, token);
                err_silent!(format!("Could not decode {token_name}: {err}"))
            }
        }
    }

    pub async fn decode_token<T: DeserializeOwned + Clone + Send>(&self, token: &str, validation: &Validation) -> Result<T, jsonwebtoken::errors::Error> {
        if CONFIG.sso_jwt_authorizer_enabled() {
            let authorizer = SSO_JWT_AUTHORIZER.get().unwrap();
            let header_result = decode_header(token);
            if header_result.is_err() {
                return Err(header_result.err().unwrap());
            }

            let key_result = authorizer.key_source.get_key(header_result.unwrap()).await;
            if key_result.is_err() {
                println!("[ERROR] Failed to load JSON Web Key: {:?}", key_result.err().unwrap());
                return Err(jsonwebtoken::errors::Error::from(InvalidKeyFormat));
            }

            match decode::<T>(token, &key_result.unwrap().key, &secure_validation()) {
                Ok(payload) => Ok(payload.claims),
                Err(err) => Err(jsonwebtoken::errors::Error::from(err.kind().clone())),
            }
        } else {
            match decode::<T>(token, &self.key, &validation) {
                Ok(payload) => Ok(payload.claims),
                Err(err) => Err(jsonwebtoken::errors::Error::from(err.kind().clone())),
            }
        }
    }

    pub fn log_debug(&self, token_name: &str, token: &str) {
        let _ = jsonwebtoken::decode::<serde_json::Value>(token, &self.debug_key, &self.debug_validation)
            .map(|payload| debug!("Token {token_name}: {}", payload.claims));
    }
}

fn secure_validation() -> Validation {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.leeway = 30;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_audience(&[CONFIG.sso_client_id()]);
    validation.set_issuer(&[CONFIG.sso_authority()]);

    validation
}

fn insecure_validation() -> Validation {
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&[CONFIG.sso_client_id()]);
    validation.insecure_disable_signature_validation();

    validation
}

// DecodingKey and Validation used to read the SSO JWT token response
// If there is no key fallback to reading without validation
fn prepare_decoding() -> Decoding {
    let maybe_key = CONFIG.sso_enabled().then_some(()).and_then(|_| match std::fs::read(CONFIG.sso_key_filepath()) {
        Ok(key) => Some(DecodingKey::from_rsa_pem(&key).unwrap_or_else(|e| {
            panic!(
                "Failed to decode optional SSO public RSA Key, format should exactly match:\n\
                -----BEGIN PUBLIC KEY-----\n\
                ...\n\
                -----END PUBLIC KEY-----\n\
                Error: {e}"
            );
        })),
        Err(err) => {
            println!("[INFO] Can't read optional SSO public key at {} : {err}", CONFIG.sso_key_filepath());
            None
        }
    });

    match maybe_key {
        Some(key) => Decoding::new(key, secure_validation()),
        None => Decoding::new(DecodingKey::from_secret(&[]), insecure_validation()),
    }
}

#[derive(Clone, Debug)]
pub struct UserInformation {
    pub email: String,
    pub user_name: Option<String>,
}

// Wrap the errors in a JWT token to be able to pass it as an OpenID response `code`
pub fn wrap_sso_errors(error: String, error_description: Option<String>) -> String {
    format!("error_{}", auth::generate_sso_error_claims(error, error_description))
}

// Check if the code is not in fact errors
fn unwrap_sso_erors(code: &str) -> Option<Result<auth::SSOCodeErrorClaims, crate::error::Error>> {
    SSO_ERRORS_REGEX.captures(code).and_then(|captures| captures.get(1).map(|ma| auth::decode_sso_error(ma.as_str())))
}

// Use URL to encode query parameters
pub fn format_bitwarden_redirect(code: &str, state: &str, jar: &CookieJar<'_>) -> ApiResult<Redirect> {
    let redirect_root = jar
        .get(COOKIE_NAME_REDIRECT)
        .map(|c| c.value().to_string())
        .unwrap_or(format!("{}/sso-connector.html", CONFIG.domain()));

    let mut url = match url::Url::parse(&redirect_root) {
        Err(err) => err!(format!("Failed to parse redirect url ({redirect_root}): {err}")),
        Ok(url) => url,
    };

    url.query_pairs_mut().append_pair("code", code).append_pair("state", state);

    debug!("Redirection to {url}");

    Ok(Redirect::temporary(String::from(url)))
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on the `AC_CACHE` since the `code` has already been exchanged.
// The `nonce` will ensure that the user is authorized only once.
// We return only the `UserInformation` to force calling `redeem` to obtain the `refresh_token`.
pub async fn exchange_code(code: &String) -> ApiResult<UserInformation> {
    match unwrap_sso_erors(code) {
        Some(Ok(auth::SSOCodeErrorClaims {
            error,
            error_description,
            ..
        })) => {
            let description = error_description.unwrap_or(String::new());
            err!(format!("Failed to login: {}, {}", error, description))
        }
        Some(Err(error)) => err!(format!("Failed to decode SSO error: {error}")),
        None => (),
    }

    if let Some(authenticated_user) = AC_CACHE.get(code) {
        return Ok(UserInformation {
            email: authenticated_user.email,
            user_name: authenticated_user.user_name,
        });
    }

    let oidc_code = AuthorizationCode::new(code.clone());
    let client = CoreClient::cached().await?;

    match client.exchange_code(oidc_code).request_async(async_http_client).await {
        Ok(token_response) => {
            let user_info = client.user_info_async(token_response.access_token().to_owned()).await?;
            let id_token = SSO_JWT_VALIDATION.id_token(token_response.extra_fields().id_token()).await?;
            let user_name = user_info.preferred_username().map(|un| un.to_string());

            let email = match id_token.email {
                Some(email) => email,
                None => match user_info.email() {
                    None => err!("Neither id token nor userinfo contained an email"),
                    Some(email) => email.to_owned().to_string(),
                },
            };

            let access_token = SSO_JWT_VALIDATION.access_token(&email, token_response.access_token()).await?;

            let refresh_token = token_response.refresh_token().map(|t| t.secret().to_string());
            if refresh_token.is_none() && CONFIG.sso_scopes_vec().contains(&"offline_access".to_string()) {
                error!("Scope offline_access is present but response contain no refresh_token");
            }

            let authenticated_user = AuthenticatedUser {
                nonce: id_token.nonce,
                refresh_token,
                access_token: token_response.access_token().secret().to_string(),
                expires_in: token_response.expires_in(),
                email: email.clone(),
                user_name: user_name.clone(),
                role: access_token.role,
                groups: access_token.groups,
            };

            AC_CACHE.insert(code.clone(), authenticated_user);

            Ok(UserInformation {
                email,
                user_name,
            })
        }
        Err(err) => err!(format!("Failed to contact token endpoint: {err}")),
    }
}

// User has passed 2FA flow we can delete `nonce` and clear the cache.
pub async fn redeem(code: &String, conn: &mut DbConn) -> ApiResult<AuthenticatedUser> {
    if let Some(au) = AC_CACHE.get(code) {
        AC_CACHE.invalidate(code);

        if let Some(sso_nonce) = SsoNonce::find(&au.nonce, conn).await {
            match sso_nonce.delete(conn).await {
                Err(msg) => err!(format!("Failed to delete nonce: {msg}")),
                Ok(_) => Ok(au),
            }
        } else {
            err!("Failed to retrive nonce from db")
        }
    } else {
        err!("Failed to retrieve user info from sso cache")
    }
}

// We always return a refresh_token (with no refresh_token some secrets are not displayed in the web front).
// If there is no SSO refresh_token, we keep the access_token to be able to call user_info to check for validity
pub async fn create_auth_tokens(
    device: &Device,
    user: &User,
    refresh_token: Option<String>,
    access_token: &str,
    expires_in: Option<Duration>,
) -> ApiResult<auth::AuthTokens> {
    let (ap_nbf, ap_exp) = match (SSO_JWT_VALIDATION.basic_token("access_token", access_token).await, expires_in) {
        (Ok(ap), _) => (ap.nbf(), ap.exp),
        (Err(_), Some(exp)) => {
            let time_now = Utc::now().naive_utc();
            (time_now.timestamp(), (time_now + exp).timestamp())
        }
        _ => err!("Non jwt access_token and empty expires_in"),
    };

    let access_claims = auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, auth::AuthMethod::Sso.scope_vec());

    _create_auth_tokens(device, refresh_token, access_claims, access_token).await
}

async fn _create_auth_tokens(
    device: &Device,
    refresh_token: Option<String>,
    access_claims: auth::LoginJwtClaims,
    access_token: &str,
) -> ApiResult<auth::AuthTokens> {
    let (nbf, exp, token) = if let Some(rt) = refresh_token.as_ref() {
        match SSO_JWT_VALIDATION.basic_token("refresh_token", rt).await {
            Err(_) => {
                let time_now = Utc::now().naive_utc();
                let exp = (time_now + *DEFAULT_REFRESH_VALIDITY).timestamp();
                debug!("Non jwt refresh_token (expiration set to {})", exp);
                (time_now.timestamp(), exp, TokenWrapper::Refresh(rt.to_string()))
            }
            Ok(refresh_payload) => {
                debug!("Refresh_payload: {:?}", refresh_payload);
                (refresh_payload.nbf(), refresh_payload.exp, TokenWrapper::Refresh(rt.to_string()))
            }
        }
    } else {
        debug!("No refresh_token present");
        (access_claims.nbf, access_claims.exp, TokenWrapper::Access(access_token.to_string()))
    };

    let refresh_claims = auth::RefreshJwtClaims {
        nbf,
        exp,
        iss: auth::JWT_LOGIN_ISSUER.to_string(),
        sub: auth::AuthMethod::Sso,
        device_token: device.refresh_token.clone(),
        token: Some(token),
    };

    Ok(auth::AuthTokens {
        refresh_claims,
        access_claims,
    })
}

// This endpoint is called in two case
//  - the session is close to expiration we will try to extend it
//  - the user is going to make an action and we check that the session is still valid
pub async fn exchange_refresh_token(
    device: &Device,
    user: &User,
    refresh_claims: &auth::RefreshJwtClaims,
) -> ApiResult<auth::AuthTokens> {
    match &refresh_claims.token {
        Some(TokenWrapper::Refresh(refresh_token)) => {
            let rt = RefreshToken::new(refresh_token.to_string());

            let client = CoreClient::cached().await?;

            let token_response = match client.exchange_refresh_token(&rt).request_async(async_http_client).await {
                Err(err) => err!(format!("Request to exchange_refresh_token endpoint failed: {:?}", err)),
                Ok(token_response) => token_response,
            };

            // Use new refresh_token if returned
            let rolled_refresh_token = token_response
                .refresh_token()
                .map(|token| token.secret().to_string())
                .unwrap_or(refresh_token.to_string());

            create_auth_tokens(
                device,
                user,
                Some(rolled_refresh_token),
                token_response.access_token().secret(),
                token_response.expires_in(),
            ).await
        }
        Some(TokenWrapper::Access(access_token)) => {
            let exp_limit = (Utc::now().naive_utc() + *DEFAULT_BW_EXPIRATION).timestamp();

            match SSO_JWT_VALIDATION.basic_token("access_token", access_token).await {
                Err(err) => err!(format!("Impossible to read access_token: {err}")),
                Ok(claims) if claims.exp < exp_limit => {
                    err_silent!("Access token is close to expiration but we have no refresh token")
                }
                Ok(claims) => {
                    let at = AccessToken::new(access_token.to_string());
                    let client = CoreClient::cached().await?;
                    match client.user_info_async(at).await {
                        Err(err) => err_silent!(format!(
                            "Failed to retrieve user info, token has probably been invalidated: {err}"
                        )),
                        Ok(_) => {
                            let access_claims = auth::LoginJwtClaims::new(
                                device,
                                user,
                                claims.nbf(),
                                claims.exp,
                                auth::AuthMethod::Sso.scope_vec(),
                            );
                            _create_auth_tokens(device, None, access_claims, access_token).await
                        }
                    }
                }
            }
        }
        None => err!("No token present while in SSO"),
    }
}

pub async fn sync_groups(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    groups: &Vec<String>,
    conn: &mut DbConn,
) -> ApiResult<()> {
    if CONFIG.sso_organizations_invite() {
        let db_user_orgs = UserOrganization::find_any_state_by_user(&user.uuid, conn).await;
        let user_orgs = db_user_orgs.iter().map(|uo| (uo.org_uuid.clone(), uo)).collect::<HashMap<_, _>>();

        // Only support `access_all=true` for groups/collections
        let org_groups: Vec<String> = Vec::with_capacity(0);
        let org_collections: Vec<CollectionData> = Vec::with_capacity(0);

        for group in groups {
            if let Some(org) = Organization::find_by_name(group, conn).await {
                if user_orgs.get(&org.uuid).is_none() {
                    info!("Invitation to {} organization sent to {}", group, user.email);
                    organization_logic::invite(
                        user,
                        device,
                        ip,
                        &org,
                        UserOrgType::User,
                        &org_groups,
                        true,
                        &org_collections,
                        org.billing_email.clone(),
                        conn,
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}
