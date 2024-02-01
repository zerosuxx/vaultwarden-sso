# SSO using OpenId Connect

To use an external source of authentication your SSO will need to support OpenID Connect :

 - And OpenID Connect Discovery endpoint should be available
 - Client authentication will be done using Id and Secret.

A master password will still required and not controlled by the SSO (depending of your point of view this might be a feature ;).
This introduce another way to control who can use the vault without having to use invitation or using an LDAP.

## Configuration

The following configurations are available

 - `SSO_ENABLED` : Activate the SSO
 - `SSO_ONLY` : disable email+Master password authentication
 - `SSO_AUTHORITY` : the OpendID Connect Discovery endpoint of your SSO
 	- Should not include the `/.well-known/openid-configuration` part and no trailing `/`
 	- $SSO_AUTHORITY/.well-known/openid-configuration should return the a json document: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
 - `SSO_SCOPES` : Optional, allow to override scopes if needed (default `"email profile"`)
 - `SSO_CLIENT_ID` : Client Id
 - `SSO_CLIENT_SECRET` : Client Secret
 - `SSO_KEY_FILEPATH` : Optional public key to validate the JWT token (without it signature check will not be done).
 - `SSO_MASTER_PASSWORD_POLICY`: Optional Master password policy
 - `SSO_ROLES_ENABLED`: control if the mapping is done, default is `false`
 - `SSO_ROLES_DEFAULT_TO_USER`: do not block login in case of missing or invalid roles, default is `true`.
 - `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the Access token
 - `SSO_ORGANIZATIONS_INVIT`: control if the mapping is done, default is `false`
 - `SSO_ORGANIZATIONS_TOKEN_PATH`: path to read groups/organization in the Access token

The callback url is : `https://your.domain/identity/connect/oidc-signin`

## Configuration example using GitLab

Create an application in your Gitlab Settings with

- `redirectURI`: https://your.domain/identity/connect/oidc-signin
- `Confidential`: `true`
- `scopes`: `openid`, `profile`, `email`

Then configure your server with `SSO_AUTHORITY=https://gitlab.com`, `SSO_CLIENT_ID` and `SSO_CLIENT_SECRET`.

## Configuration hints using Google

Google [Documentation](https://developers.google.com/identity/openid-connect/openid-connect).
Then configure your server with `SSO_AUTHORITY=https://accounts.google.com`, `SSO_CLIENT_ID` and `SSO_CLIENT_SECRET`.

## Microsoft Entra ID

1. Create an "App registration" in [Entra ID](https://entra.microsoft.com/) following [Identity | Applications | App registrations](https://entra.microsoft.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade/quickStartType//sourceType/Microsoft_AAD_IAM).
2. From the "Overview" of your "App registration", you'll need the "Directory (tenant) ID" for the `SSO_AUTHORITY` variable and the "Application (client) ID" as the `SSO_CLIENT_ID` value.
3. In "Certificates & Secrets" create an "App secret" , you'll need the "Secret Value" for the `SSO_CLIENT_SECRET` variable.
4. In "Authentication" add https://vaultwarden.example.org/identity/connect/oidc-signin as "Web Redirect URI".
5. In "API Permissions" make sure you have `profile`, `email` and `offline_access` listed under "API / Permission name" (`offline_access` is required, otherwise no refresh_token is returned, see https://github.com/MicrosoftDocs/azure-docs/issues/17134).

Only the v2 endpooint is compliant with the OpenID spec, see https://github.com/MicrosoftDocs/azure-docs/issues/38427 and https://github.com/ramosbugs/openidconnect-rs/issues/122.

Your configuration should look like this:

* `SSO_AUTHORITY=https://login.microsoftonline.com/${Directory (tenant) ID}/v2.0`
* `SSO_SCOPES="email profile offline_access"`
* `SSO_CLIENT_ID=${Application (client) ID}`
* `SSO_CLIENT_SECRET=${Secret Value}`

## Session lifetime

Session lifetime is dependant on refresh token and access token returned after calling your sso token endpoint (grant type `authorization_code`).
If no refresh token is returned then the session will be limited to the access token lifetime.

Tokens are not persisted in VaultWarden but wrapped in JWT tokens and returned to the application (The `refresh_token` and `access_token` values returned by VW `identity/connect/token` endpoint).
Note that VaultWarden will always return a `refresh_token` for compatibility reasons with the web front and it presence does not indicate that a refresh token was returned by your sso (But you can decode its value with https://jwt.io and then check if the `token` field contain anything).

With a refresh token present, activity in the application will trigger a refresh of the access token when it's close to expiration ([5min](https://github.com/bitwarden/clients/blob/0bcb45ed5caa990abaff735553a5046e85250f24/libs/common/src/auth/services/token.service.ts#L126) in web client).

Additionnaly for certain action a token check is performed, if we have a refresh token we will perform a refresh otherwise we'll call the user information endpoint to check the access token validity.

### Debug information

Running with `LOG_LEVEL=debug` you'll be able to see information on token expiration.
