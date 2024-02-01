# Fork from [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)

Goal is to help testing code for the SSO [PR](https://github.com/dani-garcia/vaultwarden/pull/3899).
Based on [Timshel/sso-support](https://github.com/Timshel/vaultwarden/tree/sso-support)

#### :warning: Branch will be rebased and forced-pushed when updated. :warning:

## Additionnal features

This branch now contain features not added to the SSO [PR](https://github.com/dani-garcia/vaultwarden/pull/3899) since it would slow even more it's review.

### Role mapping

Allow to map roles from the Access token to users to grant access to `VaultWarden` `admin` console.
Support two roles: `admin` or `user`.

This feature is controlled by the following conf:

- `SSO_ROLES_ENABLED`: control if the mapping is done, default is `false`
- `SSO_ROLES_DEFAULT_TO_USER`: do not block login in case of missing or invalid roles, default is `true`.
- `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the Access token


### Group/Organization invitation mapping

Allow to invite user to existing Oganization if they are listed in the Access token.
If activated it will check if the token contain a list of potential Orgnaization.
If an Oganization with a matching name (case sensitive) is found it will the start the invitation process for this user.
It will use the email associated with the Organization to send further notifications (admin side).

The flow look like this:

- Decode the JWT Access token and check if a list of organization is present (default path is `/groups`).
- Check if an Organization with a matching name exist and the user is not part of it.
- Depending on `SSO_ACCEPTALL_INVITES` :
- `false` - Invite the user to the Orgnization
  - The user will need to click on the link in the mail he received
  - A notification is sent tto he `email` associated with the Organization that a new user is ready to join
  - An admin will have to validate the user to finalize the user joining the org.
- `true` - Add the user to the Organization
  - A notification is sent to the user to inform of the enrollment in the org
  - A notification is sent to the `email` associated with the Organization that a new user is ready to join
  - An admin will have to validate the user to confirm the user joining the org.

If email are disabled then the user will silently be enrolled and the admin will need to check the org to finish the process.

One of the bonus of invitation is that if an organization define a specific password policy then it will apply to new user when they set their new master password.
If a user is part of two organizations then it will order them using the role of the user (`Owner`, `Admin`, `User` or `Manager` for now manager is last :() and return the password policy of the first one.

This feature is controlled with the following conf:

- `SSO_SCOPES`: Optional scope override if additionnal scopes are needed, default is `"email profile"`
- `SSO_ORGANIZATIONS_INVITE`: control if the mapping is done, default is `false`
- `SSO_ORGANIZATIONS_TOKEN_PATH`: path to read groups/organization in the Access token, default is `/groups`


## Additionnal features

This branch now contain additionnal features not added to the SSO [PR](https://github.com/dani-garcia/vaultwarden/pull/3899) since it would slow even more it's review.

### Role mapping

Allow to map roles from the Access token to users to grant access to `VaultWarden` `admin` console.
Support two roles: `admin` or `user`.

This feature is controlled by the following conf:

- `SSO_ROLES_ENABLED`: control if the mapping is done, default is `false`
- `SSO_ROLES_DEFAULT_TO_USER`: do not block login in case of missing or invalid roles, default is `true`.
- `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the Access token

## Docker

Change the docker files to package both front-end from [Timshel/oidc_web_builds](https://github.com/Timshel/oidc_web_builds/releases).
\
By default it will use the release which only make the `sso` button visible.

If you want to use the version with the additional features mentionned, default redirection to `/sso` and fix organization invitation.
You need to pass an env variable: `-e SSO_FRONTEND='override'` (cf [start.sh](docker/start.sh)).

Docker images available at:

 - Docker hub [hub.docker.com/r/oidcwarden/vaultwarden-oidc](https://hub.docker.com/r/oidcwarden/vaultwarden-oidc/tags)
 - Github container registry [ghcr.io/timshel/vaultwarden](https://github.com/Timshel/vaultwarden/pkgs/container/vaultwarden)

### Front-end version

By default front-end version is fixed to prevent regression (check [CHANGELOG.md](CHANGELOG.md)).
\
When building the docker image it can be overrided by passing the `OIDC_WEB_RELEASE` arg.
\
Ex to build with latest: `--build-arg OIDC_WEB_RELEASE="https://github.com/Timshel/oidc_web_builds/releases/latest/download"`

## To test VaultWarden with Keycloak

[Readme](test/oidc/README.md)

## Experimental version

### Stop storing Master Password hash

This allow to stop storing the Master password in the server database.
This is a work in progress and released for testing.
Once activated newly created account will no longer store a master password hash, making reverting to a standard VaultWarden instance troublesome.

#### To activate

 - `SSO_EXPERIMENTAL_NO_MASTER_PWD`: Control the activation of the feature. Default `false`.

Additionnaly a new web build is available which stop sending the hash cf `experimental` in [Timshel/oidc_web_builds](https://github.com/Timshel/oidc_web_builds/releases)
You'll need to pass an env variable: `-e SSO_FRONTEND='experimental'` (cf [start.sh](docker/start.sh)).

#### To revert

You'll first need to run the server without the `experimental` front-end.
\
You can then go to `Account settings \ Security \ Keys` and trigger the `Change KDF`.
\
This endpoint is not modified and will save the new master password hash, every user will need to do this to restore a Master password in db.

## DB Migration

ATM The migrations add an independant table `sso_nonce` and a column `invited_by_email` to `users_organizations`.

### Revert to default VW

Reverting to the default VW DB state can easily be done manually (Make a backup :) :

```psql
>BEGIN;
BEGIN
>DELETE FROM __diesel_schema_migrations WHERE version in ('20230910133000', '20230914133000');
DELETE 2
>DROP TABLE sso_nonce;
DROP TABLE
>ALTER TABLE users_organizations DROP COLUMN invited_by_email;
ALTER TABLE
> COMMIT / ROLLBACK;
```

### FROM old PR Version

:warning: Changed the past migration creating the `sso_nonce` table in a recent [commit](https://github.com/Timshel/vaultwarden/commit/afa26f3cf5a39ff0bc4c3cbe563cfcfaf91b40a0).:warning: <br>
If you already deployed the previous version you'll need to do some manual cleanup :

```psql
>BEGIN;
BEGIN
>DELETE FROM __diesel_schema_migrations WHERE version = '20230201133000';
DELETE 1
>DROP TABLE sso_nonce;
DROP TABLE
> COMMIT / ROLLBACK;
```

Then the new migration will play without issue.
