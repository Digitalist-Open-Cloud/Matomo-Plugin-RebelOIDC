# Rebel OIDC plugin for Matomo

![matomo](https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/actions/workflows/matomo.yaml/badge.svg)
![phpcs](https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/actions/workflows/phpcs.yaml/badge.svg)
![semgrep oss scan](https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/actions/workflows/semgrep.yaml/badge.svg)

## Description

Login to Matomo with third party authentication services that provides Open ID Connect (OIDC). Check in [FAQ](docs/faq.md) for details on how to connect with your provider.

## What is Rebel?

Rebel is short for RebelMetrics. RebelMetrics is Matomo on super charged batteries from Digitalist Open Cloud, with pre-configured dashboards, SQL-lab and more. We offer 1 month free trial for organizations and companies. If you are interested, email us at <cloud@digitalist.com> to book a demo.

## Installation

Install from Marketplace, or put the files from this repo in <MATOMO_INSTALLATION>/plugins/RebelOIDC and activate it.

## Setup

As an super user, go to Admin (cog wheel) -> System -> General settings -> Rebel OIDC.

For specific settings for your OIDC provider, see the [faq](docs/faq.md)

### Username Attribute from OIDC

You can use any claim, like preferred_username, id etc. to create the Matomo user name.

[Standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)

### Initial site

You can set an initial site for all new users which logs in with OIDC for the first time. Default is set to "none", which means that the first a user logs in and has no permissions set, they will get an error and a notification that they need to contact the admin of the site.

### Restrict user login with specific role

If you have an organisation where not all in the organisations should have access, you can choose which role should have access to Matomo. The role needs to be part of the JWT token (default behavior in many OIDC providers, otherwise you need to configure it).

## Token verification (recommended)

By default the plugin works without verifying tokens. We recommend enabling verification by setting both of these in Admin -> System -> General settings -> Rebel OIDC:

- **JWKS URL**: the provider's JSON Web Key Set, used to verify the RS256 signature of tokens.
- **Issuer**: the expected `iss` claim, exactly as the provider reports it.

When both are set, the ID token is required and verified (signature, issuer, expiry, audience), claims for roles and permissions are only read from verified tokens, and the userinfo `sub` must match the ID token. GitHub OAuth and other providers that are not OpenID Connect (no id_token, no JWKS) must leave both empty. When both are empty, the plugin behaves as in earlier versions. If only one of them is set, the plugin is treated as not configured. Nothing changes for existing installations until you set them.

Examples (replace the placeholders):

- Keycloak: JWKS URL `https://idp.example.com/realms/<realm>/protocol/openid-connect/certs`, issuer `https://idp.example.com/realms/<realm>`
- Entra ID: JWKS URL `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`, issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`

Your provider's discovery document (`/.well-known/openid-configuration`) lists the exact `jwks_uri` and `issuer` values.

## PKCE

The plugin uses PKCE (S256) in the authorization code flow. If your identity provider rejects the PKCE parameters (`code_challenge`, `code_verifier`), tick **Disable PKCE** in the settings.

## Fine-grained permissions

You can set fine-grained permissions for users through adding a `matomo-permission-path` claim.
In that claim, multiple permissions can be added as a path in the format `/matomo/<siteID>/<permission>`
Available permissions are `admin`, `write` and `view` .
If you are using Keycloak, this claim can be added to your token through creating a group/childgroup hierarchy and adding a custom group mapper for the matomo client.

Fine-grained permissions can be enabled in the settings in Admin (cog wheel) -> System -> General settings -> Rebel OIDC.

## Keycloak groups per site (optional)

The plugin can keep Keycloak groups in step with the sites in Matomo. With the group layout

```
/matomo/<idsite>/view
/matomo/<idsite>/write
/matomo/<idsite>/admin
```

and a group mapper that puts the group paths in the `matomo-permission-path` claim, access per site is managed in Keycloak (see Fine-grained permissions above).

Enable **Provision site groups in Keycloak** in the settings and fill in the Keycloak base URL, realm and a service-account client. The service account needs rights to view and manage groups in the realm (for example the `manage-users` and `query-groups` roles of the `realm-management` client). When enabled, groups are created, renamed and removed as sites are added, updated and deleted.

To reconcile existing sites and groups, run:

```sh
./console rebeloidc:keycloak-groups-sync --dry-run
./console rebeloidc:keycloak-groups-sync
```

`--dry-run` only reports what would change. We suggest running the command from cron to keep the groups in sync.

## Sync users

### Keycloak

This function is in beta, and should be handled with care.

A console command can be used to sync users from Keycloak to Matomo. While this is not using OIDC, it is something that could be used to import or sync your users to Matomo to be able to set user permissions etc. before they login the first time. If you rerun the Keycloak sync, and user already exists, it will not import it again.

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret
```

Recommendation is to use a service account in Keycloak for the operation, set it up so it has the right permissions so you could fetch the users.

The console command overwrites the defaults for user creation in system settings, so make sure you match the settings you have when you run the command.

You can specify which field to use for username, and add default view permissions on one site, like:

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret --user-field=email --id-site=1
```

Default field to use for user name is `id` when running the console command.

Hopefully. more integrations to other supported OIDC authenticators will be added further on (contributions are more than welcome!).

## Fork

This plugin started as a fork of the [LoginOIDC](https://github.com/dominik-th/matomo-plugin-LoginOIDC) plugin. We are happy to continue the work that [dominik-th](https://github.com/dominik-th/) started. We also hope to get contributions in.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
