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

The easiest way is to set the `Discovery URL` of your provider, `<YOUR_PROVIDER_URL>/.well-known/openid-configuration`. The plugin then reads the other URLs, the issuer and the keys from there, and only accepts ID tokens the provider issued and signed. Without it, fill in the URLs yourself, and set `Issuer` and `Keys URL` to get the same checks. The URLs have to start with `https://`. See the [faq](docs/faq.md).

### Linking existing users

A user that already exists in Matomo logs in with the password and links the account of the provider under Personal -> Security. Matomo asks for the password before linking.

With `Enable auto linking` this happens at the first login instead, when the provider reports the email address of the Matomo user as verified.

### Username Attribute from OIDC

You can use any claim, like preferred_username, id etc. to create the Matomo user name.

[Standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)

### Initial site

You can set an initial site for all new users which logs in with OIDC for the first time. Default is set to "none", which means that the first a user logs in and has no permissions set, they will get an error and a notification that they need to contact the admin of the site.

### Restrict user login with specific role

If you have an organisation where not all in the organisations should have access, you can choose which role should have access to Matomo. The role needs to be part of the JWT token (default behavior in many OIDC providers, otherwise you need to configure it).

## Roles

The plugin reads the roles of a user from the tokens and the user info. Without further settings it looks where Keycloak (`realm_access.roles`, `resource_access.<client ID>.roles`) and Microsoft Entra ID (`roles`) have them. If your provider has roles or groups in another claim, set `Roles claim` to its name, for example `groups`. A claim inside another is written with dots.

Roles are used for three things: restricting login to a role, access to websites, and super user access.

## Fine-grained permissions

With `Use fine-grained permissions` ticked, the provider decides which websites a user has access to. At every login, access is added and removed to match what the provider sends. Access given in Matomo is removed.

The provider sends access as paths in the format `/matomo/<siteID>/<permission>`, where the permission is `admin`, `write` or `view` and the site ID can be `all`:

- in a claim named `matomo-permission-path`. In Keycloak, create a group/childgroup hierarchy and add a group mapper with that claim name to the Matomo client.
- as roles, written as `/matomo/<siteID>/<permission>` or `matomo.<siteID>.<permission>`. Use this when your provider cannot add a claim of your own, as Microsoft Entra ID.

The highest permission a user gets for a website counts.

## Super user access by role

`Role that gives super user access` makes every user with that role a super user, and takes super user access away at the next login without the role. Everyone who can hand out that role at your provider can then take full control over Matomo, so leave it empty unless that is what you want. Keep one super user that logs in with a password, in case the provider cannot be reached. Do not combine it with the setting that keeps super users from logging in with OIDC.

## Passwords

With `Linked users cannot set a password`, a user that is linked to an account of the provider cannot change or reset the Matomo password. A super user can still set a password for another user.

## Sync users

### Keycloak

This function is in beta, and should be handled with care.

A console command can be used to sync users from Keycloak to Matomo. While this is not using OIDC, it is something that could be used to import or sync your users to Matomo to be able to set user permissions etc. before they login the first time. If you rerun the Keycloak sync, and user already exists, it will not import it again. A user that exists in Matomo is only linked when Keycloak has the same email address for it and has verified it.

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret
```

Recommendation is to use a service account in Keycloak for the operation, set it up so it has the right permissions so you could fetch the users: the roles `view-users` and `query-users` of the client `realm-management`. Recent versions of Keycloak also want the client scope `kc-admin-api` on the client of the service account, and answer with `401` without it.

The console command overwrites the defaults for user creation in system settings, so make sure you match the settings you have when you run the command.

You can specify which field to use for username, and add default view permissions on one site, like:

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret --user-field=email --id-site=1
```

Default field to use for user name is `id` when running the console command.

Hopefully. more integrations to other supported OIDC authenticators will be added further on (contributions are more than welcome!).

## Tests

The tests log in with the answers of each supported provider, kept in `tests/resources/providers`, and at a real Keycloak when one is running. Start one with the realm of the tests and tell the tests where it is:

```sh
docker run -d -p 8080:8080 -v "$PWD/tests/keycloak:/opt/keycloak/data/import:ro" quay.io/keycloak/keycloak:<tag> start-dev --import-realm
KEYCLOAK_URL=http://localhost:8080 ./console tests:run RebelOIDC
```

Without `KEYCLOAK_URL` the tests that need Keycloak are skipped.

## Fork

This plugin started as a fork of the [LoginOIDC](https://github.com/dominik-th/matomo-plugin-LoginOIDC) plugin. We are happy to continue the work that [dominik-th](https://github.com/dominik-th/) started. We also hope to get contributions in.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
