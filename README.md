# Rebel OIDC plugin for Matomo

![UNIT tests](https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/actions/workflows/ci-pipeline.yml/badge.svg)
![phpcs](https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/actions/workflows/phpcs.yaml/badge.svg)
![semgrep oss scan](https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/actions/workflows/semgrep.yaml/badge.svg)

## Description

Login to Matomo with third party authentication services that provides Open ID Connect (OIDC). Check in [FAQ](docs/faq.md) for details on how to connect.

## Installation

Put the files from this repo in <MATOMO_INSTALLATION>/plugins/RebelOIDC and activate it.

Go to the system settings and add needed settings to get things working. See the [faq](docs/faq.md) for hints how to setup your OIDC application.

## Sync users

### Keycloak user import

A console command can be used to sync users from Keycloak to Matomo:

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret
```

Recommendation is to use a service account in Keycloak for the operation, set it up so it has the right permissions so you could fetch the users.

The console command overwrites the defaults for user creation in system settings, so make sure you match the settings you have when you run the command.

You can specify which field to use for username, and if add default view permissions on one site, like:

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret --user-field=email --id-site=1
```

Default field to use for user name is `id` when running the console command.

Hopefully. more integrations to other supported OIDC authenticators will be added further on.

## Fork

This plugin started as a fork of the [LoginOIDC](https://github.com/dominik-th/matomo-plugin-LoginOIDC) plugin. We are happy to continue the work that [dominik-th](https://github.com/dominik-th/) started. We also hope to get contributions in.

## License

GNU General Public License v3.0
