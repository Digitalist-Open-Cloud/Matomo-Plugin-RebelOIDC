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

### Keycloak

A console command can be used to sync users from Keycloak to Matomo:

```sh
./console rebeloidc:keycloak-sync --url=keycloak.url --realm=A-realm --client=a-keycloak-service-account --secret=a-secret
```

Recommendation is to use a service account in Keycloak for the operation, set it up so it has the right permissions so you could fetch the users.

## Fork

This plugin is a fork of the [LoginOIDC](https://github.com/dominik-th/matomo-plugin-LoginOIDC) plugin.

## License

GNU General Public License v3.0
