# Change Log

## [5.2.0] - 2026-11-19

No configuration change is required when upgrading: existing installations keep working as before. Token signature verification is opt-in. A login started before the upgrade and finished after it fails once (PKCE); just retry.

### Added

- PKCE (S256) is used in the authorization code flow.
- Optional token signature verification (RS256): set both `jwksUrl` and `issuer` in the settings to enable it. When both are empty the plugin works as before, without verification. Setting only one of them leaves the plugin unconfigured.
- Optional Keycloak group provisioning per site (`/matomo/<idsite>/{view,write,admin}`), including the console command `rebeloidc:keycloak-groups-sync` (with `--dry-run`) to reconcile sites and groups.
- New setting `disablePkce` for identity providers that reject PKCE parameters.

### Changed

- One generic login-failure message is shown on the login page; the reason is only written to the Matomo log.
- Outgoing requests to the identity provider now have timeouts.
- The site-change events `SitesManager.addSite.end`, `API.SitesManager.updateSite.end` and `SitesManager.deleteSite.end` are used when provisioning is enabled.

### Fixed

- Logins with opaque or encrypted (JWE) access tokens, and base64url decoding of tokens (`-` and `_`), which failed in 5.1.4-5.1.6.
- A failed or cancelled login no longer clears the OIDC session flags of a user who is already signed in.
- Strict parsing of the `matomo-permission-path` claim (`/matomo/<siteID>/<permission>`).
- The password-confirmation bypass flag is only set after a successful login.
- Removed the registration of an event handler that does not exist.

## [5.1.6] - 2026-02-04

### Added

- The access token is kept in a variable in the callback (#42). Thanks to @acassaro-traf for this contribution.

## [5.1.5] - 2026-02-03

### Fixed

- Token handling bug fixes, including permissions in the callback (#41).
- Removed dumping of users in the Keycloak sync command.

## [5.1.4] - 2026-02-03

### Fixed

- #35 Extract Roles from MS Entra ID tokens. Thanks to @acassaro-traf for this contribution.
- #39 Add decodedToken variable. Thanks to @acassaro-traf for this contribution.

## [5.1.3] - 2026-02-02

### Added

- Fine-Grained permissions for users based on claim - <https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/pull/32>. Thanks to @daniellienert for this contribution.

## [5.1.2] - 2026-02-01

### Changed

- If token is encrypted, it should now succeed. Thanks to @ fpellet for this contribution.

## [5.1.1] - 2025-01-18

### Added

- Possibility to configure which claim to use for user name in Matomo - like id, email, preferred_username etc.

## [5.1.0] - 2025-01-17

### Added

- This plugin was released, with several fixes from the pull request queue from the original plugin [LoginOIDC](https://github.com/dominik-th/matomo-plugin-LoginOIDC). Changes will from now be documented in the Change Log. Also some new functions were added, that were not in the LoginOIDC pull request queue. Also, this plugin is not a drop in replacement for LoginOIDC, you need to remove LoginOIDC and add and install this plugin instead.
