# Change Log

## [Unreleased]

### Security

- Auto linking and `rebeloidc:keycloak-sync` no longer link an account to a Matomo user because the names are the same. The provider also has to report the email address of the Matomo user, as verified.
- Linking an account to the user that is logged in needs a confirmed password.
- "Disable password confirmation" only applies after the provider identified the user of the session. Before, any account of the provider turned the confirmation off.
- New users are only created with an email address the provider reports as verified. If your provider does not send `email_verified`, see the new setting "Trust email addresses the provider has not verified".
- The ID token is checked: it has to be issued for the client ID, not be expired, belong to the login that was started and, with the new setting "Issuer", come from that issuer. The user info has to be about the same user.
- The login uses PKCE and a nonce.
- The authorize, token and userinfo URLs have to use HTTPS. `[RebelOIDC] allow_http = 1` in `config.ini.php` allows HTTP for a test setup.
- The FAQ no longer recommends a redirect URI pattern that matches every URL.

### Added

- Setting "Email attribute", for providers that have the email address in another field than `email`. #21

### Changed

- Auto linking finds the Matomo user by the verified email address of the provider. The user ID of the provider no longer has to be the Matomo username. #14, #20

### Fixed

- After logging out at the provider the browser is sent back to Matomo. #49
- Login works when the access token is not a JWT, as with GitHub.
- Tokens with characters outside ASCII in their claims are read correctly.

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
