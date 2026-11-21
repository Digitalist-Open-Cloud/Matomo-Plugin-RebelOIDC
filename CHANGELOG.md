# Change Log

## [Unreleased]

### Security

- Auto linking and `rebeloidc:keycloak-sync` no longer link an account to a Matomo user because the names are the same. The provider also has to report the email address of the Matomo user, as verified.
- Linking an account to the user that is logged in needs a confirmed password.
- "Disable password confirmation" only applies after the provider identified the user of the session. Before, any account of the provider turned the confirmation off.
- New users are only created with an email address the provider reports as verified. If your provider does not send `email_verified`, see the new setting "Trust email addresses the provider has not verified".
- The ID token is checked: it has to be issued for the client ID, not be expired, belong to the login that was started and, with the new setting "Issuer", come from that issuer. The user info has to be about the same user.
- The login uses PKCE and a nonce.
- The signature of the ID token is checked against the keys of the provider, when they are known: through the new setting "Keys URL" or the discovery URL. Based on the work of @tomper00 in #56.
- The authorize, token and userinfo URLs have to use HTTPS. `[RebelOIDC] allow_http = 1` in `config.ini.php` allows HTTP for a test setup.
- The FAQ no longer recommends a redirect URI pattern that matches every URL.

### Added

- Setting "Discovery URL": the provider's `.well-known/openid-configuration`. With it the authorize, token, userinfo and logout URLs and the issuer do not have to be filled in. #19
- Setting "Read the user from the ID token", for providers whose userinfo URL does not return the user's claims, as AD FS. #22
- Setting "Roles claim", for providers that have the roles or groups of the user in another claim than Keycloak and Microsoft Entra ID. #31
- Roles written as `matomo.<idSite>.<access>` or `/matomo/<idSite>/<access>` give access to websites, as the claim `matomo-permission-path` does. The site can be `all`. #31
- Setting "Role that gives super user access". #31
- Setting "Linked users cannot set a password". #24
- Setting "Email attribute", for providers that have the email address in another field than `email`. #21

### Changed

- With fine-grained permissions, the highest access the provider gives to a website counts, and websites that do not exist are skipped.
- Auto linking finds the Matomo user by the verified email address of the provider. The user ID of the provider no longer has to be the Matomo username. #14, #20

### Fixed

- A user without the role that is required sees a message. Before, the login page was shown without one.
- A user that logs in with the provider while logged in is sent on to Matomo, with the access the provider gives, instead of to an error.
- An email address with capital letters in its domain is accepted for sign-up when the domain is allowed.
- `rebeloidc:keycloak-sync` returns a failure code when it could not run or a user could not be synced, and reports users that are already synced as such.
- Matomo knows the table of the plugin, so it is not reported as unknown.
- The settings card under Personal -> Security is shown as a card again.
- Requests to the provider use Matomo's HTTP client, so the proxy and the certificates set in `config.ini.php` apply, and a provider that cannot be reached is reported. #46
- An error of the token URL is shown with its code instead of "Unexpected response".
- `rebeloidc:keycloak-sync` reads all users, not only the first 100.
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
