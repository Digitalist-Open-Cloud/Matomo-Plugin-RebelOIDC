## FAQ

**What is the callback url?**

`http(s)://<YOUR_MATOMO_URL>/index.php?module=RebelOIDC&action=callback&provider=oidc`

**If I have existing users in Matomo, and adding RebelOIDC - how would I handle the existing users?**

In the system settings there is a checkbox to auto link users. With it, an account of the provider is linked to the Matomo user with the same email address the first time it logs in. The provider has to report the email address as verified (`email_verified`).

A user that is not linked this way can log in with the password and link the account under Personal -> Security. Matomo asks for the password first.

**My provider does not send `email_verified`. What now?**

Creating users and auto linking need an email address the provider vouches for. Some providers, for example Microsoft Entra ID and GitHub, do not send `email_verified`. If your users cannot set their email address at the provider themselves, tick `Trust email addresses the provider has not verified` in the settings. Otherwise leave it off: someone could use the email address of another person.

**Does the provider have to use HTTPS?**

Yes. The authorize, token and userinfo URLs have to start with `https://`, as the plugin trusts what it receives over that connection. For a test setup without HTTPS, add this to `config/config.ini.php`:

```ini
[RebelOIDC]
allow_http = 1
```

**What is the Issuer setting for?**

When it is set, a login is refused unless the ID token comes from that issuer. You find the value as `issuer` in `<YOUR_PROVIDER_URL>/.well-known/openid-configuration`. The plugin always checks that the ID token was issued for your client ID, has not expired and belongs to the login that was started.

**Where does the user end up after logging out?**

With a `Logout URL` set, logging out of Matomo also logs the user out of the provider, which then sends the browser back to Matomo, or to `login_logout_url` if that is set in `config/config.ini.php`. The provider has to allow that address as a post logout redirect URI. In Keycloak this is `Valid post logout redirect URIs` of the client.

**My provider has the email address in another field than `email`. What now?**

Set `Email attribute` to the name of that field. If the provider does not send `email_verified` with it, see the question about `email_verified` above.

**Can I keep the settings in `config.ini.php`?**

Yes. A setting that is in the `[RebelOIDC]` section of `config/config.ini.php` is used instead of the saved one and cannot be changed in the settings page. The names are those of the settings in `SystemSettings.php`, for example:

```ini
[RebelOIDC]
authorizeUrl = "https://<YOUR_PROVIDER_URL>/authorize"
tokenUrl = "https://<YOUR_PROVIDER_URL>/token"
userInfoUrl = "https://<YOUR_PROVIDER_URL>/userinfo"
clientId = "<CLIENT_ID>"
clientSecret = "<CLIENT_SECRET>"
scope = "openid email"
allowSignup = 1
```

**Do I have to fill in all the URLs of the provider?**

No. Set `Discovery URL` to `<YOUR_PROVIDER_URL>/.well-known/openid-configuration` and leave the authorize, token, userinfo and logout URLs and the issuer empty. The plugin reads them from there and keeps them for a day. A URL you do fill in is used instead of the published one.

**The userinfo URL of my provider only returns `sub`. What now?**

Tick `Read the user from the ID token`. The user ID, email address and username are then taken from the ID token, and the userinfo URL is not used. AD FS needs this.

**Matomo reaches the internet through a proxy, or my provider has a certificate of our own CA. What now?**

The plugin uses Matomo's HTTP client. Set the proxy in the `[proxy]` section and the CA bundle as `custom_cacert_pem` in the `[General]` section of `config/config.ini.php`.

**Is the signature of the ID token checked?**

Yes, when the plugin knows the keys of the provider: with a `Discovery URL`, or with `Keys URL` set to the `jwks_uri` of `<YOUR_PROVIDER_URL>/.well-known/openid-configuration`. A login is then refused unless the provider signed the ID token. Tokens signed with RS256, RS384, RS512 and ES256 are accepted. The keys are kept for a day and fetched again when a token is signed with a key that is not among them.

Roles and permissions in an access token are then only used when the provider signed that token as well. Some providers sign access tokens with keys they do not publish: have those send the roles in the ID token or the user info.

Without the keys, the plugin trusts the ID token because it receives it from the token URL over HTTPS.

**Which providers can I use?**

I tested the plugin with Auth0, GitHub and Keycloak, which work fine.
If your provider does not seem to work, leave an issue on GitHub.

**How can I unlink all users?**

The easiest way is to fully uninstall the plugin and reinstall afterwards.
Otherwise you can delete data from `matomo_rebeloidc_provider` in your sql database.

If you change the OAuth provider and there could be user id collisions, you should make sure to unlink all users beforehand.

**Can I embed the Login button on another website?**

You have to uncheck the `Disable direct login url` option in the settings.
Afterwards you can link to `http(s)://<YOUR_MATOMO_URL>/index.php?module=RebelOIDC&action=signIn&provider=oidc` and Matomo will redirect the client accordingly.

**Can I setup more than one provider?**

Currently that is **not** possible.
But you can use services like Auth0, which support multiple providers.

**I get a `Can't create table` error when installing the plugin**

Most likely you are using a very old Piwik installation, which still uses MyISAM tables.
Learn here on how to update the database engine:
https://matomo.org/faq/troubleshooting/faq_25610/

**What are the settings for ...?**

- GitHub:

  - Authorize URL: `https://github.com/login/oauth/authorize`
  - Token URL: `https://github.com/login/oauth/access_token`
  - Userinfo URL: `https://api.github.com/user`
  - Userinfo ID: `id`
  - OAuth Scopes: `<EMPTY>`

- Auth0:

  - Authorize URL: `https://<USERNAME>.eu.auth0.com/authorize`
  - Token URL: `https://<USERNAME>.eu.auth0.com/oauth/token`
  - Userinfo URL: `https://<USERNAME>.eu.auth0.com/userinfo`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid email`


- Keycloak (after 17.x):

  - Authorize URL: `http(s)://<YOUR_KEYCLOAK_URL>/realms/<REALM>/protocol/openid-connect/auth`
  - Token URL: `http(s)://<YOUR_KEYCLOAK_URL>/realms/<REALM>/protocol/openid-connect/token`
  - Userinfo URL: `http(s)://<YOUR_KEYCLOAK_URL>/realms/<REALM>/protocol/openid-connect/userinfo`
  - Logout URL: `http(s)://<YOUR_KEYCLOAK_URL>/realms/<REALM>/protocol/openid-connect/logout`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid email`

- Keycloak (before 17.x):

  - Authorize URL: `http(s)://<YOUR_KEYCLOAK_URL>/auth/realms/<REALM>/protocol/openid-connect/auth`
  - Token URL: `http(s)://<YOUR_KEYCLOAK_URL>/auth/realms/<REALM>/protocol/openid-connect/token`
  - Userinfo URL: `http(s)://<YOUR_KEYCLOAK_URL>/auth/realms/<REALM>/protocol/openid-connect/userinfo`
  - Logout URL: `http(s)://<YOUR_KEYCLOAK_URL>/auth/realms/<REALM>/protocol/openid-connect/logout`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid email`

- Gitlab (self-hosted Community Edition 12.6.2):

  - Authorize URL: `http(s)://<YOUR_GITLAB_URL>/oauth/authorize`
  - Token URL: `http(s)://<YOUR_GITLAB_URL>/oauth/token`
  - Userinfo URL: `http(s)://<YOUR_GITLAB_URL>/oauth/userinfo`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid email`

- Unikname Connect:

  - Name: `Connect with your private @unikname`
  - Authorize URL: `https://connect.unikname.com/oidc/authorize`
  - Token URL: `https://connect.unikname.com/oidc/accessToken`
  - Userinfo URL: `https://connect.unikname.com/oidc/profile`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid email`

- Microsoft Entra ID:
  - Authorize URL: `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize`
  - Token URL: `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token`
  - Userinfo URL: `https://graph.microsoft.com/oidc/userinfo`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid email`

- Authentik:
  - Authorize URL: `https://<YOUR_AUTHENTIK_URL>/application/o/authorize/`
  - Token URL: `https://<YOUR_AUTHENTIK_URL>/application/o/token/`
  - Userinfo URL: `https://<YOUR_AUTHENTIK_URL>/application/o/userinfo/`
  - Logout URL: `https://<YOUR_AUTHENTIK_URL>/application/o/<YOUR_AUTHENTIK_APPLICATION_SLUG>/end-session/`
  - Userinfo ID: `sub`
  - Client ID + Secret from Authentik Provider
  - OAuth Scopes: `openid email`

  In the Authentik Provider:
  - Redirect URIs: the callback URL of your Matomo, with the matching mode `Strict`. Do not use a pattern such as `.*`: it lets the provider send the login of your users to any website.
  Remaining inputs for provider and application as normal.

- Okta:

  - Authorize URL: `https://${yourOktaDomain}/oauth2/v1/authorize`
  - Token URL: `https://${yourOktaDomain}/oauth2/v1/token`
  - Userinfo URL: `https://${yourOktaDomain}/oauth2/v1/userinfo`
  - Userinfo ID: `email`
  - OAuth Scopes: `openid email`

- Authelia
  - Authorize URL: `https://<YOUR_AUTHENTIK_URL>/api/oidc/authorization`
  - Token URL: `https://<YOUR_AUTHENTIK_URL>/api/oidc/token`
  - Userinfo URL: `https://<YOUR_AUTHENTIK_URL>/api/oidc/userinfo`
  - Userinfo ID: `sub`
  - OAuth Scopes: `openid profile email groups`
