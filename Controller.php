<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

use Exception;
use Piwik\Access;
use Piwik\Plugins\RebelOIDC\Auth;
use Piwik\Container\StaticContainer;
use Piwik\Nonce;
use Piwik\Piwik;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Request;
use Piwik\Session\SessionFingerprint;
use Piwik\Session\SessionInitializer;
use Piwik\Url;
use Piwik\Plugins\RebelOIDC\SystemSettings;
use Piwik\Plugins\RebelOIDC\Helper;

class Controller extends \Piwik\Plugin\Controller
{
    use Helper;

    /**
     * @var string
     */
    public const OIDC_NONCE = "RebelOIDC.nonce";

    /**
     * @var string
     */
    public const OIDC_PROVIDER = 'oidc';

    /**
     * Auth implementation to login users.
     * @var Auth
     */
    protected $auth;

    /**
     * Initializes authenticated sessions.
     *
     * @var SessionInitializer
     */
    protected $sessionInitializer;

    /**
     * The id token (raw, verified in verification mode), kept for the logout redirect once sign-in succeeds.
     * @var string|null
     */
    private $rawIdToken = null;

    /**
     * Revalidate user authentication.
     *
     * @var PasswordVerifier
     */
    protected $passwordVerify;

    /**
     * Constructor.
     *
     * @param Auth                $auth
     * @param SessionInitializer  $sessionInitializer
     */
    public function __construct(Auth $auth = null, SessionInitializer $sessionInitializer = null)
    {
        parent::__construct();

        $this->auth = $auth ?: new Auth();
        $this->sessionInitializer = $sessionInitializer ?: new SessionInitializer();
        $this->passwordVerify = StaticContainer::get("Piwik\Plugins\Login\PasswordVerifier");
    }

    /**
     * Render the custom user settings layout.
     *
     * @return string
     */
    public function userSettings(): string
    {
        $providerUser = $this->getProviderUser(self::OIDC_PROVIDER);
        return $this->renderTemplate('userSettings', [
            'isLinked' => !empty($providerUser),
            'remoteUserId' => $providerUser['provider_user'] ?? '',
            'nonce' => Nonce::getNonce(self::OIDC_NONCE),
        ]);
    }

    /**
     * Render the oauth login button.
     *
     * @return string
     */
    public function loginMod(): string
    {
        $settings = new SystemSettings();
        if ($this->isPluginSetup($settings)) {
            $failed = isset($_SESSION) && LoginFailureFlag::take($_SESSION);
            return $this->renderTemplate('loginMod', [
                'loginFailedMessage' => $failed ? Piwik::translate('RebelOIDC_LoginFailed') : null,
                'caption' => $settings->authenticationName->getValue(),
                'nonce' => Nonce::getNonce(self::OIDC_NONCE),
            ]);
        }
        return '';
    }

    /**
     * Render the oauth login button when current user is linked to a remote user.
     *
     * @return string|null
     */
    public function confirmPasswordMod(): ?string
    {
        $providerUser = $this->getProviderUser(self::OIDC_PROVIDER);
        return empty($providerUser) ? null : $this->loginMod();
    }

    /**
     * Redirect to the authorize url of the remote oauth service.
     *
     * @return void
     */
    public function signIn()
    {
        $settings = new SystemSettings();

        $allowedMethods = array("POST");
        if (!$settings->disableDirectLoginUrl->getValue()) {
            array_push($allowedMethods, "GET");
        }
        if (!in_array($_SERVER["REQUEST_METHOD"], $allowedMethods)) {
            throw new Exception(Piwik::translate("RebelOIDC_MethodNotAllowed"));
        }

        if ($_SERVER["REQUEST_METHOD"] === "POST") {
            // csrf protection
            Nonce::checkNonce(self::OIDC_NONCE, $_POST["form_nonce"]);
        }

        if (!$this->isPluginSetup($settings)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionNotConfigured"));
        }

        $_SESSION["loginoidc_state"] = $this->generateKey(32);

        $params = array(
            "client_id" => $settings->clientId->getValue(),
            "scope" => $settings->scope->getValue(),
            "redirect_uri" => $this->getRedirectUri(),
            "state" => $_SESSION["loginoidc_state"],
            "response_type" => "code",
        );
        if ($settings->disablePkce->getValue()) {
            // only for identity providers that reject PKCE parameters
            unset($_SESSION["rebeloidc_pkce_verifier"]);
        } else {
            $_SESSION["rebeloidc_pkce_verifier"] = Pkce::newVerifier();
            $params["code_challenge"] = Pkce::challenge($_SESSION["rebeloidc_pkce_verifier"]);
            $params["code_challenge_method"] = "S256";
        }
        $url = $settings->authorizeUrl->getValue();
        $url .= (parse_url($url, PHP_URL_QUERY) ? "&" : "?") . http_build_query($params);
        Url::redirectToUrl($url);
    }

    /**
     * Handle callback from oauth service.
     * Verify callback code, exchange for authorization token and fetch userinfo.
     *
     * @return void
     */
    public function callback(): void
    {
        $settings = new SystemSettings();
        if (!$this->isPluginSetup($settings)) {
            $this->failLogin('plugin is not configured');
        }

        $usePkce = !$settings->disablePkce->getValue();
        $verifyTokens = self::verificationMode((string) $settings->jwksUrl->getValue(), (string) $settings->issuer->getValue()) === true;

        $pkceVerifier = $_SESSION["rebeloidc_pkce_verifier"] ?? null;
        unset($_SESSION["rebeloidc_pkce_verifier"]);

        // an IdP error redirect (e.g. ?error=access_denied) carries neither state nor code
        $state = Request::fromGet()->getStringParameter("state", "");
        $code = Request::fromGet()->getStringParameter("code", "");
        if ($state === "" || $code === "") {
            $this->failLogin('callback lacks state or code');
        }

        if (($_SESSION["loginoidc_state"] ?? null) !== $state || ($usePkce && (!is_string($pkceVerifier) || $pkceVerifier === ""))) {
            $this->failLogin('state mismatch or missing PKCE verifier');
        } else {
            unset($_SESSION["loginoidc_state"]);
        }

        if (Request::fromGet()->getStringParameter("provider", "") !== self::OIDC_PROVIDER) {
            $this->failLogin('unknown provider');
        }

        // payload for token request
        $data = array(
            "client_id" => $settings->clientId->getValue(),
            "client_secret" => $settings->clientSecret->getValue(),
            "code" => $code,
            "redirect_uri" => $this->getRedirectUri(),
            "grant_type" => "authorization_code",
            "state" => $state
        );
        if ($usePkce) {
            $data["code_verifier"] = $pkceVerifier;
        }
        $dataString = http_build_query($data);

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $dataString);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: " . strlen($dataString),
            "Accept: application/json",
            "User-Agent: RebelOIDC-Matomo-Plugin"
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_URL, $settings->tokenUrl->getValue());
        // request authorization token
        $response = curl_exec($curl);
        $httpCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_errno($curl) !== 0 ? curl_error($curl) : '';
        curl_close($curl);

        if ($response === false || $curlError !== '' || $httpCode >= 400) {
            $this->failLogin('token request failed (HTTP ' . $httpCode . ') ' . $curlError);
        }
        $result = json_decode((string) $response);

        $verifiedId = [];
        $decodedToken = [];
        if ($verifyTokens) {
            $verifiedAccess = [];
            try {
                if (!is_object($result) || empty($result->access_token) || empty($result->id_token)
                    || !is_string($result->access_token) || !is_string($result->id_token)) {
                    throw new InvalidTokenException('token response lacks access_token or id_token');
                }
                $clientId = (string) $settings->clientId->getValue();
                $verifier = new JwtVerifier(function (bool $forceRefresh) use ($settings): array {
                    return (new JwksProvider())->fetch((string) $settings->jwksUrl->getValue(), $forceRefresh);
                });
                $issuer = (string) $settings->issuer->getValue();
                $verifiedId = $verifier->verify($result->id_token, $issuer, time());
                JwtVerifier::assertAudience($verifiedId, $clientId);
                // The access token is only a claims source when it is a JWS from our issuer;
                // otherwise it is opaque (bearer for userinfo only, no claims read from it).
                if (JwtVerifier::shouldVerifyAccessToken($result->access_token, $issuer)) {
                    $verifiedAccess = $verifier->verify($result->access_token, $issuer, time());
                    JwtVerifier::assertAuthorizedParty($verifiedAccess, $clientId);
                }
            } catch (\Exception $e) {
                $this->failLogin($e->getMessage());
            }
            // only verified claims are used from here on
            $decodedToken = array_merge($verifiedAccess, $verifiedId);
        } else {
            // Legacy mode (no jwksUrl/issuer configured): behaves like 5.1.x. The id token is
            // optional and claims are decoded WITHOUT signature verification.
            if (!is_object($result) || empty($result->access_token) || !is_string($result->access_token)) {
                $this->failLogin('token response lacks access_token');
            }
            $result->id_token = isset($result->id_token) && is_string($result->id_token) ? $result->id_token : '';
            $decodedToken = array_merge(
                JwtVerifier::unverifiedClaims($result->access_token),
                JwtVerifier::unverifiedClaims($result->id_token)
            );
        }

        $roles = $this->extractRoles($decodedToken, $settings->clientId->getValue());

        $has_correct_role = in_array($settings->allowedRole->getValue(), $roles, true);
        if (!empty($settings->allowedRole->getValue()) && !$has_correct_role) {
            $this->failLogin('required role missing');
        }

        $this->rawIdToken = $result->id_token !== '' ? $result->id_token : null;

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            "Authorization: Bearer " . $result->access_token,
            "Accept: application/json",
            "User-Agent: RebelOIDC-Matomo-Plugin"
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_URL, $settings->userInfoUrl->getValue());
        // request remote userinfo and remote user id
        $response = curl_exec($curl);
        $httpCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_errno($curl) !== 0 ? curl_error($curl) : '';
        curl_close($curl);

        if ($response === false || $curlError !== '' || $httpCode >= 400) {
            $this->failLogin('userinfo request failed (HTTP ' . $httpCode . ') ' . $curlError);
        }
        $userinfoArray = json_decode((string) $response, true);
        try {
            if (!is_array($userinfoArray)) {
                throw new InvalidTokenException('userinfo response is not a JSON object');
            }
            if ($verifyTokens) {
                JwtVerifier::assertSameSubject($verifiedId, $userinfoArray);
            }
        } catch (\Exception $e) {
            $this->failLogin($e->getMessage());
        }

        $providerUserId = $this->providerUserIdFrom($userinfoArray, (string) $settings->userInfoId->getValue());
        if ($providerUserId === null) {
            $this->failLogin('userinfo lacks a valid user id field');
        }

        $user = $this->getUserByRemoteId(self::OIDC_PROVIDER, $providerUserId);
        $userOIDCPermissions = $this->extractPermissions($decodedToken);


        // auto linking
        // if setting is activated, the oidc account is automatically linked, if the user ID of the OpenID Connect Provider is equal to the internal matomo user ID
        if ($settings->autoLinking->getValue()) {
            $userModel = new Model();
            $matomoUser = $userModel->getUser($providerUserId);
            if (!empty($matomoUser)) {
                if (empty($user)) {
                    $this->linkAccount($providerUserId, $providerUserId);
                }
                $user = $this->getUserByRemoteId(self::OIDC_PROVIDER, $providerUserId);
                $this->assignPermissions($userOIDCPermissions, $user['login']);
            }
        }

        if (empty($user)) {
            if (Piwik::isUserIsAnonymous()) {
                // user with the remote id is currently not in our database
                // verification mode: prefer verified claims, fall back to userinfo values only when absent there
                // legacy mode: userinfo only (unverified token claims are never used for the identity)
                $signupClaims = $verifyTokens ? $decodedToken : [];
                $signupInfo = (object) array_merge($userinfoArray, $signupClaims);
                $signupEmail = $signupClaims['email'] ?? null;
                if (!is_string($signupEmail) || $signupEmail === '') {
                    $signupEmail = isset($userinfoArray['email']) && is_string($userinfoArray['email']) ? $userinfoArray['email'] : null;
                }
                $this->signupUser($settings, $providerUserId, $signupEmail, $signupInfo, $userOIDCPermissions);
            } else {
                // link current user with the remote user
                $this->linkAccount($providerUserId);
                $this->markOidcAuthenticated();
                $currentUserLogin = Piwik::getCurrentUserLogin();
                $this->assignPermissions($userOIDCPermissions, $currentUserLogin);
                $this->redirectToIndex("UsersManager", "userSecurity");
            }
        } else {
            // users identity has been successfully confirmed by the remote oidc server
            if (Piwik::isUserIsAnonymous()) {
                if ($settings->disableSuperuser->getValue() && $this->hasTheUserSuperUserAccess($user["login"])) {
                    $this->failLogin('external login disabled for superusers');
                } else {

                    $this->assignPermissions($userOIDCPermissions, $user['login']);
                    $this->signInAndRedirect($user, $settings);
                }
            } else {
                if (Piwik::getCurrentUserLogin() === $user["login"]) {
                    $this->markOidcAuthenticated();
                    $this->passwordVerify->setPasswordVerifiedCorrectly();
                    $this->assignPermissions($userOIDCPermissions, $user['login']);
                    return;
                } else {
                    $this->failLogin('remote user is linked to a different account');
                }
            }
        }
    }

    /**
     * Sign up a new user and link him with a given remote user id.
     *
     * @param  SystemSettings  $settings
     * @param  string          $providerUserId   Remote user id
     * @param  string          $providerEmail    Users email address
     * @param  array           $permissions      Permissions for the user as array of tuples ['permission' => <permission>, 'siteID' => <siteID>]
     * @return void
     */
    private function signupUser($settings, string $providerUserId, string $providerEmail = null, $result, array $permissions = []): void
    {
        // only sign up user if setting is enabled
        if ($settings->allowSignup->getValue()) {
            // verify response contains email address
            if (empty($providerEmail)) {
                throw new Exception(Piwik::translate("RebelOIDC_ExceptionUserNotFoundAndNoEmail"));
            }
            if (empty($providerUserId)) {
                throw new Exception(Piwik::translate("RebelOIDC_ExceptionUserNotFoundAndNoUserId"));
            }

            $userId = $this->determineUsername($settings, $result, $providerUserId, $providerEmail);
            // verify email address domain is allowed to sign up
            if (!empty($settings->allowedSignupDomains->getValue())) {
                $signupDomain = substr($providerEmail, strpos($providerEmail, "@") + 1);
                $allowedDomains = explode("\n", $settings->allowedSignupDomains->getValue());
                if (!in_array($signupDomain, $allowedDomains)) {
                    throw new Exception(Piwik::translate("RebelOIDC_ExceptionAllowedSignupDomainsDenied"));
                }
            }

            $initialIdSite = null;
            if (!empty($settings->initialIdSite->getValue())) {
                $initialIdSite = $settings->initialIdSite->getValue();
                if ($initialIdSite === 'none') {
                    $initialIdSite = null;
                }
            }

            // set an invalid pre-hashed password, to block the user from logging in by password
            Access::getInstance()->doAsSuperUser(function () use ($userId, $providerEmail, $initialIdSite) {
                UsersManagerApi::getInstance()->addUser(
                    $userId,
                    "(disallow password login)",
                    $providerEmail,
                    /* $_isPasswordHashed = */ true,
                    $initialIdSite
                );
            });
            $userModel = new Model();
            $user = $userModel->getUser($userId);
            $this->linkAccount($providerUserId, $userId);
            $this->assignPermissions($permissions, $user['login']);
            $this->signInAndRedirect($user, $settings);
        } else {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionUserNotFoundAndSignupDisabled"));
        }
    }

    /**
     * Sign in the given user and redirect to the front page.
     *
     * @param  array  $user
     * @return void
     */
    private function signInAndRedirect(array $user, SystemSettings $settings)
    {
        $this->markOidcAuthenticated();
        $this->auth->setLogin($user["login"]);
        $this->auth->setForceLogin(true);
        $this->sessionInitializer->initSession($this->auth);
        if ($settings->bypassTwoFa->getValue()) {
            $sessionFingerprint = new SessionFingerprint();
            $sessionFingerprint->setTwoFactorAuthenticationVerified();
        }
        Url::redirectToUrl("index.php");
    }

    /**
     * Generate the redirect url on which the oauth service has to redirect.
     *
     * @return string
     */
    private function getRedirectUri(): string
    {
        $settings = new SystemSettings();

        if (!empty($settings->redirectUriOverride->getValue())) {
            return $settings->redirectUriOverride->getValue();
        } else {
            $params = array(
                "module" => "RebelOIDC",
                "action" => "callback",
                "provider" => self::OIDC_PROVIDER
            );
            return Url::getCurrentUrlWithoutQueryString() . "?" . http_build_query($params);
        }
    }

    /**
     * @param array $permissions
     * @param string $login
     * @return void
     *
     * Receives a set of permissions as an array of tuples ['site' => <siteID>, 'access' => <permission>].
     * Existing permissions of the given user that are not in this array are removed, missing permissions are added.
     */
    private function assignPermissions(array $permissions, string $login): void
    {
        // Check if fine-grained permissions are enabled in the settings
        $settings = new SystemSettings();
        // if it is disabled, return so that manually-managed permissions are not removed
        if (!$settings->fineGrainedPermissions->getValue()) {
            return;
        }

        $userModel = new Model();

        // get the existing permissions for the user from the matomo_access table
        $existingPermissions = $userModel->getSitesAccessFromUser($login);

        // add permissions that are not yet in the matomo_access table for the user
        foreach ($permissions as $permission) {
            if(!in_array($permission, $existingPermissions)) {
                $userModel->addUserAccess($login, $permission['access'], [$permission['site']]);
            }
        }

        // remove permissions that are already matomo_access table for the user but not in the given set of permissions
        foreach ($existingPermissions as $existingPermission) {
            if(!in_array($existingPermission, $permissions)) {
                $userModel->removeUserAccess($login, $existingPermission['access'], [$existingPermission['site']]);
            }
        }
    }

    /**
     * Extract roles from a decoded JWT token.
     *
     * @param array $decodedToken Decoded JWT payload.
     * @param string|null $clientId (Optional) Specific client ID for client roles.
     * @return array Roles assigned to the user.
     */
    private function extractRoles(array $decodedToken, ?string $clientId = null): array
    {
        $roles = [];

        // 1. Extract realm roles (if present in the token)
        if (isset($decodedToken['realm_access']['roles'])) {
            $roles = array_merge($roles, $decodedToken['realm_access']['roles']);
        }

        // 2. Extract client-specific roles (if a client ID is provided and roles exist)
        if ($clientId && isset($decodedToken['resource_access'][$clientId]['roles'])) {
            $roles = array_merge($roles, $decodedToken['resource_access'][$clientId]['roles']);
        }

        // 3. Extract roles (if present in the token - MS Entra ID)
        if (isset($decodedToken['roles'])) {
            $roles = array_merge($roles, $decodedToken['roles']);
        }

        return $roles;
    }

    /**
     * Mark the session as signed in/linked via OIDC. Only called on successful paths,
     * after the tokens and the userinfo subject have been verified.
     */
    private function markOidcAuthenticated(): void
    {
        $_SESSION['loginoidc_idtoken'] = $this->rawIdToken;
        $_SESSION['loginoidc_auth'] = true;
        LoginFailureFlag::clear($_SESSION);
    }

    /**
     * Log the (non-secret) reason and send the user back to login with one generic message.
     *
     * @param string $detail
     * @return void never returns
     */
    private function failLogin(string $detail): void
    {
        if (Piwik::isUserIsAnonymous()) {
            // keep the flags of an already signed-in user (password confirmation / link flow)
            unset($_SESSION['loginoidc_auth'], $_SESSION['loginoidc_idtoken']);
        }
        \Piwik\Log::warning('RebelOIDC: login rejected: ' . $detail);
        LoginFailureFlag::raise($_SESSION);
        $this->redirectToLogin();
        // fail-safe: never continue the login if the redirect returns (CLI/tests)
        throw new Exception(Piwik::translate('RebelOIDC_LoginFailed'));
    }

    /**
     */
    private function redirectToLogin(): void
    {
        $url = Url::getCurrentUrlWithoutQueryString();
        Url::redirectToUrl($url);
        exit();
    }

    /**
     * @return string
     */
    private function determineUsername($settings, $userInfo, string $providerUserId, string $providerEmail): string
    {
    // Get the configured username attribute
        $usernameAttribute = $settings->usernameAttribute->getValue();

        if (!empty($usernameAttribute) && isset($userInfo->$usernameAttribute)) {
            // Use the configured attribute if available
            return $userInfo->$usernameAttribute;
        }

        if ($settings->fallbackToEmail->getValue() && !empty($providerEmail)) {
            // Use email as fallback if configured
            return $providerEmail;
        }

    // Default to provider user ID if no other option is available
        return $providerUserId;
    }
}
