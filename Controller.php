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
     * @var string[]
     */
    public const ALLOWED_PERMISSIONS = ['admin', 'write', 'view'];

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
            return $this->renderTemplate('loginMod', [
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
            "response_type" => "code"
        );
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
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionNotConfigured"));
        }

        if ($_SESSION["loginoidc_state"] !== Request::fromGet()->getStringParameter("state")) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionStateMismatch"));
        } else {
            unset($_SESSION["loginoidc_state"]);
        }

        if (Request::fromGet()->getStringParameter("provider") !== self::OIDC_PROVIDER) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionUnknownProvider"));
        }

        // payload for token request
        $data = array(
            "client_id" => $settings->clientId->getValue(),
            "client_secret" => $settings->clientSecret->getValue(),
            "code" => Request::fromGet()->getStringParameter("code"),
            "redirect_uri" => $this->getRedirectUri(),
            "grant_type" => "authorization_code",
            "state" => Request::fromGet()->getStringParameter("state")
        );
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
        curl_setopt($curl, CURLOPT_URL, $settings->tokenUrl->getValue());
        // request authorization token
        $response = curl_exec($curl);
        curl_close($curl);
        $result = json_decode($response);

        if (empty($result) || empty($result->access_token)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidResponse"));
        }

        $roles = $this->tryToExtractRolesOfAccessToken($result, $settings);

        $has_correct_role = in_array($settings->allowedRole->getValue(), $roles);
        if (!empty($settings->allowedRole->getValue()) && !$has_correct_role) {
            $this->redirectToLogin("You do not have the correct role for access");
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionInvalidResponse"));
        }

        $_SESSION['loginoidc_idtoken'] = empty($result->id_token) ? null : $result->id_token;
        $_SESSION['loginoidc_auth'] = true;

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            "Authorization: Bearer " . $result->access_token,
            "Accept: application/json",
            "User-Agent: RebelOIDC-Matomo-Plugin"
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_URL, $settings->userInfoUrl->getValue());
        // request remote userinfo and remote user id
        $response = curl_exec($curl);
        curl_close($curl);
        $result = json_decode($response);

        $userInfoId = $settings->userInfoId->getValue();
        $providerUserId = $result->$userInfoId;

        if (empty($providerUserId)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidResponse"));
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
                $this->signupUser($settings, $providerUserId, $result->email, $result, $userOIDCPermissions);
            } else {
                // link current user with the remote user
                $this->linkAccount($providerUserId);
                $currentUserLogin = Piwik::getCurrentUserLogin();
                $this->assignPermissions($userOIDCPermissions, $currentUserLogin);
                $this->redirectToIndex("UsersManager", "userSecurity");
            }
        } else {
            // users identity has been successfully confirmed by the remote oidc server
            if (Piwik::isUserIsAnonymous()) {
                if ($settings->disableSuperuser->getValue() && $this->hasTheUserSuperUserAccess($user["login"])) {
                    throw new Exception(Piwik::translate("RebelOIDC_ExceptionSuperUserOauthDisabled"));
                } else {

                    $this->assignPermissions($userOIDCPermissions, $user['login']);
                    $this->signInAndRedirect($user, $settings);
                }
            } else {
                if (Piwik::getCurrentUserLogin() === $user["login"]) {
                    $this->passwordVerify->setPasswordVerifiedCorrectly();
                    $this->assignPermissions($userOIDCPermissions, $user['login']);
                    return;
                } else {
                    throw new Exception(Piwik::translate("RebelOIDC_ExceptionAlreadyLinkedToDifferentAccount"));
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
     * Validate OAuth state to mitigate CSRF attacks.
     *
     * @param string $state
     * @throws Exception
     */
    private function validateState(string $state): void
    {
        if ($_SESSION['loginoidc_state'] !== $state) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionStateMismatch"));
        }
        unset($_SESSION['loginoidc_state']);
    }

    /**
     * Decode a JWT (access token) without verification (for roles extraction).
     *
     * @param string $token The JWT access token.
     * @return array Decoded token payload.
     * @throws Exception
     */
    private function decodeJwt(string $token): array
    {
        // Explode the token into its three parts: header, payload, and signature
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT token format.');
        }

        // Base64-decode the payload (second part of the JWT)
        $payload = base64_decode($parts[1]);

        // Convert JSON payload to a PHP array
        $decoded = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Failed to decode JWT payload: ' . json_last_error_msg());
        }

        return $decoded;
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
     * Extract Permissions from a decoded JWT token.
     *
     * Permissions are expected to be found in the claim "matomo-permission-path"
     * in the format /matomo/<siteID>/<permission>).
     * Available permissions are read, write and admin.
     *
     * @param array $decodedToken Decoded JWT payload.
     * @return array permissions assigned to the user as array of tuples ['site' => <siteID>, 'access' => <permission>].
     */
    private function extractPermissions(array $decodedToken): array
    {
        $result = [];

        if (isset($decodedToken['matomo-permission-path'])) {
            foreach ($decodedToken['matomo-permission-path'] as $path) {
                $groupPathParts = array_values(array_filter(explode('/', $path)));
                if (count($groupPathParts) === 3 && $groupPathParts[0] === 'matomo' && in_array($groupPathParts[2], self::ALLOWED_PERMISSIONS)) {
                    $result[] = ['site' => $groupPathParts[1], 'access' => $groupPathParts['2']];
                }
            }
        }

        return $result;
    }

    /**
     * @param string $message
     */
    private function redirectToLogin($message): void
    {
        $url = Url::getCurrentUrlWithoutQueryString();
        $loginUrl = $url . '?notification=' . urlencode($message);
        Url::redirectToUrl($loginUrl);
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

    /**
     * @param $result
     * @param \Piwik\Plugins\RebelOIDC\SystemSettings $settings
     * @return array
     * @throws Exception
     */
    private function tryToExtractRolesOfAccessToken($result, \Piwik\Plugins\RebelOIDC\SystemSettings $settings): array
    {
        try {
            $accessToken = $result->access_token;
            // If id_token exists, merge its decoded content with access token's decoded content
            if (property_exists($result, 'id_token')) {
                $idToken = $result->id_token;
                $decodedToken = array_merge($this->decodeJwt($accessToken), $this->decodeJwt($idToken));
            } else {
                $decodedToken = $this->decodeJwt($accessToken);
            }
            return $this->extractRoles($decodedToken, $settings->clientId->getValue());
        } catch (Exception $e) {
            return [];
        }
    }
}
