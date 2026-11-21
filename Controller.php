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
use Piwik\Plugins\Login\PasswordVerifier;
use Piwik\Piwik;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Plugins\SitesManager\Model as SitesModel;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Plugins\UsersManager\UserUpdater;
use Piwik\Request;
use Piwik\Session\SessionFingerprint;
use Piwik\Session\SessionInitializer;
use Piwik\Url;
use Piwik\Plugins\RebelOIDC\SystemSettings;
use Piwik\Plugins\RebelOIDC\Helper;
use Piwik\Plugins\RebelOIDC\Protocol;
use Piwik\Plugins\RebelOIDC\Provider;
use Piwik\Log\LoggerInterface;

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
    /**
     * Whether the role of the provider makes the user of this login a super user, or null when
     * no role is set for that.
     *
     * @var bool|null
     */
    private $isSuperUserByRole = null;

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
    public function __construct(?Auth $auth = null, ?SessionInitializer $sessionInitializer = null)
    {
        parent::__construct();

        $this->auth = $auth ?: new Auth();
        $this->sessionInitializer = $sessionInitializer ?: new SessionInitializer();
        $this->passwordVerify = StaticContainer::get(PasswordVerifier::class);
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

        // A user that is logged in and has no linked account is about to link one.
        $isLinking = !Piwik::isUserIsAnonymous() && empty($this->getProviderUser(self::OIDC_PROVIDER));

        $allowedMethods = array("POST");
        // Confirming the password brings the user back here with a GET request.
        if (!$settings->disableDirectLoginUrl->getValue() || ($isLinking && $this->passwordVerify->hasBeenVerified())) {
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

        if ($isLinking && !$this->passwordVerify->requirePasswordVerifiedRecently(['module' => 'RebelOIDC', 'action' => 'signIn'])) {
            return;
        }

        $url = StaticContainer::get(Provider::class)->getEndpoints($settings)['authorizeUrl'];
        Protocol::checkSecureUrl($url);

        $_SESSION["loginoidc_state"] = $this->generateKey(32);
        $_SESSION["loginoidc_nonce"] = $this->generateKey(32);
        $_SESSION["loginoidc_verifier"] = $this->generateKey(64);

        $params = array(
            "client_id" => $settings->clientId->getValue(),
            "scope" => $settings->scope->getValue(),
            "redirect_uri" => $this->getRedirectUri(),
            "state" => $_SESSION["loginoidc_state"],
            "nonce" => $_SESSION["loginoidc_nonce"],
            "code_challenge" => Protocol::getPkceChallenge($_SESSION["loginoidc_verifier"]),
            "code_challenge_method" => "S256",
            "response_type" => "code"
        );
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

        $state = $_SESSION["loginoidc_state"] ?? null;
        $nonce = $_SESSION["loginoidc_nonce"] ?? '';
        $verifier = $_SESSION["loginoidc_verifier"] ?? '';
        unset($_SESSION["loginoidc_state"], $_SESSION["loginoidc_nonce"], $_SESSION["loginoidc_verifier"]);

        if (empty($state) || !hash_equals($state, Request::fromGet()->getStringParameter("state", ""))) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionStateMismatch"));
        }

        if (Request::fromGet()->getStringParameter("provider") !== self::OIDC_PROVIDER) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionUnknownProvider"));
        }

        $endpoints = StaticContainer::get(Provider::class)->getEndpoints($settings);
        $readsIdToken = (bool) $settings->userInfoFromIdToken->getValue();
        Protocol::checkSecureUrl($endpoints['tokenUrl']);
        if (!$readsIdToken) {
            Protocol::checkSecureUrl($endpoints['userInfoUrl']);
        }

        $tokens = $this->requestTokens(array(
            "client_id" => $settings->clientId->getValue(),
            "client_secret" => $settings->clientSecret->getValue(),
            "code" => Request::fromGet()->getStringParameter("code"),
            "code_verifier" => $verifier,
            "redirect_uri" => $this->getRedirectUri(),
            "grant_type" => "authorization_code",
            "state" => $state
        ), $endpoints['tokenUrl']);

        if (!empty($tokens->error) && is_string($tokens->error)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionProviderError", [$tokens->error]));
        }
        if (empty($tokens) || empty($tokens->access_token) || !is_string($tokens->access_token)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidResponse"));
        }

        $idToken = empty($tokens->id_token) || !is_string($tokens->id_token) ? null : $tokens->id_token;
        $idClaims = Protocol::decodeJwt($idToken);
        if ($idClaims !== null) {
            if ($endpoints['jwksUrl'] !== '' && !$this->isSignedByProvider($idToken, $endpoints['jwksUrl'], true)) {
                throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidIdToken"));
            }
            Protocol::checkIdToken($idClaims, $settings->clientId->getValue(), $endpoints['issuer'], $nonce);
        }

        $accessClaims = Protocol::decodeJwt($tokens->access_token) ?? [];
        // With the keys of the provider known, roles and permissions only count when it signed them.
        // Some providers sign access tokens with keys they do not publish, so this is not an error.
        if ($accessClaims !== [] && $endpoints['jwksUrl'] !== '' && !$this->isSignedByProvider($tokens->access_token, $endpoints['jwksUrl'], false)) {
            $accessClaims = [];
        }
        $decodedToken = array_merge($accessClaims, $idClaims ?? []);

        if ($readsIdToken && $idClaims === null) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidResponse"));
        }
        $result = $readsIdToken ? (object) $idClaims : $this->requestUserInfo($tokens->access_token, $endpoints['userInfoUrl']);

        $userInfoId = $settings->userInfoId->getValue();
        $providerUserId = $result->$userInfoId ?? null;

        if (empty($providerUserId) || !is_scalar($providerUserId)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidResponse"));
        }
        $providerUserId = (string) $providerUserId;

        // The user info has to be about the user the ID token was issued for.
        if (isset($idClaims['sub'], $result->sub) && $idClaims['sub'] !== $result->sub) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionInvalidResponse"));
        }

        $emailAttribute = $settings->emailAttribute->getValue() ?: 'email';
        $providerEmail = $result->$emailAttribute ?? $idClaims[$emailAttribute] ?? null;
        $providerEmail = is_string($providerEmail) ? $providerEmail : null;
        $isEmailTrusted = $settings->trustUnverifiedEmail->getValue()
            || Protocol::isEmailVerified($result->email_verified ?? $idClaims['email_verified'] ?? null);

        $user = $this->getUserByRemoteId(self::OIDC_PROVIDER, $providerUserId);

        // Roles are in the access token at some providers and in the ID token or the user info at others.
        $claims = array_merge((array) json_decode((string) json_encode($result), true), $decodedToken);
        $roles = Protocol::getRoles($claims, $settings->clientId->getValue(), trim((string) $settings->rolesClaim->getValue()));

        if (!empty($settings->allowedRole->getValue()) && !in_array($settings->allowedRole->getValue(), $roles)) {
            throw new Exception(Piwik::translate("RebelOIDC_ExceptionRoleMissing"));
        }

        $superUserRole = trim((string) $settings->superUserRole->getValue());
        $this->isSuperUserByRole = $superUserRole === '' ? null : in_array($superUserRole, $roles);
        $userOIDCPermissions = Protocol::getPermissions($claims, $roles, (new SitesModel())->getSitesId());

        // auto linking
        // A user that is logged in links by hand, after confirming the password.
        if (empty($user) && $settings->autoLinking->getValue() && Piwik::isUserIsAnonymous()) {
            $matomoUser = empty($providerEmail) ? [] : (new Model())->getUserByEmail($providerEmail);
            if (!empty($matomoUser) && Protocol::canLinkByEmail($matomoUser, $providerEmail, $isEmailTrusted)) {
                $this->linkAccount($providerUserId, $matomoUser['login']);
                $user = $matomoUser;
            }
        }

        if (empty($user)) {
            if (Piwik::isUserIsAnonymous()) {
                // user with the remote id is currently not in our database
                $this->signupUser($settings, $providerUserId, $providerEmail, $result, $userOIDCPermissions, $isEmailTrusted, $idToken);
            } else {
                // link current user with the remote user
                if (!$this->passwordVerify->hasBeenVerified()) {
                    throw new Exception(Piwik::translate("RebelOIDC_ExceptionPasswordConfirmationRequired"));
                }
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
                    $this->signInAndRedirect($user, $settings, $idToken);
                }
            } else {
                if (Piwik::getCurrentUserLogin() === $user["login"]) {
                    $this->markSessionAsSignedIn($idToken);
                    $this->assignPermissions($userOIDCPermissions, $user['login']);
                    if ($this->passwordVerify->hasPasswordVerifyBeenRequested()) {
                        // Sends the user on to what the password was asked for.
                        $this->passwordVerify->setPasswordVerifiedCorrectly();
                    }
                    Url::redirectToUrl("index.php");
                } else {
                    throw new Exception(Piwik::translate("RebelOIDC_ExceptionAlreadyLinkedToDifferentAccount"));
                }
            }
        }
    }

    /**
     * Remembers that the user of this session was identified by the provider. Only to be called
     * once the provider's account is known to belong to that user.
     */
    private function markSessionAsSignedIn(
        #[\SensitiveParameter]
        ?string $idToken
    ): void {
        $_SESSION['loginoidc_idtoken'] = $idToken;
        $_SESSION['loginoidc_auth'] = true;
    }

    /**
     * @param bool $mayAskForNewKeys whether to ask the provider for its keys again when none of the keys kept fits
     */
    private function isSignedByProvider(
        #[\SensitiveParameter]
        string $token,
        string $jwksUrl,
        bool $mayAskForNewKeys
    ): bool {
        $provider = StaticContainer::get(Provider::class);

        return Signature::isValid($token, $provider->getKeys($jwksUrl))
            || ($mayAskForNewKeys && Signature::isValid($token, $provider->getKeys($jwksUrl, true)));
    }

    /**
     * Exchanges the code of the callback for the tokens.
     *
     * @param array<string, string> $data
     * @return object|null the response, or null when it is not JSON
     */
    protected function requestTokens(
        #[\SensitiveParameter]
        array $data,
        string $tokenUrl
    ) {
        return $this->readJson(StaticContainer::get(Provider::class)->request($tokenUrl, [], $data));
    }

    /**
     * @return object|null the user info of the provider, or null when it did not answer with it
     */
    protected function requestUserInfo(
        #[\SensitiveParameter]
        string $accessToken,
        string $userInfoUrl
    ) {
        $response = StaticContainer::get(Provider::class)->request($userInfoUrl, ["Authorization: Bearer " . $accessToken]);

        return $response['status'] < 400 ? $this->readJson($response) : null;
    }

    /**
     * @param array{status: int, data: string} $response
     */
    private function readJson(array $response): ?object
    {
        $result = json_decode($response['data']);

        return is_object($result) ? $result : null;
    }

    /**
     * Sign up a new user and link him with a given remote user id.
     *
     * @param  SystemSettings  $settings
     * @param  string          $providerUserId   Remote user id
     * @param  string          $providerEmail    Users email address
     * @param  array           $permissions      Permissions for the user as array of tuples ['permission' => <permission>, 'siteID' => <siteID>]
     * @param  bool            $isEmailTrusted   Whether the email is known to belong to the user
     * @return void
     */
    private function signupUser(
        $settings,
        string $providerUserId,
        ?string $providerEmail,
        $result,
        array $permissions,
        bool $isEmailTrusted,
        #[\SensitiveParameter]
        ?string $idToken
    ): void {
        // only sign up user if setting is enabled
        if ($settings->allowSignup->getValue()) {
            // verify response contains email address
            if (empty($providerEmail)) {
                throw new Exception(Piwik::translate("RebelOIDC_ExceptionUserNotFoundAndNoEmail"));
            }
            if (empty($providerUserId)) {
                throw new Exception(Piwik::translate("RebelOIDC_ExceptionUserNotFoundAndNoUserId"));
            }
            if (!$isEmailTrusted) {
                throw new Exception(Piwik::translate("RebelOIDC_ExceptionEmailNotVerified"));
            }

            $userId = $this->determineUsername($settings, $result, $providerUserId, $providerEmail);
            // verify email address domain is allowed to sign up
            if (!empty($settings->allowedSignupDomains->getValue())) {
                $signupDomain = mb_strtolower(substr($providerEmail, strrpos($providerEmail, "@") + 1));
                $allowedDomains = explode("\n", $settings->allowedSignupDomains->getValue());
                if (!in_array($signupDomain, $allowedDomains, true)) {
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
            $this->signInAndRedirect($user, $settings, $idToken);
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
    private function signInAndRedirect(
        array $user,
        SystemSettings $settings,
        #[\SensitiveParameter]
        ?string $idToken
    ) {
        $this->auth->setLogin($user["login"]);
        $this->auth->setForceLogin(true);
        $this->sessionInitializer->initSession($this->auth);
        $this->markSessionAsSignedIn($idToken);
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
     * Gives the user the access the provider reported with this login, and takes away the rest.
     *
     * @param array<array{site: string, access: string}> $permissions
     */
    private function assignPermissions(array $permissions, string $login): void
    {
        if ($this->syncSuperUserAccess($login)) {
            return;
        }

        // Without the setting, access is managed in Matomo and must not be removed.
        $settings = new SystemSettings();
        if (!$settings->fineGrainedPermissions->getValue()) {
            return;
        }

        $userModel = new Model();
        $existingPermissions = $userModel->getSitesAccessFromUser($login);

        foreach ($existingPermissions as $existingPermission) {
            if (!in_array($existingPermission, $permissions)) {
                $userModel->removeUserAccess($login, $existingPermission['access'], [$existingPermission['site']]);
            }
        }

        foreach ($permissions as $permission) {
            if (!in_array($permission, $existingPermissions)) {
                $userModel->addUserAccess($login, $permission['access'], [$permission['site']]);
            }
        }
    }

    /**
     * Makes super user access follow the role of the provider, when a role is set for it.
     *
     * @return bool whether the user is a super user because of the role
     */
    private function syncSuperUserAccess(string $login): bool
    {
        if ($this->isSuperUserByRole === null || $this->isSuperUserByRole === $this->hasTheUserSuperUserAccess($login)) {
            return (bool) $this->isSuperUserByRole;
        }

        $isSuperUser = $this->isSuperUserByRole;
        if (!$isSuperUser && count((new Model())->getUsersHavingSuperUserAccess()) === 1) {
            StaticContainer::get(LoggerInterface::class)->warning('RebelOIDC: {login} keeps super user access, as the only super user.', ['login' => $login]);
            return false;
        }

        Access::doAsSuperUser(function () use ($login, $isSuperUser) {
            (new UserUpdater())->setSuperUserAccessWithoutCurrentPassword($login, (int) $isSuperUser);
        });

        return $isSuperUser;
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
