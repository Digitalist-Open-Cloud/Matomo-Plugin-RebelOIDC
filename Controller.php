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
            }
        }

        if (empty($user)) {
            if (Piwik::isUserIsAnonymous()) {
                // user with the remote id is currently not in our database
                $this->signupUser($settings, $providerUserId, $result->email);
            } else {
                // link current user with the remote user
                $this->linkAccount($providerUserId);
                $this->redirectToIndex("UsersManager", "userSecurity");
            }
        } else {
            // users identity has been successfully confirmed by the remote oidc server
            if (Piwik::isUserIsAnonymous()) {
                if ($settings->disableSuperuser->getValue() && $this->hasTheUserSuperUserAccess($user["login"])) {
                    throw new Exception(Piwik::translate("RebelOIDC_ExceptionSuperUserOauthDisabled"));
                } else {
                    $this->signInAndRedirect($user, $settings);
                }
            } else {
                if (Piwik::getCurrentUserLogin() === $user["login"]) {
                    $this->passwordVerify->setPasswordVerifiedCorrectly();
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
     * @return void
     */
    private function signupUser($settings, string $providerUserId, string $providerEmail = null): void
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
            if ($settings->useEmailAsUsername->getValue()) {
                $userId = $providerEmail;
            } else {
                $userId = $providerUserId;
            }
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
}
