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
use Piwik\Piwik;
use Piwik\Settings\FieldConfig;
use Piwik\Settings\Plugin\SystemSetting;
use Piwik\Validators\NotEmpty;
use Piwik\Validators\UrlLike;

class SystemSettings extends \Piwik\Settings\Plugin\SystemSettings
{
    /**
     * The disable superuser setting.
     *
     * @var Setting
     */
    public $disableSuperuser;

    /**
     * The disable password confirmation setting.
     *
     * @var Setting
     */
    public $disablePasswordConfirmation;

    /**
     * Whether the login procedure has to be initiated from the Matomo login page
     *
     * @var Setting
     */
    public $disableDirectLoginUrl;

    /**
     * Whether new Matomo accounts should be created for unknown users
     *
     * @var Setting
     */
    public $allowSignup;

    /**
     * Bypass 2nd factor when login with OIDC
     *
     * @var Setting
     */
    public $bypassTwoFa;

    /**
     * Enable auto linking of accounts
     *
     * @var Setting
     */
    public $autoLinking;

    /**
     * The name of the oauth provider, which is also shown on the login screen.
     *
     * @var Setting
     */
    public $authenticationName;

    /**
     * The url where the external service authenticates the user.
     *
     * @var Setting
     */
    public $authorizeUrl;

    /**
     * The url where an access token can be retreived (json response expected).
     *
     * @var Setting
     */
    public $tokenUrl;

    /**
     * The url where the external service provides the users unique id (json response expected).
     *
     * @var Setting
     */
    public $userInfoUrl;

    /**
     * The url where the OIDC provider will invalidate the users session.
     *
     * @var Setting
     */
    public $endSessionUrl;

    /**
     * The name of the unique user id field in $userInfoUrl response.
     *
     * @var Setting
     */
    public $userInfoId;

     /**
     * Use the e-mail address as username.
     *
     * @var Setting
     */
    public $useEmailAsUsername;

    /**
     * The client id given by the provider.
     *
     * @var Setting
     */
    public $clientId;

    /**
     * The client secret given by the provider.
     *
     * @var Setting
     */
    public $clientSecret;

    /**
     * The oauth scopes.
     *
     * @var Setting
     */
    public $scope;

    /**
     * The optional redirect uri override.
     *
     * @var Setting
     */
    public $redirectUriOverride;

    /**
     * Create username from attribute.
     *
     * @var Setting
     */
    public $usernameAttribute;

    /**
     * Use email as fallback if attribute does not exist.
     *
     * @var Setting
     */
     public $fallbackToEmail;

    /**
     * The domains which are allowed to create accounts.
     *
     * @var Setting
     */
    public $allowedSignupDomains;

    /**
     * The domains which are allowed to create accounts.
     *
     * @var Setting
     */
    public $initialIdSite;

    /**
     * The allowedRole.
     *
     * @var Setting
     */
    public $allowedRole;

    /**
     * Initialize the plugin settings.
     *
     * @var Setting
     */

    protected function init()
    {
        $this->disableSuperuser = $this->createDisableSuperuserSetting();
        $this->disablePasswordConfirmation = $this->createDisablePasswordConfirmationSetting();
        $this->disableDirectLoginUrl = $this->createDisableDirectLoginUrlSetting();
        $this->allowSignup = $this->createAllowSignupSetting();
        $this->bypassTwoFa = $this->createBypassTwoFaSetting();
        $this->autoLinking = $this->createAutoLinkingSetting();
        $this->authenticationName = $this->createAuthenticationNameSetting();
        $this->authorizeUrl = $this->createAuthorizeUrlSetting();
        $this->tokenUrl = $this->createTokenUrlSetting();
        $this->userInfoUrl = $this->createUserInfoUrlSetting();
        $this->endSessionUrl = $this->createEndSessionUrlSetting();
        $this->userInfoId = $this->createUserInfoIdSetting();
        $this->usernameAttribute = $this->createUsernameAttributeSetting();
        $this->fallbackToEmail = $this->createFallbackToEmailSetting();
        $this->clientId = $this->createClientIdSetting();
        $this->clientSecret = $this->createClientSecretSetting();
        $this->scope = $this->createScopeSetting();
        $this->redirectUriOverride = $this->createRedirectUriOverrideSetting();
        $this->allowedSignupDomains = $this->createAllowedSignupDomainsSetting();
        $this->initialIdSite = $this->createInitialIdSiteSetting();
        $this->allowedRole = $this->createAllowedRoleSetting();
    }

    /**
     * Add disable superuser setting.
     *
     * @return SystemSetting
     */
    private function createDisableSuperuserSetting(): SystemSetting
    {
        return $this->makeSetting("disableSuperuser", $default = false, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingDisableSuperuser");
            $field->description = Piwik::translate("RebelOIDC_SettingDisableSuperuserHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add disable password confirmation setting.
     *
     * @return SystemSetting
     */
    private function createDisablePasswordConfirmationSetting(): SystemSetting
    {
        return $this->makeSetting("disablePasswordConfirmation", $default = false, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingDisablePasswordConfirmation");
            $field->description = Piwik::translate("RebelOIDC_SettingDisablePasswordConfirmationHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add disable direct login url setting.
     *
     * @return SystemSetting
     */
    private function createDisableDirectLoginUrlSetting(): SystemSetting
    {
        return $this->makeSetting("disableDirectLoginUrl", $default = true, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingDisableDirectLoginUrl");
            $field->description = Piwik::translate("RebelOIDC_SettingDisableDirectLoginUrlHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add allowSignup setting.
     *
     * @return SystemSetting
     */
    private function createAllowSignupSetting(): SystemSetting
    {
        return $this->makeSetting("allowSignup", $default = false, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingAllowSignup");
            $field->description = Piwik::translate("RebelOIDC_SettingAllowSignupHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add bypassTwoFa setting.
     *
     * @return SystemSetting
     */
    private function createBypassTwoFaSetting(): SystemSetting
    {
        return $this->makeSetting("bypassTwoFa", $default = false, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingBypassTwoFa");
            $field->description = Piwik::translate("RebelOIDC_SettingBypassTwoFaHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add autoLinking setting.
     *
     * @return SystemSetting
     */
    private function createAutoLinkingSetting(): SystemSetting
    {
        return $this->makeSetting("autoLinking", $default = false, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingAutoLinking");
            $field->description = Piwik::translate("RebelOIDC_SettingAutoLinkingHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add authentication name setting.
     *
     * @return SystemSetting
     */
    private function createAuthenticationNameSetting(): SystemSetting
    {
        return $this->makeSetting("authenticationName", $default = "OIDC login", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingAuthenticationName");
            $field->description = Piwik::translate("RebelOIDC_SettingAuthenticationNameHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
        });
    }

    /**
     * Add authorization url setting.
     *
     * @return SystemSetting
     */
    private function createAuthorizeUrlSetting(): SystemSetting
    {
        return $this->makeSetting("authorizeUrl", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingAuthorizeUrl");
            $field->description = Piwik::translate("RebelOIDC_SettingAuthorizeUrlHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_URL;
            $field->validators[] = new UrlLike();
        });
    }

    /**
     * Add token url setting.
     *
     * @return SystemSetting
     */
    private function createTokenUrlSetting(): SystemSetting
    {
        return $this->makeSetting("tokenUrl", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingTokenUrl");
            $field->description = Piwik::translate("RebelOIDC_SettingTokenUrlHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_URL;
            $field->validators[] = new UrlLike();
        });
    }

    /**
     * Add userInfo url setting.
     *
     * @return SystemSetting
     */
    private function createUserInfoUrlSetting(): SystemSetting
    {
        return $this->makeSetting("userInfoUrl", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingUserInfoUrl");
            $field->description = Piwik::translate("RebelOIDC_SettingUserInfoUrlHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_URL;
            $field->validators[] = new UrlLike();
        });
    }

    /**
     * Add end session url setting.
     *
     * @return SystemSetting
     */
    private function createEndSessionUrlSetting(): SystemSetting
    {
        return $this->makeSetting("endSessionUrl", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingEndSessionUrl");
            $field->description = Piwik::translate("RebelOIDC_SettingEndSessionUrlHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_URL;
        });
    }

    /**
     * Add userInfo id setting.
     *
     * @return SystemSetting
     */
    private function createUserInfoIdSetting(): SystemSetting
    {
        return $this->makeSetting("userInfoId", $default = "sub", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingUserInfoId");
            $field->description = Piwik::translate("RebelOIDC_SettingUserInfoIdHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
            $field->validators[] = new NotEmpty();
        });
    }

    /**
     * Add setting to configure attribute for user name creation in Matomo
     *
     * @return SystemSetting
     */
    private function createUsernameAttributeSetting(): SystemSetting
    {
        return $this->makeSetting('usernameAttribute', 'preferred_username', FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = 'Username Attribute from OIDC';
            $field->description = 'The OIDC claim to use as username (e.g., "preferred_username", "email", "id")';
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
        });
    }

    private function createFallbackToEmailSetting(): SystemSetting
    {
        return $this->makeSetting('fallbackToEmail', true, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = 'Fallback to Email';
            $field->description = 'Use email as username if the username attribute defined is not available';
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    /**
     * Add client id setting.
     *
     * @return SystemSetting
     */
    private function createClientIdSetting(): SystemSetting
    {
        return $this->makeSetting("clientId", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingClientId");
            $field->description = Piwik::translate("RebelOIDC_SettingClientIdHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
        });
    }

    /**
     * Add client secret setting.
     *
     * @return SystemSetting
     */
    private function createClientSecretSetting(): SystemSetting
    {
        return $this->makeSetting("clientSecret", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingClientSecret");
            $field->description = Piwik::translate("RebelOIDC_SettingClientSecretHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_PASSWORD;
        });
    }

    /**
     * Add scope setting.
     *
     * @return SystemSetting
     */
    private function createScopeSetting(): SystemSetting
    {
        return $this->makeSetting("scope", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingScope");
            $field->description = Piwik::translate("RebelOIDC_SettingScopeHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
        });
    }

    /**
     * Add initial id site.
     *
     * @return SystemSetting
     */
    private function createInitialIdSiteSetting(): SystemSetting
    {
        // Create the system setting for the dropdown
        return $this->makeSetting("initialIdSite", $default = 'none', FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_InitialIdSite");
            $field->description = Piwik::translate("RebelOIDC_InitialIdSiteHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_SINGLE_SELECT;
            $field->availableValues = $this->getSites();
        });
    }

    /**
     *
     * @return array
     */
    private function getSites()
    {
        $sites = \Piwik\Plugins\SitesManager\API::getInstance()->getAllSites();
        $options = [];
        $options['none'] = Piwik::translate("RebelOIDC_None");
        foreach ($sites as $site) {
            $options[$site['idsite']] = $site['name'];
        }
        return $options;
    }


    /**
     * Add redirect uri override setting.
     *
     * @return SystemSetting
     */
    private function createRedirectUriOverrideSetting(): SystemSetting
    {
        return $this->makeSetting("redirectUriOverride", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingRedirectUriOverride");
            $field->description = Piwik::translate("RebelOIDC_SettingRedirectUriOverrideHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_URL;
        });
    }

    /**
     * Add allowed signup domains setting.
     *
     * @return SystemSetting
     */
    private function createAllowedSignupDomainsSetting(): SystemSetting
    {
        return $this->makeSetting("allowedSignupDomains", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingAllowedSignupDomains");
            $field->description = Piwik::translate("RebelOIDC_SettingAllowedSignupDomainsHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_TEXTAREA;
            $field->validate = function ($value, $setting) {
                if (empty($value)) {
                    return;
                }
                $domainPattern = "/^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$/";
                $domains = explode("\n", $value);
                foreach ($domains as $domain) {
                    $isValidDomain = preg_match($domainPattern, $domain);
                    if (!$isValidDomain) {
                        throw new Exception(Piwik::translate("RebelOIDC_ExceptionAllowedSignupDomainsValidationFailed"));
                    }
                }
            };
        });
    }

    /**
     * Add allowed signup domains setting.
     *
     * @return SystemSetting
     */
    private function createAllowedRoleSetting(): SystemSetting
    {
        return $this->makeSetting("allowedRole", $default = "", FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = Piwik::translate("RebelOIDC_SettingAllowedRole");
            $field->description = Piwik::translate("RebelOIDC_SettingAllowedRoleHelp");
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
        });
    }
}
