<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

use Piwik\Common;
use Piwik\Config;
use Piwik\Container\StaticContainer;
use Piwik\Db;
use Piwik\DbHelper;
use Piwik\FrontController;
use Piwik\Plugins\RebelOIDC\SystemSettings;
use Piwik\Plugins\RebelOIDC\Url;
use Piwik\Request;
use Piwik\Session;
use Piwik\SettingsPiwik;
use Piwik\Piwik;
use Piwik\Plugin;
use Piwik\Plugins\Login\PasswordResetter;

class RebelOIDC extends Plugin
{
    /**
     * @return array
     */
    public function registerEvents(): array
    {
        return array(
            "Session.beforeSessionStart" => "beforeSessionStart",
            "AssetManager.getStylesheetFiles" => "getStylesheetFiles",
            "Template.userSecurity.afterPassword" => "renderRebelOIDCUserSettings",
            "Template.loginNav" => "renderRebelOIDCMod",
            "Template.confirmPasswordContent" => "renderConfirmPasswordMod",
            "Login.logout" => "logoutMod",
            "Login.userRequiresPasswordConfirmation" => "userRequiresPasswordConfirmation",
            'Db.getTablesInstalled' => 'getTablesInstalled',
            'API.UsersManager.updateUser' => 'refusePasswordChange',
            'Controller.Login.confirmResetPassword' => 'refusePasswordReset',
        );
    }

    /**
     * Create RememberMe cookie.
     * @see \Piwik\Plugins\Login::beforeSessionStart
     *
     * @return void
     */
    public function beforeSessionStart(): void
    {
        if (!$this->shouldHandleRememberMe()) {
            return;
        }
        Session::rememberMe(Config::getInstance()->General["login_cookie_expire"]);
    }

    /**
     * Decide if RememberMe cookie should be handled by the plugin.
     * @see \Piwik\Plugins\Login::shouldHandleRememberMe
     *
     * @return bool
     */
    private function shouldHandleRememberMe(): bool
    {
        $module = Request::fromGet()->getStringParameter("module", "");
        $action = Request::fromGet()->getStringParameter("action", "");
        return ($module == "RebelOIDC") && ($action == "callback");
    }

    /**
     * Append additional stylesheets.
     *
     * @param  array  $files
     * @return void
     */
    public function getStylesheetFiles(array &$files)
    {
        $files[] = "plugins/RebelOIDC/stylesheets/loginMod.css";
    }

    /**
     * Register the new tables, so Matomo knows about them.
     *
     * @param array $allTablesInstalled
     */
    public function getTablesInstalled(&$allTablesInstalled)
    {
        $allTablesInstalled[] = Common::prefixTable('rebeloidc_provider');
    }

    /**
     * Append custom user settings layout.
     *
     * @param  string  $out
     * @return void
     */
    public function renderRebelOIDCUserSettings(string &$out)
    {
        $content = FrontController::getInstance()->dispatch("RebelOIDC", "userSettings");
        if (!empty($content)) {
            $out .= $content;
        }
    }

    /**
     * Append login oauth button layout.
     *
     * @param  string       $out
     * @param  string|null  $payload
     * @return void
     */
    public function renderRebelOIDCMod(string &$out, string $payload = null)
    {
        if (!empty($payload) && $payload === "bottom") {
            $content = FrontController::getInstance()->dispatch("RebelOIDC", "loginMod");
            if (!empty($content)) {
                $out .= $content;
            }
        }
    }

    /**
     * Append login oauth button layout.
     * The password confirmation modal is not consistent enough to rely on this modification.
     * It is recommended to use the `userRequiresPasswordConfirmation` event instead
     *
     * @param  string       $out
     * @param  string|null  $payload
     * @return void
     */
    public function renderConfirmPasswordMod(string &$out, string $payload = null)
    {
        if (!empty($payload) && $payload === "bottom") {
            $content = FrontController::getInstance()->dispatch("RebelOIDC", "confirmPasswordMod");
            if (!empty($content)) {
                $out .= $content;
            }
        }
    }

    /**
     * Temporarily override logout url to the oidc provider end user session endpoint.
     *
     * @return void
     */
    public function logoutMod()
    {
        $settings = new SystemSettings();
        if (empty($_SESSION["loginoidc_auth"])) {
            return;
        }
        try {
            $endSessionUrl = StaticContainer::get(Provider::class)->getEndpoints($settings)['endSessionUrl'];
        } catch (\Exception $e) {
            // Logging out of Matomo has to work when the provider cannot be reached.
            $endSessionUrl = '';
        }
        if (!empty($endSessionUrl)) {
            // make sure we properly unset the plugins session variable
            unset($_SESSION['loginoidc_auth']);
            $endSessionUrl = new Url($endSessionUrl);
            if (isset($_SESSION["loginoidc_idtoken"])) {
                $endSessionUrl->setQueryParameter("id_token_hint", $_SESSION["loginoidc_idtoken"]);
            }
            $endSessionUrl->setQueryParameter(
                "post_logout_redirect_uri",
                Config::getInstance()->General['login_logout_url'] ?? SettingsPiwik::getPiwikUrl()
            );
            Config::getInstance()->General['login_logout_url'] = $endSessionUrl->buildString();
        }
    }

    /**
     * @param array<string, mixed> $parameters the parameters of UsersManager.updateUser
     */
    public function refusePasswordChange(&$parameters): void
    {
        $login = (string) ($parameters['userLogin'] ?? '');
        if (!empty($parameters['password']) && $login === Piwik::getCurrentUserLogin() && $this->isPasswordLeftToProvider($login)) {
            throw new \Exception(Piwik::translate('RebelOIDC_ExceptionPasswordLeftToProvider'));
        }
    }

    public function refusePasswordReset(): void
    {
        $login = Request::fromRequest()->getStringParameter('login', '');
        if (!$this->isPasswordLeftToProvider($login)) {
            return;
        }

        try {
            StaticContainer::get(PasswordResetter::class)->checkValidConfirmPasswordToken(
                $login,
                Request::fromRequest()->getStringParameter('resetToken', '')
            );
        } catch (\Exception $e) {
            // Matomo answers a link that is not valid itself, without telling who is linked.
            return;
        }

        throw new \Exception(Piwik::translate('RebelOIDC_ExceptionPasswordLeftToProvider'));
    }

    private function isPasswordLeftToProvider(string $login): bool
    {
        $settings = new SystemSettings();

        return $login !== ''
            && $settings->disablePasswordChange->getValue()
            && Db::fetchOne('SELECT 1 FROM ' . Common::prefixTable('rebeloidc_provider') . ' WHERE user = ? AND provider = ?', [$login, 'oidc']);
    }

    /**
     * Disable password confirmation when user signed up with RebelOIDC.
     * This feature requires Matomo >4.12.0
     *
     * @return void
     */
    public function userRequiresPasswordConfirmation(&$requiresPasswordConfirmation, $login): void
    {
        $settings = new SystemSettings();
        $disablePasswordConfirmation = $settings->disablePasswordConfirmation->getValue();
        if ($disablePasswordConfirmation) {
            // require password confirmation when user has not signed in with the plugin
            $requiresPasswordConfirmation = !($_SESSION["loginoidc_auth"] ?? false);
        }
    }

    /**
     * Extend database.
     *
     * @return void
     */
    public function install()
    {
        // right now there is just one provider but we already add a column to support multiple providers later on
        DbHelper::createTable("rebeloidc_provider", "
            `user` VARCHAR( 100 ) NOT NULL,
            `provider_user` VARCHAR( 255 ) NOT NULL,
            `provider` VARCHAR( 255 ) NOT NULL,
            `date_connected` TIMESTAMP NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
            PRIMARY KEY ( `provider_user`, `provider` ),
            UNIQUE KEY `user_provider` ( `user`, `provider` ),
            FOREIGN KEY ( `user` ) REFERENCES " . Common::prefixTable("user") . " ( `login` ) ON DELETE CASCADE");
    }

    /**
     * Undo database changes from install.
     *
     * @return void
     */
    public function uninstall()
    {
        Db::dropTables(Common::prefixTable("rebeloidc_provider"));
    }
}
