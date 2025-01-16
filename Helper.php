<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

use Piwik\Plugins\UsersManager\Model;
use Piwik\Common;
use Piwik\Piwik;
use Piwik\Db;
use Piwik\Nonce;
use Exception;

trait Helper
{
    /**
     * @var string
     */
    public const OIDC_NONCE = "RebelOIDC.nonce";

    /**
     * @var string
     */
    public const OIDC_PROVIDER = 'oidc';

    /**
     * Generate cryptographically secure random string.
     *
     * @param  int    $length
     * @return string
     */
    private function generateKey(int $length = 64): string
    {
        // thanks ccbsschucko at gmail dot com
        // http://docs.php.net/manual/pl/function.random-bytes.php#122766
        $length = ($length < 4) ? 4 : $length;
        return bin2hex(random_bytes(($length - ($length % 2)) / 2));
    }

    /**
     * Check whether the given user has superuser access.
     * The function in Piwik\Core cannot be used because it requires an admin user being signed in.
     * It was used as a template for this function.
     * See: {@link \Piwik\Core::hasTheUserSuperUserAccess($theUser)} method.
     * See: {@link \Piwik\Plugins\UsersManager\Model::getUsersHavingSuperUserAccess()} method.
     *
     * @param  string  $theUser A username to be checked for superuser access
     * @return bool
     */
    private function hasTheUserSuperUserAccess(string $theUser)
    {
        $userModel = new Model();
        $superUsers = $userModel->getUsersHavingSuperUserAccess();

        foreach ($superUsers as $superUser) {
            if ($theUser === $superUser['login']) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create a link between the remote user and the currently signed in user.
     *
     * @param  string  $providerUserId
     * @param  string  $matomoUserLogin Override the local user if non-null
     * @return void
     */
    private function linkAccount(string $providerUserId, string $matomoUserLogin = null)
    {
        if ($matomoUserLogin === null) {
            $matomoUserLogin = Piwik::getCurrentUserLogin();
        }
        $sql = "INSERT INTO " . Common::prefixTable("loginoidc_provider") . " (user, provider_user, provider, date_connected) VALUES (?, ?, ?, ?)";
        $bind = array($matomoUserLogin, $providerUserId, self::OIDC_PROVIDER, date("Y-m-d H:i:s"));
        Db::query($sql, $bind);
    }

    /**
     * Remove link between the currently signed user and the remote user.
     *
     * @return void
     */
    public function unlink()
    {
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            throw new Exception(Piwik::translate("RebelOIDC_MethodNotAllowed"));
        }
        // csrf protection
        Nonce::checkNonce(self::OIDC_NONCE, $_POST["form_nonce"]);

        $sql = "DELETE FROM " . Common::prefixTable("loginoidc_provider") . " WHERE user=? AND provider=?";
        $bind = array(Piwik::getCurrentUserLogin(), self::OIDC_PROVIDER);
        Db::query($sql, $bind);
        $this->redirectToIndex("UsersManager", "userSecurity");
    }

    /**
     * Fetch user from database given the provider and remote user id.
     *
     * @param  string  $provider
     * @param  string  $remoteId
     * @return array
     */
    private function getUserByRemoteId($provider, $remoteId)
    {
        $sql = "SELECT user FROM " . Common::prefixTable("loginoidc_provider") . " WHERE provider=? AND provider_user=?";
        $result = Db::fetchRow($sql, array($provider, $remoteId));
        if (empty($result)) {
            return $result;
        } else {
            $userModel = new Model();
            return $userModel->getUser($result["user"]);
        }
    }

    /**
     * Determine if all the required settings have been setup.
     *
     * @param  SystemSettings  $settings
     * @return bool
     */
    private function isPluginSetup($settings): bool
    {
        return !empty($settings->authorizeUrl->getValue())
            && !empty($settings->tokenUrl->getValue())
            && !empty($settings->userInfoUrl->getValue())
            && !empty($settings->clientId->getValue())
            && !empty($settings->clientSecret->getValue());
    }

    /**
     * Fetch provider information for the currently signed in user.
     *
     * @param  string  $provider
     * @return array
     */
    private function getProviderUser($provider)
    {
        $sql = "SELECT user, provider_user, provider FROM " . Common::prefixTable("loginoidc_provider") . " WHERE provider=? AND user=?";
        return Db::fetchRow($sql, array($provider, Piwik::getCurrentUserLogin()));
    }

    /**
     * @return array
     */
    private function getUsers($baseUrl, $realm, $clientId, $clientSecret)
    {
        // Get an access token
        $tokenUrl = $baseUrl . "/realms/" . $realm . "/protocol/openid-connect/token";
        $ch = curl_init($tokenUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true); // POST request
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
        ]);
        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            throw new Exception('Error getting access token: ' . curl_error($ch));
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($httpCode >= 400) {
            throw new Exception("Failed to retrieve token. HTTP Code: $httpCode. Response: $response");
        }
        $tokenData = json_decode($response, true);
        curl_close($ch);
        if (!isset($tokenData['access_token'])) {
            throw new Exception('Access token not found in Keycloak response');
        }

        $token = $tokenData['access_token'];

        // Fetch users
        $usersUrl = $baseUrl . "/admin/realms/" . $realm . "/users";
        $ch = curl_init($usersUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
        ]);
        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            throw new Exception('Error retrieving users: ' . curl_error($ch));
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($httpCode >= 400) {
            throw new Exception("Failed to fetch users. HTTP Code: $httpCode. Response: $response");
        }
        $users = json_decode($response, true);
        curl_close($ch);

        return $users;
    }
}
