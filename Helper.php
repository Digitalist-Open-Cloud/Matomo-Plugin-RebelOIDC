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
use Piwik\Config;
use Piwik\Log;
use Piwik\Nonce;
use Exception;

trait Helper
{
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
        $sql = "INSERT INTO " . Common::prefixTable("rebeloidc_provider") . " (user, provider_user, provider, date_connected) VALUES (?, ?, ?, ?)";
        $bind = [$matomoUserLogin, $providerUserId, "oidc", date("Y-m-d H:i:s")];
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
        Nonce::checkNonce("RebelOIDC.nonce", $_POST["form_nonce"]);

        $sql = "DELETE FROM " . Common::prefixTable("rebeloidc_provider") . " WHERE user=? AND provider=?";
        $bind = array(Piwik::getCurrentUserLogin(), "oidc");
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
        $sql = "SELECT user FROM " . Common::prefixTable("rebeloidc_provider") . " WHERE provider=? AND provider_user=?";
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
        $sql = "SELECT user, provider_user, provider FROM " . Common::prefixTable("rebeloidc_provider") . " WHERE provider=? AND user=?";
        return Db::fetchRow($sql, array($provider, Piwik::getCurrentUserLogin()));
    }

    /**
     * Apply SSL verification options to a cURL handle for OIDC calls.
     *
     * Supports [RebelOIDC] verify_ssl in config.ini.php and falls back to plugin setting verifySsl.
     *
     * @param resource $ch
     * @return void
     */
    private function applyOidcCurlSslOptions($ch): void
    {
        $verifySsl = $this->shouldVerifySslForOidcCalls();
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifySsl);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verifySsl ? 2 : 0);
    }

    /**
     * Resolve OIDC SSL verification behavior from config and plugin settings.
     *
     * @return bool
     */
    private function shouldVerifySslForOidcCalls(): bool
    {
        $config = Config::getInstance();
        if (isset($config->RebelOIDC['verify_ssl'])) {
            return $this->toBool($config->RebelOIDC['verify_ssl']);
        }

        $settings = new SystemSettings();
        return (bool) $settings->verifySsl->getValue();
    }

    /**
     * Convert config values like "FALSE", "0" or "off" to boolean.
     *
     * @param mixed $value
     * @return bool
     */
    private function toBool($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        $normalized = strtolower(trim((string) $value));
        return !in_array($normalized, ['', '0', 'false', 'off', 'no'], true);
    }

    /**
     * Whether OIDC request/response warnings should be logged.
     *
     * Controlled by [RebelOIDC] oidc_logging in config.ini.php.
     *
     * @return bool
     */
    private function shouldLogOidcWarnings(): bool
    {
        $config = Config::getInstance();
        if (!isset($config->RebelOIDC['oidc_logging'])) {
            return false;
        }

        return $this->toBool($config->RebelOIDC['oidc_logging']);
    }

    /**
     * Log OIDC diagnostics at warn level when enabled.
     *
     * @param string $message
     * @param mixed ...$args
     * @return void
     */
    private function logOidcWarn(string $message, ...$args): void
    {
        if (!$this->shouldLogOidcWarnings()) {
            return;
        }

        Log::warning($message, ...$args);
    }

    /**
     * Fetch an access token from Keycloak using the client credentials.
     *
     * @param string $baseUrl Base URL of the Keycloak server.
     * @param string $realm Keycloak realm.
     * @param string $clientId Client ID for the credentials.
     * @param string $clientSecret Client secret for the credentials.
     * @return string Access token.
     * @throws Exception
     */
    private function getAccessToken(string $baseUrl, string $realm, string $clientId, string $clientSecret): string
    {
        $tokenUrl = $baseUrl . "/realms/" . $realm . "/protocol/openid-connect/token";
        $this->logOidcWarn(
            'RebelOIDC::getAccessToken start. token_url=%s realm=%s',
            $tokenUrl,
            $realm
        );

        $ch = curl_init($tokenUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $this->applyOidcCurlSslOptions($ch);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
        ]);

        $response = curl_exec($ch);
        $curlErrno = curl_errno($ch);
        $curlError = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $this->logOidcWarn(
            'RebelOIDC::getAccessToken finished. token_url=%s http_code=%d curl_errno=%d curl_error=%s response_bytes=%d',
            $tokenUrl,
            (int) $httpCode,
            (int) $curlErrno,
            $curlError === '' ? '<none>' : $curlError,
            is_string($response) ? strlen($response) : 0
        );

        if ($curlErrno !== 0) {
            $this->logOidcWarn(
                'RebelOIDC::getAccessToken curl failure details. token_url=%s curl_errno=%d curl_error=%s',
                $tokenUrl,
                (int) $curlErrno,
                $curlError
            );
            throw new Exception('Error getting access token: ' . curl_error($ch));
        }

        if ($httpCode >= 400) {
            $this->logOidcWarn(
                'RebelOIDC::getAccessToken HTTP failure. token_url=%s http_code=%d response_bytes=%d',
                $tokenUrl,
                (int) $httpCode,
                is_string($response) ? strlen($response) : 0
            );
            throw new Exception("Failed to retrieve token. HTTP Code: $httpCode. Response: $response");
        }

        $tokenData = json_decode($response, true);
        curl_close($ch);

        if (!isset($tokenData['access_token'])) {
            $this->logOidcWarn(
                'RebelOIDC::getAccessToken response missing access_token. token_url=%s',
                $tokenUrl
            );
            throw new Exception('Access token not found in Keycloak response');
        }

        $this->logOidcWarn('RebelOIDC::getAccessToken success. token_url=%s', $tokenUrl);

        return $tokenData['access_token'];
    }

    /**
     * Fetch users from the Keycloak Admin API.
     *
     * @param string $baseUrl Base URL of the Keycloak server.
     * @param string $realm Keycloak realm.
     * @param string $token Access token for the API.
     * @return array List of users.
     * @throws Exception
     */
    private function fetchUsers(string $baseUrl, string $realm, string $token): array
    {
        $usersUrl = $baseUrl . "/admin/realms/" . $realm . "/users";

        $ch = curl_init($usersUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $this->applyOidcCurlSslOptions($ch);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
        ]);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            throw new Exception('Error retrieving users: ' . curl_error($ch));
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode >= 400) {
            throw new Exception("Failed to fetch users. HTTP Code: $httpCode. Response: $response");
        }

        $users = json_decode($response, true);
        return is_array($users) ? $users : [];
    }

    /**
     * Fetch realm-level roles for a specific user from Keycloak.
     *
     * @param string $baseUrl Base URL of the Keycloak server.
     * @param string $realm Keycloak realm.
     * @param string $userId User ID in Keycloak.
     * @param string $token Access token for the API.
     * @return array Roles assigned to the user at the realm level.
     * @throws Exception
     */
    private function fetchRealmRoles(string $baseUrl, string $realm, string $userId, string $token): array
    {
        // Use the /role-mappings/realm endpoint
        $rolesUrl = $baseUrl . "/admin/realms/" . $realm . "/users/" . $userId . "/role-mappings/realm";

        $ch = curl_init($rolesUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $this->applyOidcCurlSslOptions($ch);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
        ]);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            throw new Exception('Error retrieving realm roles for user ' . $userId . ': ' . curl_error($ch));
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);

        if ($httpCode === 404 || empty($response)) {
            return []; // No roles assigned
        } elseif ($httpCode >= 400) {
            throw new Exception("Failed to fetch realm roles for user $userId. HTTP Code: $httpCode. Response: $response");
        }

        // Decode the JSON response
        $rolesData = json_decode($response, true);
        if (!is_array($rolesData)) {
            return [];
        }

        // Extract the role names
        $roles = [];
        foreach ($rolesData as $role) {
            if (isset($role['name'])) {
                $roles[] = $role['name']; // Role name
            }
        }

        return $roles; // Return the list of realm roles
    }

    /**
     * Fetch all users from Keycloak along with their realm roles.
     *
     * @param string $baseUrl Base URL of the Keycloak server.
     * @param string $realm Keycloak realm.
     * @param string $clientId Client ID for the API (not used for roles).
     * @param string $clientSecret Client secret for the API.
     * @return array List of users with their realm roles.
     * @throws Exception
     */
    private function getUsers(string $baseUrl, string $realm, string $clientId, string $clientSecret): array
    {
        $token = $this->getAccessToken($baseUrl, $realm, $clientId, $clientSecret);
        $users = $this->fetchUsers($baseUrl, $realm, $token);
        foreach ($users as &$user) {
            $userId = $user['id'];
            $roles = $this->fetchRealmRoles($baseUrl, $realm, $userId, $token);
            $user['roles'] = $roles; // Append roles directly to the user array
        }

        return $users;
    }
}
