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
use Piwik\Container\StaticContainer;
use Piwik\Piwik;
use Piwik\Db;
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
        $hasUrls = !empty($settings->authorizeUrl->getValue())
            && !empty($settings->tokenUrl->getValue())
            && (!empty($settings->userInfoUrl->getValue()) || $settings->userInfoFromIdToken->getValue());

        return ($hasUrls || !empty($settings->discoveryUrl->getValue()))
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

        $response = StaticContainer::get(Provider::class)->request($tokenUrl, [], [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);
        if ($response['status'] >= 400) {
            throw new Exception("Failed to retrieve token. HTTP Code: {$response['status']}. Response: {$response['data']}");
        }

        $tokenData = json_decode($response['data'], true);
        if (!isset($tokenData['access_token'])) {
            throw new Exception('Access token not found in Keycloak response');
        }

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
    private function fetchUsers(
        string $baseUrl,
        string $realm,
        #[\SensitiveParameter]
        string $token
    ): array {
        $usersUrl = $baseUrl . "/admin/realms/" . $realm . "/users";
        $pageSize = 100;

        $users = [];
        do {
            $response = StaticContainer::get(Provider::class)->request(
                $usersUrl . '?first=' . count($users) . '&max=' . $pageSize,
                ['Authorization: Bearer ' . $token]
            );
            if ($response['status'] >= 400) {
                throw new Exception("Failed to fetch users. HTTP Code: {$response['status']}. Response: {$response['data']}");
            }

            $page = json_decode($response['data'], true);
            $page = is_array($page) ? $page : [];
            $users = array_merge($users, $page);
        } while (count($page) === $pageSize);

        return $users;
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

        $response = StaticContainer::get(Provider::class)->request($rolesUrl, ['Authorization: Bearer ' . $token]);

        if ($response['status'] === 404 || $response['data'] === '') {
            return []; // No roles assigned
        } elseif ($response['status'] >= 400) {
            throw new Exception("Failed to fetch realm roles for user $userId. HTTP Code: {$response['status']}. Response: {$response['data']}");
        }

        // Decode the JSON response
        $rolesData = json_decode($response['data'], true);
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
    protected function getUsers(string $baseUrl, string $realm, string $clientId, string $clientSecret): array
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
