<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link    https://matomo.org
 * @license https://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\RebelOIDC\Commands;

use Piwik\Plugin\ConsoleCommand;
use Exception;

/**
 */
class KeyCloakSync extends ConsoleCommand
{
    /**
     * @inheritDoc
     */
    protected function configure()
    {
        $this->setName('rebeloidc:keycloak-sync');
        $this->setDescription('KeyCloakSync');
        $this->addRequiredValueOption('url', null, 'Base url');
        $this->addRequiredValueOption('realm', null, 'Realm');
        $this->addRequiredValueOption('client', null, 'Client ID');
        $this->addRequiredValueOption('secret', null, 'Secret');
    }

    /**
     * @inheritDoc
     */
    protected function doExecute(): int
    {
        $input = $this->getInput();
        $output = $this->getOutput();

        $baseUrl = $input->getOption('url');
        $realm = $input->getOption('realm');
        $client = $input->getOption('client');
        $secret = $input->getOption('secret');

        try {
            $users = $this->getUsers($baseUrl, $realm, $client, $secret);
            var_dump($users);
        } catch (Exception $e) {
            echo 'Error: ' . $e->getMessage();
        }
        //$message = sprintf('<info>KeyCloakSync: %s</info>', $name);
        //$output->writeln($message);

        return self::SUCCESS;
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
