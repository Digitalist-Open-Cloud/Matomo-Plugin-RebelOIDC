<?php

namespace Piwik\Plugins\RebelOIDC\Commands;

use Exception;
use Piwik\Plugin\ConsoleCommand;
use Piwik\Plugins\RebelOIDC\Helper;
use Piwik\Plugins\UsersManager\API as UsersManagerApi;
use Piwik\Common;
use Piwik\Db;
use Piwik\Plugins\RebelOIDC\SystemSettings;

class KeyCloakSync extends ConsoleCommand
{
    use Helper;

    public const SUCCESS = 0;
    public const ERROR = 1;
    private const PROVIDER_NAME = 'oidc';

    /**
     * Configures the command.
     */
    protected function configure(): void
    {
        $this->setName('rebeloidc:keycloak-sync')
            ->setDescription('Sync users from Keycloak with Matomo.')
            ->addRequiredValueOption('url', null, 'Base URL of Keycloak')
            ->addRequiredValueOption('realm', null, 'Keycloak Realm')
            ->addRequiredValueOption('client', null, 'Client ID for Keycloak API')
            ->addRequiredValueOption('secret', null, 'Client Secret for Keycloak API')
            ->addOptionalValueOption('user-field', null, 'Field to use for username (default: "username")', 'username')
            ->addOptionalValueOption('id-site', null, 'Initial site ID to assign view permission', null);
    }

    /**
     * Executes the command.
     */
    protected function doExecute(): int
    {
        $input = $this->getInput();
        $output = $this->getOutput();
        $settings = new SystemSettings();
        if (!$this->isPluginSetup($settings)) {
            $output->writeln('<error>RebelODIC is not setup yet</error>');
            return self::ERROR;
        }
        // Validate required options
        try {
            $baseUrl = $this->validateOption($input->getOption('url'), '--url');
            $realm = $this->validateOption($input->getOption('realm'), '--realm');
            $client = $this->validateOption($input->getOption('client'), '--client');
            $secret = $this->validateOption($input->getOption('secret'), '--secret');
        } catch (Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return self::SUCCESS;
        }

        // Optional options with default values
        $userField = $input->getOption('user-field') ?? 'username';
        $initialIdSite = $input->getOption('id-site');

        try {
            $users = $this->getUsers($baseUrl, $realm, $client, $secret);
            $output->writeln(sprintf('<info>Fetched %d users from Keycloak.</info>', count($users)));
        } catch (Exception $e) {
            $output->writeln('<error>Failed to fetch users from Keycloak: ' . $e->getMessage() . '</error>');
            return self::SUCCESS;
        }

        foreach ($users as $user) {
            try {
                $this->processUser($user, $userField, $initialIdSite, $output);
            } catch (Exception $e) {
                $output->writeln('<error>Error processing user: ' . $e->getMessage() . '</error>');
            }
        }

        $output->writeln('<info>User synchronization completed successfully.</info>');
        return self::SUCCESS;
    }

    /**
     * Processes and synchronizes user.
     */
    private function processUser(array $user, string $userField, ?int $initialIdSite, $output): void
    {
        $userId = $user[$userField] ?? null;
        $providerEmail = $user['email'] ?? null;
        $providerUserId = $user['id'] ?? null;

        if (empty($userId) || empty($providerEmail) || empty($providerUserId)) {
            throw new Exception('User is missing required fields.');
        }

        if ($this->addUser($userId, $providerUserId, $providerEmail, $initialIdSite)) {
            $output->writeln(sprintf('<info>Successfully added user: %s</info>', $userId));
        } else {
            $output->writeln(sprintf('<error>Failed to add user: %s</error>', $userId));
        }
    }

    /**
     * Adds a user to Matomo and links it to a remote user ID from Keycloak.
     */
    private function addUser(string $userId, string $providerUserId, string $providerEmail, ?int $initialIdSite): bool
    {
        $api = UsersManagerApi::getInstance();

        // Check if user already exists in Matomo
        if (!$api->userExists($userId) && !$api->userEmailExists($providerEmail)) {
            $api->addUser(
                $userId,
                "(disallow password login)", // Prevent password login
                $providerEmail,
                true, // $_isPasswordHashed = true
                $initialIdSite
            );
        }

        // Link the user in the custom OIDC table
        $sql = "INSERT INTO " . Common::prefixTable("rebeloidc_provider") . " (user, provider_user, provider, date_connected)
                VALUES (?, ?, ?, ?)";
        $bind = [$userId, $providerUserId, self::PROVIDER_NAME, date("Y-m-d H:i:s")];

        try {
            Db::query($sql, $bind); // Insert into database
            return true;
        } catch (Exception $e) {
            return false; // Return failure if any DB error occurs
        }
    }

    /**
     * Helper to validate required options.
     */
    private function validateOption(?string $value, string $optionName): string
    {
        if (empty($value)) {
            throw new Exception(sprintf('Missing required option: %s', $optionName));
        }
        return $value;
    }
}
