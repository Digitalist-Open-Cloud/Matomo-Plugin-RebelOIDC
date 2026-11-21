<?php

namespace Piwik\Plugins\RebelOIDC\Commands;

use Exception;
use Piwik\Plugin\ConsoleCommand;
use Piwik\Plugins\RebelOIDC\Helper;
use Piwik\Plugins\RebelOIDC\Protocol;
use Piwik\Plugins\UsersManager\Model;
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
            $output->writeln('<error>RebelOIDC is not set up yet</error>');
            return self::FAILURE;
        }
        // Validate required options
        try {
            $baseUrl = $this->validateOption($input->getOption('url'), '--url');
            $realm = $this->validateOption($input->getOption('realm'), '--realm');
            $client = $this->validateOption($input->getOption('client'), '--client');
            $secret = $this->validateOption($input->getOption('secret'), '--secret');
        } catch (Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return self::FAILURE;
        }

        // Optional options with default values
        $userField = $input->getOption('user-field') ?? 'username';
        $initialIdSite = $input->getOption('id-site');

        try {
            $users = $this->getUsers($baseUrl, $realm, $client, $secret);
            $output->writeln(sprintf('<info>Fetched %d users from Keycloak.</info>', count($users)));
        } catch (Exception $e) {
            $output->writeln('<error>Failed to fetch users from Keycloak: ' . $e->getMessage() . '</error>');
            return self::FAILURE;
        }

        $failed = 0;
        foreach ($users as $user) {
            try {
                $failed += $this->processUser($user, $userField, $initialIdSite, $output) ? 0 : 1;
            } catch (Exception $e) {
                $failed++;
                $output->writeln('<error>Error processing user: ' . $e->getMessage() . '</error>');
            }
        }

        if ($failed > 0) {
            $output->writeln(sprintf('<error>User synchronization completed, %d users failed.</error>', $failed));
            return self::FAILURE;
        }

        $output->writeln('<info>User synchronization completed successfully.</info>');
        return self::SUCCESS;
    }

    /**
     * Processes and synchronizes user.
     */
    private function processUser(array $user, string $userField, ?int $initialIdSite, $output): bool
    {
        $userId = $user[$userField] ?? null;
        $providerEmail = $user['email'] ?? null;
        $providerUserId = $user['id'] ?? null;

        if (empty($userId) || empty($providerEmail) || empty($providerUserId)) {
            throw new Exception('User is missing required fields.');
        }

        $isLinked = Db::fetchOne(
            "SELECT 1 FROM " . Common::prefixTable("rebeloidc_provider") . " WHERE provider_user = ? AND provider = ?",
            [$providerUserId, self::PROVIDER_NAME]
        );
        if ($isLinked) {
            $output->writeln(sprintf('<info>Already synced: %s</info>', $userId));
            return true;
        }

        $isEmailTrusted = (new SystemSettings())->trustUnverifiedEmail->getValue() || Protocol::isEmailVerified($user['emailVerified'] ?? null);

        if ($this->addUser($userId, $providerUserId, $providerEmail, $initialIdSite, $isEmailTrusted)) {
            $output->writeln(sprintf('<info>Successfully added user: %s</info>', $userId));
            return true;
        }

        $output->writeln(sprintf('<error>Failed to add user: %s</error>', $userId));
        return false;
    }

    /**
     * Adds a user to Matomo and links it to a remote user ID from Keycloak.
     */
    private function addUser(string $userId, string $providerUserId, string $providerEmail, ?int $initialIdSite, bool $isEmailTrusted): bool
    {
        $api = UsersManagerApi::getInstance();

        // A Matomo user with the same name is not known to be the same person.
        $matomoUser = (new Model())->getUser($userId);
        if (!empty($matomoUser) && !Protocol::canLinkByEmail($matomoUser, $providerEmail, $isEmailTrusted)) {
            throw new Exception("$userId exists in Matomo and was not linked: Keycloak has to report the email address of the Matomo user, as verified.");
        }

        // Check if user already exists in Matomo
        if (empty($matomoUser) && !$api->userEmailExists($providerEmail)) {
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
