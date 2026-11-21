<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Common;
use Piwik\Db;
use Piwik\Plugins\RebelOIDC\Commands\KeyCloakSync;
use Piwik\Plugins\RebelOIDC\SystemSettings;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Tests\Framework\Fixture;
use Piwik\Tests\Framework\TestCase\IntegrationTestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * A sync that gets the users of Keycloak from the test.
 */
class KeyCloakSyncWithFakeKeycloak extends KeyCloakSync
{
    public $users = [];

    protected function getUsers(string $baseUrl, string $realm, string $clientId, string $clientSecret): array
    {
        return $this->users;
    }
}

/**
 * @group RebelOIDC
 * @group Plugins
 */
class KeyCloakSyncTest extends IntegrationTestCase
{
    public function setUp(): void
    {
        // Matomo empties the user table between tests, which the foreign key of the plugin's table forbids.
        Db::exec('SET FOREIGN_KEY_CHECKS = 0');
        parent::setUp();
        Db::exec('SET FOREIGN_KEY_CHECKS = 1');
        Db::exec('DELETE FROM ' . Common::prefixTable('rebeloidc_provider'));

        Fixture::createSuperUser();
        UsersManagerAPI::getInstance()->addUser('anna', 'a-long-secret-1', 'anna@example.org');

        $settings = new SystemSettings();
        foreach (['authorizeUrl', 'tokenUrl', 'userInfoUrl'] as $name) {
            $settings->$name->setValue('https://idp.example/' . $name);
        }
        $settings->clientId->setValue('matomo');
        $settings->clientSecret->setValue('secret');
        $settings->save();
    }

    public function testAKeycloakUserIsNotLinkedToAMatomoUserThatOnlyHasItsName()
    {
        $output = $this->sync([
            ['id' => 'kc-1', 'username' => Fixture::ADMIN_USER_LOGIN, 'email' => 'attacker@example.org', 'emailVerified' => true],
            ['id' => 'kc-2', 'username' => 'anna', 'email' => 'anna@example.org', 'emailVerified' => false],
        ]);

        $this->assertStringContainsString('was not linked', $output);
        $this->assertSame([], $this->getLinks());
    }

    public function testAKeycloakUserIsLinkedToTheMatomoUserWithItsVerifiedEmailAndNewUsersAreAdded()
    {
        $this->sync([
            ['id' => 'kc-2', 'username' => 'anna', 'email' => 'anna@example.org', 'emailVerified' => true],
            ['id' => 'kc-3', 'username' => 'bertil', 'email' => 'bertil@example.org'],
        ]);

        $this->assertSame(['anna' => 'kc-2', 'bertil' => 'kc-3'], $this->getLinks());
        $this->assertSame('bertil@example.org', (new Model())->getUser('bertil')['email']);
    }

    private function sync(array $users): string
    {
        $command = new KeyCloakSyncWithFakeKeycloak();
        $command->users = $users;
        $output = new BufferedOutput();
        $command->run(new ArrayInput(['--url' => 'https://kc.example', '--realm' => 'r', '--client' => 'c', '--secret' => 's']), $output);

        return $output->fetch();
    }

    private function getLinks(): array
    {
        return array_column(Db::fetchAll('SELECT user, provider_user FROM ' . Common::prefixTable('rebeloidc_provider') . ' ORDER BY user'), 'provider_user', 'user');
    }

    protected static function configureFixture($fixture)
    {
        parent::configureFixture($fixture);

        $fixture->extraPluginsToLoad = ['RebelOIDC'];
    }
}
