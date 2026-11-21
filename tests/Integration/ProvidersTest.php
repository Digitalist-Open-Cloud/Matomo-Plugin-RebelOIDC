<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Plugins\UsersManager\Model;

/**
 * Logs in with what each provider answers, as its documentation describes it, and the settings the
 * FAQ gives for it. A provider is a file in tests/resources/providers:
 *
 * - settings: the settings of the plugin for the provider
 * - accessToken: its claims, or the token itself when it is not a JWT
 * - idToken: its claims, or null when the provider sends none
 * - userInfo: the response of the user info endpoint
 * - expect: the user ID, username and email the login results in, whether the provider says the
 *   email is verified, and the roles it gives
 *
 * @group RebelOIDC
 * @group Plugins
 */
class ProvidersTest extends OidcTestCase
{
    /**
     * @dataProvider getProviders
     */
    public function testAUserLinkedToTheProviderIsLoggedIn(array $provider)
    {
        $this->set($provider['settings'] + ['issuer' => $provider['idToken']['iss'] ?? '']);
        $this->link('anna', $provider['expect']['providerUser']);

        $message = $this->answerAs($provider);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
    }

    /**
     * @dataProvider getProviders
     */
    public function testANewUserGetsTheNameAndEmailOfTheProvider(array $provider)
    {
        $this->set($provider['settings'] + ['allowSignup' => true, 'trustUnverifiedEmail' => !$provider['expect']['verifiesEmail']]);

        $message = $this->answerAs($provider);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame($provider['expect']['email'], (new Model())->getUser($provider['expect']['username'])['email'] ?? null);
        $this->assertSame([$provider['expect']['username'] => $provider['expect']['providerUser']], $this->getLinks());
    }

    /**
     * @dataProvider getProviders
     */
    public function testANewUserIsOnlyCreatedWithoutFurtherSettingsWhenTheProviderVerifiesEmails(array $provider)
    {
        $this->set($provider['settings'] + ['allowSignup' => true]);

        $this->answerAs($provider);

        $this->assertSame($provider['expect']['verifiesEmail'], !empty((new Model())->getUser($provider['expect']['username'])));
    }

    /**
     * @dataProvider getProviders
     */
    public function testLoginCanBeRestrictedToTheRolesOfTheProvider(array $provider)
    {
        $this->link('anna', $provider['expect']['providerUser']);

        foreach ($provider['expect']['roles'] as $role) {
            $this->set($provider['settings'] + ['allowedRole' => $role]);
            $this->assertStringContainsString(self::REDIRECT . 'index.php', $this->answerAs($provider), $role);
        }

        $this->set($provider['settings'] + ['allowedRole' => 'a-role-nobody-has']);
        $this->assertStringContainsString('notification=', $this->answerAs($provider));
    }

    public function getProviders(): array
    {
        $providers = [];
        foreach (glob(__DIR__ . '/../resources/providers/*.json') as $file) {
            $providers[basename($file, '.json')] = [json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR)];
        }

        return $providers;
    }

    private function answerAs(array $provider): string
    {
        $accessToken = is_array($provider['accessToken']) ? $this->jwt($provider['accessToken']) : $provider['accessToken'];

        return $this->answer($accessToken, $provider['idToken'], $provider['userInfo']);
    }
}
