<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Access;
use Piwik\Common;
use Piwik\Container\StaticContainer;
use Piwik\Db;
use Piwik\Plugins\Login\PasswordVerifier;
use Piwik\Plugins\RebelOIDC\Auth;
use Piwik\Plugins\RebelOIDC\Controller;
use Piwik\Plugins\RebelOIDC\SystemSettings;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Session\SessionInitializer;
use Piwik\Tests\Framework\Fixture;
use Piwik\Tests\Framework\Mock\FakeAccess;
use Piwik\Tests\Framework\TestCase\IntegrationTestCase;

/**
 * A Matomo with the user "anna" and a provider at https://idp.example that the test answers for.
 */
abstract class OidcTestCase extends IntegrationTestCase
{
    protected const REDIRECT = 'Matomo would redirect you to this URL: ';

    /**
     * @var Controller
     */
    protected $controller;

    /**
     * @var bool
     */
    protected $isPasswordConfirmed = false;

    public function setUp(): void
    {
        // Matomo empties the user table between tests, which the foreign key of the plugin's table forbids.
        Db::exec('SET FOREIGN_KEY_CHECKS = 0');
        parent::setUp();
        Db::exec('SET FOREIGN_KEY_CHECKS = 1');
        Db::exec('DELETE FROM ' . Common::prefixTable('rebeloidc_provider'));

        Fixture::createSuperUser();
        Fixture::createWebsite('2024-01-01 00:00:00');
        UsersManagerAPI::getInstance()->addUser('anna', 'a-long-secret-1', 'anna@example.org');

        $this->set([
            'authorizeUrl' => 'https://idp.example/authorize',
            'tokenUrl' => 'https://idp.example/token',
            'userInfoUrl' => 'https://idp.example/userinfo',
            'clientId' => 'matomo',
            'clientSecret' => 'secret',
            'scope' => 'openid email',
            'disableDirectLoginUrl' => false,
        ]);

        $passwordVerifier = $this->createMock(PasswordVerifier::class);
        $passwordVerifier->method('hasBeenVerified')->willReturnCallback(fn () => $this->isPasswordConfirmed);
        $passwordVerifier->method('requirePasswordVerifiedRecently')->willReturnCallback(fn () => $this->isPasswordConfirmed ?: null);
        StaticContainer::getContainer()->set(PasswordVerifier::class, $passwordVerifier);

        $_SESSION = [];
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->logInAs('anonymous');

        $this->controller = $this->createController();
    }

    protected function createController(): Controller
    {
        return new ControllerWithFakeProvider(new Auth(), $this->createMock(SessionInitializer::class));
    }

    public function tearDown(): void
    {
        $_SESSION = [];
        $_GET = [];
        unset($_SERVER['REQUEST_METHOD']);

        parent::tearDown();
    }

    /**
     * @return string|null the URL the browser is sent to, or null when it is not sent to the provider
     */
    protected function signIn(): ?string
    {
        try {
            $this->controller->signIn();
        } catch (\Exception $e) {
            return trim(explode(self::REDIRECT, $e->getMessage())[1] ?? $e->getMessage());
        }

        return null;
    }

    /**
     * Comes back from the provider, with the user info and the ID token claims it answers with.
     *
     * @return string what the callback ended with: the redirect or the error
     */
    protected function comeBack(array $userInfo, array $idClaims = [], ?string $accessToken = null, bool $withIdToken = true, bool $startSignIn = true): string
    {
        $idClaims += ['iss' => 'https://idp.example', 'aud' => 'matomo', 'sub' => $userInfo['sub']];

        return $this->answer($accessToken ?? $this->jwt(['sub' => $userInfo['sub']]), $withIdToken ? $idClaims : null, $userInfo, $startSignIn);
    }

    /**
     * Comes back from the provider with exactly these answers. The ID token gets the nonce of the
     * login and an expiry, unless it has them.
     *
     * @return string what the callback ended with: the redirect or the error
     */
    protected function answer(string $accessToken, ?array $idClaims, array $userInfo, bool $startSignIn = true): string
    {
        if ($startSignIn) {
            $this->signIn();
        }

        $this->controller->tokens = (object) ['access_token' => $accessToken, 'token_type' => 'Bearer'];
        if ($idClaims !== null) {
            $this->controller->tokens->id_token = $this->jwt($idClaims + ['exp' => time() + 300, 'nonce' => $_SESSION['loginoidc_nonce'] ?? '']);
        }
        $this->controller->userInfo = (object) $userInfo;

        return $this->finishLogin(['state' => $_SESSION['loginoidc_state'] ?? '', 'code' => 'the-code']);
    }

    /**
     * Runs the callback the provider sends the browser to.
     *
     * @param array<string, string> $query what the provider added to the redirect URI
     * @return string what the callback ended with: the redirect or the error
     */
    protected function finishLogin(array $query): string
    {
        $_GET = $query + ['provider' => 'oidc'];

        try {
            $this->controller->callback();
        } catch (\Exception $e) {
            return $e->getMessage();
        }

        return '';
    }

    protected function jwt(array $claims): string
    {
        return 'e30.' . rtrim(strtr(base64_encode(json_encode($claims, JSON_UNESCAPED_UNICODE)), '+/', '-_'), '=') . '.signature';
    }

    protected function set(array $values): void
    {
        Access::doAsSuperUser(function () use ($values) {
            $settings = new SystemSettings();
            foreach ($values as $name => $value) {
                $settings->$name->setValue($value);
            }
            $settings->save();
        });
    }

    protected function logInAs(string $login): void
    {
        FakeAccess::clearAccess(false, [], $login === 'anonymous' ? [] : [1], $login);
    }

    protected function link(string $login, string $providerUser): void
    {
        Db::query('INSERT INTO ' . Common::prefixTable('rebeloidc_provider') . ' (user, provider_user, provider) VALUES (?, ?, ?)', [$login, $providerUser, 'oidc']);
    }

    protected function getLinks(): array
    {
        return array_column(Db::fetchAll('SELECT user, provider_user FROM ' . Common::prefixTable('rebeloidc_provider')), 'provider_user', 'user');
    }

    public function provideContainerConfig()
    {
        return ['Piwik\Access' => new FakeAccess()];
    }

    protected static function configureFixture($fixture)
    {
        parent::configureFixture($fixture);

        $fixture->extraPluginsToLoad = ['RebelOIDC'];
    }
}
