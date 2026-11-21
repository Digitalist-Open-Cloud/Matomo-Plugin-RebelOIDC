<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Access;
use Piwik\Common;
use Piwik\Config;
use Piwik\Container\StaticContainer;
use Piwik\Db;
use Piwik\Plugins\Login\PasswordVerifier;
use Piwik\Plugins\RebelOIDC\Auth;
use Piwik\Plugins\RebelOIDC\Controller;
use Piwik\Plugins\RebelOIDC\Protocol;
use Piwik\Plugins\RebelOIDC\SystemSettings;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Session\SessionInitializer;
use Piwik\Tests\Framework\Fixture;
use Piwik\Tests\Framework\Mock\FakeAccess;
use Piwik\Tests\Framework\TestCase\IntegrationTestCase;

/**
 * A controller that gets the answers of the provider from the test.
 */
class ControllerWithFakeProvider extends Controller
{
    public $tokens;
    public $userInfo;
    public $tokenRequest;

    protected function requestTokens(array $data, string $tokenUrl)
    {
        $this->tokenRequest = $data;
        return $this->tokens;
    }

    protected function requestUserInfo(string $accessToken, string $userInfoUrl)
    {
        return $this->userInfo;
    }
}

/**
 * @group RebelOIDC
 * @group Plugins
 */
class LoginTest extends IntegrationTestCase
{
    private const REDIRECT = 'Matomo would redirect you to this URL: ';

    /**
     * @var ControllerWithFakeProvider
     */
    private $controller;

    /**
     * @var bool
     */
    private $isPasswordConfirmed = false;

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

        $this->controller = new ControllerWithFakeProvider(new Auth(), $this->createMock(SessionInitializer::class));
    }

    public function tearDown(): void
    {
        $_SESSION = [];
        $_GET = [];
        unset($_SERVER['REQUEST_METHOD']);

        parent::tearDown();
    }

    public function testSignInSendsAChallengeAndTheCallbackSendsItsVerifier()
    {
        $url = $this->signIn();

        parse_str((string) parse_url($url, PHP_URL_QUERY), $sent);
        $this->assertStringStartsWith('https://idp.example/authorize?', $url);
        $this->assertSame('S256', $sent['code_challenge_method']);
        $this->assertNotEmpty($sent['nonce']);
        $this->assertNotSame($sent['state'], $sent['nonce']);

        $this->comeBack(['sub' => 'unknown'], [], null, true, false);

        $this->assertSame($sent['code_challenge'], Protocol::getPkceChallenge($this->controller->tokenRequest['code_verifier']));
    }

    public function testALinkedUserIsLoggedIn()
    {
        $this->link('anna', 'idp-anna');

        $message = $this->comeBack(['sub' => 'idp-anna']);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertTrue($_SESSION['loginoidc_auth']);
    }

    public function testAnAccessTokenThatIsNotAJwtIsAccepted()
    {
        $this->link('anna', 'idp-anna');

        $message = $this->comeBack(['sub' => 'idp-anna'], [], 'gho_16C7e42F292c6912E7710c838347Ae178B4a', false);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
    }

    /**
     * @dataProvider getIdTokensOfOtherLogins
     */
    public function testAnIdTokenThatIsNotForThisLoginIsRefused(array $claims)
    {
        $this->link('anna', 'idp-anna');
        $this->set(['issuer' => 'https://idp.example']);

        $message = $this->comeBack(['sub' => 'idp-anna'], $claims);

        $this->assertStringContainsString('ExceptionInvalidIdToken', $message);
        $this->assertArrayNotHasKey('loginoidc_auth', $_SESSION);
    }

    public function getIdTokensOfOtherLogins(): array
    {
        return [
            'another client' => [['aud' => 'other']],
            'nonce of another login' => [['nonce' => 'replayed']],
            'expired' => [['exp' => time() - 3600]],
            'another issuer' => [['iss' => 'https://evil.example']],
        ];
    }

    public function testUserInfoOfAnotherUserThanTheIdTokenIsRefused()
    {
        $this->link('anna', 'idp-anna');

        $message = $this->comeBack(['sub' => 'idp-anna'], ['sub' => 'idp-bertil']);

        $this->assertStringContainsString('ExceptionInvalidResponse', $message);
        $this->assertArrayNotHasKey('loginoidc_auth', $_SESSION);
    }

    public function testAProviderOverHttpIsRefused()
    {
        $this->link('anna', 'idp-anna');
        Config::getInstance()->RebelOIDC = ['allow_http' => 1];
        $this->set(['tokenUrl' => 'http://idp.example/token']);
        Config::getInstance()->RebelOIDC = [];

        $message = $this->comeBack(['sub' => 'idp-anna']);

        $this->assertStringContainsString('ExceptionUrlNotHttps', $message);
    }

    public function testAnHttpUrlCannotBeSaved()
    {
        $this->expectException(\Exception::class);

        $this->set(['tokenUrl' => 'http://idp.example/token']);
    }

    public function testAutoLinkingRefusesAnAccountThatOnlyHasTheNameOfAMatomoUser()
    {
        $this->set(['autoLinking' => true]);

        $message = $this->comeBack(['sub' => Fixture::ADMIN_USER_LOGIN, 'email' => 'attacker@example.org', 'email_verified' => true]);

        $this->assertStringContainsString('ExceptionUserNotFoundAndSignupDisabled', $message);
        $this->assertSame([], $this->getLinks());
        $this->assertArrayNotHasKey('loginoidc_auth', $_SESSION);
    }

    public function testAutoLinkingRefusesAnEmailTheProviderHasNotVerified()
    {
        $this->set(['autoLinking' => true]);

        $this->comeBack(['sub' => 'anna', 'email' => 'anna@example.org', 'email_verified' => false]);
        $this->comeBack(['sub' => 'anna', 'email' => 'anna@example.org']);

        $this->assertSame([], $this->getLinks());
    }

    public function testAutoLinkingLinksAnAccountWithTheVerifiedEmailOfTheMatomoUser()
    {
        $this->set(['autoLinking' => true]);

        $message = $this->comeBack(['sub' => 'anna', 'email' => 'anna@example.org', 'email_verified' => true]);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame(['anna' => 'anna'], $this->getLinks());
    }

    public function testAnAccountNobodyKnowsDoesNotTurnOffPasswordConfirmation()
    {
        $this->set(['disablePasswordConfirmation' => true]);
        $this->logInAs('anna');
        $this->startSignInWithAPasswordConfirmationThatRunsOut();

        $message = $this->comeBack(['sub' => 'idp-stranger'], [], null, true, false);

        $this->assertStringContainsString('ExceptionPasswordConfirmationRequired', $message);
        $this->assertArrayNotHasKey('loginoidc_auth', $_SESSION);
    }

    public function testLinkingStartsWithConfirmingThePassword()
    {
        $this->logInAs('anna');

        $this->assertNull($this->signIn());
        $this->assertArrayNotHasKey('loginoidc_state', $_SESSION);
    }

    public function testLinkingIsRefusedWithoutAConfirmedPassword()
    {
        $this->logInAs('anna');
        $this->startSignInWithAPasswordConfirmationThatRunsOut();

        $message = $this->comeBack(['sub' => 'idp-attacker'], [], null, true, false);

        $this->assertStringContainsString('ExceptionPasswordConfirmationRequired', $message);
        $this->assertSame([], $this->getLinks());
    }

    public function testLinkingWorksWithAConfirmedPassword()
    {
        $this->logInAs('anna');
        $this->isPasswordConfirmed = true;

        $this->assertStringStartsWith('https://idp.example/authorize?', $this->signIn());
        $this->comeBack(['sub' => 'idp-anna'], [], null, true, false);

        $this->assertSame(['anna' => 'idp-anna'], $this->getLinks());
    }

    public function testSignUpNeedsAVerifiedEmail()
    {
        $this->set(['allowSignup' => true, 'allowedSignupDomains' => 'example.org']);

        $message = $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser', 'email' => 'new@example.org', 'email_verified' => false]);
        $this->assertStringContainsString('ExceptionEmailNotVerified', $message);

        $message = $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser', 'email' => 'new@example.org']);
        $this->assertStringContainsString('ExceptionEmailNotVerified', $message);

        $this->assertEmpty((new Model())->getUser('newuser'));
    }

    public function testSignUpCreatesAUserWithAVerifiedEmail()
    {
        $this->set(['allowSignup' => true]);

        $message = $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser', 'email' => 'new@example.org', 'email_verified' => true]);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame('new@example.org', (new Model())->getUser('newuser')['email']);
        $this->assertSame(['newuser' => 'idp-new'], $this->getLinks());
    }

    public function testSignUpTakesTheVerifiedEmailFromTheIdTokenToo()
    {
        $this->set(['allowSignup' => true]);

        $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser'], ['sub' => 'idp-new', 'email' => 'new@example.org', 'email_verified' => true]);

        $this->assertSame('new@example.org', (new Model())->getUser('newuser')['email']);
    }

    public function testSignUpAcceptsAnUnverifiedEmailWhenTheSettingSaysSo()
    {
        $this->set(['allowSignup' => true, 'trustUnverifiedEmail' => true]);

        $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser', 'email' => 'new@example.org']);

        $this->assertNotEmpty((new Model())->getUser('newuser'));
    }

    private function startSignInWithAPasswordConfirmationThatRunsOut(): void
    {
        $this->isPasswordConfirmed = true;
        $this->signIn();
        $this->isPasswordConfirmed = false;
    }

    /**
     * @return string|null the URL the browser is sent to, or null when it is not sent to the provider
     */
    private function signIn(): ?string
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
    private function comeBack(array $userInfo, array $idClaims = [], ?string $accessToken = null, bool $withIdToken = true, bool $startSignIn = true): string
    {
        if ($startSignIn) {
            $this->signIn();
        }

        $idClaims += ['iss' => 'https://idp.example', 'aud' => 'matomo', 'exp' => time() + 300, 'nonce' => $_SESSION['loginoidc_nonce'] ?? '', 'sub' => $userInfo['sub']];
        $this->controller->tokens = (object) ['access_token' => $accessToken ?? $this->jwt(['sub' => $userInfo['sub']])];
        if ($withIdToken) {
            $this->controller->tokens->id_token = $this->jwt($idClaims);
        }
        $this->controller->userInfo = (object) $userInfo;
        $_GET = ['state' => $_SESSION['loginoidc_state'] ?? '', 'code' => 'the-code', 'provider' => 'oidc'];

        try {
            $this->controller->callback();
        } catch (\Exception $e) {
            return $e->getMessage();
        }

        return '';
    }

    private function jwt(array $claims): string
    {
        return 'e30.' . rtrim(strtr(base64_encode(json_encode($claims)), '+/', '-_'), '=') . '.signature';
    }

    private function set(array $values): void
    {
        Access::doAsSuperUser(function () use ($values) {
            $settings = new SystemSettings();
            foreach ($values as $name => $value) {
                $settings->$name->setValue($value);
            }
            $settings->save();
        });
    }

    private function logInAs(string $login): void
    {
        FakeAccess::clearAccess(false, [], $login === 'anonymous' ? [] : [1], $login);
    }

    private function link(string $login, string $providerUser): void
    {
        Db::query('INSERT INTO ' . Common::prefixTable('rebeloidc_provider') . ' (user, provider_user, provider) VALUES (?, ?, ?)', [$login, $providerUser, 'oidc']);
    }

    private function getLinks(): array
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
