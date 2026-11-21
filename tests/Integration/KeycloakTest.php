<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Config;
use Piwik\Plugins\RebelOIDC\Auth;
use Piwik\Plugins\RebelOIDC\Commands\KeyCloakSync;
use Piwik\Plugins\RebelOIDC\Controller;
use Piwik\Plugins\RebelOIDC\RebelOIDC;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Session\SessionInitializer;
use Piwik\Tests\Framework\Mock\FakeAccess;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Logs in at a running Keycloak that has the realm of tests/keycloak/realm.json. The test is the
 * browser: it fills in the login form of Keycloak and brings its answer to the plugin, which talks
 * to Keycloak itself from there on.
 *
 * The realm has "anna", who is a user of the Matomo of the test with the same verified email,
 * "karin" with a verified email, the role "matomo-user" and view access to website 1, and "bertil"
 * with an email that is not verified and no role.
 *
 * Needs the URL of Keycloak in the environment variable KEYCLOAK_URL, and is skipped without it.
 *
 * @group RebelOIDC
 * @group Plugins
 */
class KeycloakTest extends OidcTestCase
{
    /**
     * @var string
     */
    private $realmUrl;

    public function setUp(): void
    {
        $keycloakUrl = rtrim((string) getenv('KEYCLOAK_URL'), '/');
        if ($keycloakUrl === '') {
            $this->markTestSkipped('KEYCLOAK_URL is not set.');
        }
        $this->realmUrl = "$keycloakUrl/realms/matomo";

        parent::setUp();

        if (parse_url($keycloakUrl, PHP_URL_SCHEME) === 'http') {
            Config::getInstance()->RebelOIDC = ['allow_http' => 1];
        }
        $this->set([
            'authorizeUrl' => "$this->realmUrl/protocol/openid-connect/auth",
            'tokenUrl' => "$this->realmUrl/protocol/openid-connect/token",
            'userInfoUrl' => "$this->realmUrl/protocol/openid-connect/userinfo",
            'issuer' => $this->realmUrl,
            'clientSecret' => 'matomo-secret',
            'redirectUriOverride' => 'http://matomo.test/index.php?module=RebelOIDC&action=callback&provider=oidc',
            'allowSignup' => true,
        ]);
    }

    protected function createController(): Controller
    {
        return new Controller(new Auth(), $this->createMock(SessionInitializer::class));
    }

    public function testAUserOfKeycloakIsCreatedAndLoggedIn()
    {
        $message = $this->logInAtKeycloak('karin');

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame('karin@example.org', (new Model())->getUser('karin')['email'] ?? null);
        $this->assertSame(['karin'], array_keys($this->getLinks()));
        $this->assertTrue($_SESSION['loginoidc_auth']);
    }

    public function testAutoLinkingLinksTheMatomoUserWithTheSameNameAndVerifiedEmail()
    {
        $this->set(['allowSignup' => false, 'autoLinking' => true, 'userInfoId' => 'preferred_username']);

        $message = $this->logInAtKeycloak('anna');

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame(['anna' => 'anna'], $this->getLinks());
    }

    public function testAUserWithAnEmailKeycloakHasNotVerifiedIsNotCreated()
    {
        $message = $this->logInAtKeycloak('bertil');

        $this->assertStringContainsString('ExceptionEmailNotVerified', $message);
        $this->assertEmpty((new Model())->getUser('bertil'));
    }

    public function testLoginIsRestrictedToARealmRole()
    {
        $this->set(['allowedRole' => 'matomo-user', 'trustUnverifiedEmail' => true]);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $this->logInAtKeycloak('karin'));
        $this->assertStringContainsString('notification=', $this->logInAtKeycloak('bertil'));
        $this->assertEmpty((new Model())->getUser('bertil'));
    }

    public function testGroupsOfKeycloakBecomeAccessToWebsites()
    {
        $this->set(['fineGrainedPermissions' => true]);

        $this->logInAtKeycloak('karin');

        $this->assertEquals([['site' => 1, 'access' => 'view']], (new Model())->getSitesAccessFromUser('karin'));
    }

    public function testATokenOfAnotherIssuerThanTheOneSetIsRefused()
    {
        $this->set(['issuer' => 'https://another-issuer.example/realms/matomo']);

        $message = $this->logInAtKeycloak('karin');

        $this->assertStringContainsString('ExceptionInvalidIdToken', $message);
        $this->assertEmpty((new Model())->getUser('karin'));
    }

    public function testKeycloakRefusesTheCodeWithoutTheVerifierOfTheLogin()
    {
        $message = $this->logInAtKeycloak('karin', function () {
            $_SESSION['loginoidc_verifier'] = str_repeat('a', 64);
        });

        $this->assertStringContainsString('ExceptionInvalidResponse', $message);
        $this->assertEmpty((new Model())->getUser('karin'));
    }

    public function testSyncAddsTheUsersOfKeycloakAndTheyCanLogIn()
    {
        $this->set(['allowSignup' => false]);
        $output = new BufferedOutput();
        FakeAccess::clearAccess(true);

        (new KeyCloakSync())->run(new ArrayInput([
            '--url' => rtrim((string) getenv('KEYCLOAK_URL'), '/'),
            '--realm' => 'matomo',
            '--client' => 'matomo-sync',
            '--secret' => 'matomo-sync-secret',
        ]), $output);

        $this->assertEqualsCanonicalizing(['anna', 'bertil', 'karin'], array_keys($this->getLinks()), $output->fetch());

        $this->logInAs('anonymous');
        $this->assertStringContainsString(self::REDIRECT . 'index.php', $this->logInAtKeycloak('bertil'));
    }

    public function testLoggingOutEndsAtKeycloakAndComesBackToMatomo()
    {
        $this->set(['endSessionUrl' => "$this->realmUrl/protocol/openid-connect/logout"]);
        $general = Config::getInstance()->General;
        $general['login_logout_url'] = 'http://matomo.test/index.php';
        Config::getInstance()->General = $general;
        $this->logInAtKeycloak('karin');

        (new RebelOIDC())->logoutMod();

        $cookies = tempnam(sys_get_temp_dir(), 'keycloak');
        try {
            $answer = $this->request(Config::getInstance()->General['login_logout_url'], $cookies);
        } finally {
            unlink($cookies);
        }
        $this->assertSame('http://matomo.test/index.php', $answer['location'], $answer['body']);
    }

    /**
     * @param callable|null $beforeComingBack run between the login at Keycloak and the callback
     * @return string what the callback ended with: the redirect or the error
     */
    private function logInAtKeycloak(string $username, ?callable $beforeComingBack = null): string
    {
        $cookies = tempnam(sys_get_temp_dir(), 'keycloak');

        try {
            $loginPage = $this->request($this->signIn(), $cookies);
            $this->assertSame(1, preg_match('/<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"/', $loginPage['body'], $form), $loginPage['body']);

            $answer = $this->request(html_entity_decode($form[1]), $cookies, ['username' => $username, 'password' => "$username-password"]);
            $this->assertStringStartsWith('http://matomo.test/', $answer['location'], $answer['body']);
        } finally {
            unlink($cookies);
        }

        parse_str((string) parse_url($answer['location'], PHP_URL_QUERY), $query);
        if ($beforeComingBack) {
            $beforeComingBack();
        }

        return $this->finishLogin(['state' => $query['state'] ?? '', 'code' => $query['code'] ?? '']);
    }

    /**
     * @param array<string, string>|null $post the fields of a form to send, or null for a GET request
     * @return array{body: string, location: string}
     */
    private function request(string $url, string $cookies, ?array $post = null): array
    {
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEJAR => $cookies,
            CURLOPT_COOKIEFILE => $cookies,
            CURLOPT_TIMEOUT => 30,
        ]);
        if ($post !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($post));
        }
        $body = curl_exec($curl);
        $location = (string) curl_getinfo($curl, CURLINFO_REDIRECT_URL);
        $error = curl_error($curl);
        curl_close($curl);

        $this->assertNotFalse($body, $error);

        return ['body' => (string) $body, 'location' => $location];
    }
}
