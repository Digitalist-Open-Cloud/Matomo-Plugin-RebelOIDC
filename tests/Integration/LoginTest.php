<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Common;
use Piwik\Config;
use Piwik\Container\StaticContainer;
use Piwik\Piwik;
use Piwik\API\Request;
use Piwik\Plugins\Login\PasswordResetter;
use Piwik\Plugins\RebelOIDC\Protocol;
use Piwik\Plugins\RebelOIDC\Provider;
use Piwik\Plugins\RebelOIDC\RebelOIDC;
use Piwik\Plugins\RebelOIDC\tests\TestKeys;
use Piwik\Plugins\UsersManager\Model;
use Piwik\SettingsPiwik;
use Piwik\Tests\Framework\Fixture;
use Piwik\Tests\Framework\Mock\FakeAccess;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class LoginTest extends OidcTestCase
{
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

    public function testAutoLinkingFindsTheMatomoUserByEmailWhenTheUserIdIsNotItsName()
    {
        $this->set(['autoLinking' => true]);

        $message = $this->comeBack(['sub' => '8a1f-idp', 'email' => 'Anna@example.org', 'email_verified' => true]);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame(['anna' => '8a1f-idp'], $this->getLinks());
    }

    public function testTheEmailIsReadFromTheAttributeThatIsSet()
    {
        $this->set(['allowSignup' => true, 'trustUnverifiedEmail' => true, 'emailAttribute' => 'mail']);

        $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser', 'mail' => 'new@example.org', 'email' => 'other@example.org']);

        $this->assertSame('new@example.org', (new Model())->getUser('newuser')['email']);
    }

    public function testASettingInTheConfigFileIsUsedInsteadOfTheSavedOne()
    {
        Config::getInstance()->RebelOIDC = ['clientId' => 'from-config'];

        parse_str((string) parse_url($this->signIn(), PHP_URL_QUERY), $sent);
        Config::getInstance()->RebelOIDC = [];

        $this->assertSame('from-config', $sent['client_id']);
    }

    /**
     * @dataProvider getLogoutUrlsInTheConfig
     */
    public function testLoggingOutAtTheProviderSendsTheBrowserBack(?string $logoutUrl)
    {
        $this->set(['endSessionUrl' => 'https://idp.example/logout']);
        $_SESSION['loginoidc_auth'] = true;
        $_SESSION['loginoidc_idtoken'] = 'the-id-token';
        $general = Config::getInstance()->General;
        unset($general['login_logout_url']);
        if ($logoutUrl !== null) {
            $general['login_logout_url'] = $logoutUrl;
        }
        Config::getInstance()->General = $general;

        (new RebelOIDC())->logoutMod();

        $url = Config::getInstance()->General['login_logout_url'];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $sent);
        $this->assertStringStartsWith('https://idp.example/logout?', $url);
        $this->assertSame('the-id-token', $sent['id_token_hint']);
        $this->assertSame($logoutUrl ?? SettingsPiwik::getPiwikUrl(), $sent['post_logout_redirect_uri']);
        $this->assertNotEmpty($sent['post_logout_redirect_uri']);
    }

    public function getLogoutUrlsInTheConfig(): array
    {
        return [
            'not set' => [null],
            'set' => ['https://example.org/bye'],
        ];
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

    public function testTheUrlsThatAreNotSetComeFromTheDiscoveryUrl()
    {
        $this->link('anna', 'idp-anna');
        $this->publish(200, [
            'issuer' => 'https://published.example',
            'authorization_endpoint' => 'https://published.example/authorize',
            'token_endpoint' => 'https://published.example/token',
            'userinfo_endpoint' => 'https://published.example/userinfo',
        ]);
        $this->set(['discoveryUrl' => 'https://idp.example/.well-known/openid-configuration', 'authorizeUrl' => '', 'tokenUrl' => '', 'userInfoUrl' => '']);

        $this->assertStringStartsWith('https://published.example/authorize?', $this->signIn());
        $this->assertStringContainsString('ExceptionInvalidIdToken', $this->comeBack(['sub' => 'idp-anna']));
        $this->assertStringContainsString(self::REDIRECT . 'index.php', $this->comeBack(['sub' => 'idp-anna'], ['iss' => 'https://published.example']));

        $this->set(['authorizeUrl' => 'https://idp.example/authorize']);
        $this->assertStringStartsWith('https://idp.example/authorize?', $this->signIn());
    }

    public function testADiscoveryUrlThatDoesNotAnswerStopsTheLogin()
    {
        $this->publish(500, []);
        $this->set(['discoveryUrl' => 'https://down.example/.well-known/openid-configuration', 'authorizeUrl' => '']);

        $this->assertStringContainsString('ExceptionDiscoveryFailed', $this->signIn());
    }

    public function testTheUserIsReadFromTheIdTokenWhenTheSettingSaysSo()
    {
        $this->set(['allowSignup' => true, 'userInfoFromIdToken' => true, 'userInfoUrl' => '']);

        $message = $this->comeBack(
            ['sub' => 'idp-new'],
            ['preferred_username' => 'newuser', 'email' => 'new@example.org', 'email_verified' => true],
            'an-opaque-access-token'
        );

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertSame('new@example.org', (new Model())->getUser('newuser')['email']);
        $this->assertSame(['newuser' => 'idp-new'], $this->getLinks());
    }

    public function testAnErrorOfTheTokenUrlIsReported()
    {
        $this->signIn();
        $this->controller->tokens = (object) ['error' => 'invalid_grant', 'error_description' => 'Code not valid'];

        $message = $this->finishLogin(['state' => $_SESSION['loginoidc_state'], 'code' => 'the-code']);

        $this->assertStringContainsString('ExceptionProviderError', $message);
    }

    public function testRolesAreReadFromTheClaimThatIsSet()
    {
        $this->link('anna', 'idp-anna');
        $this->set(['rolesClaim' => 'groups', 'allowedRole' => 'analysts']);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $this->comeBack(['sub' => 'idp-anna', 'groups' => ['analysts']]));
        $this->assertStringContainsString('ExceptionRoleMissing', $this->comeBack(['sub' => 'idp-anna', 'roles' => ['analysts']]));
    }

    public function testRolesGiveAndTakeAccessToWebsites()
    {
        FakeAccess::clearAccess(true);
        Fixture::createWebsite('2024-01-01 00:00:00');
        $this->logInAs('anonymous');
        $this->link('anna', 'idp-anna');
        $this->set(['fineGrainedPermissions' => true]);

        $this->comeBack(['sub' => 'idp-anna', 'roles' => ['matomo.all.view', '/matomo/2/admin']]);
        $this->assertEqualsCanonicalizing(
            [['site' => 1, 'access' => 'view'], ['site' => 2, 'access' => 'admin']],
            (new Model())->getSitesAccessFromUser('anna')
        );

        $this->comeBack(['sub' => 'idp-anna', 'roles' => ['matomo.2.write']]);
        $this->assertEquals([['site' => 2, 'access' => 'write']], (new Model())->getSitesAccessFromUser('anna'));
    }

    public function testRolesDoNotChangeAccessWithoutTheSetting()
    {
        $this->link('anna', 'idp-anna');
        (new Model())->addUserAccess('anna', 'admin', [1]);

        $this->comeBack(['sub' => 'idp-anna', 'roles' => ['matomo.1.view', 'matomo-admins']]);

        $this->assertEquals([['site' => 1, 'access' => 'admin']], (new Model())->getSitesAccessFromUser('anna'));
        $this->assertEmpty((new Model())->getUser('anna')['superuser_access']);
    }

    public function testSuperUserAccessFollowsTheRoleThatIsSetForIt()
    {
        $this->link('anna', 'idp-anna');
        $this->set(['superUserRole' => 'matomo-admins']);

        $this->comeBack(['sub' => 'idp-anna', 'roles' => ['matomo-admins']]);
        $this->assertNotEmpty((new Model())->getUser('anna')['superuser_access']);

        $this->comeBack(['sub' => 'idp-anna', 'roles' => ['staff']]);
        $this->assertEmpty((new Model())->getUser('anna')['superuser_access']);
    }

    public function testTheOnlySuperUserKeepsSuperUserAccessWithoutTheRole()
    {
        $this->link(Fixture::ADMIN_USER_LOGIN, 'idp-admin');
        $this->set(['superUserRole' => 'matomo-admins']);

        $message = $this->comeBack(['sub' => 'idp-admin', 'roles' => ['staff']]);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertNotEmpty((new Model())->getUser(Fixture::ADMIN_USER_LOGIN)['superuser_access']);
    }

    public function testALinkedUserCannotSetAPasswordWhenTheSettingSaysSo()
    {
        $this->link('anna', 'idp-anna');
        $this->logInAs('anna');
        $this->set(['disablePasswordChange' => true]);

        $this->expectExceptionMessage('ExceptionPasswordLeftToProvider');
        Request::processRequest('UsersManager.updateUser', ['userLogin' => 'anna', 'password' => 'another-long-secret-2']);
    }

    public function testAUserThatIsNotLinkedIsNotKeptFromSettingAPassword()
    {
        $this->set(['disablePasswordChange' => true]);
        $this->logInAs('anna');

        // Matomo gets as far as asking to confirm the current password.
        $this->expectExceptionMessage('UsersManager_');
        Request::processRequest('UsersManager.updateUser', ['userLogin' => 'anna', 'password' => 'another-long-secret-2']);
    }

    /**
     * @dataProvider getResetLinks
     */
    public function testALinkedUserCannotResetThePasswordWhenTheSettingSaysSo(bool $isLinkValid, bool $isRefused)
    {
        $this->link('anna', 'idp-anna');
        $this->set(['disablePasswordChange' => true]);
        $resetter = $this->createMock(PasswordResetter::class);
        if (!$isLinkValid) {
            $resetter->method('checkValidConfirmPasswordToken')->willThrowException(new \Exception('not valid'));
        }
        StaticContainer::getContainer()->set(PasswordResetter::class, $resetter);
        $_GET = ['login' => 'anna', 'resetToken' => 'a-token'];

        if ($isRefused) {
            $this->expectExceptionMessage('ExceptionPasswordLeftToProvider');
        }
        (new RebelOIDC())->refusePasswordReset();

        $this->assertFalse($isRefused);
    }

    public function getResetLinks(): array
    {
        return [
            'a valid link' => [true, true],
            'a link that is not valid is left to Matomo' => [false, false],
        ];
    }

    public function testTheIdTokenHasToBeSignedByTheProviderWhenItsKeysAreKnown()
    {
        $this->link('anna', 'idp-anna');
        $key = TestKeys::createRsaKey();
        $this->publish(200, ['keys' => [TestKeys::toJwk($key, 'k1')]]);
        $this->set(['jwksUrl' => 'https://idp.example/keys']);

        $this->assertStringContainsString('ExceptionInvalidIdToken', $this->comeBack(['sub' => 'idp-anna']));
        $this->assertStringContainsString('ExceptionInvalidIdToken', $this->comeBackWithIdTokenSignedBy(TestKeys::createRsaKey()));
        $this->assertArrayNotHasKey('loginoidc_auth', $_SESSION);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $this->comeBackWithIdTokenSignedBy($key));
    }

    public function testRolesInAnAccessTokenOnlyCountWhenTheProviderSignedItAndItsKeysAreKnown()
    {
        $this->link('anna', 'idp-anna');
        $key = TestKeys::createRsaKey();
        $this->publish(200, ['keys' => [TestKeys::toJwk($key, 'k1')]]);
        $this->set(['jwksUrl' => 'https://idp.example/keys', 'allowedRole' => 'analysts']);
        $claims = ['sub' => 'idp-anna', 'roles' => ['analysts']];

        $message = $this->comeBackWithIdTokenSignedBy($key, TestKeys::sign(['alg' => 'RS256', 'kid' => 'k1'], $claims, TestKeys::createRsaKey()));
        $this->assertStringContainsString('ExceptionRoleMissing', $message);
        $this->assertStringContainsString('ExceptionRoleMissing', $this->comeBackWithIdTokenSignedBy($key, $this->jwt($claims)));

        $message = $this->comeBackWithIdTokenSignedBy($key, TestKeys::sign(['alg' => 'RS256', 'kid' => 'k1'], $claims, $key));
        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
    }

    /**
     * @param \OpenSSLAsymmetricKey $key
     */
    private function comeBackWithIdTokenSignedBy($key, string $accessToken = 'an-opaque-access-token'): string
    {
        $this->signIn();
        $claims = ['iss' => 'https://idp.example', 'aud' => 'matomo', 'sub' => 'idp-anna', 'exp' => time() + 300, 'nonce' => $_SESSION['loginoidc_nonce']];
        $this->controller->tokens = (object) ['access_token' => $accessToken, 'id_token' => TestKeys::sign(['alg' => 'RS256', 'kid' => 'k1'], $claims, $key)];
        $this->controller->userInfo = (object) ['sub' => 'idp-anna'];

        return $this->finishLogin(['state' => $_SESSION['loginoidc_state'], 'code' => 'the-code']);
    }

    public function testTheDomainOfAnEmailIsComparedWithoutCase()
    {
        $this->set(['allowSignup' => true, 'allowedSignupDomains' => "example.com\nexample.org"]);

        $this->comeBack(['sub' => 'idp-new', 'preferred_username' => 'newuser', 'email' => 'new@EXAMPLE.org', 'email_verified' => true]);
        $message = $this->comeBack(['sub' => 'idp-other', 'preferred_username' => 'other', 'email' => 'other@example.net', 'email_verified' => true]);

        $this->assertNotEmpty((new Model())->getUser('newuser'));
        $this->assertStringContainsString('ExceptionAllowedSignupDomainsDenied', $message);
    }

    public function testAUserThatLogsInAgainWhileLoggedInIsSentToMatomoWithTheAccessOfTheProvider()
    {
        $this->link('anna', 'idp-anna');
        $this->set(['fineGrainedPermissions' => true]);
        $this->logInAs('anna');

        $message = $this->comeBack(['sub' => 'idp-anna', 'roles' => ['matomo.1.write']]);

        $this->assertStringContainsString(self::REDIRECT . 'index.php', $message);
        $this->assertEquals([['site' => 1, 'access' => 'write']], (new Model())->getSitesAccessFromUser('anna'));
    }

    public function testMatomoKnowsTheTableOfThePlugin()
    {
        $tables = [];
        Piwik::postEvent('Db.getTablesInstalled', [&$tables]);

        $this->assertContains(Common::prefixTable('rebeloidc_provider'), $tables);
    }

    /**
     * Makes the provider answer the discovery URL and the keys URL with this.
     */
    private function publish(int $status, array $document): void
    {
        $provider = $this->getMockBuilder(Provider::class)->onlyMethods(['request'])->getMock();
        $provider->method('request')->willReturn(['status' => $status, 'data' => json_encode($document)]);
        StaticContainer::getContainer()->set(Provider::class, $provider);
    }

    private function startSignInWithAPasswordConfirmationThatRunsOut(): void
    {
        $this->isPasswordConfirmed = true;
        $this->signIn();
        $this->isPasswordConfirmed = false;
    }
}
