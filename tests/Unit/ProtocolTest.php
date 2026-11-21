<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\Protocol;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class ProtocolTest extends TestCase
{
    private const NOW = 1700000000;

    public function testDecodeJwtReadsBase64UrlPayloads()
    {
        $claims = ['sub' => '1', 'name' => 'Zoë >>>? ~~~ ÿÿÿ'];
        $payload = rtrim(strtr(base64_encode(json_encode($claims, JSON_UNESCAPED_UNICODE)), '+/', '-_'), '=');
        $this->assertRegExp('/[-_]/', $payload);

        $this->assertSame($claims, Protocol::decodeJwt("header.$payload.signature"));
    }

    /**
     * @dataProvider getTokensThatAreNotReadable
     */
    public function testDecodeJwtReturnsNullForATokenItCannotRead(?string $token)
    {
        $this->assertNull(Protocol::decodeJwt($token));
    }

    public function getTokensThatAreNotReadable(): array
    {
        return [
            'none' => [null],
            'opaque' => ['gho_16C7e42F292c6912E7710c838347Ae178B4a'],
            'encrypted' => ['a.b.c.d.e'],
            'not base64' => ['a.%%%.c'],
            'not json' => ['a.' . base64_encode('hello') . '.c'],
            'not an object' => ['a.' . base64_encode('"hello"') . '.c'],
        ];
    }

    public function testCheckIdTokenAcceptsATokenForThisLogin()
    {
        Protocol::checkIdToken($this->getClaims(), 'matomo', 'https://idp.example/', 'the-nonce', self::NOW);
        Protocol::checkIdToken($this->getClaims(), 'matomo', '', 'the-nonce', self::NOW);
        Protocol::checkIdToken($this->getClaims(['aud' => ['matomo', 'other'], 'azp' => 'matomo']), 'matomo', '', 'the-nonce', self::NOW);

        $this->addToAssertionCount(3);
    }

    /**
     * @dataProvider getClaimsOfOtherLogins
     */
    public function testCheckIdTokenRefusesATokenThatIsNotForThisLogin(array $changedClaims)
    {
        $this->expectException(\Exception::class);

        $claims = array_filter($this->getClaims($changedClaims), fn ($value) => $value !== null);
        Protocol::checkIdToken($claims, 'matomo', 'https://idp.example', 'the-nonce', self::NOW);
    }

    public function getClaimsOfOtherLogins(): array
    {
        return [
            'for another client' => [['aud' => 'other']],
            'no audience' => [['aud' => null]],
            'several audiences, authorized party is another client' => [['aud' => ['matomo', 'other'], 'azp' => 'other']],
            'several audiences, no authorized party' => [['aud' => ['matomo', 'other']]],
            'expired' => [['exp' => self::NOW - 3600]],
            'no expiry' => [['exp' => null]],
            'nonce of another login' => [['nonce' => 'another-nonce']],
            'no nonce' => [['nonce' => null]],
            'another issuer' => [['iss' => 'https://evil.example']],
            'no issuer' => [['iss' => null]],
        ];
    }

    public function testPkceChallengeIsTheOneOfTheSpecification()
    {
        $this->assertSame(
            'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            Protocol::getPkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
        );
    }

    public function testEmailIsOnlyVerifiedWhenTheProviderSaysSo()
    {
        $this->assertTrue(Protocol::isEmailVerified(true));
        $this->assertTrue(Protocol::isEmailVerified('true'));
        $this->assertFalse(Protocol::isEmailVerified(false));
        $this->assertFalse(Protocol::isEmailVerified(null));
        $this->assertFalse(Protocol::isEmailVerified('false'));
        $this->assertFalse(Protocol::isEmailVerified(1));
    }

    public function testLinkingByEmailNeedsTheTrustedEmailOfTheMatomoUser()
    {
        $user = ['login' => 'anna', 'email' => 'Anna@Example.org'];

        $this->assertTrue(Protocol::canLinkByEmail($user, 'anna@example.org', true));
        $this->assertFalse(Protocol::canLinkByEmail($user, 'anna@example.org', false));
        $this->assertFalse(Protocol::canLinkByEmail($user, 'other@example.org', true));
        $this->assertFalse(Protocol::canLinkByEmail($user, null, true));
        $this->assertFalse(Protocol::canLinkByEmail(['login' => 'anna', 'email' => ''], '', true));
    }

    private function getClaims(array $changed = []): array
    {
        return $changed + [
            'iss' => 'https://idp.example',
            'aud' => 'matomo',
            'exp' => self::NOW + 300,
            'nonce' => 'the-nonce',
            'sub' => '1',
        ];
    }
}
