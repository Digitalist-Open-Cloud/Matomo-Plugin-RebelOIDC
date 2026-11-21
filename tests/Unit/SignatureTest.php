<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\Signature;
use Piwik\Plugins\RebelOIDC\tests\TestKeys;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class SignatureTest extends TestCase
{
    private const CLAIMS = ['sub' => 'anna'];

    private static $rsaKey;
    private static $otherRsaKey;
    private static $ecKey;

    public static function setUpBeforeClass(): void
    {
        self::$rsaKey = TestKeys::createRsaKey();
        self::$otherRsaKey = TestKeys::createRsaKey();
        self::$ecKey = TestKeys::createEcKey();
    }

    public function testATokenSignedWithAKeyOfTheProviderIsValid()
    {
        $keys = ['keys' => [TestKeys::toJwk(self::$otherRsaKey, 'old'), TestKeys::toJwk(self::$rsaKey, 'new'), TestKeys::toJwk(self::$ecKey, 'ec')]];

        $this->assertTrue(Signature::isValid(TestKeys::sign(['alg' => 'RS256', 'kid' => 'new'], self::CLAIMS, self::$rsaKey), $keys));
        $this->assertTrue(Signature::isValid(TestKeys::sign(['alg' => 'RS256'], self::CLAIMS, self::$rsaKey), $keys));
        $this->assertTrue(Signature::isValid(TestKeys::sign(['alg' => 'ES256', 'kid' => 'ec'], self::CLAIMS, self::$ecKey), $keys));
    }

    public function testATokenSignedWithAnotherKeyIsNotValid()
    {
        $keys = ['keys' => [TestKeys::toJwk(self::$rsaKey, 'k1'), TestKeys::toJwk(self::$ecKey, 'ec')]];

        $this->assertFalse(Signature::isValid(TestKeys::sign(['alg' => 'RS256', 'kid' => 'k1'], self::CLAIMS, self::$otherRsaKey), $keys));
        $this->assertFalse(Signature::isValid(TestKeys::sign(['alg' => 'ES256', 'kid' => 'ec'], self::CLAIMS, TestKeys::createEcKey()), $keys));
    }

    public function testATokenWithClaimsThatWereChangedIsNotValid()
    {
        $keys = ['keys' => [TestKeys::toJwk(self::$rsaKey, 'k1')]];
        [$header, , $signature] = explode('.', TestKeys::sign(['alg' => 'RS256', 'kid' => 'k1'], self::CLAIMS, self::$rsaKey));

        $this->assertFalse(Signature::isValid($header . '.' . TestKeys::encode('{"sub":"admin"}') . '.' . $signature, $keys));
    }

    public function testAKeyWithAnotherIdThanTheTokenNamesIsNotUsed()
    {
        $keys = ['keys' => [TestKeys::toJwk(self::$rsaKey, 'k1')]];

        $this->assertFalse(Signature::isValid(TestKeys::sign(['alg' => 'RS256', 'kid' => 'k2'], self::CLAIMS, self::$rsaKey), $keys));
    }

    public function testAKeyThatIsNotForSigningIsNotUsed()
    {
        $keys = ['keys' => [['use' => 'enc'] + TestKeys::toJwk(self::$rsaKey, 'k1')]];

        $this->assertFalse(Signature::isValid(TestKeys::sign(['alg' => 'RS256', 'kid' => 'k1'], self::CLAIMS, self::$rsaKey), $keys));
    }

    /**
     * @dataProvider getTokensThatAreNotSignedByAKey
     */
    public function testATokenThatIsNotSignedWithAKeyIsNotValid(callable $createToken)
    {
        $jwk = TestKeys::toJwk(self::$rsaKey, 'k1');

        $this->assertFalse(Signature::isValid($createToken($jwk), ['keys' => [$jwk]]));
    }

    public function getTokensThatAreNotSignedByAKey(): array
    {
        $unsigned = TestKeys::encode('{"alg":"none"}') . '.' . TestKeys::encode('{"sub":"admin"}');

        return [
            'no signature' => [fn () => $unsigned . '.'],
            'two parts' => [fn () => $unsigned],
            'not a token' => [fn () => 'gho_16C7e42F292c6912E7710c838347Ae178B4a'],
            'signed with the public key as a shared secret' => [function (array $jwk) {
                $signed = TestKeys::encode('{"alg":"HS256","kid":"k1"}') . '.' . TestKeys::encode('{"sub":"admin"}');
                return $signed . '.' . TestKeys::encode(hash_hmac('sha256', $signed, $jwk['n'], true));
            }],
        ];
    }

    public function testKeysThatCannotBeReadAreSkipped()
    {
        $token = TestKeys::sign(['alg' => 'RS256'], self::CLAIMS, self::$rsaKey);

        $this->assertFalse(Signature::isValid($token, []));
        $this->assertFalse(Signature::isValid($token, ['keys' => ['text', ['kty' => 'RSA', 'n' => '!', 'e' => 'AQAB'], ['kty' => 'RSA', 'n' => 'AQ', 'e' => 'AQAB']]]));
        $this->assertTrue(Signature::isValid($token, ['keys' => [['kty' => 'RSA', 'n' => 'AQ', 'e' => 'AQAB'], TestKeys::toJwk(self::$rsaKey, 'k1')]]));
    }
}
