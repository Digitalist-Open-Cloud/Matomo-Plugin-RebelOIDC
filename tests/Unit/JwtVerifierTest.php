<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\InvalidTokenException;
use Piwik\Plugins\RebelOIDC\JwtVerifier;

class JwtVerifierTest extends TestCase
{
    private const ISS = 'https://idp.example';
    private const NOW = 1800000000;

    private static $key;
    private static $otherKey;

    public static function setUpBeforeClass(): void
    {
        self::$key = self::newKey();
        self::$otherKey = self::newKey();
    }

    private static function newKey()
    {
        return openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    private static function b64($s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    private function jwks($key, string $kid = 'k1'): array
    {
        $rsa = openssl_pkey_get_details($key)['rsa'];
        return ['keys' => [['kty' => 'RSA', 'use' => 'sig', 'kid' => $kid, 'alg' => 'RS256', 'n' => self::b64($rsa['n']), 'e' => self::b64($rsa['e'])]]];
    }

    private function token(array $claims, $key = null, array $header = []): string
    {
        $header = array_merge(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'k1'], $header);
        $input = self::b64(json_encode($header)) . '.' . self::b64(json_encode($claims));
        openssl_sign($input, $sig, $key ?? self::$key, OPENSSL_ALGO_SHA256);
        return $input . '.' . self::b64($sig);
    }

    private function claims(array $over = []): array
    {
        return array_merge(['iss' => self::ISS, 'sub' => 'u1', 'exp' => self::NOW + 300], $over);
    }

    private function verifier(?array $jwks = null): JwtVerifier
    {
        $jwks = $jwks ?? $this->jwks(self::$key);
        return new JwtVerifier(function (bool $force) use ($jwks) {
            return $jwks;
        });
    }

    public function testValidTokenReturnsClaims(): void
    {
        $payload = $this->verifier()->verify($this->token($this->claims()), self::ISS, self::NOW);
        $this->assertSame('u1', $payload['sub']);
    }

    public function testWrongSignatureIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($this->claims(), self::$otherKey), self::ISS, self::NOW);
    }

    public function testWrongIssuerIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($this->claims(['iss' => 'https://evil'])), self::ISS, self::NOW);
    }

    public function testExpiredBeyondLeewayIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($this->claims(['exp' => self::NOW - 90])), self::ISS, self::NOW);
    }

    public function testExpiredWithinLeewayIsAccepted(): void
    {
        $payload = $this->verifier()->verify($this->token($this->claims(['exp' => self::NOW - 30])), self::ISS, self::NOW);
        $this->assertSame('u1', $payload['sub']);
    }

    public function testMissingExpIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['exp']);
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($claims), self::ISS, self::NOW);
    }

    public function testNotYetValidIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($this->claims(['nbf' => self::NOW + 120])), self::ISS, self::NOW);
    }

    public function testIssuedInTheFutureIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($this->claims(['iat' => self::NOW + 120])), self::ISS, self::NOW);
    }

    public function testAlgNoneIsRejected(): void
    {
        $input = self::b64(json_encode(['alg' => 'none', 'kid' => 'k1'])) . '.' . self::b64(json_encode($this->claims()));
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($input . '.', self::ISS, self::NOW);
    }

    public function testHs256IsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->token($this->claims(), null, ['alg' => 'HS256']), self::ISS, self::NOW);
    }

    public function testMissingKidIsRejected(): void
    {
        $header = self::b64(json_encode(['alg' => 'RS256']));
        $input = $header . '.' . self::b64(json_encode($this->claims()));
        openssl_sign($input, $sig, self::$key, OPENSSL_ALGO_SHA256);
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($input . '.' . self::b64($sig), self::ISS, self::NOW);
    }

    public function testMalformedTokensAreRejected(): void
    {
        $bad = ['', 'a.b', 'a.b.c.d', '!!!.!!!.!!!', self::b64('notjson') . '.' . self::b64('{}') . '.' . self::b64('x')];
        foreach ($bad as $jwt) {
            try {
                $this->verifier()->verify($jwt, self::ISS, self::NOW);
                $this->fail('Accepted malformed token: ' . $jwt);
            } catch (InvalidTokenException $e) {
                $this->assertTrue(true);
            }
        }
    }

    public function testNonSigKeyIsIgnored(): void
    {
        $jwks = $this->jwks(self::$key);
        $jwks['keys'][0]['use'] = 'enc';
        $this->expectException(InvalidTokenException::class);
        $this->verifier($jwks)->verify($this->token($this->claims()), self::ISS, self::NOW);
    }

    public function testNonRsaKeyIsIgnored(): void
    {
        $jwks = $this->jwks(self::$key);
        $jwks['keys'][0]['kty'] = 'EC';
        $this->expectException(InvalidTokenException::class);
        $this->verifier($jwks)->verify($this->token($this->claims()), self::ISS, self::NOW);
    }

    public function testFetchFailureIsRejected(): void
    {
        $v = new JwtVerifier(function (bool $force) {
            throw new \RuntimeException('network down');
        });
        $this->expectException(InvalidTokenException::class);
        $v->verify($this->token($this->claims()), self::ISS, self::NOW);
    }

    public function testUnknownKidRefetchesOnceThenAccepts(): void
    {
        $calls = [];
        $v = new JwtVerifier(function (bool $force) use (&$calls) {
            $calls[] = $force;
            return $force ? $this->jwks(self::$key) : $this->jwks(self::$otherKey, 'other');
        });
        $payload = $v->verify($this->token($this->claims()), self::ISS, self::NOW);
        $this->assertSame('u1', $payload['sub']);
        $this->assertSame([false, true], $calls);
    }

    public function testUnknownKidAfterRefetchIsRejected(): void
    {
        $calls = [];
        $v = new JwtVerifier(function (bool $force) use (&$calls) {
            $calls[] = $force;
            return $this->jwks(self::$otherKey, 'other');
        });
        try {
            $v->verify($this->token($this->claims()), self::ISS, self::NOW);
            $this->fail('Expected InvalidTokenException');
        } catch (InvalidTokenException $e) {
            $this->assertSame([false, true], $calls);
        }
    }

    public function testBase64UrlDecodeHandlesDashAndUnderscore(): void
    {
        $this->assertSame(base64_decode('+/8='), JwtVerifier::base64UrlDecode('-_8'));
    }

    public function testTamperedPayloadWithSignatureOverOriginalIsRejected(): void
    {
        $parts = explode('.', $this->token($this->claims(['sub' => 'u1'])));
        $parts[1] = self::b64(json_encode($this->claims(['sub' => 'admin'])));
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify(implode('.', $parts), self::ISS, self::NOW);
    }

    public function testShouldVerifyAccessTokenForJwsFromOurIssuer(): void
    {
        $this->assertTrue(JwtVerifier::shouldVerifyAccessToken($this->token($this->claims()), self::ISS));
    }

    public function testShouldNotVerifyAccessTokenFromOtherIssuer(): void
    {
        $this->assertFalse(JwtVerifier::shouldVerifyAccessToken($this->token($this->claims(['iss' => 'https://other.example'])), self::ISS));
    }

    public function testShouldNotVerifyOpaqueOrJweAccessToken(): void
    {
        $this->assertFalse(JwtVerifier::shouldVerifyAccessToken('K9xZ3-opaque_random~string', self::ISS));
        $this->assertFalse(JwtVerifier::shouldVerifyAccessToken('a.b.c.d.e', self::ISS));
        $this->assertFalse(JwtVerifier::shouldVerifyAccessToken('', self::ISS));
    }

    public function testJwsWithOurIssuerButBadSignatureStillFails(): void
    {
        $token = $this->token($this->claims(), self::$otherKey);
        $this->assertTrue(JwtVerifier::shouldVerifyAccessToken($token, self::ISS));
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token, self::ISS, self::NOW);
    }
}
