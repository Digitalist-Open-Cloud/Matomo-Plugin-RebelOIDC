<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\JwtVerifier;

/**
 * Legacy mode (no jwksUrl/issuer): claims are decoded without verification.
 *
 * @group RebelOIDC
 * @group Plugins
 */
class LegacyClaimsTest extends TestCase
{
    private function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    private function jws(array $payload): string
    {
        return $this->b64('{"alg":"RS256"}') . '.' . $this->b64(json_encode($payload)) . '.' . $this->b64('sig');
    }

    public function testPayloadIsDecoded(): void
    {
        $claims = ['roles' => ['matomo-user'], 'realm_access' => ['roles' => ['a']]];
        $this->assertSame($claims, JwtVerifier::unverifiedClaims($this->jws($claims)));
    }

    public function testBase64UrlAlphabetIsDecoded(): void
    {
        // chosen so the encoded payload contains both '-' and '_'
        $claims = ['name' => "\xfb\xff\xbe>>??", 'x' => '~~~'];
        $payload = json_encode($claims, JSON_INVALID_UTF8_SUBSTITUTE);
        $encoded = $this->b64($payload);
        $this->assertSame(1, preg_match('/[-_]/', $encoded), 'test payload must exercise - or _');
        $token = $this->b64('{"alg":"RS256"}') . '.' . $encoded . '.' . $this->b64('sig');
        $this->assertSame(json_decode($payload, true), JwtVerifier::unverifiedClaims($token));
    }

    public function testOpaqueTokenYieldsNoClaims(): void
    {
        $this->assertSame([], JwtVerifier::unverifiedClaims('gho_abcdefghijklmnop'));
        $this->assertSame([], JwtVerifier::unverifiedClaims(''));
    }

    public function testGarbageSegmentsYieldNoClaims(): void
    {
        $this->assertSame([], JwtVerifier::unverifiedClaims('a.!!!.c'));
        $this->assertSame([], JwtVerifier::unverifiedClaims('a..c'));
        $this->assertSame([], JwtVerifier::unverifiedClaims('a.' . $this->b64('not json') . '.c'));
        $this->assertSame([], JwtVerifier::unverifiedClaims('a.' . $this->b64('"scalar"') . '.c'));
        $this->assertSame([], JwtVerifier::unverifiedClaims('a.b.c.d.e'));
    }
}
