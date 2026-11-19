<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\Pkce;

/**
 * @group RebelOIDC
 * @group PkceTest
 * @group Plugins
 */
class PkceTest extends TestCase
{
    public function testChallengeMatchesRfc7636AppendixB(): void
    {
        $this->assertSame(
            'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            Pkce::challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
        );
    }

    public function testNewVerifierIs43Base64UrlCharsAndUnique(): void
    {
        $a = Pkce::newVerifier();
        $this->assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $a));
        $this->assertNotSame($a, Pkce::newVerifier());
    }
}
