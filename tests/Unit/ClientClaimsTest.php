<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\InvalidTokenException;
use Piwik\Plugins\RebelOIDC\JwtVerifier;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class ClientClaimsTest extends TestCase
{
    public function testAudienceStringMatches(): void
    {
        JwtVerifier::assertAudience(['aud' => 'matomo'], 'matomo');
        $this->addToAssertionCount(1);
    }

    public function testAudienceArrayMatches(): void
    {
        JwtVerifier::assertAudience(['aud' => ['other', 'matomo']], 'matomo');
        $this->addToAssertionCount(1);
    }

    /**
     * @dataProvider badAudiences
     */
    public function testAudienceRejected($payload): void
    {
        $this->expectException(InvalidTokenException::class);
        JwtVerifier::assertAudience($payload, 'matomo');
    }

    public static function badAudiences(): array
    {
        return [[[]], [['aud' => 'other']], [['aud' => ['a', 'b']]], [['aud' => []]], [['aud' => 5]], [['aud' => '']]];
    }

    public function testAzpMatches(): void
    {
        JwtVerifier::assertAuthorizedParty(['azp' => 'matomo'], 'matomo');
        $this->addToAssertionCount(1);
    }

    /**
     * @dataProvider badAzp
     */
    public function testAzpRejected($payload): void
    {
        $this->expectException(InvalidTokenException::class);
        JwtVerifier::assertAuthorizedParty($payload, 'matomo');
    }

    public static function badAzp(): array
    {
        return [[[]], [['azp' => 'other']], [['azp' => ['matomo']]]];
    }

    public function testSameSubjectOk(): void
    {
        JwtVerifier::assertSameSubject(['sub' => 'u1'], ['sub' => 'u1']);
        $this->addToAssertionCount(1);
    }

    /**
     * @dataProvider badSubjects
     */
    public function testSubjectRejected(array $id, array $userinfo): void
    {
        $this->expectException(InvalidTokenException::class);
        JwtVerifier::assertSameSubject($id, $userinfo);
    }

    public static function badSubjects(): array
    {
        return [
            'different' => [['sub' => 'u1'], ['sub' => 'u2']],
            'missing in userinfo' => [['sub' => 'u1'], []],
            'non-string userinfo' => [['sub' => '1'], ['sub' => 1]],
            'missing in id token' => [[], ['sub' => 'u1']],
            'empty' => [['sub' => ''], ['sub' => '']],
        ];
    }
}
