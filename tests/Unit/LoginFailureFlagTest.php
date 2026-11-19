<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\LoginFailureFlag;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class LoginFailureFlagTest extends TestCase
{
    public function testRaiseThenTakeReturnsTrueOnce(): void
    {
        $session = [];
        LoginFailureFlag::raise($session);
        $this->assertTrue(LoginFailureFlag::take($session));
        $this->assertFalse(LoginFailureFlag::take($session));
        $this->assertSame([], $session);
    }

    public function testTakeOnEmptySessionIsFalse(): void
    {
        $session = [];
        $this->assertFalse(LoginFailureFlag::take($session));
    }

    public function testClearRemovesFlagAndKeepsOtherData(): void
    {
        $session = ['other' => 1];
        LoginFailureFlag::raise($session);
        LoginFailureFlag::clear($session);
        $this->assertFalse(LoginFailureFlag::take($session));
        $this->assertSame(['other' => 1], $session);
    }
}
