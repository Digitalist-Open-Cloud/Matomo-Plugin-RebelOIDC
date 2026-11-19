<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class ProviderUserIdTest extends TestCase
{
    private $helper;

    protected function setUp(): void
    {
        $this->helper = new class {
            use \Piwik\Plugins\RebelOIDC\Helper;

            public function get(array $userinfo, string $key): ?string
            {
                return $this->providerUserIdFrom($userinfo, $key);
            }
        };
    }

    public function testStringIdIsReturned(): void
    {
        $this->assertSame('u1', $this->helper->get(['sub' => 'u1'], 'sub'));
    }

    public function testIntegerIdIsReturnedAsString(): void
    {
        $this->assertSame('5', $this->helper->get(['id' => 5], 'id'));
        // GitHub-shaped /user response
        $this->assertSame('583231', $this->helper->get(['login' => 'octocat', 'id' => 583231, 'type' => 'User'], 'id'));
        $this->assertSame('0', $this->helper->get(['id' => 0], 'id'));
    }

    /**
     * @dataProvider invalid
     */
    public function testInvalidGivesNull(array $userinfo, string $key): void
    {
        $this->assertNull($this->helper->get($userinfo, $key));
    }

    public static function invalid(): array
    {
        return [
            'missing' => [['sub' => 'u1'], 'email'],
            'empty string' => [['sub' => ''], 'sub'],
            'empty key' => [['sub' => 'u1'], ''],
            'negative int' => [['id' => -5], 'id'],
            'bool' => [['id' => true], 'id'],
            'float' => [['id' => 1.5], 'id'],
            'array' => [['id' => ['x']], 'id'],
            'null' => [['id' => null], 'id'],
        ];
    }
}
