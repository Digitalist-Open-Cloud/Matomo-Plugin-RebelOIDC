<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class ExtractPermissionsTest extends TestCase
{
    private $helper;

    protected function setUp(): void
    {
        $this->helper = new class {
            use \Piwik\Plugins\RebelOIDC\Helper;

            public function extract(array $token): array
            {
                return $this->extractPermissions($token);
            }
        };
    }

    public function testValidPathsAreExtracted(): void
    {
        $this->assertSame(
            [['site' => '3', 'access' => 'view'], ['site' => '12', 'access' => 'admin']],
            $this->helper->extract(['matomo-permission-path' => ['/matomo/3/view', '/matomo/12/admin']])
        );
    }

    public function testMalformedPathsAreIgnored(): void
    {
        $paths = ['/matomo/abc/view', '/matomo/3/superuser', '/matomo/3', '/other/3/view', '/matomo/3/view/extra', '/matomo/0/view', '/matomo/03/view'];
        $this->assertSame([], $this->helper->extract(['matomo-permission-path' => $paths]));
    }

    public function testMissingClaimGivesEmpty(): void
    {
        $this->assertSame([], $this->helper->extract([]));
    }

    public function testNonArrayClaimGivesEmpty(): void
    {
        $this->assertSame([], $this->helper->extract(['matomo-permission-path' => '/matomo/3/view']));
    }
}
