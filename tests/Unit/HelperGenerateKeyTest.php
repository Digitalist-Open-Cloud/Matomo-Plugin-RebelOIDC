<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * @group RebelOIDC
 * @group HelperTest
 * @group Plugins
 */
class HelperGenerateKeyTest extends TestCase
{
    /** @var object An object using the trait */
    private $helper;

    protected function setUp(): void
    {
        $this->helper = new class {
            use \Piwik\Plugins\RebelOIDC\Helper;

            // Temporary public wrapper method to expose private function
            public function testGenerateKeyWrapper(int $length = 64): string
            {
                return $this->generateKey($length);
            }
        };
    }

    public function testGenerateKeyDefaultLength(): void
    {
        $key = $this->helper->testGenerateKeyWrapper();

        $this->assertEquals(64, strlen($key), 'Generated key should have a length of 64 characters.');
    }

    public function testGenerateKeyCustomLength(): void
    {
        $key = $this->helper->testGenerateKeyWrapper(32);

        $this->assertEquals(32, strlen($key), 'Generated key should have a length of 32 characters.');
    }

    public function testGenerateKeyCustomOddLength(): void
    {
        // Test with an odd length
        $key = $this->helper->testGenerateKeyWrapper(33);

        // Length should be rounded down (33 -> 32) because of the modulus operation
        $this->assertEquals(32, strlen($key), 'Odd lengths should be rounded down to the nearest even number.');
    }

    public function testGenerateKeyMinimumLength(): void
    {
        // Test minimum length (less than 4 should default to 4)
        $key = $this->helper->testGenerateKeyWrapper(3);

        // 4 is enforced as the minimum length
        $this->assertEquals(4, strlen($key), 'Lengths below 4 should enforce a minimum length of 4 characters.');
    }

    public function testGenerateKeyUniqueness(): void
    {
        // Generate multiple keys and assert they are unique
        $key1 = $this->helper->testGenerateKeyWrapper(32);
        $key2 = $this->helper->testGenerateKeyWrapper(32);

        $this->assertNotEquals($key1, $key2, 'Generated keys should be unique for each call.');
    }
}
