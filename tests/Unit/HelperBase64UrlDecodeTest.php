<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use Exception;
use PHPUnit\Framework\TestCase;

/**
 * @group RebelOIDC
 * @group HelperTest
 * @group Plugins
 */
class HelperBase64UrlDecodeTest extends TestCase
{
    /** @var object An object using the trait */
    private $helper;

    protected function setUp(): void
    {
        $this->helper = new class {
            use \Piwik\Plugins\RebelOIDC\Helper;

            // Temporary public wrapper method to expose private function
            public function testBase64UrlDecodeWrapper(string $data): string
            {
                return $this->base64UrlDecode($data);
            }
        };
    }

    public function testBase64UrlDecodeUrlSafeCharactersWithoutPadding(): void
    {
        // A JWT payload segment: contains "-" and "_" and has its "==" padding stripped
        $decoded = $this->helper->testBase64UrlDecodeWrapper('eyJuYW1lIjoiWm_DqyB-Pz4iLCJ4IjoxfQ');

        $this->assertSame('{"name":"Zoë ~?>","x":1}', $decoded, 'base64url data should decode like the JWT spec requires.');
    }

    public function testBase64UrlDecodePlainBase64(): void
    {
        // Data without "-", "_" or missing padding decodes as before
        $decoded = $this->helper->testBase64UrlDecodeWrapper('eyJzdWIiOiIxMjMifQ==');

        $this->assertSame('{"sub":"123"}', $decoded, 'Plain base64 data should still decode.');
    }

    public function testBase64UrlDecodeInvalidData(): void
    {
        $this->expectException(Exception::class);

        $this->helper->testBase64UrlDecodeWrapper('not*base64');
    }
}
