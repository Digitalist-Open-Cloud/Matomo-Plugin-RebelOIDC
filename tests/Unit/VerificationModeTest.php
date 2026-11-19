<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * @group RebelOIDC
 * @group Plugins
 */
class VerificationModeTest extends TestCase
{
    private $helper;

    protected function setUp(): void
    {
        $this->helper = new class {
            use \Piwik\Plugins\RebelOIDC\Helper;

            public function mode(string $jwksUrl, string $issuer): ?bool
            {
                return self::verificationMode($jwksUrl, $issuer);
            }

            public function setup(array $values): bool
            {
                $settings = new \stdClass();
                foreach ($values as $name => $value) {
                    $settings->$name = new class ($value) {
                        private $value;
                        public function __construct($value)
                        {
                            $this->value = $value;
                        }
                        public function getValue()
                        {
                            return $this->value;
                        }
                    };
                }
                return $this->isPluginSetup($settings);
            }
        };
    }

    public function testBothSetMeansVerification(): void
    {
        $this->assertTrue($this->helper->mode('https://idp.example.com/jwks', 'https://idp.example.com/realms/r'));
    }

    public function testBothEmptyMeansLegacy(): void
    {
        $this->assertFalse($this->helper->mode('', ''));
        $this->assertFalse($this->helper->mode('  ', ''));
    }

    public function testOnlyOneSetIsMisconfigured(): void
    {
        $this->assertNull($this->helper->mode('https://idp.example.com/jwks', ''));
        $this->assertNull($this->helper->mode('', 'https://idp.example.com/realms/r'));
    }

    private function base(): array
    {
        return [
            'authorizeUrl' => 'https://idp.example.com/auth',
            'tokenUrl' => 'https://idp.example.com/token',
            'userInfoUrl' => 'https://idp.example.com/userinfo',
            'clientId' => 'matomo',
            'clientSecret' => 'secret',
            'jwksUrl' => '',
            'issuer' => '',
        ];
    }

    public function testPluginIsSetUpWithoutJwksAndIssuer(): void
    {
        $this->assertTrue($this->helper->setup($this->base()));
    }

    public function testPluginIsSetUpWithBoth(): void
    {
        $values = ['jwksUrl' => 'https://idp.example.com/jwks', 'issuer' => 'https://idp.example.com'] + $this->base();
        $this->assertTrue($this->helper->setup($values));
    }

    public function testPluginIsNotSetUpWithOnlyOne(): void
    {
        $this->assertFalse($this->helper->setup(['jwksUrl' => 'https://idp.example.com/jwks'] + $this->base()));
        $this->assertFalse($this->helper->setup(['issuer' => 'https://idp.example.com'] + $this->base()));
    }

    public function testPluginIsNotSetUpWithoutClientSecret(): void
    {
        $this->assertFalse($this->helper->setup(['clientSecret' => ''] + $this->base()));
    }
}
