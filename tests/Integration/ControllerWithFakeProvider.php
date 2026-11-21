<?php

namespace Piwik\Plugins\RebelOIDC\tests\Integration;

use Piwik\Plugins\RebelOIDC\Controller;

/**
 * A controller that gets the answers of the provider from the test.
 */
class ControllerWithFakeProvider extends Controller
{
    public $tokens;
    public $userInfo;
    public $tokenRequest;

    protected function requestTokens(array $data, string $tokenUrl)
    {
        $this->tokenRequest = $data;
        return $this->tokens;
    }

    protected function requestUserInfo(string $accessToken, string $userInfoUrl)
    {
        return $this->userInfo;
    }
}
