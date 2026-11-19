<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

/**
 * PKCE (RFC 7636) helpers, S256 method.
 */
class Pkce
{
    /**
     * Create a new code verifier (43 base64url characters, 256 bits of entropy).
     */
    public static function newVerifier(): string
    {
        return self::base64Url(random_bytes(32));
    }

    /**
     * Derive the S256 code challenge for the given verifier.
     */
    public static function challenge(string $verifier): string
    {
        return self::base64Url(hash('sha256', $verifier, true));
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
