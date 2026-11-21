<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\RebelOIDC;

use Exception;
use Piwik\Config;
use Piwik\Piwik;

/**
 * The checks of the OpenID Connect login that need no request and no database.
 */
class Protocol
{
    /**
     * Seconds the clock of the provider may differ from ours.
     */
    private const CLOCK_LEEWAY = 60;

    /**
     * @return array<string, mixed>|null the claims, or null when the token is not a readable JWT, as an
     *                                   opaque or an encrypted token
     */
    public static function decodeJwt(
        #[\SensitiveParameter]
        ?string $token
    ): ?array {
        $parts = explode('.', (string) $token);
        if (count($parts) !== 3) {
            return null;
        }

        $payload = base64_decode(strtr($parts[1], '-_', '+/'), true);
        $claims = $payload === false ? null : json_decode($payload, true);

        return is_array($claims) ? $claims : null;
    }

    /**
     * The token is not checked for its signature: it comes straight from the token endpoint over
     * TLS, which OpenID Connect accepts in its place.
     *
     * @param array<string, mixed> $claims
     * @param string $issuer the issuer the token has to be from, or empty to accept any
     * @throws Exception if the token is not meant for this login
     */
    public static function checkIdToken(array $claims, string $clientId, string $issuer, string $nonce, ?int $now = null): void
    {
        $now = $now ?? time();
        $audience = (array) ($claims['aud'] ?? []);

        $valid = in_array($clientId, $audience, true)
            && (count($audience) === 1 || ($claims['azp'] ?? null) === $clientId)
            && is_numeric($claims['exp'] ?? null) && $claims['exp'] > $now - self::CLOCK_LEEWAY
            && is_string($claims['nonce'] ?? null) && hash_equals($nonce, $claims['nonce'])
            && ($issuer === '' || rtrim((string) ($claims['iss'] ?? ''), '/') === rtrim($issuer, '/'));

        if (!$valid) {
            throw new Exception(Piwik::translate('RebelOIDC_ExceptionInvalidIdToken'));
        }
    }

    public static function getPkceChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    /**
     * @throws Exception if the URL is not HTTPS, unless the config file allows HTTP
     */
    public static function checkSecureUrl(string $url): void
    {
        $config = Config::getInstance()->RebelOIDC;
        if (!empty($config['allow_http'])) {
            return;
        }

        if (strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https') {
            throw new Exception(Piwik::translate('RebelOIDC_ExceptionUrlNotHttps', $url));
        }
    }

    /**
     * @param mixed $verified the claim "email_verified", which some providers send as a string
     */
    public static function isEmailVerified($verified): bool
    {
        return $verified === true || $verified === 'true';
    }

    /**
     * Whether an account of the provider may be linked to a Matomo user nobody linked by hand: only
     * when the provider vouches for an email that is the email of the Matomo user.
     *
     * @param array<string, mixed> $matomoUser
     */
    public static function canLinkByEmail(array $matomoUser, ?string $email, bool $isEmailTrusted): bool
    {
        return $isEmailTrusted
            && !empty($email)
            && mb_strtolower($email) === mb_strtolower((string) ($matomoUser['email'] ?? ''));
    }
}
