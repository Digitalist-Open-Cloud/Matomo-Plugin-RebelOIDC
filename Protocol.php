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
     * From the lowest to the highest.
     */
    public const ACCESS_LEVELS = ['view', 'write', 'admin'];

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

    /**
     * The roles the provider gives the user.
     *
     * @param array<string, mixed> $claims the claims of the tokens and the user info
     * @param string $rolesClaim the name of the claim with the roles, or the path to it with dots.
     *                           Empty for the places Keycloak and Entra ID use.
     * @return string[]
     */
    public static function getRoles(array $claims, string $clientId, string $rolesClaim = ''): array
    {
        $paths = [['realm_access', 'roles'], ['resource_access', $clientId, 'roles'], ['roles']];
        if ($rolesClaim !== '') {
            // The name of a claim can have dots itself, as the namespaced claims of Auth0.
            $paths = [[$rolesClaim], explode('.', $rolesClaim)];
        }

        $roles = [];
        foreach ($paths as $path) {
            $value = $claims;
            foreach ($path as $key) {
                $value = is_array($value) ? ($value[$key] ?? null) : null;
            }
            foreach ((array) $value as $role) {
                if (is_string($role)) {
                    $roles[] = $role;
                }
            }
        }

        return array_values(array_unique($roles));
    }

    /**
     * The access to websites the provider gives the user: in the claim "matomo-permission-path"
     * and in roles, written as /matomo/<idSite>/<access> or matomo.<idSite>.<access>. The site
     * "all" stands for every website. The highest access to a website counts.
     *
     * @param array<string, mixed> $claims
     * @param string[] $roles
     * @param int[] $idSites the websites that exist
     * @return array<array{site: string, access: string}>
     */
    public static function getPermissions(array $claims, array $roles, array $idSites): array
    {
        $rank = array_flip(self::ACCESS_LEVELS);

        $accessBySite = [];
        foreach (array_merge((array) ($claims['matomo-permission-path'] ?? []), $roles) as $path) {
            $parts = is_string($path) ? preg_split('~[/.]~', $path, -1, PREG_SPLIT_NO_EMPTY) : [];
            if (count($parts) !== 3 || $parts[0] !== 'matomo' || !isset($rank[$parts[2]])) {
                continue;
            }

            foreach ($parts[1] === 'all' ? $idSites : array_intersect($idSites, [$parts[1]]) as $idSite) {
                if (!isset($accessBySite[$idSite]) || $rank[$parts[2]] > $rank[$accessBySite[$idSite]]) {
                    $accessBySite[$idSite] = $parts[2];
                }
            }
        }

        $permissions = [];
        foreach ($accessBySite as $idSite => $access) {
            $permissions[] = ['site' => (string) $idSite, 'access' => $access];
        }

        return $permissions;
    }
}
