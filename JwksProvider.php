<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

use Piwik\Cache;

/**
 * Fetches (and caches for one hour) the JWKS document of the identity provider.
 */
class JwksProvider
{
    private const TTL = 3600;

    /**
     * @param  string  $jwksUrl
     * @param  bool    $forceRefresh  Bypass the cache (used when a token has an unknown kid).
     * @return array   ['keys' => [...]]
     * @throws \Exception on transport/HTTP/JSON errors
     */
    public function fetch(string $jwksUrl, bool $forceRefresh): array
    {
        $cache = Cache::getLazyCache();
        $cacheKey = 'RebelOIDC_jwks_' . md5($jwksUrl);

        if (!$forceRefresh) {
            $cached = $cache->fetch($cacheKey);
            if (is_array($cached) && isset($cached['keys'])) {
                return $cached;
            }
        }

        $ch = curl_init($jwksUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new \Exception('Error fetching JWKS: ' . $error);
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \Exception("Failed to fetch JWKS. HTTP Code: $httpCode");
        }

        $jwks = json_decode((string) $response, true);
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new \Exception('Invalid JWKS document');
        }

        $cache->save($cacheKey, $jwks, self::TTL);
        return $jwks;
    }
}
