<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

use Exception;
use Piwik\Cache;
use Piwik\Http;
use Piwik\Piwik;

/**
 * Requests to the provider, and what it publishes about itself.
 */
class Provider
{
    private const TIMEOUT = 10;
    private const DISCOVERY_LIFETIME = 86400;

    /**
     * The name of the setting and of the field in the discovery document.
     */
    private const ENDPOINTS = [
        'authorizeUrl' => 'authorization_endpoint',
        'tokenUrl' => 'token_endpoint',
        'userInfoUrl' => 'userinfo_endpoint',
        'endSessionUrl' => 'end_session_endpoint',
        'issuer' => 'issuer',
    ];

    /**
     * Matomo's HTTP client is used, so that the proxy and certificates of the config file apply.
     *
     * @param string[] $headers
     * @param array<string, string>|null $post the fields of a form to send, or null for a GET request
     * @return array{status: int, data: string}
     * @throws Exception when the server cannot be reached
     */
    public function request(
        string $url,
        #[\SensitiveParameter]
        array $headers = [],
        #[\SensitiveParameter]
        ?array $post = null
    ): array {
        $response = Http::sendHttpRequestBy(
            Http::getTransportMethod(),
            $url,
            self::TIMEOUT,
            'RebelOIDC-Matomo-Plugin',
            null,
            null,
            0,
            false,
            false,
            false,
            true,
            $post === null ? 'GET' : 'POST',
            null,
            null,
            $post,
            array_merge(['Accept: application/json'], $headers)
        );

        return ['status' => (int) ($response['status'] ?? 0), 'data' => (string) ($response['data'] ?? '')];
    }

    /**
     * The URLs and the issuer of the provider. A value that is set wins over what the provider
     * publishes at the discovery URL.
     *
     * @return array{authorizeUrl: string, tokenUrl: string, userInfoUrl: string, endSessionUrl: string, issuer: string}
     * @throws Exception when the discovery URL is set and cannot be read
     */
    public function getEndpoints(SystemSettings $settings): array
    {
        $discoveryUrl = trim((string) $settings->discoveryUrl->getValue());
        $published = $discoveryUrl === '' ? [] : $this->getDiscoveryDocument($discoveryUrl);

        $endpoints = [];
        foreach (self::ENDPOINTS as $setting => $field) {
            $value = trim((string) $settings->$setting->getValue());
            $endpoints[$setting] = $value !== '' || !is_string($published[$field] ?? null) ? $value : $published[$field];
        }

        return $endpoints;
    }

    private function getDiscoveryDocument(string $url): array
    {
        Protocol::checkSecureUrl($url);

        $cache = Cache::getLazyCache();
        $cacheId = 'RebelOIDC_discovery_' . md5($url);
        $document = $cache->fetch($cacheId);
        if (is_array($document)) {
            return $document;
        }

        $response = $this->request($url);
        $document = json_decode($response['data'], true);
        if ($response['status'] !== 200 || !is_array($document) || empty($document['authorization_endpoint'])) {
            throw new Exception(Piwik::translate('RebelOIDC_ExceptionDiscoveryFailed', [$url]));
        }

        $cache->save($cacheId, $document, self::DISCOVERY_LIFETIME);

        return $document;
    }
}
