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
 * Keycloak Admin REST adapter for the per-site group layout:
 *
 *   /matomo/<idsite>/{view,write,admin}
 *
 * with the site group carrying the attributes matomo_site_name and matomo_site_url.
 * Only children of /matomo whose name is a positive integer are considered sites;
 * anything else is never touched.
 *
 * This class deliberately has no Matomo dependencies except inside fromSettings(),
 * so it can be unit tested outside Matomo.
 */
class KeycloakGroups
{
    use Helper;

    private const TOP = 'matomo';
    private const LEVELS = ['view', 'write', 'admin'];

    /** @var string */
    private $adminBaseUrl;
    /** @var string */
    private $realm;
    /** @var callable */
    private $tokenProvider;
    /** @var callable */
    private $http;
    /** @var string|null */
    private $token = null;

    /**
     * @param callable $token fn(): string, returns an admin access token
     * @param callable $http  fn(string $method, string $url, array $headers, ?string $body): array{0:int,1:string}
     */
    public function __construct(string $adminBaseUrl, string $realm, callable $token, callable $http)
    {
        $this->adminBaseUrl = rtrim($adminBaseUrl, '/');
        $this->realm = $realm;
        $this->tokenProvider = $token;
        $this->http = $http;
    }

    /**
     * @return self|null null when provisioning is not enabled/configured
     */
    public static function fromSettings(SystemSettings $s): ?self
    {
        if (!$s->provisionerEnabled->getValue()) {
            return null;
        }
        $url = trim((string) $s->keycloakAdminUrl->getValue());
        $realm = trim((string) $s->keycloakRealm->getValue());
        $clientId = trim((string) $s->provisionerClientId->getValue());
        $secret = (string) $s->provisionerClientSecret->getValue();
        if ($url === '' || $realm === '' || $clientId === '' || $secret === '') {
            return null;
        }

        $self = null;
        $token = function () use (&$self, $url, $realm, $clientId, $secret): string {
            return $self->fetchAccessToken($url, $realm, $clientId, $secret);
        };
        $self = new self($url, $realm, $token, [self::class, 'curlRequest']);
        return $self;
    }

    /** @internal used by the token closure built in fromSettings() */
    public function fetchAccessToken(string $url, string $realm, string $clientId, string $secret): string
    {
        return $this->getAccessToken(rtrim($url, '/'), $realm, $clientId, $secret);
    }

    /** @internal real HTTP transport */
    public static function curlRequest(string $method, string $url, array $headers, ?string $body): array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $response = curl_exec($ch);
        if ($response === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException('Keycloak request failed: ' . $err);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$status, (string) $response];
    }

    /**
     * @return array<int, array{id:string, name:string, url:string}>
     */
    public function listSites(): array
    {
        $top = $this->findTop();
        if ($top === null) {
            return [];
        }
        $sites = [];
        foreach ($this->children($top['id']) as $child) {
            $name = (string) ($child['name'] ?? '');
            if (!preg_match('/^[1-9][0-9]*$/', $name)) {
                continue;
            }
            $attrs = is_array($child['attributes'] ?? null) ? $child['attributes'] : [];
            $sites[(int) $name] = [
                'id' => (string) $child['id'],
                'name' => (string) ($attrs['matomo_site_name'][0] ?? ''),
                'url' => (string) ($attrs['matomo_site_url'][0] ?? ''),
            ];
        }
        return $sites;
    }

    public function ensureSite(int $idSite, string $name, string $url): void
    {
        $top = $this->findTop();
        if ($top === null) {
            $this->request('POST', $this->groupsUrl(), ['name' => self::TOP], true);
            $top = $this->findTop();
            if ($top === null) {
                throw new \RuntimeException('Keycloak group /matomo missing after create');
            }
        }

        $siteName = (string) $idSite;
        $site = $this->findChild($top['id'], $siteName);
        $wanted = ['matomo_site_name' => [$name], 'matomo_site_url' => [$url]];

        if ($site === null) {
            $this->request('POST', $this->groupsUrl($top['id']) . '/children', ['name' => $siteName, 'attributes' => $wanted], true);
            $site = $this->findChild($top['id'], $siteName);
            if ($site === null) {
                throw new \RuntimeException('Keycloak site group missing after create');
            }
        } else {
            $attrs = is_array($site['attributes'] ?? null) ? $site['attributes'] : [];
            if (($attrs['matomo_site_name'] ?? null) !== $wanted['matomo_site_name']
                || ($attrs['matomo_site_url'] ?? null) !== $wanted['matomo_site_url']) {
                $this->request('PUT', $this->groupsUrl($site['id']), [
                    'name' => $siteName,
                    'attributes' => array_merge($attrs, $wanted),
                ]);
            }
        }

        $existing = [];
        foreach ($this->children($site['id']) as $child) {
            $existing[(string) ($child['name'] ?? '')] = true;
        }
        foreach (self::LEVELS as $level) {
            if (!isset($existing[$level])) {
                $this->request('POST', $this->groupsUrl($site['id']) . '/children', ['name' => $level], true);
            }
        }
    }

    public function deleteSite(int $idSite): void
    {
        $top = $this->findTop();
        if ($top === null) {
            return;
        }
        $site = $this->findChild($top['id'], (string) $idSite);
        if ($site === null) {
            return;
        }
        $this->request('DELETE', $this->groupsUrl($site['id']), null);
    }

    /** @return array|null */
    private function findTop(): ?array
    {
        $groups = $this->request(
            'GET',
            $this->groupsUrl() . '?search=' . self::TOP . '&exact=true&briefRepresentation=false',
            null
        );
        foreach ($groups as $g) {
            if (is_array($g) && ($g['name'] ?? null) === self::TOP && ($g['path'] ?? null) === '/' . self::TOP) {
                return $g;
            }
        }
        return null;
    }

    private const PAGE_SIZE = 100;

    private function children(string $groupId): array
    {
        $all = [];
        for ($first = 0;; $first += self::PAGE_SIZE) {
            $page = $this->request(
                'GET',
                $this->groupsUrl($groupId) . '/children?briefRepresentation=false&first=' . $first . '&max=' . self::PAGE_SIZE,
                null
            );
            foreach ($page as $c) {
                $all[] = $c;
            }
            if (count($page) < self::PAGE_SIZE) {
                break;
            }
        }
        return $all;
    }

    private function findChild(string $groupId, string $name): ?array
    {
        foreach ($this->children($groupId) as $c) {
            if (is_array($c) && ($c['name'] ?? null) === $name) {
                return $c;
            }
        }
        return null;
    }

    private function groupsUrl(?string $id = null): string
    {
        $u = $this->adminBaseUrl . '/admin/realms/' . rawurlencode($this->realm) . '/groups';
        return $id === null ? $u : $u . '/' . rawurlencode($id);
    }

    /**
     * @param array|null $payload
     * @param bool $tolerateConflict treat 409 (already exists) as success, for creating POSTs
     * @return array decoded JSON body (empty array when none)
     */
    private function request(string $method, string $url, ?array $payload, bool $tolerateConflict = false): array
    {
        if ($this->token === null) {
            $this->token = (string) ($this->tokenProvider)();
        }
        $headers = ['Authorization: Bearer ' . $this->token, 'Content-Type: application/json'];
        $body = $payload === null ? null : json_encode($payload, JSON_THROW_ON_ERROR);
        [$status, $resp] = ($this->http)($method, $url, $headers, $body);
        if ($tolerateConflict && $status === 409) {
            return [];
        }
        if ($status >= 400) {
            throw new \RuntimeException("Keycloak admin API $method failed with HTTP $status");
        }
        $decoded = $resp === '' ? [] : json_decode($resp, true);
        return is_array($decoded) ? $decoded : [];
    }
}
