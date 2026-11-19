<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\KeycloakGroups;

class KeycloakGroupsTest extends TestCase
{
    private const BASE = 'http://kc:8080';
    private const G = 'http://kc:8080/admin/realms/r/groups';
    private const TOP_SEARCH = self::G . '?search=matomo&exact=true&briefRepresentation=false';

    /** @var array<int, array{string,string,?string}> */
    private $calls = [];

    /** Build a KeycloakGroups with a fake http answering from "METHOD URL" => [status, body]. */
    private function make(array $table): KeycloakGroups
    {
        $this->calls = [];
        $http = function (string $method, string $url, array $headers, ?string $body) use ($table) {
            $this->calls[] = [$method, $url, $body];
            $key = $method . ' ' . $url;
            if (!array_key_exists($key, $table)) {
                return [200, '[]'];
            }
            $r = $table[$key];
            return $r;
        };
        return new KeycloakGroups(self::BASE, 'r', function () {
            return 'tok';
        }, $http);
    }

    private function seqHttp(array $table): KeycloakGroups
    {
        $this->calls = [];
        $http = function (string $method, string $url, array $headers, ?string $body) use (&$table) {
            $this->calls[] = [$method, $url, $body];
            $key = $method . ' ' . $url;
            if (!isset($table[$key])) {
                return [200, '[]'];
            }
            $r = $table[$key];
            if (isset($r['seq'])) {
                $out = count($r['seq']) > 1 ? array_shift($table[$key]['seq']) : $r['seq'][0];
                return $out;
            }
            return $r;
        };
        return new KeycloakGroups(self::BASE, 'r', function () {
            return 'tok';
        }, $http);
    }

    private function json($x): array
    {
        return [200, json_encode($x)];
    }

    private function callList(): array
    {
        return array_map(function ($c) {
            return $c[0] . ' ' . str_replace(self::G, '', $c[1]);
        }, $this->calls);
    }

    private function writes(): array
    {
        return array_values(array_filter($this->calls, function ($c) {
            return $c[0] !== 'GET';
        }));
    }

    public function testEnsureSiteCreatesTopSiteAndThreeLevels(): void
    {
        $kc = $this->seqHttp([
            'GET ' . self::TOP_SEARCH => ['seq' => [$this->json([]), $this->json([['id' => 'top', 'name' => 'matomo', 'path' => '/matomo']])]],
            'POST ' . self::G => [201, ''],
            'GET ' . self::G . '/top/children?briefRepresentation=false&first=0&max=100' => ['seq' => [
                $this->json([]),
                $this->json([['id' => 's3', 'name' => '3', 'path' => '/matomo/3', 'attributes' => [], 'subGroups' => []]]),
            ]],
            'POST ' . self::G . '/top/children' => [201, ''],
            'GET ' . self::G . '/s3/children?briefRepresentation=false&first=0&max=100' => $this->json([]),
            'POST ' . self::G . '/s3/children' => [201, ''],
        ]);
        $kc->ensureSite(3, 'Sobi', 'https://sobi.com');

        $w = $this->writes();
        $this->assertCount(5, $w);
        $this->assertSame(self::G, $w[0][1]);
        $this->assertSame(['name' => 'matomo'], json_decode($w[0][2], true));
        $this->assertSame(self::G . '/top/children', $w[1][1]);
        $this->assertSame(
            ['name' => '3', 'attributes' => ['matomo_site_name' => ['Sobi'], 'matomo_site_url' => ['https://sobi.com']]],
            json_decode($w[1][2], true)
        );
        $this->assertSame(self::G . '/s3/children', $w[2][1]);
        $this->assertSame(['name' => 'view'], json_decode($w[2][2], true));
        $this->assertSame(['name' => 'write'], json_decode($w[3][2], true));
        $this->assertSame(['name' => 'admin'], json_decode($w[4][2], true));
    }

    private function fullTable(string $name = 'Sobi'): array
    {
        return [
            'GET ' . self::TOP_SEARCH => $this->json([['id' => 'top', 'name' => 'matomo', 'path' => '/matomo']]),
            'GET ' . self::G . '/top/children?briefRepresentation=false&first=0&max=100' => $this->json([
                ['id' => 's3', 'name' => '3', 'path' => '/matomo/3', 'attributes' => ['matomo_site_name' => [$name], 'matomo_site_url' => ['https://sobi.com']]],
                ['id' => 'sx', 'name' => 'test', 'path' => '/matomo/test'],
            ]),
            'GET ' . self::G . '/s3/children?briefRepresentation=false&first=0&max=100' => $this->json([
                ['id' => 'a', 'name' => 'view'], ['id' => 'b', 'name' => 'write'], ['id' => 'c', 'name' => 'admin'],
            ]),
        ];
    }

    public function testEnsureSiteIsIdempotent(): void
    {
        $kc = $this->make($this->fullTable());
        $kc->ensureSite(3, 'Sobi', 'https://sobi.com');
        $this->assertSame([], $this->writes());
    }

    public function testEnsureSiteUpdatesChangedName(): void
    {
        $kc = $this->make($this->fullTable('Gammalt'));
        $kc->ensureSite(3, 'Sobi', 'https://sobi.com');
        $w = $this->writes();
        $this->assertCount(1, $w);
        $this->assertSame('PUT', $w[0][0]);
        $this->assertSame(self::G . '/s3', $w[0][1]);
        $this->assertSame(
            ['name' => '3', 'attributes' => ['matomo_site_name' => ['Sobi'], 'matomo_site_url' => ['https://sobi.com']]],
            json_decode($w[0][2], true)
        );
    }

    public function testEnsureSiteCreatesMissingSubgroupOnly(): void
    {
        $t = $this->fullTable();
        $t['GET ' . self::G . '/s3/children?briefRepresentation=false&first=0&max=100'] = $this->json([['id' => 'a', 'name' => 'view']]);
        $t['POST ' . self::G . '/s3/children'] = [201, ''];
        $kc = $this->make($t);
        $kc->ensureSite(3, 'Sobi', 'https://sobi.com');
        $w = $this->writes();
        $this->assertCount(2, $w);
        $this->assertSame(['name' => 'write'], json_decode($w[0][2], true));
        $this->assertSame(['name' => 'admin'], json_decode($w[1][2], true));
    }

    public function testListSitesIgnoresNonNumericChildren(): void
    {
        $t = $this->fullTable();
        $t['GET ' . self::G . '/top/children?briefRepresentation=false&first=0&max=100'] = $this->json([
            ['id' => 'g3', 'name' => '3', 'attributes' => ['matomo_site_name' => ['Sobi'], 'matomo_site_url' => ['https://sobi.com']]],
            ['id' => 'g12', 'name' => '12'],
            ['id' => 'gt', 'name' => 'test'],
            ['id' => 'g0', 'name' => '0'],
        ]);
        $kc = $this->make($t);
        $sites = $kc->listSites();
        $this->assertSame([3, 12], array_keys($sites));
        $this->assertSame(['id' => 'g3', 'name' => 'Sobi', 'url' => 'https://sobi.com'], $sites[3]);
        $this->assertSame(['id' => 'g12', 'name' => '', 'url' => ''], $sites[12]);
    }

    public function testListSitesWithoutTopGroupIsEmpty(): void
    {
        $kc = $this->make([self::TOP_SEARCH => $this->json([])]);
        $this->assertSame([], $kc->listSites());
    }

    public function testTopGroupSelectionIgnoresNestedMatch(): void
    {
        $t = $this->fullTable();
        $t['GET ' . self::TOP_SEARCH] = $this->json([
            ['id' => 'other', 'name' => 'org', 'path' => '/org', 'subGroups' => [['id' => 'n', 'name' => 'matomo', 'path' => '/org/matomo']]],
            ['id' => 'top', 'name' => 'matomo', 'path' => '/matomo'],
        ]);
        $kc = $this->make($t);
        $this->assertSame([3], array_keys($kc->listSites()));
    }

    public function testDeleteSite(): void
    {
        $t = $this->fullTable();
        $t['DELETE ' . self::G . '/s3'] = [204, ''];
        $kc = $this->make($t);
        $kc->deleteSite(3);
        $w = $this->writes();
        $this->assertCount(1, $w);
        $this->assertSame('DELETE', $w[0][0]);
        $this->assertSame(self::G . '/s3', $w[0][1]);
    }

    public function testDeleteMissingSiteIsNoop(): void
    {
        $kc = $this->make($this->fullTable());
        $kc->deleteSite(99);
        $this->assertSame([], $this->writes());
    }

    public function testHttpErrorThrows(): void
    {
        $kc = $this->make([
            'GET ' . self::TOP_SEARCH => $this->json([]),
            'POST ' . self::G => [500, 'boom'],
        ]);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('500');
        $kc->ensureSite(3, 'Sobi', 'https://sobi.com');
    }

    public function testTokenSentAsBearerAndFetchedOnce(): void
    {
        $n = 0;
        $seen = [];
        $http = function ($m, $u, $h, $b) use (&$seen) {
            $seen[] = $h;
            return [200, '[]'];
        };
        $kc = new KeycloakGroups(self::BASE, 'r', function () use (&$n) {
            $n++;
            return 'tok';
        }, $http);
        $kc->listSites();
        $kc->listSites();
        $this->assertSame(1, $n);
        $this->assertContains('Authorization: Bearer tok', $seen[0]);
    }

    public function testConflictOnCreateIsTolerated(): void
    {
        $kc = $this->seqHttp([
            'GET ' . self::TOP_SEARCH => ['seq' => [$this->json([]), $this->json([['id' => 'top', 'name' => 'matomo', 'path' => '/matomo']])]],
            'POST ' . self::G => [409, ''],
            'GET ' . self::G . '/top/children?briefRepresentation=false&first=0&max=100' => ['seq' => [
                $this->json([]),
                $this->json([['id' => 's3', 'name' => '3', 'attributes' => []]]),
            ]],
            'POST ' . self::G . '/top/children' => [409, ''],
            'GET ' . self::G . '/s3/children?briefRepresentation=false&first=0&max=100' => $this->json([]),
            'POST ' . self::G . '/s3/children' => [409, ''],
        ]);
        $kc->ensureSite(3, 'Sobi', 'https://sobi.com');
        $this->assertCount(5, $this->writes());
    }

    private function pagedTable(): array
    {
        $page1 = [];
        for ($i = 1; $i <= 100; $i++) {
            $page1[] = ['id' => 'g' . $i, 'name' => 'x' . $i];
        }
        $base = self::G . '/top/children?briefRepresentation=false';
        return [
            'GET ' . self::TOP_SEARCH => $this->json([['id' => 'top', 'name' => 'matomo', 'path' => '/matomo']]),
            'GET ' . $base . '&first=0&max=100' => $this->json($page1),
            'GET ' . $base . '&first=100&max=100' => $this->json([
                ['id' => 's150', 'name' => '150', 'attributes' => ['matomo_site_name' => ['P'], 'matomo_site_url' => ['u']]],
            ]),
            'GET ' . self::G . '/s150/children?briefRepresentation=false&first=0&max=100' => $this->json([
                ['id' => 'a', 'name' => 'view'], ['id' => 'b', 'name' => 'write'], ['id' => 'c', 'name' => 'admin'],
            ]),
        ];
    }

    public function testListSitesPagesThroughChildren(): void
    {
        $kc = $this->make($this->pagedTable());
        $this->assertSame([150], array_keys($kc->listSites()));
    }

    public function testEnsureSiteFindsSiteOnSecondPage(): void
    {
        $kc = $this->make($this->pagedTable());
        $kc->ensureSite(150, 'P', 'u');
        $this->assertSame([], $this->writes());
    }
}
