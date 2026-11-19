<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\SiteGroupsListener;

class SiteEventsTest extends TestCase
{
    /** @var array<int, array> */
    private $calls = [];
    /** @var string[] */
    private $warnings = [];

    private function fakeGroups(?\Throwable $throws = null): object
    {
        $self = $this;
        return new class ($self, $throws) {
            private $t;
            private $throws;
            public function __construct($t, $throws)
            {
                $this->t = $t;
                $this->throws = $throws;
            }
            public function ensureSite(int $id, string $name, string $url): void
            {
                $this->t->record(['ensure', $id, $name, $url]);
                if ($this->throws) {
                    throw $this->throws;
                }
            }
            public function deleteSite(int $id): void
            {
                $this->t->record(['delete', $id]);
                if ($this->throws) {
                    throw $this->throws;
                }
            }
        };
    }

    public function record(array $c): void
    {
        $this->calls[] = $c;
    }

    private function listener(?object $groups, ?callable $siteInfo = null): SiteGroupsListener
    {
        $this->calls = [];
        $this->warnings = [];
        return new SiteGroupsListener(
            function () use ($groups) {
                return $groups;
            },
            $siteInfo ?? function (int $id) {
                return ['name' => 'Namn', 'url' => 'https://x'];
            },
            function (string $m) {
                $this->warnings[] = $m;
            }
        );
    }

    public function testAddedSiteIsEnsured(): void
    {
        $this->listener($this->fakeGroups())->onSiteAdded(7);
        $this->assertSame([['ensure', 7, 'Namn', 'https://x']], $this->calls);
        $this->assertSame([], $this->warnings);
    }

    public function testUpdatedSiteIsEnsured(): void
    {
        $this->listener($this->fakeGroups())->onSiteUpdated(7);
        $this->assertSame([['ensure', 7, 'Namn', 'https://x']], $this->calls);
    }

    public function testDeletedSiteIsDeleted(): void
    {
        $this->listener($this->fakeGroups())->onSiteDeleted(7);
        $this->assertSame([['delete', 7]], $this->calls);
    }

    public function testKeycloakErrorIsSwallowedAndLogged(): void
    {
        $this->listener($this->fakeGroups(new \RuntimeException('boom')))->onSiteAdded(7);
        $this->assertCount(1, $this->warnings);
        $this->assertStringContainsString('7', $this->warnings[0]);
        $this->assertStringContainsString('boom', $this->warnings[0]);
    }

    public function testSiteInfoErrorIsSwallowed(): void
    {
        $l = $this->listener($this->fakeGroups(), function (int $id) {
            throw new \RuntimeException('nosite');
        });
        $l->onSiteUpdated(9);
        $this->assertSame([], $this->calls);
        $this->assertCount(1, $this->warnings);
        $this->assertStringContainsString('9', $this->warnings[0]);
        $this->assertStringContainsString('nosite', $this->warnings[0]);
    }

    public function testNotConfiguredDoesNothing(): void
    {
        $l = $this->listener(null);
        $l->onSiteAdded(7);
        $l->onSiteUpdated(7);
        $l->onSiteDeleted(7);
        $this->assertSame([], $this->calls);
        $this->assertSame([], $this->warnings);
    }
}
