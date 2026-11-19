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
 * Keeps Keycloak groups in step with Matomo site events. Never throws:
 * a Keycloak outage must not break creating or editing a site.
 */
class SiteGroupsListener
{
    /** @var callable */
    private $groups;
    /** @var callable */
    private $siteInfo;
    /** @var callable */
    private $warn;

    /**
     * @param callable $groups   fn(): ?object with ensureSite/deleteSite (null when not configured)
     * @param callable $siteInfo fn(int $idSite): array{name: string, url: string}
     * @param callable $warn     fn(string $message): void
     */
    public function __construct(callable $groups, callable $siteInfo, callable $warn)
    {
        $this->groups = $groups;
        $this->siteInfo = $siteInfo;
        $this->warn = $warn;
    }

    public function onSiteAdded(int $idSite): void
    {
        $this->ensure($idSite);
    }

    public function onSiteUpdated(int $idSite): void
    {
        $this->ensure($idSite);
    }

    public function onSiteDeleted(int $idSite): void
    {
        try {
            $groups = ($this->groups)();
            if ($groups === null) {
                return;
            }
            $groups->deleteSite($idSite);
        } catch (\Throwable $e) {
            $this->warnFailure('delete', $idSite, $e);
        }
    }

    private function ensure(int $idSite): void
    {
        try {
            $groups = ($this->groups)();
            if ($groups === null) {
                return;
            }
            $info = ($this->siteInfo)($idSite);
            $groups->ensureSite($idSite, (string) $info['name'], (string) $info['url']);
        } catch (\Throwable $e) {
            $this->warnFailure('sync', $idSite, $e);
        }
    }

    private function warnFailure(string $what, int $idSite, \Throwable $e): void
    {
        ($this->warn)('RebelOIDC: Keycloak group ' . $what . ' failed for idsite ' . $idSite . ': ' . $e->getMessage());
    }
}
