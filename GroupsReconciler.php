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
 * Pure diff between Matomo sites and Keycloak site groups.
 * Both inputs: idsite => ['name' => string, 'url' => string] (extra keys ignored).
 */
class GroupsReconciler
{
    /**
     * An empty Matomo site list while Keycloak has site groups would delete every group;
     * that is almost certainly a read failure, so callers must refuse.
     */
    public static function isSuspiciousMassDelete(array $matomoSites, array $keycloakSites): bool
    {
        return count($matomoSites) === 0 && count($keycloakSites) > 0;
    }

    /**
     * @return array{create: int[], update: int[], delete: int[]}
     */
    public static function plan(array $matomoSites, array $keycloakSites): array
    {
        $create = [];
        $update = [];
        $delete = [];

        foreach ($matomoSites as $id => $site) {
            $id = (int) $id;
            if (!isset($keycloakSites[$id])) {
                $create[] = $id;
                continue;
            }
            $kc = $keycloakSites[$id];
            if (($kc['name'] ?? null) !== ($site['name'] ?? null) || ($kc['url'] ?? null) !== ($site['url'] ?? null)) {
                $update[] = $id;
            }
        }
        foreach (array_keys($keycloakSites) as $id) {
            if (!isset($matomoSites[$id])) {
                $delete[] = (int) $id;
            }
        }

        sort($create);
        sort($update);
        sort($delete);

        return ['create' => $create, 'update' => $update, 'delete' => $delete];
    }
}
