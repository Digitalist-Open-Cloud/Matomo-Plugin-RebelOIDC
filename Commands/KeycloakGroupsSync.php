<?php

namespace Piwik\Plugins\RebelOIDC\Commands;

use Piwik\Access;
use Piwik\Plugin\ConsoleCommand;
use Piwik\Plugins\RebelOIDC\GroupsReconciler;
use Piwik\Plugins\RebelOIDC\KeycloakGroups;
use Piwik\Plugins\RebelOIDC\SystemSettings;

/**
 * Reconciles Matomo sites against Keycloak site groups (/matomo/<idsite>).
 */
class KeycloakGroupsSync extends ConsoleCommand
{
    public const SUCCESS = 0;
    public const ERROR = 1;

    protected function configure(): void
    {
        $this->setName('rebeloidc:keycloak-groups-sync')
            ->setDescription('Reconcile Matomo sites with Keycloak site groups.')
            ->addNoValueOption('dry-run', null, 'Only print the plan, change nothing');
    }

    protected function doExecute(): int
    {
        $output = $this->getOutput();
        $dryRun = (bool) $this->getInput()->getOption('dry-run');

        $kc = KeycloakGroups::fromSettings(new SystemSettings());
        if ($kc === null) {
            $output->writeln('<error>Keycloak group provisioning is not configured</error>');
            return self::ERROR;
        }

        try {
            // Read Keycloak FIRST, then Matomo: a site created between the two reads then
            // shows up as "create" rather than as an unknown group that would be deleted.
            $keycloak = $kc->listSites();
            $matomo = $this->matomoSites();
            if (GroupsReconciler::isSuspiciousMassDelete($matomo, $keycloak)) {
                $output->writeln(sprintf(
                    '<error>Refusing to sync: Matomo reports no sites but Keycloak has %d site group(s); nothing was changed.</error>',
                    count($keycloak)
                ));
                return self::ERROR;
            }
            $plan = GroupsReconciler::plan($matomo, $keycloak);
        } catch (\Throwable $e) {
            $output->writeln('<error>Could not build plan: ' . $e->getMessage() . '</error>');
            return self::ERROR;
        }

        $this->printPlan($plan);
        $planEmpty = !$plan['create'] && !$plan['update'] && !$plan['delete'];

        if ($dryRun) {
            return $planEmpty ? self::SUCCESS : self::ERROR;
        }

        foreach (array_merge($plan['create'], $plan['update']) as $id) {
            try {
                $kc->ensureSite($id, $matomo[$id]['name'], $matomo[$id]['url']);
                $output->writeln(sprintf('<info>Ensured site %d</info>', $id));
            } catch (\Throwable $e) {
                $output->writeln(sprintf('<error>Site %d failed: %s</error>', $id, $e->getMessage()));
            }
        }
        foreach ($plan['delete'] as $id) {
            try {
                $kc->deleteSite($id);
                $output->writeln(sprintf('<info>Deleted site %d</info>', $id));
            } catch (\Throwable $e) {
                $output->writeln(sprintf('<error>Site %d failed: %s</error>', $id, $e->getMessage()));
            }
        }

        try {
            $after = GroupsReconciler::plan($matomo, $kc->listSites());
        } catch (\Throwable $e) {
            $output->writeln('<error>Could not verify result: ' . $e->getMessage() . '</error>');
            return self::ERROR;
        }
        if ($after['create'] || $after['update'] || $after['delete']) {
            $output->writeln('<error>Not in sync after reconcile:</error>');
            $this->printPlan($after);
            return self::ERROR;
        }
        $output->writeln('<info>In sync.</info>');
        return self::SUCCESS;
    }

    /** @return array<int, array{name: string, url: string}> */
    private function matomoSites(): array
    {
        $rows = Access::doAsSuperUser(function () {
            return \Piwik\Plugins\SitesManager\API::getInstance()->getAllSites();
        });
        $sites = [];
        foreach ($rows as $row) {
            $sites[(int) $row['idsite']] = ['name' => (string) $row['name'], 'url' => (string) ($row['main_url'] ?? '')];
        }
        return $sites;
    }

    private function printPlan(array $plan): void
    {
        $out = $this->getOutput();
        foreach (['create', 'update', 'delete'] as $k) {
            $out->writeln(sprintf('%s: %d%s', $k, count($plan[$k]), $plan[$k] ? ' (' . implode(', ', $plan[$k]) . ')' : ''));
        }
    }
}
