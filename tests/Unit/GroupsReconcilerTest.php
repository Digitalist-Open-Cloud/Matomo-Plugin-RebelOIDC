<?php

namespace Piwik\Plugins\RebelOIDC\tests\Unit;

use PHPUnit\Framework\TestCase;
use Piwik\Plugins\RebelOIDC\GroupsReconciler;

class GroupsReconcilerTest extends TestCase
{
    private function s(string $name = 'A', string $url = 'https://a.example'): array
    {
        return ['name' => $name, 'url' => $url];
    }

    public function testMissingSiteIsCreated(): void
    {
        $plan = GroupsReconciler::plan([3 => $this->s(), 4 => $this->s()], [3 => $this->s()]);
        $this->assertSame([4], $plan['create']);
        $this->assertSame([], $plan['update']);
        $this->assertSame([], $plan['delete']);
    }

    public function testRenamedSiteIsUpdated(): void
    {
        $plan = GroupsReconciler::plan([3 => $this->s('New')], [3 => $this->s('Old')]);
        $this->assertSame([3], $plan['update']);
        $this->assertSame([], $plan['create']);
        $this->assertSame([], $plan['delete']);
    }

    public function testUrlOnlyChangeIsUpdated(): void
    {
        $plan = GroupsReconciler::plan([3 => $this->s('A', 'https://new')], [3 => $this->s('A', 'https://old')]);
        $this->assertSame([3], $plan['update']);
    }

    public function testRemovedSiteIsDeleted(): void
    {
        $plan = GroupsReconciler::plan([3 => $this->s()], [3 => $this->s(), 9 => $this->s()]);
        $this->assertSame([9], $plan['delete']);
        $this->assertSame([], $plan['create']);
        $this->assertSame([], $plan['update']);
    }

    public function testInSyncIsEmpty(): void
    {
        $plan = GroupsReconciler::plan([3 => $this->s()], [3 => $this->s()]);
        $this->assertSame(['create' => [], 'update' => [], 'delete' => []], $plan);
    }

    public function testExtraKeysInKeycloakEntriesAreIgnored(): void
    {
        $kc = [3 => ['id' => 'uuid-1', 'name' => 'A', 'url' => 'https://a.example']];
        $plan = GroupsReconciler::plan([3 => $this->s()], $kc);
        $this->assertSame(['create' => [], 'update' => [], 'delete' => []], $plan);
    }

    public function testResultsAreSortedInts(): void
    {
        $plan = GroupsReconciler::plan([10 => $this->s(), 2 => $this->s()], [30 => $this->s(), 5 => $this->s()]);
        $this->assertSame([2, 10], $plan['create']);
        $this->assertSame([5, 30], $plan['delete']);
    }

    public function testMixedPlanCreatesUpdatesAndDeletes(): void
    {
        $plan = GroupsReconciler::plan(
            [1 => $this->s(), 2 => $this->s('Renamed'), 4 => $this->s()],
            [1 => $this->s(), 2 => $this->s('Old'), 7 => $this->s()]
        );
        $this->assertSame(['create' => [4], 'update' => [2], 'delete' => [7]], $plan);
    }

    public function testEmptyMatomoWithKeycloakGroupsIsSuspicious(): void
    {
        $this->assertTrue(GroupsReconciler::isSuspiciousMassDelete([], [3 => $this->s()]));
    }

    public function testNonEmptyMatomoOrEmptyKeycloakIsNotSuspicious(): void
    {
        $this->assertFalse(GroupsReconciler::isSuspiciousMassDelete([3 => $this->s()], [3 => $this->s(), 4 => $this->s()]));
        $this->assertFalse(GroupsReconciler::isSuspiciousMassDelete([], []));
        $this->assertFalse(GroupsReconciler::isSuspiciousMassDelete([3 => $this->s()], []));
    }
}
