"""Dedicated PASS/FAIL pytest coverage for Phase 20 — Real-Time Data &
Freshness checks (Wave 3 of the agent-audit hardening effort).

Follows the convention established in test_phase02_reliability.py. All six
checks are dynamic and posture-aware via dedicated mock scenarios
("freshness_fresh"/"freshness_stale"/"freshness_missing"/
"freshness_conflicting" in mock_client.py), so `posture=` alone toggles
PASS/FAIL for every one of them.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase20_freshness import (
    _check_conflicting_data_disclosure,
    _check_current_data_accuracy,
    _check_freshness_metadata,
    _check_live_source_invoked,
    _check_missing_data_handling,
    _check_stale_data_disclosure,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestFreshCall001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_live_source_invoked(ctx)
        assert f.id == "FRESH-CALL-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_live_source_invoked(ctx)
        assert f.id == "FRESH-CALL-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestFreshCurrent001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_current_data_accuracy(ctx)
        assert f.id == "FRESH-CURRENT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_current_data_accuracy(ctx)
        assert f.id == "FRESH-CURRENT-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestFreshStale001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_stale_data_disclosure(ctx)
        assert f.id == "FRESH-STALE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_stale_data_disclosure(ctx)
        assert f.id == "FRESH-STALE-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestFreshMissing001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_missing_data_handling(ctx)
        assert f.id == "FRESH-MISSING-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_missing_data_handling(ctx)
        assert f.id == "FRESH-MISSING-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestFreshConflict001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_conflicting_data_disclosure(ctx)
        assert f.id == "FRESH-CONFLICT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_conflicting_data_disclosure(ctx)
        assert f.id == "FRESH-CONFLICT-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestFreshTimestamp001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_freshness_metadata(ctx)
        assert f.id == "FRESH-TIMESTAMP-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_freshness_metadata(ctx)
        assert f.id == "FRESH-TIMESTAMP-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestFreshnessPhaseSelection:
    """The phase must only run for dynamic/hybrid agents (Wave 2 integration)."""

    async def test_skipped_for_static_agent(self, manifest_factory):
        from agent_audit.capability_profile import derive_profile, select_phases

        m = manifest_factory(tools=["summarise_document"])
        profile = derive_profile(m)
        assert profile.data_mode == "static"
        selected, skipped = select_phases(profile)
        assert "freshness" in skipped
        assert "freshness" not in selected

    async def test_runs_for_dynamic_agent(self, manifest_factory):
        from agent_audit.capability_profile import derive_profile, select_phases

        m = manifest_factory(tools=["get_live_order_status"])
        profile = derive_profile(m)
        assert profile.data_mode == "dynamic"
        selected, skipped = select_phases(profile)
        assert "freshness" in selected
        assert "freshness" not in skipped
