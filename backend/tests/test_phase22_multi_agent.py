"""Dedicated PASS/FAIL pytest coverage for Phase 22 — Multi-Agent System
Safety checks (completing item #9 of the original spec: dedicated coverage
for multi-agent/orchestrator architectures).

All three checks are dynamic and posture-aware via the shared "session_bleed"
scenario (reused for MULTI-LEAK-001, same mechanism as REL-SESS-001),
`ctx.mock_posture`-selected injection scenarios (MULTI-TRUST-001, same
mechanism as MCP-RESULT-001), and the dedicated "delegation_probe" scenario
(MULTI-DELEGATE-001).
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase22_multi_agent import (
    _check_delegated_output_trust,
    _check_delegation_isolation,
    _check_delegation_permission_boundary,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestMultiLeak001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_delegation_isolation(ctx)
        assert f.id == "MULTI-LEAK-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_delegation_isolation(ctx)
        assert f.id == "MULTI-LEAK-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestMultiTrust001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_delegated_output_trust(ctx)
        assert f.id == "MULTI-TRUST-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_delegated_output_trust(ctx)
        assert f.id == "MULTI-TRUST-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestMultiDelegate001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_delegation_permission_boundary(ctx)
        assert f.id == "MULTI-DELEGATE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_delegation_permission_boundary(ctx)
        assert f.id == "MULTI-DELEGATE-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestMultiAgentPhaseSelection:
    """The phase must only run for agents whose profile declares
    is_multi_agent (Wave 2 integration)."""

    async def test_skipped_for_single_agent(self, manifest_factory):
        from agent_audit.capability_profile import derive_profile, select_phases

        m = manifest_factory(tools=["search_kb"])
        profile = derive_profile(m)
        assert profile.is_multi_agent is False
        selected, skipped = select_phases(profile)
        assert "multi_agent" in skipped
        assert "multi_agent" not in selected

    async def test_runs_for_delegation_tools(self, manifest_factory):
        from agent_audit.capability_profile import derive_profile, select_phases

        m = manifest_factory(tools=["delegate_to_sub_agent", "route_to_specialist"])
        profile = derive_profile(m)
        assert profile.is_multi_agent is True
        selected, skipped = select_phases(profile)
        assert "multi_agent" in selected
        assert "multi_agent" not in skipped
