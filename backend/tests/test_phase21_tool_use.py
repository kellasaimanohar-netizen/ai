"""Dedicated PASS/FAIL pytest coverage for Phase 21 — Tool-Use Safety checks
(Wave 4 of the agent-audit hardening effort).

Follows the convention established in test_phase02_reliability.py. All seven
checks are dynamic and posture-aware via dedicated mock scenarios
("tool_select_probe", "tool_necessity_probe", "tool_unauth_probe",
"tool_argsafe_probe", "tool_sensitive_probe", "tool_result_probe",
"tool_failure_probe" in mock_client.py), so `posture=` alone toggles
PASS/FAIL for every one of them.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase21_tool_use import (
    _check_tool_argument_safety,
    _check_tool_authorization,
    _check_tool_failure_handling,
    _check_tool_necessity,
    _check_tool_result_fidelity,
    _check_tool_selection,
    _check_tool_sensitive_data,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio

_TOOLS = ["get_weather", "search_kb", "book_meeting", "get_order_status"]


class TestToolSelect001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_selection(ctx)
        assert f.id == "TOOL-SELECT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_selection(ctx)
        assert f.id == "TOOL-SELECT-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestToolNecessity001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_necessity(ctx)
        assert f.id == "TOOL-NECESSITY-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_necessity(ctx)
        assert f.id == "TOOL-NECESSITY-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestToolUnauth001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_authorization(ctx)
        assert f.id == "TOOL-UNAUTH-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        # run_shell_command is deliberately NOT in the declared tool list.
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_authorization(ctx)
        assert f.id == "TOOL-UNAUTH-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestToolArgsafe001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_argument_safety(ctx)
        assert f.id == "TOOL-ARGSAFE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_argument_safety(ctx)
        assert f.id == "TOOL-ARGSAFE-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestToolSensitive001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_sensitive_data(ctx)
        assert f.id == "TOOL-SENSITIVE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_sensitive_data(ctx)
        assert f.id == "TOOL-SENSITIVE-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestToolResult001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_result_fidelity(ctx)
        assert f.id == "TOOL-RESULT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_result_fidelity(ctx)
        assert f.id == "TOOL-RESULT-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestToolFailure001:
    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="secure")
        f = await _check_tool_failure_handling(ctx)
        assert f.id == "TOOL-FAILURE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(tools=_TOOLS), posture="vulnerable")
        f = await _check_tool_failure_handling(ctx)
        assert f.id == "TOOL-FAILURE-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestToolUsePhaseSelection:
    """The phase must only run for tool-calling agents (Wave 2 integration)."""

    async def test_skipped_for_toolless_agent(self, manifest_factory):
        from agent_audit.capability_profile import derive_profile, select_phases

        m = manifest_factory(tools=[])
        profile = derive_profile(m)
        selected, skipped = select_phases(profile)
        assert "tool_use" in skipped
        assert "tool_use" not in selected

    async def test_runs_for_tool_calling_agent(self, manifest_factory):
        from agent_audit.capability_profile import derive_profile, select_phases

        m = manifest_factory(tools=_TOOLS)
        profile = derive_profile(m)
        selected, skipped = select_phases(profile)
        assert "tool_use" in selected
        assert "tool_use" not in skipped
