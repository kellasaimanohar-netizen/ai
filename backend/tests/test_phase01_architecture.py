"""Dedicated PASS/FAIL pytest coverage for Phase 1 — Architecture checks.

Convention (see test_phase02_reliability.py for the canonical description):
  * One test class per check ID, `test_pass` / `test_fail` methods.
  * Every check in phase1_architecture.py is implemented inline inside
    `run_phase()` — there is no per-check helper to import — so every test
    here calls `run_phase(ctx)` and picks the finding it cares about out of
    the returned list by `.id`.
  * None of these checks call `ctx.call_agent` (they're pure manifest
    inspection), so `posture` is irrelevant here; PASS/FAIL is driven purely
    by which manifest is built via `manifest_factory`/`build_manifest`.
"""
from __future__ import annotations

import pytest

from agent_audit.manifest import ToolSpec
from agent_audit.phases.phase1_architecture import run_phase
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


def _find(findings, finding_id: str):
    for f in findings:
        if f.id == finding_id:
            return f
    raise AssertionError(f"no finding with id {finding_id!r} in {[f.id for f in findings]}")


class TestArchTool001:
    """ARCH-TOOL-001 — at least one tool is declared for the agent."""

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["search_kb"])
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-TOOL-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=[])
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-TOOL-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestArchCtx001:
    """ARCH-CTX-001 — a context token budget is declared."""

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(context_budget_tokens=8000)
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-CTX-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(context_budget_tokens=None)
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-CTX-001")
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestArchHandoff001:
    """ARCH-HANDOFF-001 — declared tools stay consistent across sources.

    FAIL fires when a tool is discovered via a non-YAML source (e.g. a repo
    scan) that isn't also declared in the YAML config — a "shadow tool".
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["search_kb"])
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-HANDOFF-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["search_kb"])
        # build_manifest's `tools=[...]` convenience kwarg always stamps
        # declared_in=["yaml"], so to exercise the "repo found it, yaml
        # didn't declare it" FAIL branch we append a ToolSpec by hand with
        # different provenance.
        m.capabilities.tools.append(
            ToolSpec(name="shadow_delete", declared_in=["repo"], source_location="app.py:42")
        )
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-HANDOFF-001")
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestArchHitl001:
    """ARCH-HITL-001 — destructive tools require human-in-the-loop."""

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(
            tools=["delete_user"], destructive_tools=["delete_user"], requires_hitl=True,
        )
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-HITL-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(
            tools=["delete_user"], destructive_tools=["delete_user"], requires_hitl=False,
        )
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "ARCH-HITL-001")
        assert f.passed is False
        assert f.severity is Severity.CRITICAL
