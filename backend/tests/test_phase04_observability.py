"""Dedicated PASS/FAIL pytest coverage for Phase 4 — Observability checks.

Convention (see test_phase02_reliability.py for the canonical description):
  * One test class per check ID, `test_pass` / `test_fail` methods.
  * Every check in phase4_observability.py is implemented inline inside
    `run_phase()` — there is no per-check helper to import — so every test
    here calls `run_phase(ctx)` (which internally samples
    `max(5, ctx.variability_runs)` mock calls under the `trace_probe`
    scenario) and picks the finding it cares about out of the returned list
    by `.id`.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase4_observability import run_phase
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


def _find(findings, finding_id: str):
    for f in findings:
        if f.id == finding_id:
            return f
    raise AssertionError(f"no finding with id {finding_id!r} in {[f.id for f in findings]}")


class TestObsTrace001:
    """OBS-TRACE-001 — every response carries a distinct trace_id.

    Posture-aware (Wave 0 fix) via the `trace_probe` mock scenario, used
    internally by `run_phase`'s sampling loop.
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "OBS-TRACE-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        findings = await run_phase(ctx)
        f = _find(findings, "OBS-TRACE-001")
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestObsLatency001:
    """OBS-LATENCY-001 — sampled p95 latency stays within the declared SLO."""

    async def test_pass(self, manifest_factory, ctx_factory):
        # No injected latency + a generous SLO budget -> p95 comfortably
        # under budget.
        m = manifest_factory(p95_latency_ms=10_000)
        ctx = ctx_factory(m, posture="secure", inject_latency_ms=0)
        findings = await run_phase(ctx)
        f = _find(findings, "OBS-LATENCY-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        # Inject real per-call latency and set an unreachably tight SLO
        # budget so p95 exceeds it.
        m = manifest_factory(p95_latency_ms=10)
        ctx = ctx_factory(m, posture="secure", inject_latency_ms=50)
        findings = await run_phase(ctx)
        f = _find(findings, "OBS-LATENCY-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestObsCost001:
    """OBS-COST-001 — max observed cost stays within the per-task budget.

    The `trace_probe` scenario returns a fixed cost_usd=0.021 per call
    regardless of posture, so budget is driven purely via the manifest's
    `max_cost_per_task_usd`.
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(max_cost_per_task_usd=1.0)
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "OBS-COST-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(max_cost_per_task_usd=0.001)
        ctx = ctx_factory(m, posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "OBS-COST-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING
