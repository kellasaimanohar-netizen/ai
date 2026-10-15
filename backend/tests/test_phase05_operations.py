"""Dedicated PASS/FAIL pytest coverage for Phase 5 — Operations checks.

All three checks in phase5_operations.py are implemented inline inside
`run_phase()` (no per-check helper functions), so every test here calls
`run_phase(ctx)` and picks the specific finding out of the returned list by
`.id`. See test_phase02_reliability.py for the general conventions this
suite follows.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase5_operations import run_phase
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


def _find(findings, finding_id):
    return next(f for f in findings if f.id == finding_id)


class TestOpsRunbook001:
    """OPS-RUNBOOK-001 — runbooks directory present and non-empty (static)."""

    async def test_pass(self, manifest_factory, ctx_factory, tmp_path):
        rb_dir = tmp_path / "runbooks"
        rb_dir.mkdir()
        (rb_dir / "rollback.md").write_text("# Rollback runbook", encoding="utf-8")
        ctx = ctx_factory(manifest_factory(runbooks_dir=rb_dir))
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-RUNBOOK-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail_no_dir_declared(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(runbooks_dir=None))
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-RUNBOOK-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING

    async def test_fail_dir_declared_but_missing(self, manifest_factory, ctx_factory, tmp_path):
        missing_dir = tmp_path / "does_not_exist"
        ctx = ctx_factory(manifest_factory(runbooks_dir=missing_dir))
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-RUNBOOK-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING

    async def test_fail_dir_exists_but_empty(self, manifest_factory, ctx_factory, tmp_path):
        empty_dir = tmp_path / "runbooks_empty"
        empty_dir.mkdir()
        ctx = ctx_factory(manifest_factory(runbooks_dir=empty_dir))
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-RUNBOOK-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestOpsShutdown001:
    """OPS-SHUTDOWN-001 — agent raises a structured error on abort/timeout.

    Wave-0-fixed: posture-aware via the mock "timeout" scenario — secure
    posture raises asyncio.TimeoutError (graceful), vulnerable posture
    returns a late-but-normal response (not graceful).
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-SHUTDOWN-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-SHUTDOWN-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestOpsCanary001:
    """OPS-CANARY-001 — multi-region deployment heuristic (static)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(allowed_data_regions=["us-east-1", "eu-west-1"])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-CANARY-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail_single_region(self, manifest_factory, ctx_factory):
        m = manifest_factory(allowed_data_regions=["us-east-1"])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-CANARY-001")
        assert f.passed is False
        assert f.severity is Severity.INFO

    async def test_fail_no_regions(self, manifest_factory, ctx_factory):
        m = manifest_factory(allowed_data_regions=[])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "OPS-CANARY-001")
        assert f.passed is False
        assert f.severity is Severity.INFO
