"""Dedicated PASS/FAIL pytest coverage for Phase 2 — Reliability checks.

Convention (followed by every test_phaseNN_*.py file in this suite):
  * One test class per check ID.
  * `test_pass` drives the check into its PASS branch, `test_fail` into FAIL.
  * Checks with a named `_test_*`/`_check_*` helper are called directly via
    that helper (imported from the phase module) with a `mock_ctx(...)`.
  * Checks implemented inline in `run_phase()` (no per-check helper) are
    exercised by calling `run_phase(ctx)` and picking the finding by `.id`
    out of the returned list — see phase1/phase4/phase5/phase7's test files.
  * Dynamic checks (call the mock agent) toggle `posture="secure"` (PASS) vs
    `posture="vulnerable"` (FAIL) via `mock_ctx`/`ctx_factory`.
  * Static/manifest-only checks build two manifests via
    `build_manifest(...)`/`manifest_factory` instead of touching posture.
  * Variability-based checks (use `run_variability` internally, e.g.
    ADV-CHAIN-001, SEC-INJ-DIRECT-001) need `variability_runs>=15` — at the
    default of 5, a 100% pass rate still Wilson-CIs into HIGH_UNCERTAINTY
    instead of ROBUST/STABLE, which would make a passing check look like it
    failed for a statistical-power reason, not a real defect.
  * Every test asserts `finding.id` and `finding.passed` at minimum; add
    `finding.severity` where the check's docstring/remediation implies a
    specific severity for that branch.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase2_reliability import (
    _test_iteration_cap,
    _test_output_schema,
    _test_session_isolation,
    _test_timeout,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestRelTimeout001:
    """REL-TIMEOUT-001 — agent honours the timeout / aborts fast."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_timeout(ctx)
        assert f.id == "REL-TIMEOUT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_timeout(ctx)
        assert f.id == "REL-TIMEOUT-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestRelIter001:
    """REL-ITER-001 — agent halts at max_steps rather than running past it."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_iteration_cap(ctx)
        assert f.id == "REL-ITER-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_iteration_cap(ctx)
        assert f.id == "REL-ITER-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL

    async def test_not_applicable_for_openapi_sources(self, manifest_factory, ctx_factory):
        """Static short-circuit: no iteration concept for a plain REST API source. Not applicable is reported as
        not tested (informational), never as a pass that would raise the score."""
        m = manifest_factory(provenance_trail={"openapi": ["runtime"]})
        ctx = ctx_factory(m, posture="vulnerable")
        f = await _test_iteration_cap(ctx)
        assert f.id == "REL-ITER-001"
        assert f.passed is False
        assert f.severity is Severity.INFO
        assert f.description.startswith("Skipped:")


class TestRelSchema001:
    """REL-SCHEMA-001 — response includes the required fields."""

    async def test_fail_missing_fields(self, manifest_factory, ctx_factory):
        # `_test_output_schema` always forces the "schema_invalid" mock
        # scenario (deliberately missing fields) regardless of posture —
        # there is no "clean schema" scenario, so only FAIL is exercised
        # here; PASS is covered indirectly by every other check in this
        # file, whose responses all carry the required fields.
        ctx = ctx_factory(manifest_factory())
        f = await _test_output_schema(ctx)
        assert f.id == "REL-SCHEMA-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestRelSess001:
    """REL-SESS-001 — no state bleed across session IDs."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_session_isolation(ctx)
        assert f.id == "REL-SESS-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_session_isolation(ctx)
        assert f.id == "REL-SESS-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL
