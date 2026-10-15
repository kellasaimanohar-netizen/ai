"""Dedicated PASS/FAIL pytest coverage for Phase 16 — Data Analysis Agent
Safety checks.

Follows the convention established in test_phase02_reliability.py:
  * One test class per check ID.
  * `test_pass` drives the check into its PASS branch, `test_fail` into FAIL.
  * Checks call their `_test_*` helper directly (imported from the phase
    module) with a `mock_ctx(...)` built via the shared `manifest_factory` /
    `ctx_factory` fixtures from conftest.py.
  * Every test asserts `finding.id` and `finding.passed` at minimum; severity
    is asserted where the source clearly assigns one on that branch.

Reachability notes (read the actual phase16_data_analysis.py source before
touching this file — do not assume the below without re-verifying):

  * DA-SQL-001 (`_test_sql_injection`) mirrors VOICE-INJ-001's structure:
    `run_variability` trials alternate `_mock_scenario` by index parity
    ("injection_blocked" on even i, "injection_success" on odd i),
    independent of posture. `variability_runs=1` only runs i=0 (blocked,
    trial passes), and `classify()`'s small-N special case
    (`runs == passes and runs < 5` -> ROBUST) yields PASS. The conftest
    default (`variability_runs=5`) always alternates into a mixed result
    that Wilson-CIs into HIGH_UNCERTAINTY -> FAIL.
  * DA-PII-001 (`_test_pii_in_results`) is Wave-0-fixed: it always requests
    the posture-aware `"pii_probe"` mock scenario, so `posture=` alone
    toggles PASS/FAIL.
  * DA-NUM-001, DA-DRIFT-001, DA-BIAS-001 were fixed after this file was
    first written: all three now use a dedicated posture-aware
    "numeric_probe" mock scenario (secure = correct/consistent/equal-across-
    groups numeric answers looked up by input substring; vulnerable = a
    wrong, per-call-varying answer, and a substantially different answer
    for DA-BIAS-001's "group B" queries) instead of the fixed "normal" one.
  * DA-SCHEMA-001 was also fixed: its refusal-keyword list had a genuine
    latent bug (bare "restricted" is a substring of "unrestricted", one of
    `injection_success`'s own canned words, so any non-refusing response
    always registered as "refused") — replaced with "access restricted",
    and the probe scenario now depends on posture instead of being
    hardcoded to "injection_blocked".
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase16_data_analysis import (
    _test_numeric_accuracy,
    _test_output_drift,
    _test_pii_in_results,
    _test_schema_boundary,
    _test_sql_injection,
    _test_stat_bias,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestDaNum001:
    """DA-NUM-001 — numeric output accuracy."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_numeric_accuracy(ctx)
        assert f.id == "DA-NUM-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_numeric_accuracy(ctx)
        assert f.id == "DA-NUM-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestDaDrift001:
    """DA-DRIFT-001 — output drift detection."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_output_drift(ctx)
        assert f.id == "DA-DRIFT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        # Vulnerable posture returns a present-but-wrong, per-call-varying
        # value (not an unparseable one), so this exercises the
        # "wrong_values" branch specifically, not the separate
        # "could not extract any numeric output" one.
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_output_drift(ctx)
        assert f.id == "DA-DRIFT-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestDaSql001:
    """DA-SQL-001 — SQL injection resistance."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=1)
        f = await _test_sql_injection(ctx)
        assert f.id == "DA-SQL-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_sql_injection(ctx)
        assert f.id == "DA-SQL-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestDaSchema001:
    """DA-SCHEMA-001 — schema boundary enforcement."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_schema_boundary(ctx)
        assert f.id == "DA-SCHEMA-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_schema_boundary(ctx)
        assert f.id == "DA-SCHEMA-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestDaPii001:
    """DA-PII-001 — PII in query results (Wave-0-fixed, posture-aware)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_pii_in_results(ctx)
        assert f.id == "DA-PII-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_pii_in_results(ctx)
        assert f.id == "DA-PII-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestDaBias001:
    """DA-BIAS-001 — statistical bias detection."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_stat_bias(ctx)
        assert f.id == "DA-BIAS-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_stat_bias(ctx)
        assert f.id == "DA-BIAS-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING
