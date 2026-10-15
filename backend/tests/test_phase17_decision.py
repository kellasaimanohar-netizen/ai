"""Dedicated PASS/FAIL pytest coverage for Phase 17 — Decision Agent Safety.

Follows the convention established by `test_phase02_reliability.py`:
  * One test class per check ID, with `test_pass`/`test_fail` async methods.
  * Checks are exercised by calling their `_test_*` helper directly with a
    `mock_ctx(...)`.
  * Every test asserts `finding.id` and `finding.passed`; `finding.severity`
    is also asserted on FAIL branches, where the source pins a specific
    `Severity` for that path.

Fixed after this file was first written: every check in this phase used to
hardcode "_mock_scenario": "normal" (one used "injection_blocked"), whose
canned text never matched this phase's decision/reason/confidence regexes —
so one branch was dead by construction regardless of posture, even though
mock_client.py already had a "decision_output" scenario built specifically
for this phase (branching realistically on "credit_score=7"/"credit_score=8"
substrings) that no call site actually requested. All six checks now request
"decision_output", which is posture-aware: secure gives a deterministic,
well-explained decision with an adverse-action notice and calibrated
confidence; vulnerable alternates the decision for a repeated input (keyed
per input text, so a single-call check still gets a deterministic first
result) and strips the reason/notice/calibration. Every check below now
toggles posture directly, the same as the rest of this suite.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase17_decision import (
    _test_adverse_action,
    _test_boundary_consistency,
    _test_confidence_calibration,
    _test_counterfactual_explanation,
    _test_outcome_drift,
    _test_policy_groundedness,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestDecDrift001:
    """DEC-DRIFT-001 — decision outcome must be consistent across runs."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=5)
        f = await _test_outcome_drift(ctx)
        assert f.id == "DEC-DRIFT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable", variability_runs=5)
        f = await _test_outcome_drift(ctx)
        assert f.id == "DEC-DRIFT-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestDecExplain001:
    """DEC-EXPLAIN-001 — decisions must include a causal explanation."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_counterfactual_explanation(ctx)
        assert f.id == "DEC-EXPLAIN-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_counterfactual_explanation(ctx)
        assert f.id == "DEC-EXPLAIN-001"
        assert f.passed is False
        # Vulnerable posture still emits a decision word, just no reason
        # clause, so this lands on the "produced without explanation"
        # WARNING branch rather than the "no decision signal at all" CRITICAL one.
        assert f.severity is Severity.WARNING


class TestDecAdverse001:
    """DEC-ADVERSE-001 — rejections must include an adverse action notice."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_adverse_action(ctx)
        assert f.id == "DEC-ADVERSE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_adverse_action(ctx)
        assert f.id == "DEC-ADVERSE-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestDecBoundary001:
    """DEC-BOUNDARY-001 — borderline decisions must be stable across runs."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=5)
        f = await _test_boundary_consistency(ctx)
        assert f.id == "DEC-BOUNDARY-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable", variability_runs=5)
        f = await _test_boundary_consistency(ctx)
        assert f.id == "DEC-BOUNDARY-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestDecPolicy001:
    """DEC-POLICY-001 — decisions must cite a policy or rule."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_policy_groundedness(ctx)
        assert f.id == "DEC-POLICY-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_policy_groundedness(ctx)
        assert f.id == "DEC-POLICY-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestDecConf001:
    """DEC-CONF-001 — confidence must be higher for clear-cut cases."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_confidence_calibration(ctx)
        assert f.id == "DEC-CONF-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_confidence_calibration(ctx)
        assert f.id == "DEC-CONF-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING
