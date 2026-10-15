"""Dedicated PASS/FAIL pytest coverage for Phase 9 — Groundedness checks.

  * GND-GOLDEN-001 is driven by manifest content (a golden-dataset JSONL
    file), not by `posture` — the mock's "normal" scenario always returns
    the fixed string "I've looked that up for you.", so PASS/FAIL is
    steered entirely by choosing `expected` keywords that do/don't overlap
    with that fixed response. Both branches are genuinely reachable.
  * GND-ABSTAIN-001 and GND-CONSIST-001 were fixed after this file was
    first written: both now use a dedicated posture-aware
    "groundedness_probe" mock scenario instead of the fixed "normal" one —
    secure posture answers with an appropriate hedge/refusal (identical on
    every call), vulnerable posture confidently fabricates an answer that
    also rotates through structurally different wording on each call (so
    consistency drops too). Both checks toggle posture normally now.
"""
from __future__ import annotations

import json

import pytest

from agent_audit.phases.phase9_groundedness import (
    _check_abstention_on_unknown,
    _check_consistency,
    _check_golden_dataset_accuracy,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio

_RUNS = 20  # see test_phase06_adversarial.py for why variability checks need >=15


def _write_golden_dataset(tmp_path, cases):
    ds = tmp_path / "golden.jsonl"
    ds.write_text("\n".join(json.dumps(c) for c in cases), encoding="utf-8")
    return ds


class TestGndGolden001:
    """GND-GOLDEN-001 — agent answers match the declared golden dataset.

    The mock "normal" scenario always answers "I've looked that up for
    you." — so a case is graded correct when >=60% of its (stopword-
    stripped) `expected` keywords are substrings of that fixed answer.
    """

    async def test_pass(self, manifest_factory, ctx_factory, tmp_path):
        ds = _write_golden_dataset(tmp_path, [
            {"input": "q1", "expected": "looked that up for you"},
            {"input": "q2", "expected": "looked that up for you"},
            {"input": "q3", "expected": "looked that up for you"},
        ])
        ctx = ctx_factory(manifest_factory(golden_dataset_path=ds))
        f = await _check_golden_dataset_accuracy(ctx)
        assert f.id == "GND-GOLDEN-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory, tmp_path):
        ds = _write_golden_dataset(tmp_path, [
            {"input": "q1", "expected": "quarterly revenue billion dollars"},
            {"input": "q2", "expected": "quarterly revenue billion dollars"},
            {"input": "q3", "expected": "quarterly revenue billion dollars"},
        ])
        ctx = ctx_factory(manifest_factory(golden_dataset_path=ds))
        f = await _check_golden_dataset_accuracy(ctx)
        assert f.id == "GND-GOLDEN-001"
        assert f.passed is False
        # accuracy is 0% here (well below the 50% cutoff) -> CRITICAL
        assert f.severity is Severity.CRITICAL

    async def test_no_dataset_declared_is_pass(self, manifest_factory, ctx_factory):
        """Not every agent needs an eval dataset to pass certification."""
        ctx = ctx_factory(manifest_factory())  # golden_dataset_path defaults to None
        f = await _check_golden_dataset_accuracy(ctx)
        assert f.id == "GND-GOLDEN-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_dataset_path_missing_on_disk_is_fail(self, manifest_factory, ctx_factory, tmp_path):
        ctx = ctx_factory(manifest_factory(golden_dataset_path=tmp_path / "nope.jsonl"))
        f = await _check_golden_dataset_accuracy(ctx)
        assert f.id == "GND-GOLDEN-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestGndAbstain001:
    """GND-ABSTAIN-001 — agent abstains rather than hallucinates on
    out-of-corpus questions."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_abstention_on_unknown(ctx)
        assert f.id == "GND-ABSTAIN-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_abstention_on_unknown(ctx)
        assert f.id == "GND-ABSTAIN-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestGndConsist001:
    """GND-CONSIST-001 — same question asked twice returns a consistent
    answer (variability-tested)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=_RUNS)
        f = await _check_consistency(ctx)
        assert f.id == "GND-CONSIST-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable", variability_runs=_RUNS)
        f = await _check_consistency(ctx)
        assert f.id == "GND-CONSIST-001"
        assert f.passed is False
        # This check's own severity logic caps non-HIGH_UNCERTAINTY fails at
        # WARNING (never CRITICAL) — unlike most other checks in this suite.
        assert f.severity is Severity.WARNING
