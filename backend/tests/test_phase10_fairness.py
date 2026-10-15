"""Dedicated PASS/FAIL pytest coverage for Phase 10 — Fairness & Bias checks.

Follows the convention established in test_phase02_reliability.py:
  * One test class per check ID.
  * `test_pass` drives the check into its PASS branch, `test_fail` into FAIL.
  * FAIR-PARITY-001 and FAIR-TOXICITY-001 are Wave-0-fixed dynamic checks:
    they both drive `agent_audit.bias_probes.PAIRED_PROBES` through the
    mock client's `bias_probe` scenario, whose "vulnerable" posture returns
    a shorter, dismissive response (containing the toxic word "lazy") for
    every probe's group-B prompt and a warm generic response otherwise —
    so both checks flip PASS/FAIL together off the same posture toggle.
  * FAIR-EQUITY-001 is NOT part of the Wave-0 fix — its own keyword-matching
    accuracy comparison against a golden dataset is a separate, deeper
    limitation left for a later wave (see KNOWN-GAP below). Only its real,
    reachable skip-path branches are tested here.
  * Every test asserts `finding.id` and `finding.passed` at minimum; severity
    is asserted on FAIL branches where the source clearly assigns one.
"""
from __future__ import annotations

import json

import pytest

from agent_audit.phases.phase10_fairness import (
    _check_demographic_parity,
    _check_golden_dataset_equity,
    _check_toxicity_variance,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestFairParity001:
    """FAIR-PARITY-001 — demographic parity across paired probes."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_demographic_parity(ctx)
        assert f.id == "FAIR-PARITY-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_demographic_parity(ctx)
        assert f.id == "FAIR-PARITY-001"
        assert f.passed is False
        # All 6 paired probes' group-B prompts carry a group_b_signal, and
        # the vulnerable bias_probe response is different enough (low
        # Jaccard overlap) from the group-A response for every pair, so
        # >= 2 disparities are detected -> CRITICAL.
        assert f.severity is Severity.CRITICAL


class TestFairToxicity001:
    """FAIR-TOXICITY-001 — no toxic language across demographic probes."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_toxicity_variance(ctx)
        assert f.id == "FAIR-TOXICITY-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_toxicity_variance(ctx)
        assert f.id == "FAIR-TOXICITY-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestFairEquity001:
    """FAIR-EQUITY-001 — accuracy should not differ >10pp across demographic slices.

    Fixed after this file was first written: `_check_golden_dataset_equity`
    now routes every probe through the posture-aware "equity_probe" mock
    scenario (passing `_group`/`_expected` in the payload) instead of the
    fixed "normal" one. Secure posture echoes each case's own expected
    answer for every group (0% gap); vulnerable posture only answers
    correctly for the first group seen, producing a real, measurable gap.
    Both the real 2-group accuracy-gap path and the four skip-path branches
    are covered below.
    """

    async def test_pass_two_groups_equal_accuracy(self, manifest_factory, ctx_factory, tmp_path):
        ds_path = tmp_path / "equity.jsonl"
        cases = [
            {"input": "What is the policy?", "expected": "The policy is XYZ.", "group": "us"},
            {"input": "What is the return window?", "expected": "The window is 30 days.", "group": "us"},
            {"input": "What is the policy?", "expected": "The policy is XYZ.", "group": "india"},
            {"input": "What is the return window?", "expected": "The window is 30 days.", "group": "india"},
        ]
        ds_path.write_text("\n".join(json.dumps(c) for c in cases), encoding="utf-8")
        m = manifest_factory(golden_dataset_path=ds_path)
        ctx = ctx_factory(m, posture="secure")
        f = await _check_golden_dataset_equity(ctx)
        assert f.id == "FAIR-EQUITY-001"
        assert f.passed is True
        assert "0% gap" in f.title

    async def test_fail_two_groups_accuracy_gap(self, manifest_factory, ctx_factory, tmp_path):
        ds_path = tmp_path / "equity.jsonl"
        cases = [
            {"input": "What is the policy?", "expected": "The policy is XYZ.", "group": "us"},
            {"input": "What is the return window?", "expected": "The window is 30 days.", "group": "us"},
            {"input": "What is the policy?", "expected": "The policy is XYZ.", "group": "india"},
            {"input": "What is the return window?", "expected": "The window is 30 days.", "group": "india"},
        ]
        ds_path.write_text("\n".join(json.dumps(c) for c in cases), encoding="utf-8")
        m = manifest_factory(golden_dataset_path=ds_path)
        ctx = ctx_factory(m, posture="vulnerable")
        f = await _check_golden_dataset_equity(ctx)
        assert f.id == "FAIR-EQUITY-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING

    async def test_pass_no_golden_dataset(self, manifest_factory, ctx_factory):
        m = manifest_factory(golden_dataset_path=None)
        ctx = ctx_factory(m, posture="secure")
        f = await _check_golden_dataset_equity(ctx)
        assert f.id == "FAIR-EQUITY-001"
        assert f.passed is True
        assert "no golden dataset" in f.title.lower()

    async def test_pass_golden_dataset_file_not_found(self, manifest_factory, ctx_factory, tmp_path):
        missing = tmp_path / "does_not_exist.jsonl"
        m = manifest_factory(golden_dataset_path=missing)
        ctx = ctx_factory(m, posture="secure")
        f = await _check_golden_dataset_equity(ctx)
        assert f.id == "FAIR-EQUITY-001"
        assert f.passed is True
        assert "not found" in f.title.lower()

    async def test_pass_no_group_field(self, manifest_factory, ctx_factory, tmp_path):
        ds_path = tmp_path / "nogroup.jsonl"
        cases = [
            {"input": "What is your refund policy?", "expected": "refund policy details"},
            {"input": "How do I reset my password?", "expected": "password reset steps"},
        ]
        ds_path.write_text("\n".join(json.dumps(c) for c in cases), encoding="utf-8")
        m = manifest_factory(golden_dataset_path=ds_path)
        ctx = ctx_factory(m, posture="secure")
        f = await _check_golden_dataset_equity(ctx)
        assert f.id == "FAIR-EQUITY-001"
        assert f.passed is True
        assert "no 'group' field" in f.title.lower()

    async def test_pass_only_one_group(self, manifest_factory, ctx_factory, tmp_path):
        ds_path = tmp_path / "onegroup.jsonl"
        cases = [
            {"input": "What is your refund policy?", "expected": "refund policy details", "group": "india"},
            {"input": "How do I reset my password?", "expected": "password reset steps", "group": "india"},
        ]
        ds_path.write_text("\n".join(json.dumps(c) for c in cases), encoding="utf-8")
        m = manifest_factory(golden_dataset_path=ds_path)
        ctx = ctx_factory(m, posture="secure")
        f = await _check_golden_dataset_equity(ctx)
        assert f.id == "FAIR-EQUITY-001"
        assert f.passed is True
        assert "only 1 group(s)" in f.title.lower()
