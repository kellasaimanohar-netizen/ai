"""Dedicated PASS/FAIL pytest coverage for Phase 11 — Multi-Turn & Session
Security checks.

Follows the convention established in test_phase02_reliability.py:
  * One test class per check ID.
  * `test_pass` drives the check into its PASS branch, `test_fail` into FAIL.
  * MT-POISON-001 and MT-MEMORY-001 are Wave-0-fixed: their final probing
    turn picks "injection_success" vs "injection_blocked" based directly on
    `ctx.mock_posture`, so they toggle posture via `ctx_factory` like the
    phase2 checks do.
  * MT-TURNLIMIT-001 was already posture-aware via the mock client's
    `infinite_loop` scenario (secure -> steps==max_steps with
    finish_reason="max_steps_reached"; vulnerable -> steps well past
    max_steps with finish_reason="complete") — not part of the Wave-0 fix
    list, but reachable both ways already, so it also toggles posture.
  * MT-ESCALATE-001 was also fixed (posture-aware scenario selection for
    turns 2-3, plus a refusal-keyword substring collision) — see
    `TestMtEscalate001` for what was wrong and how it was fixed.
  * Every test asserts `finding.id` and `finding.passed` at minimum; severity
    is asserted on FAIL branches where the source clearly assigns one.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase11_multi_turn import (
    _check_context_poisoning,
    _check_memory_accumulation,
    _check_privilege_escalation,
    _check_turn_count_limit,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestMtPoison001:
    """MT-POISON-001 — sleeper context-poisoning instruction must not activate."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_context_poisoning(ctx)
        assert f.id == "MT-POISON-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_context_poisoning(ctx)
        assert f.id == "MT-POISON-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestMtEscalate001:
    """MT-ESCALATE-001 — privilege escalation across turns must be refused.

    Fixed after this file was first written: `_check_privilege_escalation`
    now picks "injection_success"/"injection_blocked" for turns 2-3 from
    `ctx.mock_posture` (previously hardcoded to "injection_success"
    unconditionally), and the "restricted" refusal keyword — a substring of
    "unrestricted", one of the check's own _ESCALATION_SIGNALS — was replaced
    with non-colliding refusal phrases so a genuine escalation no longer
    self-refutes as "refused". Both branches are real now.
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_privilege_escalation(ctx)
        assert f.id == "MT-ESCALATE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_privilege_escalation(ctx)
        assert f.id == "MT-ESCALATE-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestMtTurnlimit001:
    """MT-TURNLIMIT-001 — agentic loop must halt at manifest max_steps."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_turn_count_limit(ctx)
        assert f.id == "MT-TURNLIMIT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_turn_count_limit(ctx)
        assert f.id == "MT-TURNLIMIT-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestMtMemory001:
    """MT-MEMORY-001 — repeated injection attempts across turns must be resisted."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_memory_accumulation(ctx)
        assert f.id == "MT-MEMORY-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_memory_accumulation(ctx)
        assert f.id == "MT-MEMORY-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL
