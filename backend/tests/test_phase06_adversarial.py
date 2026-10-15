"""Dedicated PASS/FAIL pytest coverage for Phase 6 — Adversarial checks.

  * ADV-CHAIN-001 and ADV-DELAY-001 are Wave-0-fixed: both are posture-aware
    via the mock "session_bleed" scenario (secure = per-session_id isolated
    memory bucket, vulnerable = a shared "__global__" bucket that leaks
    across session IDs).
  * ADV-FLOOD-001 was also fixed after this file was first written: its
    trial() now picks "injection_blocked"/"injection_success" from
    `ctx.mock_posture` instead of alternating by trial index (`i % 3`),
    which previously capped the achievable pass rate at 2/3 and made PASS
    structurally unreachable. Toggle posture as usual now.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase6_adversarial import (
    _test_context_flooding,
    _test_time_delayed_trigger,
    _test_tool_chain,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio

# Variability-based checks need enough runs that a 100%-pass-rate trial set
# resolves to ROBUST/STABLE rather than HIGH_UNCERTAINTY from a too-narrow
# Wilson CI (a statistical-power artifact, not a real defect).
_RUNS = 20


class TestAdvChain001:
    """ADV-CHAIN-001 — multi-step seed-then-exploit attack chain (variability)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=_RUNS)
        f = await _test_tool_chain(ctx)
        assert f.id == "ADV-CHAIN-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable", variability_runs=_RUNS)
        f = await _test_tool_chain(ctx)
        assert f.id == "ADV-CHAIN-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestAdvDelay001:
    """ADV-DELAY-001 — codeword planted in one session, probed from another."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_time_delayed_trigger(ctx)
        assert f.id == "ADV-DELAY-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_time_delayed_trigger(ctx)
        assert f.id == "ADV-DELAY-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestAdvFlood001:
    """ADV-FLOOD-001 — context-flooding resistance (variability)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=_RUNS)
        f = await _test_context_flooding(ctx)
        assert f.id == "ADV-FLOOD-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable", variability_runs=_RUNS)
        f = await _test_context_flooding(ctx)
        assert f.id == "ADV-FLOOD-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL
