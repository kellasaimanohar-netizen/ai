"""Audit phases — v7.

v7 adds five new phases that fill the gaps identified for partial-coverage
and previously unsupported agent types:

  Phase 15 — voice          : Voice agent safety (ASR injection, TTS safety,
                               call escalation, consent, disfluency robustness)
  Phase 16 — data_analysis  : Data analysis agent safety (numeric accuracy,
                               output drift, SQL injection, schema boundary,
                               PII in query results, statistical bias)
  Phase 17 — decision       : Decision agent safety (outcome drift, counterfactual
                               explanation, adverse action, boundary consistency,
                               policy groundedness, confidence calibration)
  Phase 18 — security_agent : Security agent safety (HITL gate, threat-intel
                               injection, alert flood, false positives,
                               secret exposure in reports, IOC validation)
  Phase 19 — browser        : Browser agent safety — NEW FULL PHASE
                               (navigation boundary, credential exfiltration,
                               clickjacking, form data leakage, action scope,
                               session isolation, unconfirmed destructive actions)

All v6 phases (1–11, 14) are preserved unchanged.
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_audit.manifest import TargetManifest
    from agent_audit.mock_client import MockAgentClient

log = logging.getLogger(__name__)

# The phase a live call belongs to, set by the runner for each phase (concurrent phases each get their own value)
current_phase: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_phase", default=None)


@dataclass(slots=True)
class PhaseContext:
    """Everything a phase needs. Built by the runner, immutable to phases."""

    manifest: TargetManifest
    mock_tools: bool = False
    mock_posture: str = "secure"   # "secure" | "vulnerable" — see mock_client.py
    inject_latency_ms: int = 0
    concurrency: int = 4
    variability_runs: int = 5
    variability_store: dict[str, Any] = field(default_factory=dict)
    # v8: shared budget across all live calls in one audit (None in mock mode)
    budget: Any = None
    _mock_client: "MockAgentClient | None" = field(default=None, init=False, repr=False)
    _live_client: Any = field(default=None, init=False, repr=False)
    # Live runs: per phase, how many requests the agent answered ("ok") and how many it did not ("unanswered":
    # unreachable, or refused with 403 before the agent saw them). The runner reports a phase whose requests were
    # never answered as not tested, because its checks would only be grading empty answers.
    phase_calls: dict[str, dict[str, int]] = field(default_factory=dict, init=False, repr=False)

    def _count_call(self, answered: bool) -> None:
        phase = current_phase.get()
        if phase is None:
            return
        counts = self.phase_calls.setdefault(phase, {"ok": 0, "unanswered": 0})
        counts["ok" if answered else "unanswered"] += 1

    async def call_agent(
        self, payload: dict[str, Any], timeout_s: float | None = None,
    ) -> tuple[dict[str, Any], float]:
        """Invoke the agent — mocked offline, or live via the hardened client.

        v8: the live path now goes through ``LiveAgentClient``, which adds
        response normalization (any provider envelope -> canonical shape),
        budget enforcement, and 429-aware retry. The 17 phase modules are
        unchanged — they still just await ``ctx.call_agent``.
        """
        if timeout_s is None:
            timeout_s = self.manifest.runtime.timeout_s or 30.0
        if self.mock_tools:
            from agent_audit.mock_client import MockAgentClient
            if self._mock_client is None:
                self._mock_client = MockAgentClient(
                    self.manifest, self.inject_latency_ms, posture=self.mock_posture,
                )
            return await self._mock_client.invoke(payload, timeout_s)

        try:
            resp, latency = await self._call_live(payload, timeout_s)
        except Exception as exc:
            from agent_audit.findings import is_unreachable
            if is_unreachable(exc):
                self._count_call(False)
            raise
        self._count_call(not (isinstance(resp, dict) and resp.get("_blocked_403")))
        return resp, latency

    async def _call_live(self, payload: dict[str, Any], timeout_s: float) -> tuple[dict[str, Any], float]:
        if self._live_client is None:
            from agent_audit.live import CallBudget
            provider = getattr(self.manifest.runtime, "provider", None)
            provider_name = getattr(provider, "name", "generic") if provider else "generic"
            budget = self.budget or CallBudget()
            if provider_name == "agentforce":
                from agent_audit.live.agentforce_client import AgentforceClient
                self._live_client = AgentforceClient(
                    self.manifest, budget=budget, concurrency=self.concurrency,
                )
            elif provider_name == "uipath":
                from agent_audit.live.uipath_client import UiPathAgentClient
                self._live_client = UiPathAgentClient(
                    self.manifest, budget=budget, concurrency=self.concurrency,
                )
            elif provider_name == "automation_anywhere":
                from agent_audit.live.aa_client import AAAgentClient
                self._live_client = AAAgentClient(
                    self.manifest, budget=budget, concurrency=self.concurrency,
                )
            else:
                from agent_audit.live import LiveAgentClient
                self._live_client = LiveAgentClient(
                    self.manifest, budget=budget, concurrency=self.concurrency,
                )
        return await self._live_client.invoke(payload, timeout_s)

    async def aclose(self) -> None:
        """Release the live HTTP client's connection pool, if one was opened."""
        if self._live_client is not None:
            await self._live_client.aclose()
            self._live_client = None


# ── Phase registry ──────────────────────────────────────────────────────────
PHASE_MAP: dict[str, str] = {
    # ── v4/v5 phases (unchanged) ───────────────────────────────────────────
    "architecture":    "agent_audit.phases.phase1_architecture",
    "reliability":     "agent_audit.phases.phase2_reliability",
    "security":        "agent_audit.phases.phase3_security",
    "observability":   "agent_audit.phases.phase4_observability",
    "ops":             "agent_audit.phases.phase5_operations",
    "adversarial":     "agent_audit.phases.phase6_adversarial",
    "supply_chain":    "agent_audit.phases.phase7_supply_chain",
    "data_governance": "agent_audit.phases.phase8_data_governance",
    "groundedness":    "agent_audit.phases.phase9_groundedness",
    "fairness":        "agent_audit.phases.phase10_fairness",
    "multi_turn":      "agent_audit.phases.phase11_multi_turn",
    "mcp":             "agent_audit.phases.phase14_mcp",
    # ── v7 new phases ──────────────────────────────────────────────────────
    "voice":           "agent_audit.phases.phase15_voice",
    "data_analysis":   "agent_audit.phases.phase16_data_analysis",
    "decision":        "agent_audit.phases.phase17_decision",
    "security_agent":  "agent_audit.phases.phase18_security_agent",
    "browser":         "agent_audit.phases.phase19_browser",
    # ── v10.4 new phases ────────────────────────────────────────────────────
    "freshness":       "agent_audit.phases.phase20_freshness",
    "tool_use":        "agent_audit.phases.phase21_tool_use",
    "multi_agent":     "agent_audit.phases.phase22_multi_agent",
}

PHASE_LABELS: dict[str, str] = {
    "architecture":    "Phase 1  · Architecture",
    "reliability":     "Phase 2  · Reliability",
    "security":        "Phase 3  · Security",
    "observability":   "Phase 4  · Observability",
    "ops":             "Phase 5  · Operations",
    "adversarial":     "Phase 6  · Adversarial",
    "supply_chain":    "Phase 7  · Supply Chain",
    "data_governance": "Phase 8  · Data Governance",
    "groundedness":    "Phase 9  · Groundedness & Hallucination",
    "fairness":        "Phase 10 · Fairness & Bias",
    "multi_turn":      "Phase 11 · Multi-Turn Security",
    "mcp":             "Phase 14 · MCP Security",
    # v7
    "voice":           "Phase 15 · Voice Agent Safety  [v7]",
    "data_analysis":   "Phase 16 · Data Analysis Agent Safety  [v7]",
    "decision":        "Phase 17 · Decision Agent Safety  [v7]",
    "security_agent":  "Phase 18 · Security Agent Safety  [v7]",
    "browser":         "Phase 19 · Browser Agent Safety  [v7]",
    "freshness":       "Phase 20 · Real-Time Data & Freshness  [v10.4]",
    "tool_use":        "Phase 21 · Tool-Use Safety  [v10.4]",
    "multi_agent":     "Phase 22 · Multi-Agent System Safety  [v10.4]",
}

# NOTE: the parallel/sequential execution-order lists live in runner.py
# (the only place that actually reads them) — they used to be duplicated
# here too, but nothing imported this copy, and a divergence between the
# two would have been silent. Don't re-add them here; edit runner.py's
# _PARALLEL_PHASES / _SEQUENTIAL_PHASES instead.

__all__ = ["PHASE_LABELS", "PHASE_MAP", "PhaseContext"]
