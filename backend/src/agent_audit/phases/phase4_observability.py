"""Phase 4 — Observability.

  * trace_completeness — every response carries a trace_id
  * latency_slo        — p95 under declared SLO
  * cost_tracking      — cost_usd present and below per-task budget
"""
from __future__ import annotations

import statistics
import time

from agent_audit.findings import Evidence, Finding, StandardRef, fail_finding, pass_finding
from agent_audit.phases import PhaseContext
from agent_audit.severity import Severity

PHASE = "observability"

_AG08 = StandardRef.from_registry("owasp_agentic_2025", "AG08")   # Repudiation / untraceability
_EUAI_12 = StandardRef.from_registry("eu_ai_act", "Art.12")       # Record keeping
_MG41 = StandardRef.from_registry("nist_ai_rmf_genai", "MG-4.1")  # Post-deployment monitoring


async def run_phase(ctx: PhaseContext) -> list[Finding]:
    out: list[Finding] = []

    # Sample N calls to build a latency / cost distribution
    samples = max(5, ctx.variability_runs)
    latencies: list[float] = []
    costs: list[float] = []
    trace_ids: set[str] = set()

    for i in range(samples):
        resp, latency_ms = await ctx.call_agent({
            "input": f"ping {i}", "_mock_scenario": "trace_probe",
        })
        latencies.append(latency_ms)
        cost = resp.get("cost_usd")
        if isinstance(cost, (int, float)):
            costs.append(float(cost))
        tid = resp.get("trace_id")
        if tid:
            trace_ids.add(str(tid))

    # ── trace completeness ─────────────────────────────────────────────
    t0 = time.perf_counter()
    if len(trace_ids) < samples:
        missing = samples - len(trace_ids)
        out.append(fail_finding(
            finding_id="OBS-TRACE-001", phase=PHASE, test_name="trace_completeness",
            severity=Severity.CRITICAL,
            title=f"Missing trace_id on {missing}/{samples} calls",
            description="Every response must carry a unique trace_id for audit-log linkage.",
            remediation="Generate a UUID trace_id at request boundary; include in every response and log line.",
            standards=[_AG08, _EUAI_12, _MG41],
            cwe=["CWE-532"],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        out.append(pass_finding(
            finding_id="OBS-TRACE-001", phase=PHASE, test_name="trace_completeness",
            title=f"All {samples} calls carried distinct trace_ids",
            standards=[_AG08],
        ))

    # ── latency SLO ────────────────────────────────────────────────────
    t0 = time.perf_counter()
    latencies_sorted = sorted(latencies)
    p95_index = max(0, int(0.95 * len(latencies_sorted)) - 1)
    p95 = latencies_sorted[p95_index]
    slo = ctx.manifest.slos.p95_latency_ms
    if p95 > slo:
        out.append(fail_finding(
            finding_id="OBS-LATENCY-001", phase=PHASE, test_name="latency_slo",
            severity=Severity.WARNING,
            title=f"p95 latency {p95:.0f}ms exceeds SLO {slo}ms",
            description=f"p50={statistics.median(latencies):.0f}ms, p95={p95:.0f}ms, max={max(latencies):.0f}ms over {samples} samples.",
            remediation="Add a caching layer, smaller model for planning, or raise the SLO if the workload genuinely requires it.",
            standards=[_MG41],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        out.append(pass_finding(
            finding_id="OBS-LATENCY-001", phase=PHASE, test_name="latency_slo",
            title=f"p95 latency {p95:.0f}ms within SLO {slo}ms",
        ))

    # ── cost tracking ──────────────────────────────────────────────────
    t0 = time.perf_counter()
    if not costs:
        out.append(fail_finding(
            finding_id="OBS-COST-001", phase=PHASE, test_name="cost_tracking",
            severity=Severity.WARNING,
            title="Responses did not report cost_usd",
            description="Cost tracking requires every response to include cost_usd.",
            remediation="Instrument the agent to emit per-call token usage and convert to USD.",
            standards=[_MG41],
        ))
    else:
        budget = ctx.manifest.slos.max_cost_per_task_usd
        max_cost = max(costs)
        if max_cost > budget:
            out.append(fail_finding(
                finding_id="OBS-COST-001", phase=PHASE, test_name="cost_tracking",
                severity=Severity.WARNING,
                title=f"Max cost ${max_cost:.4f} exceeds budget ${budget:.4f}",
                description=f"Costs observed: min=${min(costs):.4f} max=${max_cost:.4f}",
                remediation="Apply a budget enforcer that halts when per-task cost exceeds the SLO.",
                standards=[StandardRef.from_registry("owasp_llm_2025", "LLM10")],
                evidence=[Evidence(kind="log", content=f"costs={costs}")],
            ))
        else:
            out.append(pass_finding(
                finding_id="OBS-COST-001", phase=PHASE, test_name="cost_tracking",
                title=f"Cost within budget (max=${max_cost:.4f}, budget=${budget:.4f})",
            ))
    return out
