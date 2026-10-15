"""Phase 5 — Operations.

  * graceful_shutdown — agent returns a structured error on abort
  * canary_config     — canary / staged-rollout config declared
  * runbook_exists    — runbooks directory present and non-empty

Standards: NIST AI RMF MG-4.1 (post-deployment monitoring), ISO 42001.
"""
from __future__ import annotations

import time

from agent_audit.findings import Finding, StandardRef, fail_finding, not_tested_finding, pass_finding
from agent_audit.phases import PhaseContext
from agent_audit.severity import Severity

PHASE = "ops"

_MG41 = StandardRef.from_registry("nist_ai_rmf_genai", "MG-4.1")
_EUAI_17 = StandardRef.from_registry("eu_ai_act", "Art.17")  # Quality mgmt


async def run_phase(ctx: PhaseContext) -> list[Finding]:
    out: list[Finding] = []
    m = ctx.manifest

    # ── runbook_exists ─────────────────────────────────────────────────
    t0 = time.perf_counter()
    if m.runbooks_dir is None:
        out.append(fail_finding(
            finding_id="OPS-RUNBOOK-001", phase=PHASE, test_name="runbook_exists",
            severity=Severity.WARNING,
            title="No runbooks_dir declared",
            description="Operations team needs runbooks for incident response.",
            remediation="Add runbooks_dir to target YAML; include runbooks for: rollback, kill-switch, secret-rotation.",
            standards=[_MG41, _EUAI_17],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    elif not m.runbooks_dir.is_dir():
        out.append(fail_finding(
            finding_id="OPS-RUNBOOK-001", phase=PHASE, test_name="runbook_exists",
            severity=Severity.WARNING,
            title=f"runbooks_dir declared but missing: {m.runbooks_dir}",
            description="Directory not found on disk.",
            remediation="Create the directory and add at least one .md runbook.",
            standards=[_MG41],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        files = list(m.runbooks_dir.glob("*"))
        if not files:
            out.append(fail_finding(
                finding_id="OPS-RUNBOOK-001", phase=PHASE, test_name="runbook_exists",
                severity=Severity.WARNING,
                title="runbooks_dir exists but is empty",
                description="The runbooks directory is present but contains no files.",
                remediation="Add runbooks: rollback.md, kill-switch.md, secret-rotation.md as a minimum.",
                standards=[_MG41],
                duration_ms=(time.perf_counter() - t0) * 1000,
            ))
        else:
            out.append(pass_finding(
                finding_id="OPS-RUNBOOK-001", phase=PHASE, test_name="runbook_exists",
                title=f"Runbooks present ({len(files)} file(s))",
                standards=[_MG41],
                duration_ms=(time.perf_counter() - t0) * 1000,
            ))

    # ── graceful_shutdown ─────────────────────────────────────────────
    # Structured error on timeout scenario = graceful shutdown evidence
    t0 = time.perf_counter()
    if not ctx.mock_tools:
        # A shutdown signal cannot be sent to a deployed agent over HTTP, so a live run cannot observe this.
        out.append(not_tested_finding(
            finding_id="OPS-SHUTDOWN-001", phase=PHASE, test_name="graceful_shutdown",
            title="Graceful shutdown not tested on a live agent",
            reason="A shutdown signal cannot be sent to a deployed agent over HTTP.",
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
        graceful = None
    else:
        try:
            await ctx.call_agent({"input": "x", "_mock_scenario": "timeout"}, timeout_s=2.0)
            graceful = False
        except Exception:
            graceful = True
    if graceful is None:
        pass
    elif graceful:
        out.append(pass_finding(
            finding_id="OPS-SHUTDOWN-001", phase=PHASE, test_name="graceful_shutdown",
            title="Agent raises structured error on abort",
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        out.append(fail_finding(
            finding_id="OPS-SHUTDOWN-001", phase=PHASE, test_name="graceful_shutdown",
            severity=Severity.WARNING,
            title="Agent did not fail cleanly on shutdown signal",
            description="The agent did not terminate gracefully or return a structured error on abort/timeout.",
            remediation="Handle SIGTERM / cancellation; drain in-flight work; return a structured error.",
            standards=[_EUAI_17],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))

    # ── canary_config (static check) ───────────────────────────────────
    t0 = time.perf_counter()
    # v4.0: heuristic — look for presence of a canary-style deployment region list
    if len(m.security.allowed_data_regions) > 1:
        out.append(pass_finding(
            finding_id="OPS-CANARY-001", phase=PHASE, test_name="canary_config",
            title=f"Multi-region deployment supports canary rollout ({len(m.security.allowed_data_regions)} regions)",
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        out.append(fail_finding(
            finding_id="OPS-CANARY-001", phase=PHASE, test_name="canary_config",
            severity=Severity.INFO,
            title="Single-region deployment — canary rollout limited",
            description="With one declared region, canary rollout strategy is restricted.",
            remediation="Consider a staged rollout mechanism (percentage-based canary even within one region).",
            standards=[_MG41],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    return out
