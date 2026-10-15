"""Audit runner — orchestrates phases, custom checkers, and suppressions.

v4.1 fixes applied:
  Fix 4 — independent phases (architecture, observability, ops, supply_chain)
           run concurrently via asyncio.gather.
  Fix 4b — AuditReport now carries audit_id, total_duration_ms, and trust_score
           for richer reporting and consistent serialisation across exporters.
  Fix 4c — findings are sorted canonically (phase order → severity → id) so
           JSON/HTML reports are deterministic across runs.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import importlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from agent_audit.checkers import CheckerRegistry
from agent_audit.exceptions import PhaseError
from agent_audit.findings import Finding, is_unreachable
from agent_audit.manifest import TargetManifest
from agent_audit.phases import PHASE_LABELS, PHASE_MAP, PhaseContext, current_phase
from agent_audit.severity import Severity
from agent_audit.suppressions import SuppressionRegister

log = logging.getLogger(__name__)

# Canonical phase order for sorted output
_PHASE_ORDER = list(PHASE_MAP.keys())  # auto-includes v7 phases from updated PHASE_MAP

# Severity sort priority (lower = more important = shown first)
_SEVERITY_PRIORITY = {
    Severity.CRITICAL: 0,
    Severity.HIGH_UNCERTAINTY: 1,
    Severity.WARNING: 2,
    Severity.INFO: 3,
    Severity.PASS: 4,
}

# Phases with no inter-phase dependencies — safe to run concurrently
_PARALLEL_PHASES = frozenset({
    "architecture", "observability", "ops", "supply_chain",
    # v5 phases
    "data_governance", "fairness", "mcp",
    # v7 phases — all independent
    "voice", "data_analysis", "decision", "security_agent", "browser",
    # adversarial runs its own independent variability trials — it never
    # reads ctx.variability_store (only phase3_security writes to it, and
    # nothing reads it back), so the two don't need to be serialized.
    "adversarial",
    # v10.4 — independent freshness probes, no shared state with other phases.
    "freshness",
    # v10.4 — independent tool-use probes, no shared state with other phases.
    "tool_use",
    # v10.4 — independent multi-agent delegation probes.
    "multi_agent",
})

# Phases that must run in order
_SEQUENTIAL_PHASES = [
    "reliability", "security",
    "groundedness",  # reads golden_dataset, sequential for predictable eval order
    "multi_turn",    # depends on session state — sequential for clean isolation
]


@dataclass(slots=True)
class AuditReport:
    """Output of one audit run."""

    agent_name: str
    started_at: str
    audit_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    finished_at: str = ""
    total_duration_ms: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    manifest_summary: dict = field(default_factory=dict)
    mode: str = "validate"
    audit_version: str = "10.3.0"
    phases_run: list[str] = field(default_factory=list)
    # v8: live-run governance metadata (empty in mock mode)
    live_safety: dict = field(default_factory=dict)
    budget_usage: dict = field(default_factory=dict)
    audit_summary: dict = field(default_factory=dict)
    diagnostics: list[dict] = field(default_factory=list)
    skipped_phases: list[dict] = field(default_factory=list)
    capability_profile: dict = field(default_factory=dict)
    # v10.4: which environment the findings actually came from — "mock" when
    # mock_tools=True, else the detected/declared TargetEnv (sandbox/
    # development/staging/production/unknown). Consulted by certificate.py
    # so a mock-mode run can never be issued as if it were a live/staging
    # certification (see issue_certificate's framework_validation_only guard).
    test_environment: str = "unknown"
    dataset_used: str | None = None
    # Phases that could not observe the agent (unreachable, crashed, budget). They are not scored, and a live
    # report with any of these cannot be CERTIFIED.
    untested_phases: list[dict] = field(default_factory=list)
    # Live runs only: did the agent answer at least one request? None when no call was attempted (mock or static).
    agent_reached: bool | None = None

    @property
    def critical_failures(self) -> list[Finding]:
        return [f for f in self.findings
                if not f.passed and not f.suppressed and f.severity is Severity.CRITICAL]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings
                if not f.passed and not f.suppressed
                and f.severity in (Severity.WARNING, Severity.HIGH_UNCERTAINTY)]

    @property
    def passes(self) -> list[Finding]:
        return [f for f in self.findings if f.passed]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    # ── status-bucket counts (user-facing report shape) ─────────────────────
    @property
    def skip_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.severity is Severity.INFO and str(f.description).startswith("Skipped:")
        )

    @property
    def info_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.severity is Severity.INFO and not str(f.description).startswith("Skipped:")
        )

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if not f.passed and f.severity is not Severity.INFO)

    @property
    def enterprise_ready(self) -> bool:
        return not self.critical_failures

    @property
    def trust_score(self) -> int:
        """Consistent trust score used by both the cert and drift monitor."""
        executed_findings = [f for f in self.findings if f.severity is not Severity.INFO and not str(f.description).startswith("Skipped:")]
        total = len(executed_findings)
        if total == 0:
            return 0
        executed_passes = [f for f in executed_findings if f.passed]
        score = int(round((len(executed_passes) / total) * 100))
        score -= min(40, len(self.critical_failures) * 10)
        score -= min(20, len(self.warnings) * 2)
        return max(0, score)

    def sorted_findings(self) -> list[Finding]:
        """Findings in canonical order: phase → severity → id."""
        def _key(f: Finding) -> tuple:
            phase_idx = _PHASE_ORDER.index(f.phase) if f.phase in _PHASE_ORDER else 99
            sev_idx = _SEVERITY_PRIORITY.get(f.severity, 5)
            return (phase_idx, sev_idx, f.id)
        return sorted(self.findings, key=_key)


async def run_audit(
    manifest: TargetManifest,
    *,
    phases: list[str] | str | None = None,
    mode: str = "validate",
    mock_tools: bool = False,
    mock_posture: str = "secure",
    variability_runs: int = 5,
    concurrency: int = 4,
    inject_latency_ms: int = 0,
    checker_registry: CheckerRegistry | None = None,
    suppressions: SuppressionRegister | None = None,
    target_env: str | None = None,
    allow_destructive: bool = False,
    live_authorized: bool = False,
    max_calls: int = 5_000,
    max_cost_usd: float = 25.0,
    skip_inapplicable: bool = False,
) -> AuditReport:
    """Run every requested phase; apply custom checkers; apply suppressions.

    v8: when running live (not ``mock_tools``), a shared ``CallBudget`` caps
    total calls/spend and a ``SafetyGate`` blocks destructive phases against a
    non-sandbox endpoint.
    """
    t0 = time.monotonic()
    report = AuditReport(
        agent_name=manifest.agent_name,
        started_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        manifest_summary=manifest.to_dict(),
        mode=mode,
    )

    if phases == "auto":
        from agent_audit.capability_profile import derive_profile, select_phases

        profile = derive_profile(manifest)
        phases_to_run, capability_skips = select_phases(profile)
        report.capability_profile = profile.to_dict()
        for phase_key, reason in capability_skips.items():
            report.skipped_phases.append({
                "phase": phase_key,
                "reason": reason,
                "remediation": (
                    f"Not run — {reason} If this is wrong, declare it explicitly in the "
                    f"target YAML's capability_profile: block, or pass phases=[...] to force it."
                ),
            })
    else:
        phases_to_run = phases or list(PHASE_MAP.keys())
        if skip_inapplicable:
            # Chosen phases that do not fit this kind of agent (a browser phase for a chat agent) are not run,
            # so the agent is never failed on behaviour it does not have. Each one is listed with its reason.
            from agent_audit.capability_profile import derive_profile, phase_skip_reason

            profile = derive_profile(manifest)
            report.capability_profile = profile.to_dict()
            kept = []
            for phase_key in phases_to_run:
                reason = phase_skip_reason(phase_key, profile)
                if reason is None:
                    kept.append(phase_key)
                else:
                    report.skipped_phases.append({
                        "phase": phase_key,
                        "reason": f"Not applicable: {reason}",
                        "remediation": "If the agent does have this capability, declare it in the target YAML's "
                                       "capability_profile: block and run the audit again.",
                    })
            phases_to_run = kept
    report.phases_run = phases_to_run

    # ── v8: live-safety scaffolding ─────────────────────────────────────────
    from agent_audit.live import CallBudget, SafetyGate, TargetEnv
    from agent_audit.live.budget import BudgetExceededError
    from agent_audit.live.safety import SandboxViolationError

    live = not mock_tools
    budget = CallBudget(max_calls=max_calls, max_cost_usd=max_cost_usd) if live else None
    gate = SafetyGate(
        env=TargetEnv.parse(target_env or manifest.runtime.target_env, manifest.runtime.endpoint),
        live=live,
        allow_destructive_override=allow_destructive,
        live_authorized=live_authorized,
    )
    report.live_safety = gate.summary()

    ctx = PhaseContext(
        manifest=manifest,
        mock_tools=mock_tools,
        mock_posture=mock_posture,
        inject_latency_ms=inject_latency_ms,
        concurrency=concurrency,
        variability_runs=variability_runs,
        budget=budget,
    )

    async def _run_one_phase(phase_key: str) -> list[Finding]:
        if phase_key not in PHASE_MAP:
            log.warning("unknown phase: %s", phase_key)
            return []
        label = PHASE_LABELS.get(phase_key, phase_key)
        # v8: refuse destructive phases against a non-sandbox live endpoint.
        try:
            gate.authorize(phase_key)
        except SandboxViolationError as exc:
            log.warning("safety gate blocked %s: %s", phase_key, exc)
            if gate.env == TargetEnv.PRODUCTION and not gate.live_authorized:
                cmd_suggestion = "run_audit(..., live_authorized=True) — only with explicit authorization"
            else:
                cmd_suggestion = "agy run <target> --target-env sandbox"
                if gate.env == TargetEnv.STAGING:
                    cmd_suggestion += " --allow-destructive"

            reason_str = str(exc)
            report.skipped_phases.append({
                "phase": phase_key,
                "reason": reason_str,
                "remediation": f"Run with: {cmd_suggestion}"
            })
            # Our own safety rule kept this phase from running; it says nothing about the agent, so it is not scored,
            # but the report cannot be CERTIFIED with a phase left untested.
            report.untested_phases.append({"phase": phase_key, "reason": f"Skipped by the safety gate: {reason_str}"})
            return [Finding(
                id=f"SAFETY-BLOCK-{phase_key.upper()}",
                phase=phase_key, test_name="safety_gate",
                severity=Severity.INFO, passed=False,
                title=f"Phase {phase_key} not tested — unsafe against {gate.env.value} endpoint",
                description=f"Skipped: {reason_str} To execute this phase, run: `{cmd_suggestion}`",
                remediation=f"Configure target environment to sandbox/development, or use: `{cmd_suggestion}`",
            )]
        log.info("starting %s", label)
        t_phase = time.monotonic()
        current_phase.set(phase_key)
        try:
            module = importlib.import_module(PHASE_MAP[phase_key])
            runner_fn = getattr(module, "run_phase", None)
            if runner_fn is None:
                raise PhaseError(f"phase module {phase_key!r} has no run_phase()")
            result = runner_fn(ctx)
            findings = await result if asyncio.iscoroutine(result) else result
            elapsed = (time.monotonic() - t_phase) * 1000
            log.info("completed %s — %d finding(s) in %.0fms", label, len(findings), elapsed)
            return _judge_by_answers(phase_key, findings, ctx.phase_calls.get(phase_key), report) if live else findings
        except BudgetExceededError as exc:
            # Cost/call ceiling hit — the rest of the phase never reached the agent, so it is not tested.
            log.warning("budget exceeded during %s: %s", phase_key, exc)
            report.untested_phases.append({"phase": phase_key, "reason": f"Audit call/spend budget exceeded: {exc}"})
            return [Finding(
                id=f"BUDGET-STOP-{phase_key.upper()}",
                phase=phase_key, test_name="call_budget",
                severity=Severity.INFO, passed=False,
                title=f"Phase {phase_key} not tested — audit call/spend budget exceeded",
                description=f"Skipped: {exc}",
                remediation="Raise --max-calls / --max-cost-usd, or lower --variability-runs.",
            )]
        except Exception as exc:
            # A phase that crashed or could not reach the agent says nothing about the agent's behaviour:
            # it is reported as not tested, never as a pass or a failure of the agent.
            unreachable = is_unreachable(exc)
            if unreachable:
                log.warning("phase %s could not reach the agent: %s", phase_key, exc)
                reason = "the agent could not be reached"
                fix = "Check runtime.endpoint, that the agent is running, and its login settings, then run the audit again."
            else:
                log.exception("phase %s failed: %s", phase_key, exc)
                reason = "the check itself failed (an audit-engine error, not the agent's behaviour)"
                fix = "Check the server logs and run the audit again."
            report.untested_phases.append({"phase": phase_key, "reason": f"{reason}: {exc}", "unreachable": unreachable})
            return [Finding(
                id=f"PHASE-ERR-{phase_key.upper()}",
                phase=phase_key, test_name="phase_execution",
                severity=Severity.INFO, passed=False,
                title=f"Phase {phase_key} not tested — {reason}",
                description=f"Skipped: {exc}",
                remediation=fix,
            )]

    # Independent phases run concurrently; sequential phases run in dependency order
    parallel_keys = [k for k in phases_to_run if k in _PARALLEL_PHASES]
    sequential_keys = [k for k in phases_to_run if k not in _PARALLEL_PHASES]

    if parallel_keys:
        log.info(
            "running %d independent phases concurrently: %s",
            len(parallel_keys), ", ".join(parallel_keys),
        )
        for findings in await asyncio.gather(*[_run_one_phase(k) for k in parallel_keys]):
            report.findings.extend(findings)

    for phase_key in sequential_keys:
        report.findings.extend(await _run_one_phase(phase_key))

    # Custom checkers
    if checker_registry is not None and len(checker_registry) > 0:
        log.info("running %d custom checker(s)", len(checker_registry))
        custom = _run_custom_checkers(checker_registry, manifest, report.findings)
        report.findings.extend(custom)

    # If there is no repo source, we are performing an OpenAPI-only or URL-only scan.
    # We automatically ignore/pass static file-based check findings since they cannot be tested.
    has_repo_source = any(k.startswith("repo") for k in manifest.provenance_trail.keys())
    if not has_repo_source:
        file_based_check_ids = {
            "SC-DEPS-001",
            "SC-PIN-001",
            "SC-MODEL-001",
            "ARCH-PROMPT-001",
            "OBS-LOGS-001",
            "OBS-TRACE-001",
            "OPS-RUNBOOK-001",
            "MCP-SERVER-001"
        }
        filtered = []
        for f in report.findings:
            if (f.id in file_based_check_ids or f.phase in ("supply_chain", "ops", "observability", "mcp")) and not f.passed:
                f.passed = False
                f.severity = Severity.INFO
                f.description = f"Skipped: {f.description} (Target has no repository source for static file analysis)"
                f.remediation = "Repository source required for static file analysis checks."
            filtered.append(f)
        report.findings = filtered

    # Passes that only repeat what the target file declares (a tool list, a policy flag) are not evidence of
    # behaviour. They are kept as information but do not raise the score. Their failures still count.
    for f in report.findings:
        if f.passed and f.id in DECLARATION_ONLY_CHECKS:
            f.passed = False
            f.severity = Severity.INFO
            f.title = f"Declared (not tested): {f.title}"
            if not f.description:
                f.description = "Taken from the target's own declaration; the agent was not tested for this."

    # Suppressions
    if suppressions is not None:
        report.findings = suppressions.apply(report.findings)

    # v8: record budget usage and release the live HTTP connection pool.
    if budget is not None:
        report.budget_usage = budget.snapshot()

    if ctx._live_client is not None:
        client_stats = getattr(ctx._live_client, "stats", {})
        report.audit_summary = {
            "total_endpoints_tested": client_stats.get("total_endpoints_tested", 0),
            "successful_requests": client_stats.get("successful_requests", 0),
            "failed_requests": client_stats.get("failed_requests", 0),
            "retry_attempts": client_stats.get("retry_attempts", 0),
            "endpoints_returning_405": list(client_stats.get("endpoints_returning_405", [])),
            "endpoints_skipped": [item["phase"] for item in report.skipped_phases],
            "root_cause_analysis": client_stats.get("root_cause_analysis", ""),
            "recommended_fixes": list(client_stats.get("recommended_fixes", [])),
        }
        report.diagnostics = list(client_stats.get("diagnostics", []))
        if "successful_requests" in client_stats:
            report.agent_reached = client_stats.get("successful_requests", 0) > 0
            if not report.agent_reached and not report.audit_summary["root_cause_analysis"]:
                blocked = client_stats.get("blocked_403", 0)
                report.audit_summary["root_cause_analysis"] = (
                    f"Every request was refused with HTTP 403 ({blocked}), so the agent's own answers were never seen."
                    if blocked else "The agent did not answer any request."
                )
    else:
        report.audit_summary = {
            "total_endpoints_tested": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retry_attempts": 0,
            "endpoints_returning_405": [],
            "endpoints_skipped": [item["phase"] for item in report.skipped_phases],
            "root_cause_analysis": ("Mock mode enabled. No live calls made." if mock_tools
                                    else "No calls were made to the agent; only checks that read files and declarations ran."),
            "recommended_fixes": [],
        }
        report.diagnostics = []

    # No live client could even be set up (for example no endpoint) but phases tried to call the agent
    if live and report.agent_reached is None and any(p.get("unreachable") for p in report.untested_phases):
        report.agent_reached = False
        report.audit_summary["root_cause_analysis"] = "The agent could not be reached: " + next(
            p["reason"] for p in report.untested_phases if p.get("unreachable"))

    await ctx.aclose()

    report.test_environment = "mock" if mock_tools else gate.env.value
    report.dataset_used = str(manifest.golden_dataset.path) if manifest.golden_dataset else None

    report.total_duration_ms = (time.monotonic() - t0) * 1000
    report.finished_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    log.info(
        "audit complete — %d findings (%d critical, %d warnings, %d passed) in %.0fms",
        len(report.findings),
        len(report.critical_failures),
        len(report.warnings),
        len(report.passes),
        report.total_duration_ms,
    )
    return report


def _judge_by_answers(phase_key: str, findings: list[Finding], calls: dict | None, report: AuditReport) -> list[Finding]:
    """A live phase is only as good as the answers it got. If the agent answered none of its requests, its checks
    graded empty answers, so the phase is reported as not tested. If only some were answered, the results are kept,
    flagged, and the phase counts as not fully tested (which keeps the report from CERTIFIED)."""
    if not calls or not calls.get("unanswered"):
        return findings
    total = calls["ok"] + calls["unanswered"]
    if not calls["ok"]:
        report.untested_phases.append({"phase": phase_key, "unreachable": True,
                                       "reason": f"the agent answered none of the phase's {total} request(s)"})
        return [Finding(
            id=f"PHASE-NOANSWER-{phase_key.upper()}", phase=phase_key, test_name="phase_execution",
            severity=Severity.INFO, passed=False,
            title=f"Phase {phase_key} not tested — the agent did not answer",
            description=(f"Skipped: none of the {total} request(s) in this phase got an answer from the agent "
                         "(unreachable, or refused with HTTP 403 before reaching it), so its checks were not scored."),
            remediation="Check runtime.endpoint, that the agent is running, and its login settings, then run the audit again.",
        )]
    report.untested_phases.append({"phase": phase_key, "partial": True,
                                   "reason": f"{calls['unanswered']} of {total} request(s) got no answer from the agent"})
    return findings + [Finding(
        id=f"PHASE-PARTIAL-{phase_key.upper()}", phase=phase_key, test_name="phase_execution",
        severity=Severity.INFO, passed=False,
        title=f"Phase {phase_key} only partly tested — {calls['unanswered']} of {total} request(s) got no answer",
        description="Checks that relied on the unanswered requests may be incomplete.",
        remediation="Check that the agent is stable and reachable, then run the audit again.",
    )]


# Checks whose PASS only restates the target file's declarations (see the loop in run_audit).
DECLARATION_ONLY_CHECKS = frozenset({
    "ARCH-TOOL-001", "ARCH-CTX-001", "ARCH-HANDOFF-001", "ARCH-HITL-001",
    "OPS-CANARY-001",
    "DG-CONSENT-001", "DG-RETENTION-001", "DG-ERASURE-001", "DG-XBORDER-001",
    "MCP-SCOPE-000", "MCP-SQUAT-001", "MCP-DESCINJEC-001", "MCP-SCOPE-001", "MCP-UNDECL-001",
    "VOICE-CONSENT-001", "SECAGENT-HITL-001",
})


def _run_custom_checkers(
    registry: CheckerRegistry, manifest: TargetManifest, existing: list[Finding],
) -> list[Finding]:
    """Apply custom checkers to evidence harvested from built-in findings."""
    from agent_audit.checkers.base import CheckContext

    extra: list[Finding] = []

    for checker in registry.checkers_for("manifest"):
        ctx = CheckContext(
            manifest=manifest, artifact_kind="manifest",
            content=str(manifest.to_dict()),
        )
        f = checker.check(ctx)
        if f is not None:
            extra.append(f)

    for prompt in manifest.prompts:
        for checker in registry.checkers_for("prompt"):
            ctx = CheckContext(
                manifest=manifest, artifact_kind="prompt",
                content=prompt.content, artifact_path=prompt.source_location,
            )
            f = checker.check(ctx)
            if f is not None:
                extra.append(f)

    for finding in existing:
        for ev in finding.evidence:
            kinds_map = {"response": "response", "tool_call": "tool_args"}
            target_kind = kinds_map.get(ev.kind)
            if not target_kind:
                continue
            for checker in registry.checkers_for(target_kind):  # type: ignore[arg-type]
                ctx = CheckContext(
                    manifest=manifest, artifact_kind=target_kind,  # type: ignore[arg-type]
                    content=ev.content,
                )
                f = checker.check(ctx)
                if f is not None:
                    extra.append(f)

    return extra


def run_audit_sync(
    manifest: TargetManifest,
    *,
    target_dir: Path | None = None,
    **kwargs,
) -> AuditReport:
    """Sync wrapper over ``run_audit`` for CLI / scripts."""
    return asyncio.run(run_audit(manifest, **kwargs))
