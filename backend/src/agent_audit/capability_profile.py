"""Agent capability profile — what a target agent actually does.

Two ways a profile gets built:
  1. **Derived** — heuristics over the already-loaded `TargetManifest`
     (tool-name keyword matching, declared PII fields, HITL flag, provider
     name, golden dataset presence, ...).
  2. **Declared** — an explicit `capability_profile:` block in the target
     YAML (parsed by `YamlAdapter` into `TargetManifest.capability_profile_raw`).
     Declared fields always win over derived ones — a human/CI-declared fact
     about the agent is more trustworthy than a keyword-matching guess.

`select_phases()` turns a profile into the phase list `run_audit(phases="auto")`
should run, plus a one-line skip reason for every phase it omits — so a
report can honestly say *why* a phase didn't run instead of just not
mentioning it (see AuditReport.capability_profile / skipped_phases).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from agent_audit.manifest import TargetManifest

DataMode = Literal["static", "dynamic", "hybrid"]
RiskLevel = Literal["low", "medium", "high", "critical"]
IOType = Literal["text", "voice", "multimodal"]

# Archetype vocabulary (user-facing "what kind of agent is this"). An agent
# can hold more than one — e.g. a customer_service agent that also does
# tool_calling and rag.
ARCHETYPES: tuple[str, ...] = (
    "conversational", "rag", "tool_calling", "api_based", "workflow_automation",
    "browser_use", "mcp_based", "multi_agent", "planning_reasoning",
    "data_analysis", "customer_service", "financial_decision", "code_agent",
)


@dataclass(slots=True)
class AgentCapabilityProfile:
    """What a target agent does — declared or derived, drives phase selection."""

    archetypes: list[str] = field(default_factory=lambda: ["conversational"])
    io_type: IOType = "text"
    tools: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    browser_access: bool = False
    mcp_servers: list[str] = field(default_factory=list)
    has_memory: bool = False
    uses_rag: bool = False
    external_data_sources: list[str] = field(default_factory=list)
    data_mode: DataMode = "static"
    auth_required: bool = False
    user_roles: list[str] = field(default_factory=list)
    sensitive_data_handling: bool = False
    decision_making: bool = False
    requires_human_approval: bool = False
    expected_behavior: str = ""
    risk_level: RiskLevel = "low"
    is_multi_agent: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "archetypes": list(self.archetypes),
            "io_type": self.io_type,
            "tools": list(self.tools),
            "apis": list(self.apis),
            "browser_access": self.browser_access,
            "mcp_servers": list(self.mcp_servers),
            "has_memory": self.has_memory,
            "uses_rag": self.uses_rag,
            "external_data_sources": list(self.external_data_sources),
            "data_mode": self.data_mode,
            "auth_required": self.auth_required,
            "user_roles": list(self.user_roles),
            "sensitive_data_handling": self.sensitive_data_handling,
            "decision_making": self.decision_making,
            "requires_human_approval": self.requires_human_approval,
            "expected_behavior": self.expected_behavior,
            "risk_level": self.risk_level,
            "is_multi_agent": self.is_multi_agent,
        }


# ── heuristic keyword tables (tool-name substrings, lowercased) ─────────────
_BROWSER_HINTS = ("browser", "navigate", "click", "screenshot", "page_", "playwright", "selenium", "webdriver")
_VOICE_HINTS = ("voice", "asr", "tts", "ivr", "speech", "call_transfer", "dial")
_RAG_HINTS = ("search_kb", "retrieve", "rag", "knowledge", "vector_search", "semantic_search")
_DECISION_HINTS = ("approve", "decision", "underwrit", "credit_score", "risk_score", "eligib", "reject", "adjudicat")
_FINANCIAL_HINTS = ("payment", "loan", "credit", "transfer_funds", "invoice", "ledger", "allocation", "trading", "portfolio", "disburs")
_CODE_HINTS = ("code_exec", "compile", "run_shell", "git_", "deploy", "run_code", "execute_code")
_DATA_ANALYSIS_HINTS = ("query", "sql", "report", "analytics", "dashboard", "aggregate", "export_data")
_CUSTOMER_SERVICE_HINTS = ("ticket", "customer", "support", "billing", "order", "account_lookup", "refund")
_DYNAMIC_DATA_HINTS = (
    "live", "current", "status", "price", "rate", "lookup", "fetch", "realtime",
    "real_time", "quote", "balance", "inventory", "track",
)
_MULTI_AGENT_HINTS = ("handoff", "delegate", "sub_agent", "subagent", "orchestrat", "route_to")


def derive_profile(manifest: TargetManifest) -> AgentCapabilityProfile:
    """Heuristic profile from an already-loaded manifest. Explicit YAML
    overrides (manifest.capability_profile_raw) are applied on top."""
    tool_names = [t.name for t in manifest.capabilities.tools]
    joined = " ".join(t.lower() for t in tool_names)

    def _any(hints: tuple[str, ...]) -> bool:
        return any(h in joined for h in hints)

    archetypes: set[str] = set()
    if tool_names:
        archetypes.add("tool_calling")
    if manifest.golden_dataset is not None or _any(_RAG_HINTS):
        archetypes.add("rag")
    if _any(_BROWSER_HINTS):
        archetypes.add("browser_use")
    if "mcp" in manifest.runtime.provider.name.lower() or any("mcp" in t.lower() for t in tool_names):
        archetypes.add("mcp_based")
    if _any(_DECISION_HINTS):
        archetypes.add("planning_reasoning")
    if _any(_FINANCIAL_HINTS):
        archetypes.add("financial_decision")
    if _any(_CODE_HINTS):
        archetypes.add("code_agent")
    if _any(_DATA_ANALYSIS_HINTS):
        archetypes.add("data_analysis")
    if _any(_CUSTOMER_SERVICE_HINTS):
        archetypes.add("customer_service")
    if not tool_names and manifest.runtime.endpoint:
        archetypes.add("api_based")
    if not archetypes:
        archetypes.add("conversational")

    io_type: IOType = "voice" if _any(_VOICE_HINTS) else "text"
    decision_making = _any(_DECISION_HINTS) or "financial_decision" in archetypes
    sensitive = bool(manifest.security.pii_fields) or bool(manifest.security.data_classification)
    is_multi_agent = _any(_MULTI_AGENT_HINTS)

    data_mode: DataMode = "dynamic" if _any(_DYNAMIC_DATA_HINTS) else "static"
    if data_mode == "dynamic" and manifest.golden_dataset is not None:
        data_mode = "hybrid"  # both a live source and a static reference corpus

    risk_level: RiskLevel = "low"
    if "financial_decision" in archetypes:
        risk_level = "critical"
    elif manifest.capabilities.destructive_tool_names or decision_making:
        risk_level = "high"
    elif sensitive:
        risk_level = "medium"

    profile = AgentCapabilityProfile(
        archetypes=sorted(archetypes),
        io_type=io_type,
        tools=tool_names,
        browser_access="browser_use" in archetypes,
        mcp_servers=[t for t in tool_names if "mcp" in t.lower()],
        uses_rag="rag" in archetypes,
        data_mode=data_mode,
        auth_required=manifest.runtime.auth.type != "none",
        sensitive_data_handling=sensitive,
        decision_making=decision_making,
        requires_human_approval=manifest.capabilities.requires_hitl,
        risk_level=risk_level,
        is_multi_agent=is_multi_agent,
    )

    override = getattr(manifest, "capability_profile_raw", None) or {}
    for key, value in override.items():
        if hasattr(profile, key) and value is not None:
            setattr(profile, key, value)

    return profile


# ── phase relevance table ───────────────────────────────────────────────────
# Phases not listed here are considered universally applicable (they run for
# every agent regardless of profile) — that's the safe default: a phase is
# only ever skipped for an explicit, named reason below, never by omission.
def _phase_skip_reason(phase: str, p: AgentCapabilityProfile) -> str | None:
    if phase == "voice":
        if p.io_type != "voice":
            return "Agent has no voice/ASR/TTS capability declared or detected."
        return None
    if phase == "browser":
        if not p.browser_access:
            return "Agent has no browser-use tools declared or detected."
        return None
    if phase == "mcp":
        if not p.mcp_servers and "mcp_based" not in p.archetypes:
            return "Agent declares no MCP servers/tools."
        return None
    if phase == "data_analysis":
        if "data_analysis" not in p.archetypes:
            return "Agent has no data-analysis/query/reporting tools declared or detected."
        return None
    if phase == "decision":
        if not p.decision_making:
            return "Agent has no decision-making/underwriting/adjudication capability declared or detected."
        return None
    if phase == "security_agent":
        tools_joined = " ".join(p.tools).lower()
        soc_hint = any(kw in tools_joined for kw in ("security", "threat", "alert", "ioc", "incident", "soc_"))
        if not soc_hint:
            return "Agent shows no SOC/threat-intel/alert-handling tools — security_agent phase not applicable."
        return None
    if phase == "freshness":
        if p.data_mode == "static":
            return (
                "Agent's capability profile declares data_mode='static' — it has no "
                "live/dynamic data source, so real-time freshness checks don't apply. "
                "If this is wrong, set capability_profile.data_mode to 'dynamic' or "
                "'hybrid' in the target YAML."
            )
        return None
    if phase == "tool_use":
        if not p.tools:
            return "Agent declares no tools — there is no tool-calling behavior for this phase to check."
        return None
    if phase == "multi_agent":
        if not p.is_multi_agent:
            return (
                "Agent shows no delegation/handoff/sub-agent tools declared or detected "
                "— it does not appear to be a multi-agent/orchestrator system."
            )
        return None
    return None


def phase_skip_reason(phase: str, profile: AgentCapabilityProfile) -> str | None:
    """Why this phase does not apply to the agent, or None when it does."""
    return _phase_skip_reason(phase, profile)


def select_phases(profile: AgentCapabilityProfile) -> tuple[list[str], dict[str, str]]:
    """Capability-driven phase list. Returns (phases_to_run, {skipped_phase: reason})."""
    from agent_audit.phases import PHASE_MAP

    selected: list[str] = []
    skipped: dict[str, str] = {}
    for phase in PHASE_MAP:
        reason = _phase_skip_reason(phase, profile)
        if reason is None:
            selected.append(phase)
        else:
            skipped[phase] = reason
    return selected, skipped
