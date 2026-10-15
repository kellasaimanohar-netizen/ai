"""Phase 7 — Supply chain (new in v4).

Static checks, no network calls. Operates on the manifest's discovered
dependencies and models.

  * dependency_inventory     — at least one dependency discovered
  * model_provenance         — models have a known provider
  * pinned_versions          — dependencies declare versions (not just names)

Standards: OWASP LLM03 (Supply Chain), ISO/IEC 42001 (supplier governance).
"""
from __future__ import annotations

import re
import time

from agent_audit.findings import Evidence, Finding, StandardRef, fail_finding, pass_finding
from agent_audit.phases import PhaseContext
from agent_audit.severity import Severity

PHASE = "supply_chain"

_LLM03 = StandardRef.from_registry("owasp_llm_2025", "LLM03")
_NIST_GV = StandardRef.from_registry("nist_ai_rmf_genai", "GV-1.1")

# Version strings that declare *something* but don't actually pin a concrete
# release — these must be treated the same as a missing version. Matched
# case-insensitively against the whole (stripped) version string.
_PLACEHOLDER_VERSIONS = {
    "latest", "*", "any", "stable", "master", "main", "head", "x", "unset", "none",
}
# Bare wildcard segments like "1.*", "1.0.*", "^0.0", or a lone range operator
# with no concrete number (">=", "~", "^") also don't pin a release.
_PLACEHOLDER_VERSION_PATTERN = re.compile(
    r"^[\^~]?\d*(\.(\d+|\*|x))*\.\*$|^[\^~>=<]+\s*$", re.IGNORECASE,
)


def _is_unpinned(version: str | None) -> bool:
    """True if `version` fails to pin a concrete release (missing or placeholder)."""
    if not version:
        return True
    v = version.strip()
    if not v:
        return True
    if v.lower() in _PLACEHOLDER_VERSIONS:
        return True
    if _PLACEHOLDER_VERSION_PATTERN.match(v):
        return True
    return False


async def run_phase(ctx: PhaseContext) -> list[Finding]:
    m = ctx.manifest
    out: list[Finding] = []

    # ── dependency_inventory ──────────────────────────────────────────
    t0 = time.perf_counter()
    if not m.dependencies:
        out.append(fail_finding(
            finding_id="SC-DEPS-001", phase=PHASE, test_name="dependency_inventory",
            severity=Severity.WARNING,
            title="No dependencies discovered",
            description="Either the agent has no dependencies (unlikely) or no RepoAdapter source was configured.",
            remediation="Add a 'repo' source to your target YAML so dependencies can be discovered from pyproject.toml / requirements.txt.",
            standards=[_LLM03],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        out.append(pass_finding(
            finding_id="SC-DEPS-001", phase=PHASE, test_name="dependency_inventory",
            title=f"{len(m.dependencies)} dependency/dependencies catalogued",
            description=", ".join(d.name for d in m.dependencies[:15]),
            standards=[_LLM03],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))

    # ── pinned_versions ───────────────────────────────────────────────
    t0 = time.perf_counter()
    unpinned = [d.name for d in m.dependencies if _is_unpinned(d.version)]
    if unpinned:
        out.append(fail_finding(
            finding_id="SC-PIN-001", phase=PHASE, test_name="pinned_versions",
            severity=Severity.WARNING,
            title=f"{len(unpinned)} dependency/dependencies have no version pin",
            description=f"Unpinned: {', '.join(unpinned[:10])}",
            remediation="Pin to a concrete version or range (e.g. 'httpx>=0.27,<1.0') to stabilise the supply chain.",
            standards=[_LLM03, _NIST_GV],
            evidence=[Evidence(kind="config", content=", ".join(unpinned))],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    elif m.dependencies:
        out.append(pass_finding(
            finding_id="SC-PIN-001", phase=PHASE, test_name="pinned_versions",
            title="All dependencies declare a version",
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))

    # ── model_provenance ──────────────────────────────────────────────
    t0 = time.perf_counter()
    if not m.models:
        out.append(fail_finding(
            finding_id="SC-MODEL-001", phase=PHASE, test_name="model_provenance",
            severity=Severity.INFO,
            title="No model references discovered",
            description="Add a 'repo' source or 'model_card' source to declare model provenance.",
            remediation="Declare models used (provider + model_id) for supply-chain attestation.",
            standards=[_LLM03],
            duration_ms=(time.perf_counter() - t0) * 1000,
        ))
    else:
        unknown = [mm for mm in m.models if mm.provider == "unknown"]
        if unknown:
            out.append(fail_finding(
                finding_id="SC-MODEL-001", phase=PHASE, test_name="model_provenance",
                severity=Severity.WARNING,
                title=f"{len(unknown)} model(s) have unknown provider",
                description=", ".join(mm.model_id for mm in unknown),
                remediation="Ensure model_id follows a provider-recognisable prefix (e.g. claude-..., gpt-..., gemini-...).",
                standards=[_LLM03],
                duration_ms=(time.perf_counter() - t0) * 1000,
            ))
        else:
            out.append(pass_finding(
                finding_id="SC-MODEL-001", phase=PHASE, test_name="model_provenance",
                title=f"All {len(m.models)} model reference(s) have known providers",
                description=", ".join(f"{mm.provider}/{mm.model_id}" for mm in m.models[:5]),
                standards=[_LLM03],
                duration_ms=(time.perf_counter() - t0) * 1000,
            ))

    return out
