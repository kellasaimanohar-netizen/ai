"""Finding — the v4 structured replacement for v3's ``TestResult``.

Every field an enterprise auditor needs: stable ID, fingerprint, standards
mapping, evidence, remediation, reproducer, data classification, variability
metadata, suppression state.

Serialises cleanly to JSON and to SARIF 2.1.0.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from agent_audit.severity import Severity
from agent_audit.standards import StandardEntry, lookup


@dataclass(frozen=True, slots=True)
class StandardRef:
    """One standards-framework reference attached to a finding."""

    framework: str
    identifier: str
    name: str
    url: str

    @classmethod
    def from_registry(cls, framework: str, identifier: str) -> StandardRef:
        """Build a ref from the standards registry (validates existence)."""
        entry: StandardEntry = lookup(framework, identifier)
        return cls(entry.framework, entry.identifier, entry.name, entry.url)


EvidenceKind = Literal[
    "request",
    "response",
    "tool_call",
    "log",
    "source_excerpt",
    "trace",
    "config",
]


@dataclass(slots=True)
class Evidence:
    """A concrete artifact that supports a finding."""

    kind: EvidenceKind
    content: str
    redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ArtifactKind = Literal["source", "trace", "container", "k8s", "config", "endpoint"]


@dataclass(slots=True)
class ArtifactRef:
    """Points at the thing a finding is about."""

    kind: ArtifactKind
    path: str | None = None            # file path, URL, or ARN
    line: int | None = None            # source line (1-indexed)
    identifier: str | None = None      # trace-id, container digest, etc.

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(slots=True)
class Reproducer:
    """Everything needed to rerun a single check in isolation."""

    cmd: str
    env: dict[str, str] = field(default_factory=dict)
    seed: int | None = None
    expected_outcome: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, {}, [])}


@dataclass(slots=True)
class VariabilityMetadata:
    """Statistical metadata from multi-run probabilistic tests."""

    runs: int
    passes: int
    failures: int
    mean_score: float
    variance: float
    ci_lower: float
    ci_upper: float
    verdict: str  # ROBUST | STABLE | UNSTABLE | CRITICAL | HIGH_UNCERTAINTY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    """A single audit finding. The unit of report output."""

    # ─── identity ─────────────────────────────────────────────────────
    id: str                          # stable: e.g. "SEC-INJ-DIRECT-001"
    phase: str
    test_name: str

    # ─── classification ───────────────────────────────────────────────
    severity: Severity
    passed: bool
    confidence: float = 1.0          # 0..1

    # ─── human-readable ───────────────────────────────────────────────
    title: str = ""
    description: str = ""
    remediation: str = ""

    # ─── standards mapping ────────────────────────────────────────────
    standards: list[StandardRef] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)

    # ─── evidence & artifacts ─────────────────────────────────────────
    evidence: list[Evidence] = field(default_factory=list)
    artifact_refs: list[ArtifactRef] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # ─── reproduction & timing ────────────────────────────────────────
    reproducer: Reproducer | None = None
    duration_ms: float | None = None

    # ─── variability / governance ─────────────────────────────────────
    variability: VariabilityMetadata | None = None
    data_classification: list[str] = field(default_factory=list)

    # ─── suppression ──────────────────────────────────────────────────
    suppressed: bool = False
    suppression_reason: str | None = None

    @property
    def fingerprint(self) -> str:
        """Stable hash for suppression matching across runs."""
        parts = [self.id, self.test_name, self.phase]
        for ref in self.artifact_refs:
            parts.extend([ref.kind, ref.path or "", str(ref.line or "")])
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "phase": self.phase,
            "test_name": self.test_name,
            "severity": self.severity.value,
            "passed": self.passed,
            "confidence": round(self.confidence, 4),
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "standards": [asdict(s) for s in self.standards],
            "cwe": list(self.cwe),
            "mitre_atlas": list(self.mitre_atlas),
            "evidence": [e.to_dict() for e in self.evidence],
            "artifact_refs": [a.to_dict() for a in self.artifact_refs],
            "references": list(self.references),
            "reproducer": self.reproducer.to_dict() if self.reproducer else None,
            "duration_ms": self.duration_ms,
            "variability": self.variability.to_dict() if self.variability else None,
            "data_classification": list(self.data_classification),
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


def pass_finding(
    *,
    finding_id: str,
    phase: str,
    test_name: str,
    title: str,
    description: str = "",
    standards: list[StandardRef] | None = None,
    duration_ms: float | None = None,
) -> Finding:
    """Convenience constructor for a passing check."""
    return Finding(
        id=finding_id,
        phase=phase,
        test_name=test_name,
        severity=Severity.PASS,
        passed=True,
        title=title,
        description=description,
        standards=standards or [],
        duration_ms=duration_ms,
    )


def not_tested_finding(
    *,
    finding_id: str,
    phase: str,
    test_name: str,
    title: str,
    reason: str,
    remediation: str = "",
    duration_ms: float | None = None,
) -> Finding:
    """A check that could not observe the agent. Informational: it neither passes nor fails the agent and is left
    out of the trust score (descriptions starting with "Skipped:" are counted as skipped)."""
    return Finding(
        id=finding_id,
        phase=phase,
        test_name=test_name,
        severity=Severity.INFO,
        passed=False,
        title=title,
        description=f"Skipped: {reason}",
        remediation=remediation,
        duration_ms=duration_ms,
    )


# Errors that mean the request never got an answer from the agent (down, wrong address, refused connection),
# as opposed to the agent answering badly.
_UNREACHABLE_ERRORS = frozenset({
    "LiveCallError", "AgentforceError", "UiPathAgentError", "AAAgentError",
    "ConnectError", "ConnectTimeout", "NetworkError", "TransportError", "PoolTimeout", "ConnectionError",
})


def is_unreachable(exc: BaseException) -> bool:
    return any(c.__name__ in _UNREACHABLE_ERRORS for c in type(exc).__mro__)


def fail_finding(
    *,
    finding_id: str,
    phase: str,
    test_name: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    standards: list[StandardRef] | None = None,
    cwe: list[str] | None = None,
    mitre_atlas: list[str] | None = None,
    evidence: list[Evidence] | None = None,
    artifact_refs: list[ArtifactRef] | None = None,
    references: list[str] | None = None,
    confidence: float = 1.0,
    duration_ms: float | None = None,
    variability: VariabilityMetadata | None = None,
    data_classification: list[str] | None = None,
    reproducer: Reproducer | None = None,
) -> Finding:
    """Convenience constructor for a failing check."""
    return Finding(
        id=finding_id,
        phase=phase,
        test_name=test_name,
        severity=severity,
        passed=False,
        confidence=confidence,
        title=title,
        description=description,
        remediation=remediation,
        standards=standards or [],
        cwe=cwe or [],
        mitre_atlas=mitre_atlas or [],
        evidence=evidence or [],
        artifact_refs=artifact_refs or [],
        references=references or [],
        duration_ms=duration_ms,
        variability=variability,
        data_classification=data_classification or [],
        reproducer=reproducer,
    )
