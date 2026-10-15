"""TargetManifest — the unified view of an audit target.

Every source adapter emits a ``TargetManifest``. Every phase consumes a
``TargetManifest``. Adding a new source type means writing one adapter,
not editing six phase modules.

Each field tracks **provenance** — which source provided which fact, with
what confidence. Multi-source fusion reconciles conflicts using this data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


ProvenanceSource = Literal[
    "yaml",
    "openapi",
    "repo",
    "notebook",
    "mcp",
    "openai_assistants",
    "bedrock_agent",
    "container",
    "k8s",
    "terraform",
    "model_card",
    "traces",
    "sbom",
    "default",
]


@dataclass(slots=True)
class Provenance:
    """Where a fact came from and how confident we are in it."""

    source: ProvenanceSource
    confidence: float = 1.0
    location: str | None = None   # file path, URL, section — for traceability


@dataclass(slots=True)
class Fact:
    """A single value plus its provenance. Enables fusion + audit trail."""

    value: Any
    provenance: Provenance

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.provenance.source,
            "confidence": self.provenance.confidence,
            "location": self.provenance.location,
        }


# ─── Sub-structures ──────────────────────────────────────────────────────
_SECRET_WORDS = ("secret", "password", "passwd", "token", "apikey", "api_key", "private_key", "credential")


def _without_literal_secrets(config: dict[str, Any]) -> dict[str, Any]:
    """Provider settings safe to store: env var names (keys ending in _env) and non-secret values."""
    out: dict[str, Any] = {}
    for k, v in (config or {}).items():
        key = str(k).lower()
        if key.endswith("_env") or not any(w in key for w in _SECRET_WORDS):
            out[k] = v
    return out


@dataclass(slots=True)
class AuthSpec:
    """How to authenticate to the agent."""

    type: str = "none"                  # bearer | api_key | basic | none
    token_env: str | None = None
    header_name: str = "Authorization"


@dataclass(slots=True)
class ProviderSpec:
    """Provider-specific runtime configuration.

    ``name`` selects a specialised live client (e.g. ``agentforce``). When
    ``name`` is ``"generic"`` (the default), the standard ``LiveAgentClient``
    HTTP path is used and this block is ignored. ``config`` carries arbitrary
    provider settings; secrets are always env-var *names*, never literals.
    """

    name: str = "generic"               # generic | agentforce | bedrock | ...
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimeSpec:
    """Where the live agent is and how to reach it."""

    endpoint: str | None = None
    protocol: str = "http"              # http | grpc | sse | websocket
    auth: AuthSpec = field(default_factory=AuthSpec)
    timeout_s: float = 30.0
    provider: ProviderSpec = field(default_factory=ProviderSpec)
    target_env: str | None = None


@dataclass(slots=True)
class ToolSpec:
    """A single tool exposed by the agent."""

    name: str
    destructive: bool = False
    declared_in: list[str] = field(default_factory=list)   # source labels
    source_location: str | None = None                      # file:line


@dataclass(slots=True)
class PromptSpec:
    """A prompt template discovered in the target."""

    name: str
    content: str
    source_location: str | None = None
    role: str = "system"                 # system | user | assistant


@dataclass(slots=True)
class ModelSpec:
    """A model the agent calls."""

    provider: str                        # anthropic | openai | bedrock | ...
    model_id: str
    source_location: str | None = None


@dataclass(slots=True)
class DependencySpec:
    """One dependency from the target's package manifest."""

    name: str
    version: str | None = None
    source: str = "unknown"              # pypi | npm | github | ...


@dataclass(slots=True)
class CapabilitiesSpec:
    """Declared agent capabilities and limits."""

    max_steps: int = 25
    context_budget_tokens: int | None = None
    tools: list[ToolSpec] = field(default_factory=list)
    destructive_tool_names: list[str] = field(default_factory=list)
    requires_hitl: bool = False


@dataclass(slots=True)
class SLOSpec:
    """Service-level objectives."""

    p95_latency_ms: int = 10_000
    max_cost_per_task_usd: float = 0.10


@dataclass(slots=True)
class SecuritySpec:
    """Security and data-governance declarations."""

    pii_fields: list[str] = field(default_factory=list)
    allowed_data_regions: list[str] = field(default_factory=list)
    data_classification: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GoldenDatasetSpec:
    """Pointer to an eval dataset."""

    path: Path
    format: str = "jsonl"
    input_field: str = "input"
    expected_field: str = "expected"


# ─── The manifest itself ────────────────────────────────────────────────
@dataclass(slots=True)
class TargetManifest:
    """Everything phases need to know about the audit target."""

    agent_name: str
    version: str = "v4"

    runtime: RuntimeSpec = field(default_factory=RuntimeSpec)
    capabilities: CapabilitiesSpec = field(default_factory=CapabilitiesSpec)
    slos: SLOSpec = field(default_factory=SLOSpec)
    security: SecuritySpec = field(default_factory=SecuritySpec)
    openapi_spec: dict[str, Any] = field(default_factory=dict)

    # Artifacts discovered from various sources
    prompts: list[PromptSpec] = field(default_factory=list)
    models: list[ModelSpec] = field(default_factory=list)
    dependencies: list[DependencySpec] = field(default_factory=list)

    runbooks_dir: Path | None = None
    golden_dataset: GoldenDatasetSpec | None = None

    # Frameworks to emit in standards-coverage output
    compliance_frameworks: list[str] = field(default_factory=list)

    # Explicit capability_profile: YAML block (raw dict, field-name -> value)
    # — each present field overrides the heuristically-derived
    # AgentCapabilityProfile field of the same name. See
    # agent_audit.capability_profile.derive_profile().
    capability_profile_raw: dict[str, Any] = field(default_factory=dict)

    # Provenance: source -> list of fields that source contributed
    provenance_trail: dict[str, list[str]] = field(default_factory=dict)

    # Contested values from fusion (field_path -> [Fact, ...])
    contested_facts: dict[str, list[Fact]] = field(default_factory=dict)

    def build_http_headers(self) -> dict[str, str]:
        """Build HTTP headers for runtime calls (resolves token env)."""
        import os

        headers = {"Content-Type": "application/json"}
        auth = self.runtime.auth

        if auth.type == "none" or not auth.token_env:
            return headers

        token = os.environ.get(auth.token_env)
        if token is None:
            from agent_audit.exceptions import ConfigError
            raise ConfigError(
                f"Auth token env var '{auth.token_env}' is not set "
                f"(required by runtime.auth.type={auth.type!r})."
            )

        if auth.type == "bearer":
            headers["Authorization"] = f"Bearer {token}"
        elif auth.type == "api_key":
            headers[auth.header_name or "X-API-Key"] = token
        elif auth.type == "basic":
            import base64
            headers["Authorization"] = (
                "Basic " + base64.b64encode(token.encode("utf-8")).decode("ascii")
            )
        return headers

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly summary (omits provenance noise)."""
        return {
            "agent_name": self.agent_name,
            "version": self.version,
            "runtime": {
                "endpoint": self.runtime.endpoint,
                "protocol": self.runtime.protocol,
                "auth_type": self.runtime.auth.type,
                # Enough to run the same agent again (a saved agent's next audit). Secrets are env var names only;
                # a provider setting that looks like a literal secret is left out.
                "target_env": self.runtime.target_env,
                "timeout_s": self.runtime.timeout_s,
                "auth": {"type": self.runtime.auth.type, "token_env": self.runtime.auth.token_env,
                         "header_name": self.runtime.auth.header_name},
                "provider": {"name": self.runtime.provider.name,
                             "config": _without_literal_secrets(self.runtime.provider.config)},
            },
            "capabilities": {
                "max_steps": self.capabilities.max_steps,
                "context_budget_tokens": self.capabilities.context_budget_tokens,
                "tools": [t.name for t in self.capabilities.tools],
                "destructive_tools": list(self.capabilities.destructive_tool_names),
                "requires_hitl": self.capabilities.requires_hitl,
            },
            "slos": {
                "p95_latency_ms": self.slos.p95_latency_ms,
                "max_cost_per_task_usd": self.slos.max_cost_per_task_usd,
            },
            "security": {
                "pii_fields": list(self.security.pii_fields),
                "allowed_data_regions": list(self.security.allowed_data_regions),
                "data_classification": list(self.security.data_classification),
            },
            "prompts_discovered": len(self.prompts),
            "models_discovered": len(self.models),
            "dependencies_discovered": len(self.dependencies),
            "compliance_frameworks": list(self.compliance_frameworks),
            "provenance": {k: list(v) for k, v in self.provenance_trail.items()},
            "contested_count": len(self.contested_facts),
        }
