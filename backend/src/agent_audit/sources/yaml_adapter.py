"""YAML adapter — backwards-compatible with v3 targets.

Accepts two shapes:

1. **v3 flat**: top-level ``agent_name``, ``endpoint``, ``capabilities``, etc.
2. **v4 inline**: an entry inside the top-level ``sources:`` list with
   ``type: yaml_inline`` and a nested ``runtime:`` block.

Both produce a ``TargetManifest`` with ``source=yaml`` provenance.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agent_audit.exceptions import ConfigError
from agent_audit.manifest import (
    AuthSpec,
    CapabilitiesSpec,
    GoldenDatasetSpec,
    ProviderSpec,
    RuntimeSpec,
    SecuritySpec,
    SLOSpec,
    TargetManifest,
    ToolSpec,
)
from agent_audit.sources.base import SourceAdapter

log = logging.getLogger(__name__)


class YamlAdapter(SourceAdapter):
    """Parse a v3-flat or v4-inline YAML spec into a manifest."""

    source_type = "yaml"
    default_confidence = 1.0

    def extract(self, spec: dict[str, Any], *, agent_name: str) -> TargetManifest:
        runtime_raw = spec.get("runtime", spec)  # v3 flat puts endpoint at top level

        auth_raw = runtime_raw.get("auth", {}) or {}
        auth = AuthSpec(
            type=auth_raw.get("type", "none"),
            token_env=auth_raw.get("token_env"),
            header_name=auth_raw.get("header_name", "Authorization"),
        )

        provider_raw = runtime_raw.get("provider", {}) or {}
        provider = ProviderSpec(
            name=provider_raw.get("name", "generic"),
            config=dict(provider_raw.get("config", {}) or {}),
        )

        runtime = RuntimeSpec(
            endpoint=runtime_raw.get("endpoint"),
            protocol=runtime_raw.get("protocol", "http"),
            auth=auth,
            timeout_s=float(runtime_raw.get("timeout_s", 30.0)),
            provider=provider,
            target_env=runtime_raw.get("target_env"),
        )

        cap_raw = spec.get("capabilities") or {}
        destructive = list(cap_raw.get("destructive_tools") or [])
        tools = [
            ToolSpec(name=t, destructive=(t in destructive), declared_in=["yaml"])
            for t in (cap_raw.get("tools") or [])
        ]
        capabilities = CapabilitiesSpec(
            max_steps=int(cap_raw.get("max_steps") or 25),
            context_budget_tokens=cap_raw.get("context_budget_tokens"),
            tools=tools,
            destructive_tool_names=destructive,
            requires_hitl=bool(cap_raw.get("requires_hitl") or False),
        )

        slo_raw = spec.get("slos") or {}
        slos = SLOSpec(
            p95_latency_ms=int(slo_raw.get("p95_latency_ms") or 10_000),
            max_cost_per_task_usd=float(slo_raw.get("max_cost_per_task_usd") or 0.10),
        )

        sec_raw = spec.get("security") or {}
        security = SecuritySpec(
            pii_fields=list(sec_raw.get("pii_fields") or []),
            allowed_data_regions=list(sec_raw.get("allowed_data_regions") or []),
            data_classification=list(sec_raw.get("data_classification") or []),
        )

        manifest = TargetManifest(
            agent_name=agent_name,
            runtime=runtime,
            capabilities=capabilities,
            slos=slos,
            security=security,
            runbooks_dir=(
                Path(spec["runbooks_dir"]).expanduser()
                if spec.get("runbooks_dir") and Path(spec["runbooks_dir"]).expanduser().is_dir()
                else (
                    (Path(__file__).resolve().parent.parent.parent.parent / spec["runbooks_dir"]).resolve()
                    if spec.get("runbooks_dir") and (Path(__file__).resolve().parent.parent.parent.parent / spec["runbooks_dir"]).is_dir()
                    else (
                        (Path(__file__).resolve().parent.parent.parent.parent / "runbooks").resolve()
                        if (Path(__file__).resolve().parent.parent.parent.parent / "runbooks").is_dir()
                        else None
                    )
                )
            ),
            golden_dataset=self._parse_golden(spec.get("golden_dataset")),
            compliance_frameworks=list(spec.get("compliance_frameworks") or []),
            capability_profile_raw=dict(spec.get("capability_profile") or {}),
        )

        # Record provenance: which fields this adapter contributed
        contributed = ["runtime", "capabilities", "slos", "security"]
        if manifest.golden_dataset:
            contributed.append("golden_dataset")
        manifest.provenance_trail["yaml"] = contributed

        log.debug("YamlAdapter extracted manifest for %s", agent_name)
        return manifest

    @staticmethod
    def _parse_golden(raw: Any) -> GoldenDatasetSpec | None:
        if raw is None:
            return None
        if isinstance(raw, str):
            return GoldenDatasetSpec(path=Path(raw).expanduser())
        if isinstance(raw, dict):
            path = raw.get("path")
            if not path:
                raise ConfigError("golden_dataset.path is required")
            fields = raw.get("fields", {}) or {}
            return GoldenDatasetSpec(
                path=Path(path).expanduser(),
                format=raw.get("format", "jsonl"),
                input_field=fields.get("input", "input"),
                expected_field=fields.get("expected", "expected"),
            )
        raise ConfigError(f"Unsupported golden_dataset spec: {raw!r}")
