"""Target loader and multi-source fusion.

Reads a v4 target YAML (or a v3-flat YAML for backwards compatibility),
routes each entry in the ``sources:`` list to the right adapter, then fuses
the resulting manifests into one authoritative ``TargetManifest``.

Fusion rules:
  * Scalars: higher ``default_confidence`` wins; contested values are
    recorded in ``contested_facts`` so phases can surface them.
  * Lists of tools / prompts / models / deps: union, de-duplicated by name.
  * Provenance: merged per field.
"""
from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from agent_audit.exceptions import ConfigError
from agent_audit.manifest import (
    Fact,
    Provenance,
    TargetManifest,
    ToolSpec,
)
from agent_audit.sources.base import SourceAdapter
from agent_audit.sources.bedrock_adapter import BedrockAdapter
from agent_audit.sources.foundry_adapter import FoundryAdapter
from agent_audit.sources.openapi_adapter import OpenAPIAdapter
from agent_audit.sources.repo_adapter import RepoAdapter
from agent_audit.sources.yaml_adapter import YamlAdapter

log = logging.getLogger(__name__)


# Registry of built-in adapters. Third parties can register more via
# entry points — see checkers.registry for the same pattern.
_BUILTIN_ADAPTERS: dict[str, type[SourceAdapter]] = {
    "yaml_inline": YamlAdapter,
    "yaml":        YamlAdapter,
    "openapi":     OpenAPIAdapter,
    "repo":        RepoAdapter,
    "bedrock":     BedrockAdapter,
    "foundry":     FoundryAdapter,
}


def load_target(path: str | Path) -> TargetManifest:
    """Load a target config from disk and return the fused manifest."""
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ConfigError(f"target file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError(f"target file is not a YAML mapping: {path}")

    agent_name = raw.get("agent_name") or (raw.get("metadata", {}).get("name") if isinstance(raw.get("metadata"), dict) else None)
    if not agent_name:
        raise ConfigError("target YAML missing required field: agent_name")
    if "agent_name" not in raw:
        raw["agent_name"] = agent_name

    sources = raw.get("sources")
    if sources is None:
        # v3-compat: treat the whole document as one yaml_inline spec
        log.info("no 'sources' key — treating as v3-compat flat config")
        sources = [{"type": "yaml_inline", **raw}]

    if not isinstance(sources, list) or not sources:
        raise ConfigError("'sources' must be a non-empty list")

    manifests: list[TargetManifest] = []
    for idx, source_spec in enumerate(sources):
        if not isinstance(source_spec, dict):
            raise ConfigError(f"sources[{idx}] must be a mapping")
        stype = source_spec.get("type")
        if not stype:
            raise ConfigError(f"sources[{idx}] missing 'type'")

        adapter_cls = _BUILTIN_ADAPTERS.get(stype)
        if adapter_cls is None:
            raise ConfigError(f"unknown source type: {stype!r}")

        adapter = adapter_cls()
        manifest = adapter.extract(source_spec, agent_name=agent_name)
        manifests.append(manifest)

    fused = _fuse(agent_name, manifests)

    # Top-level keys that live on the manifest regardless of sources
    fused.compliance_frameworks = list(raw.get("compliance_frameworks") or [])
    if "slos" in raw and not any("slos" in m.provenance_trail.get("yaml", []) for m in manifests):
        slo_raw = raw["slos"]
        fused.slos.p95_latency_ms = int(slo_raw.get("p95_latency_ms", fused.slos.p95_latency_ms))
        fused.slos.max_cost_per_task_usd = float(
            slo_raw.get("max_cost_per_task_usd", fused.slos.max_cost_per_task_usd),
        )

    log.info(
        "Loaded manifest for %s from %d source(s); %d contested facts",
        agent_name, len(manifests), len(fused.contested_facts),
    )
    return fused


# ─── fusion ─────────────────────────────────────────────────────────────
def _fuse(agent_name: str, parts: list[TargetManifest]) -> TargetManifest:
    """Merge multiple partial manifests into one."""
    if not parts:
        raise ConfigError("no source manifests to fuse")

    fused = TargetManifest(agent_name=agent_name)
    fused.runtime.endpoint = None
    fused.capabilities.context_budget_tokens = None
    fused.capabilities.max_steps = None


    for part in parts:
        if part.openapi_spec:
            fused.openapi_spec = part.openapi_spec
        # NOTE: runtime.endpoint is deliberately NOT merged via _merge_scalar
        # here — it's handled below by the "first non-empty wins" whole-object
        # runtime block, which also carries over target_env/provider/auth/
        # timeout_s from the same source. Merging endpoint here first would
        # make fused_has_runtime look already-true and silently drop those
        # sibling fields from every part.
        _merge_scalar(fused, part, "capabilities.context_budget_tokens")
        _merge_scalar(fused, part, "capabilities.max_steps")

        # SLOs: take the most conservative (lowest latency target, lowest cost)
        if part.slos.p95_latency_ms and part.slos.p95_latency_ms != 10_000:
            fused.slos.p95_latency_ms = min(
                fused.slos.p95_latency_ms or part.slos.p95_latency_ms,
                part.slos.p95_latency_ms,
            )
        if part.slos.max_cost_per_task_usd:
            fused.slos.max_cost_per_task_usd = min(
                fused.slos.max_cost_per_task_usd or part.slos.max_cost_per_task_usd,
                part.slos.max_cost_per_task_usd,
            )

        # Runtime: first non-empty wins, but record subsequent contenders.
        # "Non-empty" means it carries an endpoint OR a non-generic provider
        # (e.g. agentforce), since provider-based targets have no top-level
        # endpoint but still fully describe how to reach the agent.
        part_provider = getattr(part.runtime, "provider", None)
        part_has_provider = bool(part_provider and part_provider.name != "generic")
        fused_provider = getattr(fused.runtime, "provider", None)
        fused_has_runtime = bool(
            fused.runtime.endpoint
            or (fused_provider and fused_provider.name != "generic")
        )
        if part.runtime.endpoint or part_has_provider:
            if not fused_has_runtime:
                fused.runtime = part.runtime
            elif part.runtime.endpoint and fused.runtime.endpoint != part.runtime.endpoint:
                _record_contest(fused, "runtime.endpoint", part)

        # Auth: take the first explicit one
        if part.runtime.auth.type != "none" and fused.runtime.auth.type == "none":
            fused.runtime.auth = part.runtime.auth

        # Security: union of fields; conservative region intersection
        for pii in part.security.pii_fields:
            if pii not in fused.security.pii_fields:
                fused.security.pii_fields.append(pii)
        for region in part.security.allowed_data_regions:
            if region not in fused.security.allowed_data_regions:
                fused.security.allowed_data_regions.append(region)
        for dc in part.security.data_classification:
            if dc not in fused.security.data_classification:
                fused.security.data_classification.append(dc)

        # Capabilities: tools are unioned by name
        _merge_tools(fused, part)
        for name in part.capabilities.destructive_tool_names:
            if name not in fused.capabilities.destructive_tool_names:
                fused.capabilities.destructive_tool_names.append(name)
        if part.capabilities.requires_hitl:
            fused.capabilities.requires_hitl = True

        # Prompts / models / deps: union
        fused.prompts.extend(part.prompts)
        fused.models.extend(part.models)
        fused.dependencies.extend(part.dependencies)

        # runbooks / golden dataset: first wins
        if part.runbooks_dir and not fused.runbooks_dir:
            fused.runbooks_dir = part.runbooks_dir
        if part.golden_dataset and not fused.golden_dataset:
            fused.golden_dataset = part.golden_dataset

        # capability_profile: declared fields union; first source wins a key
        for key, value in part.capability_profile_raw.items():
            fused.capability_profile_raw.setdefault(key, value)

        # Provenance trail: merge per source
        for src, fields in part.provenance_trail.items():
            fused.provenance_trail.setdefault(src, []).extend(fields)

    if fused.capabilities.max_steps is None:
        fused.capabilities.max_steps = 25

    return fused



def _merge_tools(fused: TargetManifest, part: TargetManifest) -> None:
    """Union tools by name; if both have same name, combine declared_in sources."""
    by_name: dict[str, ToolSpec] = {t.name: t for t in fused.capabilities.tools}
    for tool in part.capabilities.tools:
        if tool.name in by_name:
            existing = by_name[tool.name]
            for src in tool.declared_in:
                if src not in existing.declared_in:
                    existing.declared_in.append(src)
            if tool.destructive:
                by_name[tool.name] = replace(existing, destructive=True)
        else:
            by_name[tool.name] = tool
    fused.capabilities.tools = list(by_name.values())


def _merge_scalar(fused: TargetManifest, part: TargetManifest, dotted: str) -> None:
    """Set ``fused.<dotted>`` from part if currently empty."""
    # Check if the part actually contributed this field (or its parent segment)
    contributed = False
    for src, fields in part.provenance_trail.items():
        first_segment = dotted.split(".")[0]
        if first_segment in fields or dotted in fields:
            contributed = True
            break
    if not contributed:
        return

    existing = _get(fused, dotted)
    incoming = _get(part, dotted)
    if incoming is None:
        return
    if existing is None:
        _set(fused, dotted, incoming)
    elif existing != incoming:
        _record_contest(fused, dotted, part)


def _get(manifest: TargetManifest, dotted: str) -> Any:
    obj: Any = manifest
    for segment in dotted.split("."):
        obj = getattr(obj, segment, None)
        if obj is None:
            return None
    return obj


def _set(manifest: TargetManifest, dotted: str, value: Any) -> None:
    obj: Any = manifest
    segments = dotted.split(".")
    for segment in segments[:-1]:
        obj = getattr(obj, segment)
    setattr(obj, segments[-1], value)


def _record_contest(fused: TargetManifest, field_path: str, part: TargetManifest) -> None:
    facts = fused.contested_facts.setdefault(field_path, [])
    sources = list(part.provenance_trail.keys()) or ["unknown"]
    for src in sources:
        facts.append(Fact(
            value=_get(part, field_path),
            provenance=Provenance(source=src, confidence=0.5),  # contested → low
        ))
