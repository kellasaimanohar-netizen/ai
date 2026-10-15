"""OpenAPI adapter.

Reads an OpenAPI (v3) or Swagger (v2) spec and treats each operation as a
"tool" the agent exposes. Useful when the agent is wrapped as a REST service
and the spec is the source of truth.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from agent_audit.exceptions import SourceError
from agent_audit.manifest import TargetManifest, ToolSpec
from agent_audit.sources.base import SourceAdapter

log = logging.getLogger(__name__)

# HTTP methods that are considered "destructive" by default
_DESTRUCTIVE_METHODS = {"post", "put", "patch", "delete"}


def _assert_public_url(url: str, *, allow_insecure_http: bool = False) -> None:
    """Guard against SSRF: refuse to fetch specs from non-public addresses.

    Resolves the host and rejects loopback / private / link-local / reserved /
    multicast targets (e.g. ``169.254.169.254`` cloud metadata, ``127.0.0.1``,
    ``10.0.0.0/8``). Plain ``http://`` is refused unless explicitly opted in,
    since spec fetches should be authenticated transport in any real setup.

    Set ``AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1`` to bypass (local dev only).
    """
    import ipaddress
    import os
    import socket
    from urllib.parse import urlparse

    from agent_audit.netguard import is_non_public

    if os.environ.get("AGENT_AUDIT_ALLOW_PRIVATE_FETCH") == "1":
        return

    parsed = urlparse(url)
    if parsed.scheme == "http" and not allow_insecure_http:
        raise SourceError(
            f"refusing to fetch openapi spec over plain http: {url!r} "
            "(use https, or set AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1 for local dev)"
        )
    host = parsed.hostname
    if not host:
        raise SourceError(f"openapi url has no host: {url!r}")

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise SourceError(f"could not resolve openapi host {host!r}: {exc}") from exc

    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if is_non_public(addr):
            raise SourceError(
                f"refusing to fetch openapi spec from non-public address {addr} "
                f"(host {host!r}) — blocked to prevent SSRF. "
                "Set AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1 to override (local dev only)."
            )


class OpenAPIAdapter(SourceAdapter):
    """Parse an OpenAPI spec to enumerate operations."""

    source_type = "openapi"
    default_confidence = 0.8

    def extract(self, spec: dict[str, Any], *, agent_name: str) -> TargetManifest:
        path_str = spec.get("path")
        if not path_str:
            raise SourceError("openapi source requires 'path'")

        if path_str.startswith(("http://", "https://")):
            import httpx
            import hashlib
            import time
            import tempfile
            _assert_public_url(path_str)
            
            # Use file-based cache to avoid repeatedly fetching from a slow Render server
            cache_dir = Path(tempfile.gettempdir()) / "agent_audit_openapi_cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            url_hash = hashlib.md5(path_str.encode("utf-8")).hexdigest()
            cache_file = cache_dir / f"openapi_{url_hash}.json"
            
            loaded_from_cache = False
            if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 900:  # 15 minutes cache
                try:
                    log.info("Loading openapi spec from local cache: %s", path_str)
                    raw = cache_file.read_text(encoding="utf-8")
                    doc = json.loads(raw)
                    loaded_from_cache = True
                except Exception:
                    pass
            
            if not loaded_from_cache:
                try:
                    log.info("Fetching openapi spec from remote server: %s", path_str)
                    resp = httpx.get(path_str, timeout=60.0)
                    resp.raise_for_status()
                    raw = resp.text
                    is_json = path_str.endswith(".json") or "json" in resp.headers.get("content-type", "").lower()
                    doc = json.loads(raw) if is_json else yaml.safe_load(raw)
                    # Save to cache
                    cache_file.write_text(json.dumps(doc), encoding="utf-8")
                except Exception as exc:
                    raise SourceError(f"failed to fetch openapi spec from {path_str}: {exc}") from exc
            source_loc_base = path_str
        else:
            path = Path(path_str).expanduser()
            if not path.is_file():
                backend_dir = Path(__file__).resolve().parent.parent.parent.parent
                candidate = (backend_dir / path_str).resolve()
                if candidate.is_file():
                    path = candidate
                else:
                    log.warning("openapi spec not found or unavailable in this environment: %s. Skipping openapi scan.", path_str)
                    return TargetManifest(agent_name=agent_name)
            else:
                path = path.resolve()

            raw = path.read_text(encoding="utf-8")
            try:
                doc = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
            except (json.JSONDecodeError, yaml.YAMLError) as exc:
                raise SourceError(f"failed to parse {path}: {exc}") from exc
            source_loc_base = path.name

        if not isinstance(doc, dict) or "paths" not in doc:
            raise SourceError(f"not a valid OpenAPI document: {path_str}")

        tools: list[ToolSpec] = []
        for url_path, ops in doc.get("paths", {}).items():
            if not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                if not isinstance(op, dict):
                    continue
                name = op.get("operationId") or f"{method.upper()}_{url_path}"
                tools.append(ToolSpec(
                    name=name,
                    destructive=(method.lower() in _DESTRUCTIVE_METHODS),
                    declared_in=["openapi"],
                    source_location=f"{source_loc_base}#{method.upper()} {url_path}",
                ))

        # Resolve server URL for live agent calls
        endpoint = None
        servers = doc.get("servers", [])
        if servers and isinstance(servers, list) and isinstance(servers[0], dict):
            endpoint = servers[0].get("url")
        
        # If not found in servers, fall back to base URL of the path itself
        if not endpoint and path_str.startswith(("http://", "https://")):
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(path_str)
            endpoint = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        manifest = TargetManifest(agent_name=agent_name)
        manifest.openapi_spec = doc
        if endpoint:
            manifest.runtime.endpoint = endpoint.rstrip("/")
        
        # Extract capability extensions from OpenAPI metadata if defined
        info = doc.get("info", {})
        x_caps = info.get("x-agent-capabilities", {}) or doc.get("x-agent-capabilities", {})
        if isinstance(x_caps, dict):
            if "context_budget_tokens" in x_caps:
                try:
                    manifest.capabilities.context_budget_tokens = int(x_caps["context_budget_tokens"])
                except (ValueError, TypeError):
                    pass
            if "requires_hitl" in x_caps:
                manifest.capabilities.requires_hitl = bool(x_caps["requires_hitl"])
        manifest.capabilities.tools = tools
        manifest.capabilities.destructive_tool_names = [
            t.name for t in tools if t.destructive
        ]
        manifest.provenance_trail["openapi"] = ["tools_discovered"]

        log.info("OpenAPIAdapter: discovered %d operations in %s", len(tools), path_str)
        return manifest
