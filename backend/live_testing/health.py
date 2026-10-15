"""Light health check for a monitored live agent. Cheap enough to run every few minutes, all day.

One check looks at:
  * the OpenAPI description: reachable, and whether routes were added or removed since the last check
  * the agent itself: one real request, its status code, speed and (when known) correct answer
  * the TLS certificate: days left
  * the local repo: whether the code changed since the last check (a hint to run a full test)

It returns a status (UP, DEGRADED or DOWN) and a list of issues that the page shows as they are.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from . import packs
from .connectors import ConnectorConfig, call
from .judge import rule_checks


def tls_verify() -> bool:
    from security import tls_verify as _verify
    return _verify()


def _outbound_problem(url: str) -> str | None:
    from security import outbound_problem
    return outbound_problem(url)

SLOW_MS = 3000
VERY_SLOW_MS = 8000
CERT_WARN_DAYS = 14
FIRST_CALL_TIMEOUT = 45.0   # a sleeping free-tier server can need most of a minute to wake up
_CHAT_WORDS = ("chat", "completion", "predict", "message", "query", "ask", "agent")


def _issue(severity: str, title: str, detail: str = "") -> dict:
    return {"severity": severity, "title": title, "detail": detail}


def _headers(req: dict) -> dict[str, str]:
    h = {"Content-Type": "application/json", "User-Agent": "CertifyAI-Monitor/1.0"}
    # Custom headers always go out; a token, when set, is added on top of them
    h.update(req.get("custom_headers") or {})
    token = (req.get("auth_token") or "").strip()
    if req.get("auth_type") == "bearer" and token:
        h["Authorization"] = f"Bearer {token}"
    elif req.get("auth_type") == "api_key" and token:
        h["x-api-key"] = token
    return h


def routes_of(spec: dict) -> list[str]:
    out = []
    for path, item in (spec.get("paths") or {}).items():
        for method in (item or {}):
            if method.lower() in ("get", "post", "put", "delete", "patch"):
                out.append(f"{method.upper()} {path}")
    return sorted(out)


def pick_route(spec: dict) -> tuple[str, str] | None:
    """The route to probe: a chat-like one first, else a POST route, else the first route."""
    routes = []
    for path, item in (spec.get("paths") or {}).items():
        for method in ("post", "get", "put"):
            if method in (item or {}):
                routes.append((path, method.upper()))
    for path, method in routes:
        if any(w in path.lower() for w in _CHAT_WORDS):
            return path, method
    posts = [r for r in routes if r[1] == "POST"]
    return posts[0] if posts else (routes[0] if routes else None)


def _base_url(spec: dict, spec_url: str) -> str:
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict) and str(servers[0].get("url", "")).startswith("http"):
        return servers[0]["url"].rstrip("/")
    p = urlparse(spec_url)
    return f"{p.scheme}://{p.netloc}"


def _cert_days(host: str, port: int = 443) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                not_after = tls.getpeercert().get("notAfter")
        if not not_after:
            return None
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        return (expires - datetime.now(timezone.utc)).days
    except Exception:
        return None


def repo_fingerprint(path: str | None) -> str | None:
    """A short fingerprint of the code files, so a change can be noticed. None when there is no readable folder."""
    if not path:
        return None
    root = Path(path.strip().strip('"').strip("'")).expanduser()
    if not root.is_dir():
        return None
    h = hashlib.sha256()
    count = 0
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in sorted(files):
            if f.endswith((".py", ".yaml", ".yml", ".toml", ".txt", ".j2", ".prompt", ".json", ".ts", ".js")):
                fp = Path(dirpath) / f
                try:
                    st = fp.stat()
                except OSError:
                    continue
                h.update(f"{fp.relative_to(root)}|{st.st_size}|{int(st.st_mtime)}".encode())
                count += 1
                if count > 5000:
                    return h.hexdigest()[:16]
    return h.hexdigest()[:16] if count else None


def _probe_input(req: dict, spec: dict | None, route: tuple[str, str] | None, kind: str) -> tuple[Any, list[dict]]:
    """What to send, and the known-answer cases to judge it with (when the user supplied golden cases)."""
    rows = list(req.get("golden_cases") or [])
    if req.get("golden_jsonl"):
        try:
            rows += packs.golden_from_jsonl(req["golden_jsonl"])
        except ValueError:
            pass
    golden = [c for c in packs.golden_to_cases(rows) if c.get("input") is not None and not (c.get("expect") or {}).get("monotonic")]
    if golden:
        return golden[0]["input"], [golden[0]]
    if kind == "rest_api" and spec and route:
        cases = packs.api_cases_from_openapi(spec, route[0], route[1])
        valid = next((c["input"] for c in cases if c["id"] == "api_valid"), None)
        if valid is not None:
            return valid, [{"id": "ok", "name": "ok", "expect": {"status": [200, 299]}}]
    return "Hello", [{"id": "ok", "name": "ok", "expect": {"status": [200, 299]}}]


async def health_check(req: dict, previous: dict | None = None) -> dict:
    t0 = time.perf_counter()
    issues: list[dict] = []
    spec: dict | None = None
    route: tuple[str, str] | None = None
    spec_url = (req.get("openapi_url") or "").strip()
    if spec_url and not spec_url.startswith(("http://", "https://")):
        spec_url = "https://" + spec_url
    result: dict[str, Any] = {"checked_at": datetime.now(timezone.utc).isoformat(), "http_status": None, "latency_ms": None,
                              "routes": None, "spec_hash": None, "repo_fp": None, "cert_days": None}

    # 1. The OpenAPI description
    spec_problem = await asyncio.to_thread(_outbound_problem, spec_url) if spec_url else None
    if spec_problem:
        issues.append(_issue("CRITICAL", "The API description address is not allowed", spec_problem))
    elif spec_url:
        try:
            async with httpx.AsyncClient(timeout=FIRST_CALL_TIMEOUT, verify=tls_verify()) as c:
                r = await c.get(spec_url)
            if r.status_code != 200:
                issues.append(_issue("CRITICAL" if r.status_code >= 500 else "WARNING", "The API description is not available",
                                     f"{spec_url} returned HTTP {r.status_code}."))
            else:
                spec = r.json()
                result["routes"] = routes_of(spec)
                result["spec_hash"] = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]
                prev_routes = (previous or {}).get("routes")
                if prev_routes:
                    gone = sorted(set(prev_routes) - set(result["routes"]))
                    new = sorted(set(result["routes"]) - set(prev_routes))
                    if gone:
                        issues.append(_issue("CRITICAL", "Routes were removed", ", ".join(gone[:5])))
                    if new:
                        issues.append(_issue("INFO", "New routes appeared", ", ".join(new[:5])))
                    if not gone and not new and (previous or {}).get("spec_hash") not in (None, result["spec_hash"]):
                        issues.append(_issue("INFO", "The API description changed", "Fields or limits may have changed. Run a full test."))
        except httpx.TimeoutException:
            issues.append(_issue("WARNING", "The API description timed out", f"No answer from {spec_url} within {FIRST_CALL_TIMEOUT:.0f}s."))
        except Exception as e:
            issues.append(_issue("WARNING", "The API description could not be read", str(e)[:160]))

    # 2. The agent itself
    endpoint = (req.get("endpoint_url") or "").strip()
    probe_spec = spec
    prev_routes = (previous or {}).get("routes") or []
    if not probe_spec and prev_routes:
        # The description could not be read this time; probe the route found by the last good check.
        paths: dict[str, dict[str, dict]] = {}
        for r in prev_routes:
            method, _, path = r.partition(" ")
            paths.setdefault(path, {})[method.lower()] = {}
        probe_spec = {"paths": paths}
        result["routes"] = prev_routes
    if probe_spec and not route:
        route = pick_route(probe_spec)
    if not endpoint and probe_spec and route:
        endpoint = _base_url(probe_spec, spec_url) + route[0]
    status = "UP"
    if not endpoint:
        issues.append(_issue("WARNING", "There is no endpoint to check", "Add an OpenAPI link, or set the endpoint URL."))
        status = "DEGRADED"
    else:
        agent_type = req.get("agent_type")
        route_path = route[0] if route else ""
        kind = "rest_api" if (agent_type == "api" or (not agent_type and probe_spec and route_path and not any(w in route_path.lower() for w in _CHAT_WORDS))) else "chat"
        body, checks = _probe_input(req, spec, route, kind)
        cfg = ConnectorConfig(kind=kind, endpoint_url=endpoint, http_method=(route[1] if route and not req.get("endpoint_url") else req.get("http_method", "POST")),
                              headers=_headers(req), request_template=req.get("payload_template"), response_path=req.get("response_path"),
                              timeout_seconds=FIRST_CALL_TIMEOUT)
        if kind == "rest_api" and cfg.http_method.upper() == "GET":
            cfg.http_method = "POST"
        resp = await call(cfg, body)
        result["http_status"] = resp.status_code or None
        result["latency_ms"] = round(resp.latency_ms)
        if not resp.ok_transport:
            status = "DOWN"
            issues.append(_issue("CRITICAL", "The agent did not answer", resp.error or "No response."))
        elif resp.status_code >= 500:
            status = "DOWN"
            issues.append(_issue("CRITICAL", f"The agent returned a server error (HTTP {resp.status_code})", (resp.text or "")[:160]))
        elif resp.status_code in (401, 403):
            status = "DEGRADED"
            issues.append(_issue("WARNING", f"The agent refused the check (HTTP {resp.status_code})", "The login token may have expired or been changed."))
        elif resp.status_code >= 400:
            status = "DEGRADED"
            issues.append(_issue("WARNING", f"The agent rejected the check request (HTTP {resp.status_code})", "The request format may have changed."))
        else:
            for case in checks:
                for c in rule_checks(case, resp):
                    if c.passed is False:
                        status = "DEGRADED"
                        sev = "CRITICAL" if case["id"] != "ok" else "WARNING"
                        issues.append(_issue(sev, "A known answer is wrong" if case["id"] != "ok" else c.name, f"{c.name}. {c.detail}".strip()))
            if resp.latency_ms > VERY_SLOW_MS:
                status = "DEGRADED"
                issues.append(_issue("CRITICAL", "The agent is very slow", f"It took {resp.latency_ms / 1000:.1f}s to answer."))
            elif resp.latency_ms > SLOW_MS:
                status = "DEGRADED"
                issues.append(_issue("WARNING", "The agent is slow", f"It took {resp.latency_ms / 1000:.1f}s to answer."))

        # 3. The certificate
        p = urlparse(endpoint)
        if p.scheme == "https" and p.hostname and resp.ok_transport:
            days = await asyncio.get_running_loop().run_in_executor(None, _cert_days, p.hostname, p.port or 443)
            result["cert_days"] = days
            if days is not None and days < 0:
                status = "DOWN"
                issues.append(_issue("CRITICAL", "The security certificate has expired", f"It expired {abs(days)} days ago."))
            elif days is not None and days < CERT_WARN_DAYS:
                issues.append(_issue("WARNING", "The security certificate expires soon", f"{days} days left."))

    # 4. The repo
    fp = repo_fingerprint(req.get("repo_path"))
    result["repo_fp"] = fp
    if req.get("repo_path") and fp is None and not str(req.get("repo_path")).startswith(("http://", "https://")):
        issues.append(_issue("INFO", "The repo folder cannot be read", "Check the path. Only a folder on the backend's computer can be scanned."))
    elif fp and (previous or {}).get("repo_fp") not in (None, fp):
        issues.append(_issue("INFO", "The code changed since the last check", "Run a full test to see whether results moved."))

    if any(i["severity"] == "CRITICAL" for i in issues) and status == "UP":
        status = "DEGRADED"
    result.update({"status": status, "issues": issues, "duration_ms": round((time.perf_counter() - t0) * 1000)})
    return result
