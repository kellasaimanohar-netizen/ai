"""Connectors: how to talk to a live agent and read its answer.

Every connector takes one test input and returns a ProbeResponse. The runner never needs to know
whether the agent is a chat bot, a REST API, an async job or an MCP server.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

CONNECTOR_KINDS = ("chat", "openai", "rest_api", "async_job", "mcp")

_TEXT_KEYS = ("response", "reply", "answer", "message", "content", "output", "text", "result")


@dataclass
class ConnectorConfig:
    kind: str = "chat"
    endpoint_url: str = ""
    http_method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    request_template: str | None = None      # JSON text; {PROMPT} is replaced for text inputs
    response_path: str | None = None         # dotted path to the answer, e.g. "data.answer" or "choices.0.message.content"
    timeout_seconds: float = 20.0
    model: str | None = None                 # openai kind
    # async_job kind
    status_url_template: str | None = None   # e.g. "https://host/jobs/{job_id}"
    job_id_path: str = "id"
    status_path: str = "status"
    done_values: tuple[str, ...] = ("done", "completed", "complete", "succeeded", "success", "finished")
    failed_values: tuple[str, ...] = ("failed", "error", "cancelled", "canceled")
    poll_interval_seconds: float = 2.0
    max_wait_seconds: float = 60.0
    auth_header_name: str = "Authorization"  # where the credential goes (an API key scheme may use another header)
    local_handler: Any = None                # in-process handler, used by the built-in demo endpoint


@dataclass
class ProbeResponse:
    status_code: int = 0
    text: str = ""
    data: Any = None
    latency_ms: float = 0.0
    error: str | None = None
    error_kind: str | None = None            # "timeout" | "network" | None
    tool_calls: list[str] = field(default_factory=list)

    @property
    def ok_transport(self) -> bool:
        return self.error_kind is None


def dig(data: Any, path: str | None) -> Any:
    """Read a dotted path such as "a.b.0.c" from nested dicts and lists. Returns None when missing."""
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _auto_text(data: Any) -> str:
    if isinstance(data, dict):
        for k in _TEXT_KEYS:
            v = data.get(k)
            if isinstance(v, str) and v:
                return v
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            msg = (choices[0] or {}).get("message") or {}
            if isinstance(msg.get("content"), str):
                return msg["content"]
        return json.dumps(data)
    return data if isinstance(data, str) else json.dumps(data)


def _collect_tool_calls(data: Any) -> list[str]:
    """Tool names called, for OpenAI-style responses and for common custom shapes."""
    names: list[str] = []
    if not isinstance(data, dict):
        return names
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        for tc in ((choices[0] or {}).get("message") or {}).get("tool_calls") or []:
            n = (tc.get("function") or {}).get("name")
            if n:
                names.append(n)
    for key in ("tool_calls", "tools_used", "tools_called", "actions"):
        for item in data.get(key) or []:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                n = item.get("name") or item.get("tool") or (item.get("function") or {}).get("name")
                if n:
                    names.append(str(n))
    return names


def _render_body(cfg: ConnectorConfig, test_input: Any) -> Any:
    """Build the JSON body. Dict inputs are sent as they are. Text goes into the template."""
    if isinstance(test_input, dict):
        return test_input
    text = str(test_input)
    if cfg.kind == "openai":
        body: dict[str, Any] = {"messages": [{"role": "user", "content": text}]}
        body["model"] = cfg.model or "gpt-4o-mini"
        return body
    if cfg.request_template and "{PROMPT}" in cfg.request_template:
        raw = cfg.request_template.replace("{PROMPT}", json.dumps(text)[1:-1])
        try:
            return json.loads(raw)
        except ValueError:
            pass
    return {"message": text, "prompt": text, "query": text}


async def _blocked(url: str) -> str | None:
    """Why this address must not be called (this server, a private network, cloud metadata), or None.
    Checked on every call, so a spec's servers entry or a changed DNS record cannot point probes inward."""
    from security import outbound_problem
    return await asyncio.to_thread(outbound_problem, url)


def _verify() -> bool:
    from security import tls_verify
    return tls_verify()


async def warm_up(cfg: ConnectorConfig) -> None:
    """Wake a sleeping host (for example a free-tier server) so the first probe is not a timeout."""
    p = urlparse(cfg.endpoint_url)
    if not p.scheme or not p.netloc or cfg.local_handler is not None:
        return
    if await _blocked(f"{p.scheme}://{p.netloc}/"):
        return
    try:
        async with httpx.AsyncClient(timeout=50.0, verify=_verify()) as c:
            await c.get(f"{p.scheme}://{p.netloc}/")
    except Exception:
        pass


async def _send(client: httpx.AsyncClient, cfg: ConnectorConfig, body: Any) -> httpx.Response:
    method = cfg.http_method.upper()
    if method == "GET":
        flat = isinstance(body, dict) and all(not isinstance(v, (dict, list)) for v in body.values())
        params = body if flat else {"q": json.dumps(body)}
        return await client.get(cfg.endpoint_url, params=params, headers=cfg.headers)
    return await client.request(method, cfg.endpoint_url, json=body, headers=cfg.headers)


def _parse(resp: httpx.Response, cfg: ConnectorConfig) -> tuple[Any, str]:
    try:
        data = resp.json()
    except ValueError:
        return None, resp.text
    picked = dig(data, cfg.response_path) if cfg.response_path else None
    if cfg.response_path and picked is not None:
        return data, picked if isinstance(picked, str) else json.dumps(picked)
    if cfg.kind == "rest_api":
        return data, json.dumps(data)
    return data, _auto_text(data)


AUTH_MODES = ("none", "invalid", "malformed", "basic", "query_token")


def with_auth_mode(cfg: ConnectorConfig, auth_mode: str | None, extra_headers: dict[str, str] | None = None) -> ConnectorConfig:
    """A copy of the config that sends a deliberately wrong (or missing) credential, or another user's headers.

    none         no credential at all
    invalid      a well-formed but unknown token
    malformed    the header is present but not a usable credential
    basic        the wrong scheme (Basic instead of Bearer)
    query_token  the token in the URL instead of the header
    """
    if not auth_mode and not extra_headers:
        return cfg
    keep = {k: v for k, v in cfg.headers.items() if k.lower() not in ("authorization", cfg.auth_header_name.lower())}
    headers = dict(keep if auth_mode else cfg.headers)
    url = cfg.endpoint_url
    name = cfg.auth_header_name
    if auth_mode == "invalid":
        headers[name] = "Bearer invalid.token.value" if name.lower() == "authorization" else "invalid-key-000000"
    elif auth_mode == "malformed":
        headers[name] = "Bearer" if name.lower() == "authorization" else ""
    elif auth_mode == "basic":
        headers["Authorization"] = "Basic dGVzdDp0ZXN0"
    elif auth_mode == "query_token":
        url = url + ("&" if "?" in url else "?") + "access_token=invalid.token.value&api_key=invalid-key-000000"
    if extra_headers:
        headers.update(extra_headers)
    return dataclasses.replace(cfg, headers=headers, endpoint_url=url)


async def call(cfg: ConnectorConfig, test_input: Any, auth_mode: str | None = None,
               extra_headers: dict[str, str] | None = None) -> ProbeResponse:
    """Send one input to the agent. Transport problems are returned, never raised."""
    cfg = with_auth_mode(cfg, auth_mode, extra_headers)
    t0 = time.perf_counter()
    out = ProbeResponse()
    try:
        if cfg.local_handler is not None:
            body = _render_body(cfg, test_input)
            out.data = await cfg.local_handler(body)
            out.status_code, out.text = 200, _auto_text(out.data)
            out.latency_ms = (time.perf_counter() - t0) * 1000
            return out
        problem = await _blocked(cfg.endpoint_url)
        if problem:
            out.error_kind, out.error = "network", f"This address is not allowed: {problem}"
            out.latency_ms = (time.perf_counter() - t0) * 1000
            return out
        async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=_verify()) as client:
            if cfg.kind == "mcp":
                await _call_mcp(client, cfg, test_input, out)
            elif cfg.kind == "async_job":
                await _call_async_job(client, cfg, test_input, out)
            else:
                resp = await _send(client, cfg, _render_body(cfg, test_input))
                out.status_code = resp.status_code
                out.data, out.text = _parse(resp, cfg)
                out.tool_calls = _collect_tool_calls(out.data)
    except httpx.TimeoutException:
        out.error_kind, out.error = "timeout", f"No answer within {cfg.timeout_seconds:.0f}s."
    except Exception as e:  # network errors, bad URL, TLS
        out.error_kind, out.error = "network", f"Could not connect: {e}"
    out.latency_ms = (time.perf_counter() - t0) * 1000
    return out


async def _call_async_job(client: httpx.AsyncClient, cfg: ConnectorConfig, test_input: Any, out: ProbeResponse) -> None:
    resp = await _send(client, cfg, _render_body(cfg, test_input))
    out.status_code = resp.status_code
    out.data, out.text = _parse(resp, cfg)
    if resp.status_code >= 400 or not cfg.status_url_template:
        return
    job_id = dig(out.data, cfg.job_id_path)
    if job_id is None:
        return
    url = cfg.status_url_template.replace("{job_id}", str(job_id))
    problem = await _blocked(url)
    if problem:
        out.error_kind, out.error = "network", f"The job status address is not allowed: {problem}"
        return
    deadline = time.perf_counter() + cfg.max_wait_seconds
    while time.perf_counter() < deadline:
        await asyncio.sleep(cfg.poll_interval_seconds)
        poll = await client.get(url, headers=cfg.headers)
        out.status_code = poll.status_code
        out.data, out.text = _parse(poll, cfg)
        state = str(dig(out.data, cfg.status_path) or "").lower()
        if state in cfg.done_values or state in cfg.failed_values or poll.status_code >= 400:
            out.tool_calls = _collect_tool_calls(out.data)
            return
    out.error_kind, out.error = "timeout", f"Job did not finish within {cfg.max_wait_seconds:.0f}s."


async def _call_mcp(client: httpx.AsyncClient, cfg: ConnectorConfig, test_input: Any, out: ProbeResponse) -> None:
    """MCP over HTTP (JSON-RPC). Input "list" lists tools. A dict {"tool": ..., "arguments": {...}} calls one."""
    if isinstance(test_input, dict) and test_input.get("tool"):
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": test_input["tool"], "arguments": test_input.get("arguments", {})}}
    else:
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = await client.post(cfg.endpoint_url, json=rpc, headers={**cfg.headers, "Accept": "application/json, text/event-stream"})
    out.status_code = resp.status_code
    try:
        out.data = resp.json()
    except ValueError:
        out.data, out.text = None, resp.text
        return
    out.text = json.dumps(out.data)
    if isinstance(out.data, dict) and out.data.get("error"):
        out.text = json.dumps(out.data["error"])


async def list_mcp_tools(cfg: ConnectorConfig) -> list[str]:
    r = await call(cfg, "list")
    tools = dig(r.data, "result.tools") or []
    return [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
