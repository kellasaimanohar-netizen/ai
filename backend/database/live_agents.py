"""Live agents: the `live_agents` table, each row owned by one user.

A registered live agent has an OpenAPI link; its API token and test settings are encrypted in settings_enc.
Its tests are in live_agent_tests and its monitor in live_schedules.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from .crypto import decrypt_json, encrypt_json

PUBLIC_COLUMNS = "id, user_id, name, repo_path, openapi_url, target_env, last_test_id, last_error, created_at, updated_at"
# Registered on the Live agents page, as opposed to a live agent a test run created by name
REGISTERED = "openapi_url IS NOT NULL"


def get_owned(cursor, agent_id: int, user_id: int) -> dict[str, Any] | None:
    """The live agent, only when it belongs to this user."""
    cursor.execute(f"SELECT {PUBLIC_COLUMNS}, settings_enc FROM live_agents WHERE id = ? AND user_id = ? AND {REGISTERED}",
                   (agent_id, user_id))
    row = cursor.fetchone()
    return dict(row) if row else None


def settings_of(row: dict[str, Any]) -> dict[str, Any]:
    """{'auth_token': ..., 'config': {...}} decrypted."""
    return decrypt_json(row.get("settings_enc"), {}) or {}


def seal_settings(auth_token: str | None, config: dict[str, Any] | None) -> str:
    return encrypt_json({"auth_token": auth_token or None, "config": config or {}})


def fill_request(cursor, req: dict[str, Any], user_id: int) -> dict[str, Any]:
    """A live test request for a stored agent gets that agent's token, which the browser never holds,
    and fills in stored repo_path, openapi_url, name, target_env, and config defaults if not provided in req."""
    agent_id = req.get("live_agent_id")
    if not agent_id:
        return req
    row = get_owned(cursor, int(agent_id), user_id)
    if not row:
        return req

    out = dict(req)
    settings = settings_of(row)
    token = settings.get("auth_token")
    if token and not out.get("auth_token"):
        out["auth_token"] = token
        if out.get("auth_type") in (None, "none"):
            out["auth_type"] = "bearer"

    if not out.get("repo_path") and row.get("repo_path"):
        out["repo_path"] = row["repo_path"]
    if not out.get("openapi_url") and row.get("openapi_url"):
        out["openapi_url"] = row["openapi_url"]
    if row.get("name"):   # the saved agent's name, never one sent with the run, so one agent has one name everywhere
        out["agent_name"] = row["name"]
    if not out.get("target_env") and row.get("target_env"):
        out["target_env"] = row["target_env"]

    cfg = settings.get("config") or {}
    key_map = [
        ("endpoint_url", "endpointUrl"),
        ("payload_template", "payloadTemplate"),
        ("response_path", "responsePath"),
        ("golden_jsonl", "goldenJsonl"),
        ("repeats", "repeats"),
        ("use_ai_judge", "useAiJudge"),
        ("include_multilingual", "includeMultilingual"),
        ("include_number_checks", "includeNumberChecks"),
        ("requires_auth", "requiresAuth"),
    ]
    for req_key, cfg_key in key_map:
        if out.get(req_key) in (None, "") and cfg.get(cfg_key) not in (None, ""):
            out[req_key] = cfg[cfg_key]

    return out



def normalize_url(url: str | None) -> str:
    """One spelling per address (scheme and host in lower case, no trailing slash), so the same endpoint
    matches however it was typed."""
    u = (url or "").strip().strip('"').strip("'")
    if not u:
        return ""
    if "//" not in u:
        u = f"https://{u}"
    p = urlparse(u)
    out = f"{(p.scheme or 'https').lower()}://{(p.netloc or '').lower()}{p.path.rstrip('/')}"
    return f"{out}?{p.query}" if p.query else out


def _saved_endpoint(row: dict[str, Any]) -> str:
    try:
        cfg = settings_of(row).get("config") or {}
    except RuntimeError:   # saved with another encryption key; its endpoint cannot be read
        return ""
    return normalize_url(cfg.get("endpointUrl"))


def find_registered_duplicate(cursor, user_id: int, openapi_url: str | None, endpoint_url: str | None) -> dict[str, Any] | None:
    """A registered agent of this user for the same address: the same OpenAPI link and the same target endpoint."""
    want_spec, want_ep = normalize_url(openapi_url), normalize_url(endpoint_url)
    cursor.execute(f"SELECT {PUBLIC_COLUMNS}, settings_enc FROM live_agents WHERE user_id = ? AND {REGISTERED} ORDER BY id", (user_id,))
    for r in cursor.fetchall():
        row = dict(r)
        if normalize_url(row["openapi_url"]) == want_spec and _saved_endpoint(row) == want_ep:
            return row
    return None


def find_for_endpoint(cursor, user_id: int, endpoint_url: str | None, openapi_url: str | None = None) -> dict[str, Any] | None:
    """The live agent of this user that a run against this endpoint belongs to, or None.

    In order: a registered agent whose saved endpoint is this one; an agent whose earlier runs hit this
    endpoint (registered agents first); a registered agent with the same OpenAPI link and no saved endpoint.
    """
    ep, spec = normalize_url(endpoint_url), normalize_url(openapi_url)
    if not ep:
        return None
    cursor.execute("SELECT id, name, openapi_url, settings_enc FROM live_agents WHERE user_id = ? ORDER BY (openapi_url IS NULL), id",
                   (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    registered = [r for r in rows if r.get("openapi_url")]
    for r in registered:
        if _saved_endpoint(r) == ep:
            return r
    cursor.execute("SELECT DISTINCT live_agent_id, endpoint_url FROM live_agent_tests WHERE user_id = ? AND live_agent_id IS NOT NULL",
                   (user_id,))
    tested: dict[int, set[str]] = {}
    for t in cursor.fetchall():
        tested.setdefault(t["live_agent_id"], set()).add(normalize_url(t["endpoint_url"]))
    for r in rows:
        if ep in tested.get(r["id"], set()):
            return r
    if spec:
        for r in registered:
            if normalize_url(r["openapi_url"]) == spec and not _saved_endpoint(r):
                return r
    return None


def rename_history(cursor, agent_id: int, name: str) -> int:
    """Gives every earlier test and the monitor of this agent its current name, so history shows one name.
    The stored result JSON carries the name too; a PDF already generated keeps the name it was made with.
    Returns how many tests were changed."""
    changed = 0
    cursor.execute("SELECT id, agent_name, full_result_json FROM live_agent_tests WHERE live_agent_id = ?", (agent_id,))
    for r in [dict(x) for x in cursor.fetchall()]:
        try:
            data = json.loads(r.get("full_result_json") or "null")
        except ValueError:
            data = None
        stale_json = isinstance(data, dict) and data.get("agent_name") != name
        if r["agent_name"] == name and not stale_json:
            continue
        if stale_json:
            data["agent_name"] = name
        cursor.execute("UPDATE live_agent_tests SET agent_name = ?, full_result_json = ? WHERE id = ?",
                       (name, json.dumps(data) if stale_json else r.get("full_result_json"), r["id"]))
        changed += 1
    cursor.execute("UPDATE live_schedules SET name = ? WHERE live_agent_id = ?", (name, agent_id))
    return changed
