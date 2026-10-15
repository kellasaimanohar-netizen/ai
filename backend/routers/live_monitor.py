"""Live testing v2 endpoints: agent types and packs, golden validation, schedules and alerts."""
from __future__ import annotations

import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from database import get_db_connection
from database import live_agents as live_agents_db
from database.activity import log_activity
from live_testing import packs, scans, scheduler
from security import check_outbound_url, create_access_token, get_current_user
from routers.user_api import LiveAgentTestRequest, execute_live_agent_test

router = APIRouter(prefix="/api/user/live", tags=["live-monitor"])

_tables_ready = False


def _conn():
    global _tables_ready
    conn = get_db_connection()
    if not _tables_ready:
        scheduler.ensure_tables(conn)
        _tables_ready = True
    return conn


async def _run_test(req: dict, user_id: int) -> dict:
    """Run one live test as the schedule's owner and return the result data."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, role FROM accounts WHERE id = ?", (user_id,))
        u = cur.fetchone()
    finally:
        conn.close()
    if not u:
        raise HTTPException(status_code=400, detail="The user that owns this schedule no longer exists.")
    token = create_access_token(user_id=u["id"], email=u["email"], role=u["role"], name=u["name"])
    res = await execute_live_agent_test(LiveAgentTestRequest(**req), f"Bearer {token}")
    return res["data"]


@router.get("/agent-types")
def agent_types():
    return {"types": [{"id": k, **v, "tests": len(packs.pack_for(k))} for k, v in packs.AGENT_TYPES.items()]}


@router.get("/pack/{agent_type}")
def pack_preview(agent_type: str):
    if agent_type not in packs.AGENT_TYPES:
        raise HTTPException(status_code=404, detail="Unknown agent type.")
    cases = packs.pack_for(agent_type)
    note = "Tests for this type are built from your OpenAPI spec and your known answers when you run." if agent_type == "api" else None
    return {"agent_type": agent_type, "note": note,
            "cases": [{"id": c["id"], "name": c["name"], "category": c["category"], "severity": c["severity"],
                       "expected_behavior": c["expected_behavior"]} for c in cases]}


class GoldenCheck(BaseModel):
    jsonl: str


@router.post("/golden/validate")
def golden_validate(body: GoldenCheck, current_user: dict = Depends(get_current_user)):
    try:
        rows = packs.golden_from_jsonl(body.jsonl)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"count": len(rows)}


class ScheduleIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=120)          # optional: taken from the OpenAPI title or the host
    live_agent_id: Optional[int] = None                                # the live agent this monitor watches
    frequency_minutes: int = Field(default=0, ge=0, le=60 * 24 * 30)   # full test suite, 0 = off
    health_minutes: int = Field(default=5, ge=1, le=60 * 24)           # light health check
    request: Dict[str, Any]


def _name_from(request: dict) -> str:
    """A readable name when none was given: the host of the OpenAPI link or endpoint."""
    from urllib.parse import urlparse
    url = (request.get("openapi_url") or request.get("endpoint_url") or "").strip()
    host = urlparse(url if "//" in url else f"https://{url}").hostname if url else None
    return host or "Live agent"


@router.get("/monitors")
def monitors(current_user: dict = Depends(get_current_user)):
    """Each monitored agent with its latest health, issues, uptime and history."""
    conn = _conn()
    try:
        return {"monitors": scheduler.list_monitors(conn, current_user["id"], current_user.get("role") == "ADMIN")}
    finally:
        conn.close()


@router.post("/monitors/{sid}/check-now")
async def monitor_check_now(sid: int, current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        sched = _owned(conn, sid, current_user)
        return await scheduler.run_health(conn, sched)
    finally:
        conn.close()


@router.get("/schedules")
def schedules(current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        return {"schedules": scheduler.list_schedules(conn, current_user["id"], current_user.get("role") == "ADMIN")}
    finally:
        conn.close()


@router.post("/schedules")
def schedule_create(body: ScheduleIn, current_user: dict = Depends(get_current_user)):
    _not_admin(current_user)
    agent_name = None
    if body.live_agent_id:   # someone else's agent is "not found", before anything about the request is checked
        _c = _conn()
        try:
            owned = live_agents_db.get_owned(_c.cursor(), body.live_agent_id, current_user["id"])
            if not owned:
                raise HTTPException(status_code=404, detail="Live agent not found.")
            agent_name = owned["name"]
        finally:
            _c.close()
    for key, what in (("endpoint_url", "endpoint"), ("openapi_url", "OpenAPI address")):
        if (body.request.get(key) or "").strip():
            check_outbound_url(body.request[key], what)
    try:
        LiveAgentTestRequest(**body.request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"The test settings are not valid: {e}")
    repo_arg = (body.request.get("repo_path") or "").strip()
    if repo_arg:
        _dir, repo_err = scans.resolve_repo(repo_arg)
        if repo_err and not (body.request.get("endpoint_url") or body.request.get("openapi_url")):
            raise HTTPException(status_code=400, detail=repo_err)
    conn = _conn()
    try:
        cur = conn.cursor()
        name = agent_name or (body.name or "").strip() or (body.request.get("agent_name") or "").strip() or _name_from(body.request)
        request = {**body.request, "live_agent_id": body.live_agent_id} if body.live_agent_id else body.request
        sid = scheduler.create_schedule(conn, current_user["id"], name, body.frequency_minutes, request, body.health_minutes,
                                        live_agent_id=body.live_agent_id)
        log_activity(cur, current_user, "MONITOR_CREATED", f"Turned on monitoring for '{name}'", entity_type="live_schedule", entity_id=sid)
        conn.commit()
    finally:
        conn.close()
    return {"id": sid}


def _not_admin(user: dict) -> None:
    """Admins watch live agents; only the users who own them test or change them."""
    if user.get("role") == "ADMIN":
        raise HTTPException(status_code=403, detail="Admins can view live agents but cannot test or change them.")


def _owned(conn, sid: int, user: dict) -> dict:
    _not_admin(user)
    cur = conn.cursor()
    cur.execute("SELECT * FROM live_schedules WHERE id = ?", (sid,))
    r = cur.fetchone()
    if not r or r["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return dict(r)


class LiveAgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    repo_path: Optional[str] = Field(default=None, max_length=1000)
    openapi_url: str = Field(min_length=1, max_length=2000)
    target_env: str = Field(default="production", pattern="^(production|staging|development)$")
    auth_token: Optional[str] = Field(default=None, max_length=4000)   # stored encrypted, never sent back
    config: Dict[str, Any] = Field(default_factory=dict)
    last_audit_id: Optional[str] = Field(default=None, max_length=100)   # links an earlier result when moving a list from the browser


class LiveAgentUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    target_env: Optional[str] = Field(default=None, pattern="^(production|staging|development)$")
    auth_token: Optional[str] = Field(default=None, max_length=4000)   # "" removes the stored token
    config: Optional[Dict[str, Any]] = None


def _live_agent_out(conn, row: dict) -> dict:
    """What the page shows for a live agent: the settings without the token, and the latest result."""
    out = {k: v for k, v in row.items() if k != "settings_enc"}
    try:
        settings = live_agents_db.settings_of(row)
        out["settings_unreadable"] = False
    except RuntimeError:   # saved with a different DATA_ENCRYPTION_KEY; show the agent, not its settings
        settings = {}
        out["settings_unreadable"] = True
    out["config"] = settings.get("config") or {}
    out["has_auth_token"] = bool(settings.get("auth_token"))
    out["last_result"] = None
    out["last_tested_at"] = None
    if row.get("last_test_id"):
        cur = conn.cursor()
        cur.execute("SELECT full_result_json, created_at FROM live_agent_tests WHERE id = ?", (row["last_test_id"],))
        r = cur.fetchone()
        if r:
            try:
                out["last_result"] = json.loads(r["full_result_json"] or "null")
            except ValueError:
                pass
            out["last_tested_at"] = r["created_at"]
    for k in ("created_at", "updated_at"):
        if out.get(k) is not None and not isinstance(out[k], str):
            out[k] = out[k].isoformat()
    return out


@router.get("/agents")
def live_agents_list(current_user: dict = Depends(get_current_user)):
    """The signed-in user's live agents. Admins see every user's, with the owner, and cannot change them."""
    conn = _conn()
    try:
        cur = conn.cursor()
        if current_user.get("role") == "ADMIN":
            cur.execute(f"SELECT l.{live_agents_db.PUBLIC_COLUMNS.replace(', ', ', l.')}, l.settings_enc, p.name AS owner_name, p.email AS owner_email "
                        f"FROM live_agents l JOIN accounts p ON p.id = l.user_id WHERE l.{live_agents_db.REGISTERED} ORDER BY l.id DESC")
        else:
            cur.execute(f"SELECT {live_agents_db.PUBLIC_COLUMNS}, settings_enc FROM live_agents WHERE user_id = ? AND {live_agents_db.REGISTERED} ORDER BY id DESC",
                        (current_user["id"],))
        rows = [dict(r) for r in cur.fetchall()]
        return {"agents": [_live_agent_out(conn, r) for r in rows]}
    finally:
        conn.close()


@router.get("/agents/{aid}/history")
def live_agent_history(aid: int, limit: int = 10, current_user: dict = Depends(get_current_user)):
    """The most recent test runs for one live agent — manual tests and the scheduled monitor's own
    full tests alike, since both write to live_agent_tests. The owning user sees their agent's
    history; admins can see any agent's, the same read-only access they have everywhere else here."""
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, name FROM live_agents WHERE id = ?", (aid,))
        agent = cur.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Live agent not found.")
        agent = dict(agent)
        if current_user.get("role") != "ADMIN" and agent["user_id"] != current_user["id"]:
            raise HTTPException(status_code=404, detail="Live agent not found.")

        capped_limit = max(1, min(limit, 50))
        cur.execute("""
            SELECT id, audit_id, agent_name, mode, trust_score, tier,
                   critical_count, warning_count, pass_count, duration_ms, created_at
            FROM live_agent_tests
            WHERE live_agent_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        """, (aid, capped_limit))
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["agent_name"] = agent["name"]
            if r.get("created_at") is not None and not isinstance(r["created_at"], str):
                r["created_at"] = r["created_at"].isoformat()
        return {"agent_name": agent["name"], "history": rows, "count": len(rows)}
    finally:
        conn.close()


@router.post("/agents")
def live_agent_create(body: LiveAgentIn, current_user: dict = Depends(get_current_user)):
    _not_admin(current_user)
    check_outbound_url(body.openapi_url, "OpenAPI address")
    if ((body.config or {}).get("endpointUrl") or "").strip():
        check_outbound_url(body.config["endpointUrl"], "endpoint")
    conn = _conn()
    try:
        cur = conn.cursor()
        name, now = body.name.strip(), datetime.now(timezone.utc).isoformat()
        existing = live_agents_db.find_registered_duplicate(cur, current_user["id"], body.openapi_url, (body.config or {}).get("endpointUrl"))
        if existing:   # the same address is one agent: return it rather than add a second record
            out = _live_agent_out(conn, existing)
            out["already_registered"] = True
            return out
        cur.execute("SELECT id, openapi_url FROM live_agents WHERE user_id = ? AND lower(name) = lower(?)",
                    (current_user["id"], name))
        same = cur.fetchone()
        if same and same["openapi_url"]:
            raise HTTPException(status_code=409, detail=f"You already have a live agent named '{name}'. Choose another name.")
        if same:   # an agent a live test created by name becomes this registered live agent, keeping its history
            aid = same["id"]
        else:
            cur.execute("INSERT INTO live_agents (user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                        (current_user["id"], name, now, now))
            aid = cur.lastrowid
        cur.execute("UPDATE live_agents SET repo_path = ?, openapi_url = ?, target_env = ?, settings_enc = ?, updated_at = ? WHERE id = ?",
                    ((body.repo_path or "").strip() or None, body.openapi_url.strip(), body.target_env,
                     live_agents_db.seal_settings(body.auth_token, body.config), now, aid))
        if body.last_audit_id:   # only a result this user produced
            cur.execute("UPDATE live_agents SET last_test_id = (SELECT id FROM live_agent_tests WHERE audit_id = ? AND user_id = ?) WHERE id = ?",
                        (body.last_audit_id, current_user["id"], aid))
        log_activity(cur, current_user, "LIVE_AGENT_CREATED", f"Added live agent '{body.name.strip()}' ({body.openapi_url.strip()})",
                     entity_type="live_agent", entity_id=aid)
        conn.commit()
        return _live_agent_out(conn, live_agents_db.get_owned(cur, aid, current_user["id"]))
    finally:
        conn.close()


@router.put("/agents/{aid}")
def live_agent_update(aid: int, body: LiveAgentUpdate, current_user: dict = Depends(get_current_user)):
    _not_admin(current_user)
    conn = _conn()
    try:
        cur = conn.cursor()
        row = live_agents_db.get_owned(cur, aid, current_user["id"])
        if not row:
            raise HTTPException(status_code=404, detail="Live agent not found.")
        settings = live_agents_db.settings_of(row)
        token = settings.get("auth_token") if body.auth_token is None else body.auth_token
        config = settings.get("config") if body.config is None else body.config
        if ((config or {}).get("endpointUrl") or "").strip():
            check_outbound_url(config["endpointUrl"], "endpoint")
        new_name = (body.name or row["name"]).strip()
        if new_name.lower() != row["name"].lower():
            cur.execute("SELECT id FROM live_agents WHERE user_id = ? AND lower(name) = lower(?) AND id <> ?", (current_user["id"], new_name, aid))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail=f"You already have a live agent named '{new_name}'. Choose another name.")
        cur.execute("UPDATE live_agents SET name = ?, target_env = ?, settings_enc = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                    (new_name, body.target_env or row["target_env"],
                     live_agents_db.seal_settings(token, config), datetime.now(timezone.utc).isoformat(), aid, current_user["id"]))
        if new_name != row["name"]:
            live_agents_db.rename_history(cur, aid, new_name)
        log_activity(cur, current_user, "LIVE_AGENT_UPDATED", f"Changed live agent '{row['name']}'", entity_type="live_agent", entity_id=aid)
        conn.commit()
        return _live_agent_out(conn, live_agents_db.get_owned(cur, aid, current_user["id"]))
    finally:
        conn.close()


@router.delete("/agents/{aid}")
def live_agent_delete(aid: int, current_user: dict = Depends(get_current_user)):
    """Removes the live agent and its monitor. Its past test results stay in the test history."""
    _not_admin(current_user)
    conn = _conn()
    try:
        cur = conn.cursor()
        row = live_agents_db.get_owned(cur, aid, current_user["id"])
        if not row:
            raise HTTPException(status_code=404, detail="Live agent not found.")
        cur.execute("DELETE FROM live_agents WHERE id = ? AND user_id = ?", (aid, current_user["id"]))
        log_activity(cur, current_user, "LIVE_AGENT_DELETED", f"Removed live agent '{row['name']}'", entity_type="live_agent", entity_id=aid)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.delete("/schedules/{sid}")
def schedule_delete(sid: int, current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        s = _owned(conn, sid, current_user)
        cur = conn.cursor()
        cur.execute("DELETE FROM live_schedules WHERE id = ?", (sid,))
        log_activity(cur, current_user, "MONITOR_DELETED", f"Stopped monitoring '{s['name']}'", entity_type="live_schedule", entity_id=sid)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post("/schedules/{sid}/active")
def schedule_active(sid: int, active: bool, current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        s = _owned(conn, sid, current_user)
        cur = conn.cursor()
        cur.execute("UPDATE live_schedules SET active = ? WHERE id = ?", (1 if active else 0, sid))
        log_activity(cur, current_user, "MONITOR_RESUMED" if active else "MONITOR_PAUSED",
                     f"{'Resumed' if active else 'Paused'} monitoring of '{s['name']}'", entity_type="live_schedule", entity_id=sid)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post("/schedules/{sid}/run-now")
async def schedule_run_now(sid: int, current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        s = _owned(conn, sid, current_user)
        return await scheduler.run_schedule(conn, s, _run_test)
    finally:
        conn.close()


@router.post("/schedules/run-due")
async def schedules_run_due(x_cron_secret: Optional[str] = Header(default=None)):
    """For an external cron (for example Vercel Cron or GitHub Actions) on hosts that cannot run a background loop.
    Requires the CRON_SECRET environment variable, sent in the X-Cron-Secret header."""
    secret = os.environ.get("CRON_SECRET", "")
    if not secret or not x_cron_secret or not hmac.compare_digest(secret, x_cron_secret):
        raise HTTPException(status_code=401, detail="Invalid or missing cron secret.")
    _conn().close()
    return {"health_checks": await scheduler.run_health_due(get_db_connection),
            "ran": await scheduler.run_due(get_db_connection, _run_test)}


@router.get("/alerts")
def alerts(unread_only: bool = False, current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        cur = conn.cursor()
        q = "SELECT * FROM live_alerts WHERE user_id = ?" + (" AND read_at IS NULL" if unread_only else "") + " ORDER BY id DESC LIMIT 100"
        cur.execute(q, (current_user["id"],))
        rows = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) FROM live_alerts WHERE user_id = ? AND read_at IS NULL", (current_user["id"],))
        unread = cur.fetchone()[0]
    finally:
        conn.close()
    return {"alerts": rows, "unread": unread}


@router.post("/alerts/read-all")
def alerts_read_all(current_user: dict = Depends(get_current_user)):
    conn = _conn()
    try:
        conn.cursor().execute("UPDATE live_alerts SET read_at = ? WHERE user_id = ? AND read_at IS NULL",
                              (datetime.now(timezone.utc).isoformat(), current_user["id"]))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post("/alerts/read-agent")
def alerts_read_agent(agent_name: str, current_user: dict = Depends(get_current_user)):
    """Marks only this one agent's unread alerts as read, so clearing one agent's alerts
    does not also hide another agent's unread problems."""
    conn = _conn()
    try:
        conn.cursor().execute(
            "UPDATE live_alerts SET read_at = ? WHERE user_id = ? AND agent_name = ? AND read_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), current_user["id"], agent_name),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.delete("/alerts/{alert_id}")
def alerts_delete(alert_id: int, current_user: dict = Depends(get_current_user)):
    """Clears one notification. Only the owner's own notifications can be cleared."""
    conn = _conn()
    try:
        conn.cursor().execute("DELETE FROM live_alerts WHERE id = ? AND user_id = ?", (alert_id, current_user["id"]))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.delete("/alerts")
def alerts_clear(current_user: dict = Depends(get_current_user)):
    """Clears all of this user's notifications."""
    conn = _conn()
    try:
        conn.cursor().execute("DELETE FROM live_alerts WHERE user_id = ?", (current_user["id"],))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}
