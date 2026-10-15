"""Monitoring for live agents: frequent health checks all day, full tests on a schedule, and alerts.

Tables are created here with CREATE TABLE IF NOT EXISTS, under their own names, so nothing that
already exists is touched.
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from database.crypto import open_request, seal_request
from database.live_agents import fill_request

TABLES = [
    """CREATE TABLE IF NOT EXISTS live_schedules (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        name TEXT NOT NULL,
        request_json TEXT NOT NULL,
        frequency_minutes INTEGER NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        next_run_at TEXT,
        last_run_at TEXT,
        last_audit_id TEXT,
        last_score DOUBLE PRECISION,
        last_tier TEXT,
        last_critical INTEGER,
        last_could_not_run INTEGER,
        last_latency_ms DOUBLE PRECISION,
        last_error TEXT,
        created_at TEXT NOT NULL
    )""",
    """ALTER TABLE live_schedules
        ADD COLUMN IF NOT EXISTS health_minutes INTEGER DEFAULT 5,
        ADD COLUMN IF NOT EXISTS next_health_at TEXT,
        ADD COLUMN IF NOT EXISTS last_health_at TEXT,
        ADD COLUMN IF NOT EXISTS health_status TEXT,
        ADD COLUMN IF NOT EXISTS health_json TEXT,
        ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER DEFAULT 0""",
    """CREATE TABLE IF NOT EXISTS live_health_checks (
        id SERIAL PRIMARY KEY,
        schedule_id INTEGER NOT NULL,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms INTEGER
    )""",
    "CREATE INDEX IF NOT EXISTS idx_live_health_sched ON live_health_checks(schedule_id, checked_at)",
    """CREATE TABLE IF NOT EXISTS live_alerts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        schedule_id INTEGER,
        agent_name TEXT,
        audit_id TEXT,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        read_at TEXT
    )""",
]

_TIER_RANK = {"CERTIFIED": 3, "CONDITIONAL": 2, "NOT_CERTIFIED": 1, "INCONCLUSIVE": 0}
MIN_FREQUENCY_MINUTES = 15
HEALTH_KEEP_DAYS = 7
DOWN_ALERT_AFTER = 2          # checks in a row, so one blip or a cold start does not raise an alarm


def _now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_tables(conn) -> None:
    cur = conn.cursor()
    for ddl in TABLES:
        try:
            cur.execute(ddl)
            conn.commit()
        except Exception as e:
            conn.rollback()
            logging.warning("live monitor table setup: %s", e)


def compare_runs(prev: dict | None, new: dict) -> list[dict]:
    """Alerts for what got worse (or better) since the previous run. `prev` is None on the first run."""
    alerts: list[dict] = []
    name = new.get("agent_name", "Agent")
    if new.get("tier") == "INCONCLUSIVE":
        not_decided = new.get("not_decided") or 0
        if not_decided * 2 >= (new.get("could_not_run") or 0) and not_decided:
            alerts.append({"kind": "undecided", "severity": "WARNING",
                           "message": f"{name}: most tests could not be decided ({new.get('could_not_run')} of {new.get('tests_count')}). The agent answered, but these tests need the AI judge or known answers."})
        else:
            alerts.append({"kind": "unreachable", "severity": "WARNING",
                           "message": f"{name}: most tests could not run ({new.get('could_not_run')} of {new.get('tests_count')}). The agent may be down or the request format changed."})
    if not prev:
        return alerts
    p_score, n_score = prev.get("score"), new.get("trust_score")
    if p_score is not None and n_score is not None and p_score - n_score >= 10 and new.get("tier") != "INCONCLUSIVE":
        alerts.append({"kind": "score_drop", "severity": "CRITICAL" if p_score - n_score >= 25 else "WARNING",
                       "message": f"{name}: trust score fell from {p_score:g}% to {n_score:g}%."})
    p_rank, n_rank = _TIER_RANK.get(prev.get("tier") or "", None), _TIER_RANK.get(new.get("tier") or "", None)
    if p_rank is not None and n_rank is not None and new.get("tier") != "INCONCLUSIVE":
        if n_rank < p_rank:
            alerts.append({"kind": "tier_worse", "severity": "CRITICAL" if new.get("tier") == "NOT_CERTIFIED" else "WARNING",
                           "message": f"{name}: result changed from {prev['tier'].replace('_', ' ').title()} to {new['tier'].replace('_', ' ').title()}."})
        elif n_rank > p_rank and prev.get("tier") != "INCONCLUSIVE":
            alerts.append({"kind": "tier_better", "severity": "INFO",
                           "message": f"{name}: result improved to {new['tier'].replace('_', ' ').title()}."})
    if (prev.get("critical") or 0) == 0 and (new.get("critical_count") or 0) > 0:
        alerts.append({"kind": "new_critical", "severity": "CRITICAL",
                       "message": f"{name}: {new['critical_count']} new critical finding(s) appeared."})
    p_lat, n_lat = prev.get("latency_ms"), new.get("avg_latency_ms")
    if p_lat and n_lat and n_lat > 3000 and n_lat >= p_lat * 1.5:
        alerts.append({"kind": "slower", "severity": "WARNING",
                       "message": f"{name}: average answer time rose from {p_lat:.0f} ms to {n_lat:.0f} ms."})
    return alerts


def _request_of(conn, sched: dict) -> dict:
    """The schedule's stored test request with its secrets decrypted, ready to run."""
    req = open_request(json.loads(sched["request_json"] or "{}"))
    if sched.get("live_agent_id"):
        req.setdefault("live_agent_id", sched["live_agent_id"])
        req = fill_request(conn.cursor(), req, sched["user_id"])
    return req


def _row(r) -> dict:
    return dict(r) if hasattr(r, "keys") else r


def create_schedule(conn, user_id: int, name: str, frequency_minutes: int, request: dict, health_minutes: int = 5,
                    live_agent_id: int | None = None) -> int:
    """frequency_minutes is how often the full test suite runs (0 turns it off). health_minutes is how often the light check runs."""
    freq = 0 if int(frequency_minutes) <= 0 else max(MIN_FREQUENCY_MINUTES, int(frequency_minutes))
    health = max(1, int(health_minutes))
    cur = conn.cursor()
    now = _now()
    cur.execute(
        "INSERT INTO live_schedules (user_id, name, request_json, frequency_minutes, active, next_run_at, next_health_at, health_minutes, created_at, live_agent_id) "
        "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        (user_id, name, json.dumps(seal_request(request)), freq, (now + timedelta(minutes=freq)).isoformat() if freq else None,
         now.isoformat(), health, now.isoformat(), live_agent_id),
    )
    conn.commit()
    return cur.lastrowid


def list_schedules(conn, user_id: int, is_admin: bool) -> list[dict]:
    cur = conn.cursor()
    if is_admin:
        cur.execute("SELECT * FROM live_schedules ORDER BY id DESC")
    else:
        cur.execute("SELECT * FROM live_schedules WHERE user_id = ? ORDER BY id DESC", (user_id,))
    rows = cur.fetchall()
    owners: dict[int, dict] = {}
    if is_admin and rows:
        try:
            cur.execute("SELECT id, name, email FROM accounts")
            owners = {u["id"]: {"name": u["name"], "email": u["email"]} for u in cur.fetchall()}
        except Exception:
            owners = {}   # the owner is extra detail; the list still works without it
    out = []
    for r in rows:
        d = _row(r)
        if is_admin:
            d["owner"] = owners.get(d.get("user_id"))
        try:
            req = json.loads(d.pop("request_json") or "{}")
        except ValueError:
            req = {}
        if req.get("auth_token"):
            req["auth_token"] = "********"
        for u in ((req.get("access_control_config") or {}).get("users") or []):
            if isinstance(u, dict) and u.get("token"):
                u["token"] = "********"
        d["request"] = req
        out.append(d)
    return out


# Set while a scheduled run is testing, so the test itself does not raise a second alert for the same result.
_IN_SCHEDULED_RUN: ContextVar[bool] = ContextVar("in_scheduled_run", default=False)
_notify_tables_ready = False


def notify(conn, user_id: Any, agent_name: str, kind: str, severity: str, message: str, audit_id: str | None = None) -> None:
    """Adds one notification for a user. Never raises: a missing notification must not fail a test."""
    global _notify_tables_ready
    try:
        if not _notify_tables_ready:
            ensure_tables(conn)
            _notify_tables_ready = True
        conn.cursor().execute(
            "INSERT INTO live_alerts (user_id, schedule_id, agent_name, audit_id, kind, severity, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, None, agent_name, audit_id, kind, severity, message[:500], _now().isoformat()),
        )
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logging.warning("could not add notification: %s", e)


def notify_test_result(conn, user_id: Any, agent_name: str, tier: str | None, score: Any, critical: Any,
                       audit_id: str | None, live: bool) -> None:
    """A test that ended not certified or inconclusive is a notification. Passing tests are not."""
    if live and _IN_SCHEDULED_RUN.get():
        return
    what = "live test" if live else "test"
    if tier == "NOT_CERTIFIED":
        crit = f", {critical} critical finding{'' if critical == 1 else 's'}" if critical else ""
        notify(conn, user_id, agent_name, "test_failed", "CRITICAL",
               f"{agent_name} failed its {what}: score {score}%, not certified{crit}.", audit_id)
    elif tier == "INCONCLUSIVE":
        notify(conn, user_id, agent_name, "test_inconclusive", "WARNING",
               f"{agent_name}: the {what} was inconclusive. Too many checks could not run.", audit_id)


def notify_test_error(conn, user_id: Any, agent_name: str, error: str, live: bool) -> None:
    if live and _IN_SCHEDULED_RUN.get():
        return
    notify(conn, user_id, agent_name, "test_error", "CRITICAL",
           f"{agent_name}: the {'live test' if live else 'test'} could not finish. {error}".strip())


def _alert(conn, sched: dict, audit_id: str | None, a: dict) -> None:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO live_alerts (user_id, schedule_id, agent_name, audit_id, kind, severity, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sched["user_id"], sched["id"], sched["name"], audit_id, a["kind"], a["severity"], a["message"], _now().isoformat()),
    )
    conn.commit()


async def run_schedule(conn, sched: dict, run_test: Callable[[dict, int], Awaitable[dict]]) -> dict:
    """Run one schedule now, compare with its last result, raise alerts, and set the next run time."""
    req = _request_of(conn, sched)
    prev = None
    if sched.get("last_run_at"):
        prev = {"score": sched.get("last_score"), "tier": sched.get("last_tier"), "critical": sched.get("last_critical"),
                "latency_ms": sched.get("last_latency_ms")}
    cur = conn.cursor()
    now = _now()
    token = _IN_SCHEDULED_RUN.set(True)
    try:
        data = await run_test(req, sched["user_id"])
    except Exception as e:
        err = str(getattr(e, "detail", e))[:300]
        cur.execute("UPDATE live_schedules SET last_run_at = ?, next_run_at = ?, last_error = ? WHERE id = ?",
                    (now.isoformat(), (now + timedelta(minutes=sched["frequency_minutes"])).isoformat(), err, sched["id"]))
        conn.commit()
        _alert(conn, sched, None, {"kind": "run_failed", "severity": "WARNING", "message": f"{sched['name']}: the scheduled test could not start. {err}"})
        return {"ok": False, "error": err}
    finally:
        _IN_SCHEDULED_RUN.reset(token)
    alerts = compare_runs(prev, data)
    for a in alerts:
        _alert(conn, sched, data.get("audit_id"), a)
    cur.execute(
        "UPDATE live_schedules SET last_run_at = ?, next_run_at = ?, last_audit_id = ?, last_score = ?, last_tier = ?, "
        "last_critical = ?, last_could_not_run = ?, last_latency_ms = ?, last_error = NULL WHERE id = ?",
        (now.isoformat(), (now + timedelta(minutes=sched["frequency_minutes"])).isoformat(), data.get("audit_id"), data.get("trust_score"),
         data.get("tier"), data.get("critical_count"), data.get("could_not_run"), data.get("avg_latency_ms"), sched["id"]),
    )
    conn.commit()
    return {"ok": True, "audit_id": data.get("audit_id"), "alerts": len(alerts)}


async def run_due(get_conn: Callable[[], Any], run_test: Callable[[dict, int], Awaitable[dict]], limit: int = 10) -> int:
    """Run every active schedule whose time has come. Returns how many ran."""
    conn = get_conn()
    try:
        ensure_tables(conn)
        cur = conn.cursor()
        cur.execute("SELECT * FROM live_schedules WHERE active = 1 AND frequency_minutes > 0 AND (next_run_at IS NULL OR next_run_at <= ?) ORDER BY next_run_at LIMIT ?",
                    (_now().isoformat(), limit))
        due = [_row(r) for r in cur.fetchall()]
        for s in due:
            await run_schedule(conn, s, run_test)
        return len(due)
    finally:
        conn.close()


async def run_health(conn, sched: dict) -> dict:
    """One light check. Stores it, updates the status, and raises alerts only when something changes."""
    from .health import health_check

    req = _request_of(conn, sched)
    try:
        prev = json.loads(sched["health_json"]) if sched.get("health_json") else None
    except ValueError:
        prev = None
    result = await health_check(req, prev)
    now = _now()
    failures = (sched.get("consecutive_failures") or 0) + 1 if result["status"] == "DOWN" else 0
    cur = conn.cursor()

    cur.execute("INSERT INTO live_health_checks (schedule_id, checked_at, status, latency_ms) VALUES (?, ?, ?, ?)",
                (sched["id"], result["checked_at"], result["status"], result.get("latency_ms")))
    cur.execute("DELETE FROM live_health_checks WHERE schedule_id = ? AND checked_at < ?",
                (sched["id"], (now - timedelta(days=HEALTH_KEEP_DAYS)).isoformat()))

    name = sched["name"]
    prev_titles = {i["title"] for i in (prev or {}).get("issues", [])}
    was_down = (sched.get("consecutive_failures") or 0) >= DOWN_ALERT_AFTER
    if result["status"] == "DOWN" and failures == DOWN_ALERT_AFTER:
        why = next((i["detail"] for i in result["issues"] if i["severity"] == "CRITICAL"), "")
        _alert(conn, sched, None, {"kind": "down", "severity": "CRITICAL", "message": f"{name} is down. {why}".strip()})
    elif result["status"] != "DOWN" and was_down:
        _alert(conn, sched, None, {"kind": "recovered", "severity": "INFO", "message": f"{name} is back online."})
    for issue in result["issues"]:
        if issue["title"] in prev_titles or result["status"] == "DOWN":
            continue
        if issue["severity"] in ("CRITICAL", "WARNING"):
            _alert(conn, sched, None, {"kind": "health_issue", "severity": issue["severity"],
                                       "message": f"{name}: {issue['title']}. {issue['detail']}".strip()})

    cur.execute(
        "UPDATE live_schedules SET last_health_at = ?, next_health_at = ?, health_status = ?, health_json = ?, consecutive_failures = ? WHERE id = ?",
        (result["checked_at"], (now + timedelta(minutes=sched.get("health_minutes") or 5)).isoformat(), result["status"],
         json.dumps(result), failures, sched["id"]),
    )
    conn.commit()
    return result


async def run_health_due(get_conn: Callable[[], Any], limit: int = 20) -> int:
    conn = get_conn()
    try:
        ensure_tables(conn)
        cur = conn.cursor()
        cur.execute("SELECT * FROM live_schedules WHERE active = 1 AND (next_health_at IS NULL OR next_health_at <= ?) ORDER BY next_health_at LIMIT ?",
                    (_now().isoformat(), limit))
        due = [_row(r) for r in cur.fetchall()]
        for sched in due:
            try:
                await run_health(conn, sched)
            except Exception as e:
                logging.warning("health check for %s failed: %s", sched.get("name"), e)
                try:
                    conn.rollback()
                    conn.cursor().execute("UPDATE live_schedules SET next_health_at = ? WHERE id = ?",
                                          ((_now() + timedelta(minutes=sched.get("health_minutes") or 5)).isoformat(), sched["id"]))
                    conn.commit()
                except Exception:
                    pass
        return len(due)
    finally:
        conn.close()


def list_monitors(conn, user_id: int, is_admin: bool) -> list[dict]:
    """Everything the page needs: latest status and issues, uptime, recent history and the last full test."""
    out = []
    cur = conn.cursor()
    for d in list_schedules(conn, user_id, is_admin):
        health = None
        if d.get("health_json"):
            try:
                health = json.loads(d["health_json"])
            except ValueError:
                health = None
        d.pop("health_json", None)
        cur.execute("SELECT checked_at, status, latency_ms FROM live_health_checks WHERE schedule_id = ? ORDER BY checked_at DESC LIMIT 7000",
                    (d["id"],))
        rows = [(r["checked_at"], r["status"], r["latency_ms"]) for r in cur.fetchall()]
        now = _now()
        def uptime(hours: int) -> float | None:
            cutoff = (now - timedelta(hours=hours)).isoformat()
            window = [r for r in rows if r[0] >= cutoff]
            return round(sum(1 for r in window if r[1] != "DOWN") / len(window) * 100, 2) if window else None
        d["health"] = health
        d["uptime_24h"], d["uptime_7d"] = uptime(24), uptime(24 * 7)
        d["history"] = [{"at": r[0], "status": r[1]} for r in reversed(rows[:48])]
        d["avg_latency_ms"] = round(sum(r[2] for r in rows[:48] if r[2]) / max(1, len([r for r in rows[:48] if r[2]]))) if rows else None
        out.append(d)
    return out


async def loop(get_conn: Callable[[], Any], run_test: Callable[[dict, int], Awaitable[dict]], every_seconds: int = 30) -> None:
    """Background loop for long-running servers: light health checks and the scheduled full tests.
    Serverless hosts cannot keep this alive, so an external cron should call POST /api/user/live/schedules/run-due instead."""
    while True:
        try:
            await run_health_due(get_conn)
            await run_due(get_conn, run_test)
        except Exception as e:
            logging.warning("live monitor loop: %s", e)
        await asyncio.sleep(every_seconds)
