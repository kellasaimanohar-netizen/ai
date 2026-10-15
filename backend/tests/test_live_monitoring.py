"""Tests for 24/7 monitoring: health checks, status changes, alerts, uptime. A local HTTP server stands in
for the agent and an in-memory SQLite database stands in for the real one, so nothing external is touched."""
import asyncio
import json
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live_testing import health, scheduler


def _run(coro):
    return asyncio.run(coro)


class Agent:
    """A fake loan API whose behavior the test can change while it runs."""

    def __init__(self):
        self.mode = "up"
        self.routes = ["/calculate", "/compare"]
        self.emi = 984.74
        self.delay = 0.0
        outer = self

        class H(BaseHTTPRequestHandler):
            def _send(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/openapi.json":
                    paths = {r: {"post": {"requestBody": {"content": {"application/json": {"schema": {
                        "required": ["amount"], "properties": {"amount": {"type": "number", "example": 100000}}}}}}}} for r in outer.routes}
                    return self._send(200, {"openapi": "3.0.2", "info": {"title": "Loan Advisor"}, "paths": paths,
                                            "servers": [{"url": f"http://127.0.0.1:{outer.port}"}]})
                self._send(200, {"ok": 1})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                if outer.delay:
                    import time
                    time.sleep(outer.delay)
                if outer.mode == "down":
                    return self._send(500, {"error": "boom"})
                self._send(200, {"monthly_emi": outer.emi})

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def request(self):
        return {"openapi_url": f"http://127.0.0.1:{self.port}/openapi.json", "agent_type": "api"}

    def stop(self):
        self.srv.shutdown()


def test_healthy_agent_is_up():
    a = Agent()
    try:
        r = _run(health.health_check(a.request))
    finally:
        a.stop()
    assert r["status"] == "UP" and r["http_status"] == 200 and r["issues"] == []
    assert "POST /calculate" in r["routes"]


def test_server_error_is_down():
    a = Agent()
    a.mode = "down"
    try:
        r = _run(health.health_check(a.request))
    finally:
        a.stop()
    assert r["status"] == "DOWN"
    assert any("server error" in i["title"] for i in r["issues"])


def test_unreachable_agent_is_down():
    r = _run(health.health_check({"openapi_url": "http://127.0.0.1:1/openapi.json", "endpoint_url": "http://127.0.0.1:1/calculate"}))
    assert r["status"] == "DOWN"


def test_wrong_known_answer_is_degraded_with_a_clear_issue():
    a = Agent()
    a.emi = 1200.0
    req = {**a.request, "golden_cases": [{"input": {"amount": 100000}, "expected": 984.74, "match": "number", "path": "monthly_emi", "tolerance": 0.01}]}
    try:
        r = _run(health.health_check(req))
    finally:
        a.stop()
    assert r["status"] == "DEGRADED"
    assert any(i["title"] == "A known answer is wrong" and i["severity"] == "CRITICAL" for i in r["issues"])


def test_slow_answer_is_degraded(monkeypatch):
    monkeypatch.setattr(health, "SLOW_MS", 50)
    a = Agent()
    a.delay = 0.2
    try:
        r = _run(health.health_check(a.request))
    finally:
        a.stop()
    assert r["status"] == "DEGRADED" and any("slow" in i["title"] for i in r["issues"])


def test_removed_route_is_reported_as_critical():
    a = Agent()
    try:
        first = _run(health.health_check(a.request))
        a.routes = ["/calculate"]
        second = _run(health.health_check(a.request, first))
    finally:
        a.stop()
    gone = [i for i in second["issues"] if i["title"] == "Routes were removed"]
    assert gone and gone[0]["severity"] == "CRITICAL" and "/compare" in gone[0]["detail"]


def test_repo_change_is_noticed(tmp_path):
    (tmp_path / "agent.py").write_text("print(1)")
    fp1 = health.repo_fingerprint(str(tmp_path))
    (tmp_path / "agent.py").write_text("print(22222)")
    fp2 = health.repo_fingerprint(str(tmp_path))
    assert fp1 and fp2 and fp1 != fp2
    assert health.repo_fingerprint("https://github.com/x/y") is None


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""CREATE TABLE live_schedules (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, request_json TEXT,
                 frequency_minutes INTEGER, active INTEGER DEFAULT 1, next_run_at TEXT, last_run_at TEXT, last_audit_id TEXT,
                 last_score REAL, last_tier TEXT, last_critical INTEGER, last_could_not_run INTEGER, last_latency_ms REAL, last_error TEXT,
                 created_at TEXT, health_minutes INTEGER DEFAULT 5, next_health_at TEXT, last_health_at TEXT, health_status TEXT,
                 health_json TEXT, consecutive_failures INTEGER DEFAULT 0, live_agent_id INTEGER)""")
    c.execute("CREATE TABLE live_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, schedule_id INTEGER, agent_name TEXT, audit_id TEXT, kind TEXT, severity TEXT, message TEXT, created_at TEXT, read_at TEXT)")
    c.execute("CREATE TABLE live_health_checks (id INTEGER PRIMARY KEY AUTOINCREMENT, schedule_id INTEGER, checked_at TEXT, status TEXT, latency_ms INTEGER)")
    conn.commit()
    return conn


def _sched(conn, request):
    scheduler.create_schedule(conn, 1, "Loan", 0, request, 5)
    return dict(conn.execute("SELECT * FROM live_schedules WHERE id = 1").fetchone())


def _alerts(conn):
    return [r["kind"] for r in conn.execute("SELECT kind FROM live_alerts ORDER BY id")]


def test_alerts_fire_once_when_down_and_again_on_recovery():
    a = Agent()
    conn = _db()
    sched = _sched(conn, a.request)
    try:
        def step():
            nonlocal sched
            _run(scheduler.run_health(conn, sched))
            sched = dict(conn.execute("SELECT * FROM live_schedules WHERE id = 1").fetchone())

        step()                       # up
        a.mode = "down"
        step()                       # first failure: no alarm yet
        assert "down" not in _alerts(conn)
        step()                       # second failure in a row: alarm
        step()                       # still down: no second alarm
        assert _alerts(conn).count("down") == 1
        a.mode = "up"
        step()
        assert _alerts(conn).count("recovered") == 1
        assert sched["health_status"] == "UP" and sched["consecutive_failures"] == 0
    finally:
        a.stop()


def test_uptime_and_history_are_reported():
    a = Agent()
    conn = _db()
    sched = _sched(conn, a.request)
    try:
        _run(scheduler.run_health(conn, sched))
        a.mode = "down"
        sched = dict(conn.execute("SELECT * FROM live_schedules WHERE id = 1").fetchone())
        _run(scheduler.run_health(conn, sched))
    finally:
        a.stop()
    m = scheduler.list_monitors(conn, 1, True)[0]
    assert m["uptime_24h"] == 50.0
    assert [h["status"] for h in m["history"]] == ["UP", "DOWN"]
    assert m["health"]["status"] == "DOWN"
