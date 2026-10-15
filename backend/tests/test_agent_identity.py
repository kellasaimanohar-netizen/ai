"""One agent, one record, one name: duplicate registration, the saved name on every run, rename, latest run and
history, simulated (Validate) runs kept apart from real ones, and the duplicate clean-up script. Runs against the
test database only; a local HTTP server stands in for the agent."""
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from backend import app
from database import get_db_connection, init_db
from database.accounts import create_account
from security import hash_password

client = TestClient(app)
PASSWORD = "identity-pass-1"
SPEC = {"openapi": "3.0.2", "info": {"title": "Calc Service"}, "paths": {"/calculate": {"post": {"requestBody": {"content": {
    "application/json": {"schema": {"required": ["amount"], "properties": {"amount": {"type": "number", "minimum": 0, "example": 100}}}}}}}}}}


def setup_module():
    init_db()


@pytest.fixture
def agent(tmp_path, monkeypatch):
    """A running calculator API and a repo folder the live test may read."""
    monkeypatch.setenv("AA_REPO_BASE", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def calc(x):\n    return x * 1.1\n")

    class H(BaseHTTPRequestHandler):
        def _send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send(200, {**SPEC, "servers": [{"url": f"http://127.0.0.1:{self.server.server_port}"}]})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            if not isinstance(body.get("amount"), (int, float)) or body["amount"] < 0:
                return self._send(422, {"detail": "bad"})
            self._send(200, {"result": round(body["amount"] * 1.1, 2)})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    yield {"openapi": f"{base}/openapi.json", "endpoint": f"{base}/calculate", "repo": str(repo)}
    srv.shutdown()


def _user():
    email = f"ident-{uuid.uuid4().hex[:8]}@example.com"
    conn = get_db_connection()
    cur = conn.cursor()
    uid = create_account(cur, "USER", email, f"Ident {email[:8]}", hash_password(PASSWORD))
    conn.commit()
    conn.close()
    token = client.post("/api/auth/login", json={"email": email, "password": PASSWORD, "role": "USER"}).json()["token"]
    return {"id": uid, "h": {"Authorization": f"Bearer {token}"}}


def _register(user, agent, name="Calc", endpoint=None):
    res = client.post("/api/user/live/agents", headers=user["h"], json={
        "name": name, "openapi_url": agent["openapi"], "repo_path": agent["repo"], "target_env": "staging",
        "config": {"agentType": "api", "endpointUrl": endpoint if endpoint is not None else agent["endpoint"]}})
    assert res.status_code == 200, res.text
    return res.json()


def _live_test(user, agent, **extra):
    body = {"openapi_url": agent["openapi"], "repo_path": agent["repo"], "agent_type": "api", **extra}
    res = client.post("/api/user/live-test", headers=user["h"], json=body)
    assert res.status_code == 200, res.text
    return res.json()["data"]


def _rows(sql, params=()):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _live_agents(user):
    return client.get("/api/user/live/agents", headers=user["h"]).json()["agents"]


# Duplicate registration

def test_the_same_address_registers_once(agent):
    u = _user()
    first = _register(u, agent)
    again = _register(u, {**agent, "openapi": agent["openapi"].replace("127.0.0.1", "127.0.0.1") + "/"}, name="Calc again")
    assert again["id"] == first["id"] and again["already_registered"] is True and again["name"] == "Calc"
    assert len(_live_agents(u)) == 1
    # another endpoint behind the same OpenAPI link is another agent
    other = _register(u, agent, name="Compare", endpoint=agent["endpoint"].replace("/calculate", "/compare"))
    assert other["id"] != first["id"] and not other.get("already_registered")
    assert len(_live_agents(u)) == 2


def test_the_same_address_for_two_users_is_two_agents(agent):
    a, b = _user(), _user()
    assert _register(a, agent)["id"] != _register(b, agent)["id"]


# The name always comes from the saved agent

def test_a_run_uses_the_saved_name_not_the_request_name(agent):
    u = _user()
    reg = _register(u, agent)
    data = _live_test(u, agent, live_agent_id=reg["id"], agent_name="Something Else Entirely")
    assert data["agent_name"] == "Calc"
    row = _rows("SELECT agent_name, live_agent_id, full_result_json FROM live_agent_tests WHERE audit_id = ?", (data["audit_id"],))[0]
    assert row["agent_name"] == "Calc" and row["live_agent_id"] == reg["id"]
    assert json.loads(row["full_result_json"])["agent_name"] == "Calc"
    hist = client.get(f"/api/user/live/agents/{reg['id']}/history", headers=u["h"]).json()
    assert {r["agent_name"] for r in hist["history"]} == {"Calc"}


def test_a_run_without_an_agent_id_joins_the_agent_for_its_endpoint(agent):
    u = _user()
    reg = _register(u, agent)
    data = _live_test(u, agent, agent_name="Calc Agent v2")
    assert data["agent_name"] == "Calc"
    rows = _rows("SELECT id, name FROM live_agents WHERE user_id = ?", (u["id"],))
    assert [r["id"] for r in rows] == [reg["id"]], "a second agent record was created"
    assert _rows("SELECT live_agent_id FROM live_agent_tests WHERE audit_id = ?", (data["audit_id"],))[0]["live_agent_id"] == reg["id"]


def test_two_unregistered_runs_against_one_endpoint_make_one_agent(agent):
    u = _user()
    _live_test(u, agent, agent_name="Loan Agent")
    _live_test(u, agent, agent_name="AI Loan Advisor Agent API")
    rows = _rows("SELECT id, name FROM live_agents WHERE user_id = ?", (u["id"],))
    assert len(rows) == 1 and rows[0]["name"] == "Loan Agent"
    names = {r["agent_name"] for r in _rows("SELECT agent_name FROM live_agent_tests WHERE user_id = ?", (u["id"],))}
    assert names == {"Loan Agent"}


def test_renaming_an_agent_renames_its_history(agent):
    u = _user()
    reg = _register(u, agent)
    data = _live_test(u, agent, live_agent_id=reg["id"])
    res = client.put(f"/api/user/live/agents/{reg['id']}", headers=u["h"], json={"name": "Calculator"})
    assert res.status_code == 200, res.text
    tests = client.get("/api/user/tests", headers=u["h"]).json()["tests"]
    assert {t["agent_name"] for t in tests if t["audit_id"] == data["audit_id"]} == {"Calculator"}
    detail_id = next(t["id"] for t in tests if t["audit_id"] == data["audit_id"])
    assert client.get(f"/api/user/tests/{detail_id}", headers=u["h"]).json()["test"]["full_result"]["agent_name"] == "Calculator"
    # a rename onto another agent's name is refused, not a server error
    other = _register(u, agent, name="Other", endpoint=agent["endpoint"] + "-v2")
    assert client.put(f"/api/user/live/agents/{other['id']}", headers=u["h"], json={"name": "calculator"}).status_code == 409


# Latest run and history

def test_the_agent_shows_its_latest_run_and_keeps_older_ones(agent):
    u = _user()
    reg = _register(u, agent)
    first = _live_test(u, agent, live_agent_id=reg["id"])
    second = _live_test(u, agent, live_agent_id=reg["id"])
    listed = next(a for a in _live_agents(u) if a["id"] == reg["id"])
    assert listed["last_result"]["audit_id"] == second["audit_id"]
    hist = client.get(f"/api/user/live/agents/{reg['id']}/history", headers=u["h"]).json()["history"]
    assert [h["audit_id"] for h in hist] == [second["audit_id"], first["audit_id"]]
    grouped = [g for g in client.get("/api/user/agents", headers=u["h"]).json()["agents"] if g["name"] == "Calc"]
    assert len(grouped) == 1
    assert grouped[0]["total_tests"] == 2 and grouped[0]["latest_audit_id"] == second["audit_id"]


def test_runs_of_a_removed_live_agent_stay_in_history_but_are_not_an_agent(agent):
    u = _user()
    data = _live_test(u, agent, agent_name="Gone Agent")
    aid = _rows("SELECT live_agent_id FROM live_agent_tests WHERE audit_id = ?", (data["audit_id"],))[0]["live_agent_id"]
    conn = get_db_connection()
    conn.cursor().execute("DELETE FROM live_agents WHERE id = ?", (aid,))
    conn.commit()
    conn.close()
    assert data["audit_id"] in [t["audit_id"] for t in client.get("/api/user/tests", headers=u["h"]).json()["tests"]]
    assert "Gone Agent" not in [g["name"] for g in client.get("/api/user/agents", headers=u["h"]).json()["agents"]]


# Simulated (Validate) results are kept apart

def _normal_run(user_id, name, mode, score, tier):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""INSERT INTO normal_agent_tests (audit_id, user_id, agent_name, mode, tier, trust_score, created_at, full_result_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, '{}')""",
                (f"id-{uuid.uuid4().hex[:10]}", user_id, name, mode, tier, score, f"2026-10-0{3 if mode == 'certify' else 4}T00:00:00Z"))
    conn.commit()
    conn.close()


def test_simulated_runs_are_labeled_and_not_counted_as_real(agent):
    u = _user()
    conn = get_db_connection()
    conn.cursor().execute("INSERT INTO agents (user_id, name, canonical_name, created_at, updated_at) VALUES (?, 'Sim Agent', 'Sim Agent', '2026-10-01', '2026-10-01')",
                          (u["id"],))
    conn.commit()
    conn.close()
    _normal_run(u["id"], "Sim Agent", "certify", 70.0, "CONDITIONAL")
    _normal_run(u["id"], "Sim Agent", "validate", 100.0, "FRAMEWORK_VALIDATION_ONLY")

    kpis = client.get("/api/user/dashboard", headers=u["h"]).json()["kpis"]
    assert kpis["total_tests"] == 1 and kpis["simulated_tests"] == 1 and kpis["average_score"] == 70.0

    g = next(a for a in client.get("/api/user/agents", headers=u["h"]).json()["agents"] if a["name"] == "Sim Agent")
    assert g["total_tests"] == 1 and g["latest_score"] == 70.0 and g["simulated_count"] == 1

    tests = client.get("/api/user/tests", headers=u["h"]).json()["tests"]
    sim = next(t for t in tests if t["mode"] == "validate")
    real = next(t for t in tests if t["mode"] == "certify")
    assert sim["simulated"] is True and sim["version_label"] == "Simulated" and sim["is_latest"] is False
    assert real["simulated"] is False and real["version"] == "v1" and real["is_latest"] is True


# The duplicate clean-up script

def test_cleanup_merges_shells_and_removes_only_what_it_is_told(agent):
    from scripts.merge_duplicate_live_agents import clean_up

    u, other_user = _user(), _user()
    reg = _register(u, agent, name="Loan")
    conn = get_db_connection()
    cur = conn.cursor()

    def shell(user_id, name):
        cur.execute("INSERT INTO live_agents (user_id, name, created_at, updated_at) VALUES (?, ?, '2026-09-30', '2026-09-30')", (user_id, name))
        cur.execute("SELECT id FROM live_agents WHERE user_id = ? AND name = ?", (user_id, name))
        return cur.fetchone()["id"]

    def run(user_id, agent_id, name):
        audit = f"cleanup-{uuid.uuid4().hex[:10]}"
        cur.execute("""INSERT INTO live_agent_tests (audit_id, user_id, live_agent_id, agent_name, tier, trust_score, endpoint_url,
                       openapi_url, created_at, full_result_json) VALUES (?, ?, ?, ?, 'NOT_CERTIFIED', 5, ?, ?, '2026-09-30T20:00:00Z', ?)""",
                    (audit, user_id, agent_id, name, agent["endpoint"], agent["openapi"], json.dumps({"agent_name": name})))
        return audit

    dup = shell(u["id"], "Loan Agent")
    moved = [run(u["id"], dup, "Loan Agent"), run(u["id"], dup, "Loan Agent")]
    renamed = run(u["id"], reg["id"], "AI Loan Advisor Agent API")
    lone = shell(other_user["id"], "Loan Agent")
    kept = run(other_user["id"], lone, "Loan Agent")
    untouched = shell(other_user["id"], "Keep Me")
    cur.execute("""INSERT INTO live_schedules (user_id, name, request_json, frequency_minutes, active, created_at)
                   VALUES (?, 'Loan', ?, 1440, 1, '2026-10-01')""", (u["id"], json.dumps({"openapi_url": agent["openapi"], "agent_name": "Loan"})))
    conn.commit()

    preview = clean_up(conn, {lone}, apply=False)
    assert any("Merged" in line for line in preview) and any("Removed" in line for line in preview)
    assert _rows("SELECT COUNT(*) AS n FROM live_agents WHERE id IN (?, ?)", (dup, lone))[0]["n"] == 2, "the preview saved changes"

    clean_up(conn, {lone}, apply=True)
    conn.close()
    assert _rows("SELECT id FROM live_agents WHERE id IN (?, ?)", (dup, lone)) == []
    assert _rows("SELECT id FROM live_agents WHERE id = ?", (untouched,)), "an agent it was not told to remove was removed"
    runs = {r["audit_id"]: r for r in _rows("SELECT audit_id, live_agent_id, agent_name, full_result_json FROM live_agent_tests WHERE audit_id IN (?, ?, ?, ?)",
                                              (*moved, renamed, kept))}
    for a in moved + [renamed]:
        assert runs[a]["live_agent_id"] == reg["id"] and runs[a]["agent_name"] == "Loan"
        assert json.loads(runs[a]["full_result_json"])["agent_name"] == "Loan"
    assert runs[kept]["live_agent_id"] is None and runs[kept]["agent_name"] == "Loan Agent", "history was deleted or changed"
    sched = _rows("SELECT live_agent_id, request_json FROM live_schedules WHERE user_id = ?", (u["id"],))[0]
    assert sched["live_agent_id"] == reg["id"] and json.loads(sched["request_json"])["live_agent_id"] == reg["id"]
    assert "Loan Agent" not in [g["name"] for g in client.get("/api/user/agents", headers=other_user["h"]).json()["agents"]]
