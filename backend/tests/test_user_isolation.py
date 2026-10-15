"""Many users: each sees only their own agents, tests, reports and live agents; admins see everything and change nothing."""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend import app
from database import get_db_connection, init_db
from database.accounts import create_account
from security import hash_password

client = TestClient(app)
PASSWORD = "isolation-pass-1"


def setup_module():
    init_db()


def _user():
    email = f"iso-{uuid.uuid4().hex[:8]}@example.com"
    conn = get_db_connection()
    cur = conn.cursor()
    uid = create_account(cur, "USER", email, f"Iso {email[:8]}", hash_password(PASSWORD))
    conn.commit()
    conn.close()
    token = client.post("/api/auth/login", json={"email": email, "password": PASSWORD, "role": "USER"}).json()["token"]
    return {"id": uid, "email": email, "h": {"Authorization": f"Bearer {token}"}}


def _admin():
    token = client.post("/api/auth/login", json={"email": "admin@certifyai.in", "password": "admin"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _test_run(user_id, agent_name="Private Agent"):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""INSERT INTO normal_agent_tests (audit_id, user_id, agent_name, mode, tier, trust_score, created_at, full_result_json)
                   VALUES (?, ?, ?, 'certify', 'CERTIFIED', 90, '2026-10-02T00:00:00Z', '{}')""",
                (f"iso-{uuid.uuid4().hex[:10]}", user_id, agent_name))
    run_id = cur.lastrowid
    cur.execute("INSERT INTO agents (user_id, name, canonical_name, created_at, updated_at) VALUES (?, ?, ?, '2026-10-02', '2026-10-02')",
                (user_id, agent_name, agent_name))
    agent_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id, agent_id


def _live_agent(user, token="secret-token-123"):
    res = client.post("/api/user/live/agents", headers=user["h"], json={
        "name": "Mine", "openapi_url": "https://agent.example.com/openapi.json", "target_env": "staging",
        "auth_token": token, "config": {"agentType": "chat"}})
    assert res.status_code == 200, res.text
    return res.json()


# Signing in is required

@pytest.mark.parametrize("method,path", [
    ("post", "/api/live-agent/test"),
    ("post", "/api/user/live-test"),
    ("post", "/api/user/live-agent/discover"),
    ("get", "/api/user/live/agents"),
    ("get", "/api/agents"),
])
def test_no_login_is_refused(method, path):
    body = {"openapi_url": "https://example.com/openapi.json", "source_type": "openapi", "url_or_path": "x"}
    res = client.get(path) if method == "get" else client.post(path, json=body)
    assert res.status_code == 401, (path, res.status_code, res.text)


def test_all_agents_list_is_admin_only():
    assert client.get("/api/agents", headers=_user()["h"]).status_code == 403
    assert client.get("/api/agents", headers=_admin()).status_code == 200


# Users cannot see each other's work

def test_tests_and_reports_are_private():
    a, b = _user(), _user()
    run_id, _ = _test_run(a["id"])
    assert client.get(f"/api/user/tests/{run_id}", headers=a["h"]).status_code == 200
    assert client.get(f"/api/user/tests/{run_id}", headers=b["h"]).status_code == 404
    assert client.get(f"/api/user/tests/{run_id}/pdf", headers=b["h"]).status_code == 404
    ids = [t["id"] for t in client.get("/api/user/tests", headers=b["h"]).json()["tests"]]
    assert run_id not in ids


def test_agents_are_private_even_with_the_same_name():
    a, b = _user(), _user()
    _, a_agent = _test_run(a["id"], "Same Name Agent")
    _, b_agent = _test_run(b["id"], "Same Name Agent")
    names_b = [g.get("id") for g in client.get("/api/user/agents", headers=b["h"]).json()["agents"]]
    assert a_agent not in names_b
    assert client.get(f"/api/user/agents/{a_agent}", headers=b["h"]).status_code == 404
    assert client.get(f"/api/user/agents/{b_agent}", headers=b["h"]).status_code == 200


def test_live_agents_are_private():
    a, b = _user(), _user()
    agent = _live_agent(a)
    assert agent["id"] in [x["id"] for x in client.get("/api/user/live/agents", headers=a["h"]).json()["agents"]]
    assert agent["id"] not in [x["id"] for x in client.get("/api/user/live/agents", headers=b["h"]).json()["agents"]]
    assert client.put(f"/api/user/live/agents/{agent['id']}", headers=b["h"], json={"name": "Taken"}).status_code == 404
    assert client.delete(f"/api/user/live/agents/{agent['id']}", headers=b["h"]).status_code == 404
    # Another user cannot run a test or a monitor with someone else's saved agent (and its token)
    res = client.post("/api/live-agent/test", headers=b["h"], json={"live_agent_id": agent["id"], "openapi_url": "https://example.com/o.json"})
    assert res.status_code == 404
    res = client.post("/api/user/live/schedules", headers=b["h"], json={"live_agent_id": agent["id"], "request": {"openapi_url": "https://example.com/o.json"}})
    assert res.status_code == 404


# Secrets

def test_live_agent_token_is_encrypted_and_never_returned():
    a = _user()
    agent = _live_agent(a, token="super-secret-value-9")
    assert agent["has_auth_token"] is True
    assert "super-secret-value-9" not in str(agent)
    listed = client.get("/api/user/live/agents", headers=a["h"]).text
    assert "super-secret-value-9" not in listed
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT settings_enc FROM live_agents WHERE id = ?", (agent["id"],))
    stored = cur.fetchone()[0]
    conn.close()
    assert stored.startswith("enc:v1:") and "super-secret-value-9" not in stored


# Admins watch everything and change nothing

def test_admin_sees_every_users_live_agents_with_the_owner():
    a = _user()
    agent = _live_agent(a)
    rows = client.get("/api/user/live/agents", headers=_admin()).json()["agents"]
    mine = next(r for r in rows if r["id"] == agent["id"])
    assert mine["owner_email"] == a["email"]


def test_admin_cannot_create_or_change_live_agents_or_run_tests():
    admin = _admin()
    a = _user()
    agent = _live_agent(a)
    body = {"name": "x", "openapi_url": "https://example.com/o.json"}
    assert client.post("/api/user/live/agents", headers=admin, json=body).status_code == 403
    assert client.delete(f"/api/user/live/agents/{agent['id']}", headers=admin).status_code == 403
    assert client.post("/api/live-agent/test", headers=admin, json={"openapi_url": "https://example.com/o.json"}).status_code == 403
    assert client.post("/api/audit", headers=admin, json={"openapi_url": "https://example.com/o.json"}).status_code == 403


def test_admin_activity_log_shows_what_users_did():
    a = _user()
    agent = _live_agent(a)
    res = client.get("/api/admin/activity-log", headers=_admin(), params={"user_id": a["id"]})
    assert res.status_code == 200
    events = [(e["event_type"], e["entity_id"]) for e in res.json()["entries"]]
    assert ("LIVE_AGENT_CREATED", str(agent["id"])) in events
    assert ("USER_LOGIN", str(a["id"])) in events
    assert client.get("/api/admin/activity-log", headers=a["h"]).status_code == 403


def test_activity_log_cannot_be_edited_or_deleted():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM activity_logs ORDER BY id DESC LIMIT 1")
    row_id = cur.fetchone()[0]
    for sql in ("UPDATE activity_logs SET details = 'changed' WHERE id = ?", "DELETE FROM activity_logs WHERE id = ?"):
        with pytest.raises(Exception):
            cur.execute(sql, (row_id,))
        conn.rollback()
    conn.close()
