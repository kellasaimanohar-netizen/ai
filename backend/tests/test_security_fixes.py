"""Sign-in and outbound-call protections: route logins, .env passwords, lockout, ended sessions, SSRF, log isolation."""
import asyncio
import contextvars
import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from backend import app, QueueLogHandler, _current_audit
from database import get_db_connection, init_db
from database.accounts import create_account
from security import hash_password

client = TestClient(app)
PASSWORD = "fixes-pass-123"


def setup_module():
    init_db()


def _user(role="USER"):
    email = f"fix-{uuid.uuid4().hex[:8]}@example.com"
    conn = get_db_connection()
    cur = conn.cursor()
    uid = create_account(cur, role, email, f"Fix {email[:8]}", hash_password(PASSWORD))
    conn.commit()
    conn.close()
    res = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert res.status_code == 200, res.text
    return {"id": uid, "email": email, "token": res.json()["token"], "h": {"Authorization": f"Bearer {res.json()['token']}"}}


def _admin_headers():
    token = client.post("/api/auth/login", json={"email": "admin@certifyai.in", "password": "admin"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


# 1. Every alias needs a signed-in user
def test_discover_alias_requires_sign_in():
    res = client.post("/api/live-agent/discover", json={"source_type": "repo", "url_or_path": "C:/Windows"})
    assert res.status_code == 401


# 2. The .env password opens only the account .env names
def test_env_password_does_not_open_other_accounts():
    other = _user()
    res = client.post("/api/auth/login", json={"email": other["email"], "password": "user"})   # USER_PASSWORD in tests
    assert res.status_code == 401
    # and that account's own password still works: it was not overwritten
    assert client.post("/api/auth/login", json={"email": other["email"], "password": PASSWORD}).status_code == 200


def test_env_login_still_works_for_its_own_account():
    assert client.post("/api/auth/login", json={"email": "user@certifyai.in", "password": "user"}).status_code == 200


# 6. Lockout, ended sessions, password changes, admin safeguards
def test_too_many_wrong_passwords_locks_the_account():
    u = _user()
    for _ in range(10):
        assert client.post("/api/auth/login", json={"email": u["email"], "password": "wrong-one"}).status_code == 401
    res = client.post("/api/auth/login", json={"email": u["email"], "password": PASSWORD})
    assert res.status_code == 429


def test_signing_out_ends_the_session():
    u = _user()
    assert client.get("/api/auth/me", headers=u["h"]).status_code == 200
    client.post("/api/auth/logout", headers=u["h"])
    assert client.get("/api/auth/me", headers=u["h"]).status_code == 401
    # a new sign-in works straight away
    again = client.post("/api/auth/login", json={"email": u["email"], "password": PASSWORD}).json()["token"]
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {again}"}).status_code == 200


def test_changing_the_password_needs_the_current_one_and_ends_other_sessions():
    u = _user()
    res = client.put("/api/user/profile", headers=u["h"], json={"password": "a-new-password-1"})
    assert res.status_code == 400
    res = client.put("/api/user/profile", headers=u["h"], json={"password": "a-new-password-1", "current_password": "not-it"})
    assert res.status_code == 400
    res = client.put("/api/user/profile", headers=u["h"], json={"password": "a-new-password-1", "current_password": PASSWORD})
    assert res.status_code == 200
    assert client.get("/api/auth/me", headers=u["h"]).status_code == 401
    # the device that made the change keeps working with the token it was given
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {res.json()['token']}"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": u["email"], "password": "a-new-password-1"}).status_code == 200


def test_me_includes_member_since():
    u = _user()
    assert client.get("/api/auth/me", headers=u["h"]).json()["user"]["created_at"]


def test_admin_cannot_remove_their_own_access():
    h = _admin_headers()
    me = client.get("/api/auth/me", headers=h).json()["user"]
    res = client.put(f"/api/admin/users/{me['id']}", headers=h, json={"role": "USER"})
    assert res.status_code == 400
    res = client.put(f"/api/admin/users/{me['id']}", headers=h, json={"status": "Inactive"})
    assert res.status_code == 400


def test_admin_created_accounts_need_a_real_password_and_email():
    h = _admin_headers()
    short = client.post("/api/admin/users", headers=h, json={"name": "Short", "email": f"s-{uuid.uuid4().hex[:6]}@example.com", "password": "abc"})
    assert short.status_code == 400
    bad = client.post("/api/admin/users", headers=h, json={"name": "Bad", "email": "not-an-email", "password": "long-enough-1"})
    assert bad.status_code == 400


# 3. Outbound calls refuse this server, private networks and cloud metadata
@pytest.fixture
def strict(monkeypatch):
    monkeypatch.delenv("AA_ALLOW_PRIVATE_TARGETS", raising=False)


def test_discover_refuses_internal_addresses(strict):
    u = _user()
    res = client.post("/api/user/live-agent/discover", headers=u["h"],
                      json={"source_type": "openapi", "url_or_path": "http://169.254.169.254/latest/meta-data/"})
    assert res.status_code == 400


def test_discover_repo_stays_inside_the_allowed_folder(monkeypatch, tmp_path):
    base, outside = tmp_path / "allowed", tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    monkeypatch.setenv("AA_REPO_BASE", str(base))
    u = _user()
    res = client.post("/api/user/live-agent/discover", headers=u["h"], json={"source_type": "repo", "url_or_path": str(outside)})
    assert res.status_code == 400


def test_registering_an_internal_live_agent_is_refused(strict):
    u = _user()
    res = client.post("/api/user/live/agents", headers=u["h"], json={
        "name": "Inside", "openapi_url": "http://127.0.0.1:9/openapi.json", "target_env": "staging"})
    assert res.status_code == 400


def test_the_mock_endpoint_text_is_not_a_way_around_the_check(strict):
    u = _user()
    res = client.post("/api/user/live/schedules", headers=u["h"], json={
        "request": {"endpoint_url": "http://169.254.169.254/mock-endpoint", "repo_path": "."}})
    assert res.status_code == 400


def test_connector_refuses_internal_addresses(strict):
    from live_testing.connectors import ConnectorConfig, call
    out = asyncio.run(call(ConnectorConfig(kind="chat", endpoint_url="http://127.0.0.1:9/chat"), "hello"))
    assert out.error and "not allowed" in out.error


def test_custom_headers_are_sent_together_with_a_token():
    from live_testing.health import _headers
    h = _headers({"auth_type": "bearer", "auth_token": "t-1", "custom_headers": {"X-Tenant": "acme"}})
    assert h["Authorization"] == "Bearer t-1" and h["X-Tenant"] == "acme"


# 4. Two audits at once: each stream gets only its own log lines
def test_audit_logs_do_not_cross_between_requests():
    async def scenario():
        logger = logging.getLogger("agent_audit.test_isolation")
        logger.setLevel(logging.INFO)
        q_a, q_b = asyncio.Queue(), asyncio.Queue()
        tok_a, tok_b = object(), object()
        h_a, h_b = QueueLogHandler(q_a, tok_a), QueueLogHandler(q_b, tok_b)
        logger.addHandler(h_a)
        logger.addHandler(h_b)
        try:
            async def run(token, text):
                _current_audit.set(token)
                await asyncio.to_thread(logger.info, text)   # a worker thread, as the engine uses

            await asyncio.gather(asyncio.create_task(run(tok_a, "from A"), context=contextvars.copy_context()),
                                 asyncio.create_task(run(tok_b, "from B"), context=contextvars.copy_context()))
            await asyncio.sleep(0.05)
        finally:
            logger.removeHandler(h_a)
            logger.removeHandler(h_b)
        a = [q_a.get_nowait() for _ in range(q_a.qsize())]
        b = [q_b.get_nowait() for _ in range(q_b.qsize())]
        return a, b

    a, b = asyncio.run(scenario())
    assert any("from A" in m for m in a) and not any("from B" in m for m in a)
    assert any("from B" in m for m in b) and not any("from A" in m for m in b)


# 7. Exports cannot carry spreadsheet formulas
def test_csv_cells_cannot_start_a_formula():
    from routers.admin import _csv_safe
    assert _csv_safe("=HYPERLINK(\"x\")") == "'=HYPERLINK(\"x\")"
    assert _csv_safe("Agent One") == "Agent One"
    assert _csv_safe(42) == 42


# 13. Days follow the organisation's time zone
def test_local_day_of_a_utc_time():
    from timeutil import local_date_key
    assert local_date_key("2026-10-08T20:00:00Z") == "2026-10-09"      # 01:30 in India
    assert local_date_key("2026-10-09T05:00:00+00:00") == "2026-10-09"
