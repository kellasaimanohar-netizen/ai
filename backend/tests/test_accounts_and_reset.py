"""Separate admin and user accounts, forgot password, and the two kinds of test record."""
import uuid

from fastapi.testclient import TestClient

import routers.auth as auth_router
from backend import app
from database import get_db_connection, init_db
from database.accounts import create_account, get_account, update_account
from database.test_runs import record_certify_details, record_certify_findings, record_live_details, record_live_findings
from security import hash_password

client = TestClient(app)


def setup_module():
    init_db()


def _new_user(password="old-password-1"):
    email = f"reset-{uuid.uuid4().hex[:8]}@example.com"
    conn = get_db_connection()
    cur = conn.cursor()
    account_id = create_account(cur, "USER", email, "Reset Tester", hash_password(password))
    conn.commit()
    conn.close()
    return account_id, email


def _request_reset(monkeypatch, email):
    sent = []
    monkeypatch.setattr(auth_router, "send_password_reset", lambda to, name, link, minutes: sent.append(link))
    res = client.post("/api/auth/forgot-password", json={"email": email})
    assert res.status_code == 200
    return sent


def test_new_user_is_a_user_account():
    account_id, _ = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    assert get_account(cur, account_id)["role"] == "USER"
    conn.close()


def test_login_on_the_wrong_tab_is_refused_with_a_clear_message():
    _, email = _new_user()
    res = client.post("/api/auth/login", json={"email": email, "password": "old-password-1", "role": "ADMIN"})
    assert res.status_code == 403
    assert "User tab" in res.json()["detail"]
    ok = client.post("/api/auth/login", json={"email": email, "password": "old-password-1", "role": "USER"})
    assert ok.status_code == 200 and ok.json()["role"] == "USER"


def test_wrong_tab_with_wrong_password_does_not_reveal_the_account():
    _, email = _new_user()
    res = client.post("/api/auth/login", json={"email": email, "password": "not-it", "role": "ADMIN"})
    assert res.status_code == 401


def test_forgot_password_full_flow(monkeypatch):
    _, email = _new_user()
    sent = _request_reset(monkeypatch, email)
    assert len(sent) == 1 and "/reset-password?token=" in sent[0]
    token = sent[0].split("token=", 1)[1]

    assert client.post("/api/auth/reset-password/verify", json={"token": token}).json()["valid"] is True
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": "short"}).status_code == 400

    res = client.post("/api/auth/reset-password", json={"token": token, "new_password": "brand-new-pass-9"})
    assert res.status_code == 200
    assert client.post("/api/auth/login", json={"email": email, "password": "brand-new-pass-9"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": email, "password": "old-password-1"}).status_code == 401

    # A link works once
    again = client.post("/api/auth/reset-password", json={"token": token, "new_password": "another-pass-9"})
    assert again.status_code == 400


def test_forgot_password_gives_the_same_answer_for_unknown_email(monkeypatch):
    sent = _request_reset(monkeypatch, "nobody-here@example.com")
    assert sent == []


def test_a_new_reset_link_cancels_the_previous_one(monkeypatch):
    _, email = _new_user()
    first = _request_reset(monkeypatch, email)[0].split("token=", 1)[1]
    second = _request_reset(monkeypatch, email)[0].split("token=", 1)[1]
    assert client.post("/api/auth/reset-password/verify", json={"token": first}).json()["valid"] is False
    assert client.post("/api/auth/reset-password/verify", json={"token": second}).json()["valid"] is True


def test_reset_requests_are_limited_per_hour(monkeypatch):
    _, email = _new_user()
    sent = []
    for _ in range(auth_router.MAX_RESETS_PER_HOUR + 2):
        sent += _request_reset(monkeypatch, email)
    assert len(sent) == auth_router.MAX_RESETS_PER_HOUR


def test_changing_role_keeps_the_account_and_its_id():
    account_id, _ = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    update_account(cur, account_id, role="ADMIN")
    conn.commit()
    acct = get_account(cur, account_id)
    assert acct["role"] == "ADMIN" and acct["name"] == "Reset Tester"
    conn.close()


def test_email_is_unique_across_admins_and_users():
    _, email = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        create_account(cur, "ADMIN", email, "Duplicate", hash_password("whatever-123"))
        conn.commit()
        raised = False
    except Exception:
        conn.rollback()
        raised = True
    conn.close()
    assert raised


def _run(cur, account_id, test_type):
    table = "live_agent_tests" if test_type == "live" else "normal_agent_tests"
    cur.execute(f"""INSERT INTO {table} (audit_id, user_id, agent_name, mode, tier, created_at)
                    VALUES (?, ?, 'Kind Agent', ?, 'CERTIFIED', '2026-10-02T00:00:00Z')""",
                (f"kind-{uuid.uuid4().hex[:10]}", account_id, "live_probe" if test_type == "live" else "certify"))
    return cur.lastrowid


def test_each_kind_of_test_has_its_own_table_and_details():
    account_id, _ = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    live_id = _run(cur, account_id, "live")
    record_live_details(cur, live_id, target_env="staging", endpoint_url="https://agent.example.com/chat", openapi_url=None,
                        repo_path=None, agent_type="chat", tests_total=10, could_not_run=1)
    normal_id = _run(cur, account_id, "certify")
    record_certify_details(cur, normal_id, source="yaml")
    conn.commit()
    cur.execute("SELECT target_env, tests_total FROM live_agent_tests WHERE id = ?", (live_id,))
    r = cur.fetchone()
    assert (r[0], r[1]) == ("staging", 10)
    cur.execute("SELECT mode, source FROM normal_agent_tests WHERE id = ?", (normal_id,))
    r = cur.fetchone()
    assert (r[0], r[1]) == ("certify", "yaml")
    # A test id names one test of either kind
    assert live_id != normal_id
    cur.execute("SELECT COUNT(*) FROM normal_agent_tests WHERE id = ?", (live_id,))
    assert cur.fetchone()[0] == 0
    conn.close()


def test_combined_view_takes_the_tester_from_accounts():
    account_id, email = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    normal_id = _run(cur, account_id, "certify")
    live_id = _run(cur, account_id, "live")
    conn.commit()
    cur.execute("SELECT id, test_type, tested_by_email, tested_by_name, user_role FROM all_agent_tests WHERE id IN (?, ?) ORDER BY id",
                (normal_id, live_id))
    rows = [(r[0], r[1], r[2], r[3], r[4]) for r in cur.fetchall()]
    assert rows == [(normal_id, "certify", email, "Reset Tester", "USER"), (live_id, "live", email, "Reset Tester", "USER")]
    conn.close()


def test_a_finding_belongs_to_exactly_one_test_and_goes_with_it():
    account_id, _ = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    normal_id = _run(cur, account_id, "certify")
    live_id = _run(cur, account_id, "live")
    record_certify_findings(cur, normal_id, "a", [{"id": "SEC-1", "phase": "security", "title": "t", "severity": "critical"}], "2026-10-02")
    conn.commit()
    cur.execute("SELECT test_run_id, phase_name, severity FROM audit_findings WHERE normal_test_id = ?", (normal_id,))
    r = cur.fetchone()
    assert (r[0], r[1], r[2]) == (normal_id, "Security", "CRITICAL")
    for sql, args in (("INSERT INTO audit_findings (normal_test_id, live_test_id, audit_id, rule_id, title, severity, created_at) "
                       "VALUES (?, ?, 'x', 'R', 't', 'INFO', 'now')", (normal_id, live_id)),
                      ("INSERT INTO audit_findings (audit_id, rule_id, title, severity, created_at) VALUES ('x', 'R', 't', 'INFO', 'now')", ())):
        try:
            cur.execute(sql, args)
            conn.commit()
            allowed = True
        except Exception:
            conn.rollback()
            allowed = False
        assert not allowed
    cur.execute("DELETE FROM normal_agent_tests WHERE id = ?", (normal_id,))
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM audit_findings WHERE test_run_id = ?", (normal_id,))
    assert cur.fetchone()[0] == 0
    conn.close()


def test_dashboard_counts_findings_from_both_kinds_of_test():
    account_id, email = _new_user()
    conn = get_db_connection()
    cur = conn.cursor()
    normal_id = _run(cur, account_id, "certify")
    live_id = _run(cur, account_id, "live")
    record_certify_findings(cur, normal_id, "n", [{"id": "SUP-1", "phase": "supply_chain", "title": "t", "severity": "PASS"}], "2026-10-02")
    record_live_findings(cur, live_id, "l", [{"id": "LIVE-1", "category": "Prompt Injection", "title": "t", "severity": "WARNING"}], "2026-10-02")
    conn.commit()
    conn.close()
    token = client.post("/api/auth/login", json={"email": email, "password": "old-password-1"}).json()["token"]
    dash = client.get("/api/user/dashboard", headers={"Authorization": f"Bearer {token}"}).json()
    categories = {c["category"] for c in dash["categories"]}
    assert {"Supply Chain", "Prompt Injection"} <= categories
