"""Deleting a test from the history: only its owner can, and its findings go with it."""
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend import app
from database import get_db_connection, init_db

client = TestClient(app)


def setup_module():
    init_db()


def _login(email: str, password: str) -> tuple[str, int]:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    body = res.json()
    return body.get("access_token") or body.get("token"), int(body["user_id"])


def _make_test(user_id: int) -> int:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        audit_id = f"del-test-{uuid.uuid4().hex[:10]}"
        cur.execute(
            "INSERT INTO normal_agent_tests (audit_id, user_id, agent_name, mode, tier, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (audit_id, user_id, "Delete Me Agent", "certify", "NOT_CERTIFIED", datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        cur.execute("SELECT id FROM normal_agent_tests WHERE audit_id = ?", (audit_id,))
        return cur.fetchone()["id"]
    finally:
        conn.close()


def _exists(test_id: int) -> bool:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM all_agent_tests WHERE id = ?", (test_id,))
        return cur.fetchone() is not None
    finally:
        conn.close()


def test_owner_deletes_their_test():
    token, user_id = _login("user@certifyai.in", "user")
    test_id = _make_test(user_id)
    res = client.delete(f"/api/user/tests/{test_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200, res.text
    assert not _exists(test_id)
    again = client.delete(f"/api/user/tests/{test_id}", headers={"Authorization": f"Bearer {token}"})
    assert again.status_code == 404


def test_admin_cannot_delete_and_the_test_stays():
    _, user_id = _login("user@certifyai.in", "user")
    admin_token, _ = _login("admin@certifyai.in", "admin")
    test_id = _make_test(user_id)
    try:
        res = client.delete(f"/api/user/tests/{test_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert res.status_code == 403
        assert _exists(test_id)
    finally:
        token, _ = _login("user@certifyai.in", "user")
        client.delete(f"/api/user/tests/{test_id}", headers={"Authorization": f"Bearer {token}"})


def test_delete_needs_a_login():
    assert client.delete("/api/user/tests/1").status_code == 401
