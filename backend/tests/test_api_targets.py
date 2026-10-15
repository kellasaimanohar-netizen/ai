"""Tests for Target management, path traversal prevention, and RBAC."""
import pytest
from fastapi.testclient import TestClient

from backend import app
from database import init_db

client = TestClient(app)


def setup_module():
    init_db()


def _get_tokens():
    admin_res = client.post("/api/auth/login", json={"email": "admin@certifyai.in", "password": "admin"})
    admin_token = admin_res.json().get("access_token") or admin_res.json().get("token")

    user_res = client.post("/api/auth/login", json={"email": "user@certifyai.in", "password": "user"})
    user_token = user_res.json().get("access_token") or user_res.json().get("token")

    return admin_token, user_token


def test_targets_list_requires_auth():
    res = client.get("/api/targets")
    assert res.status_code == 401


def test_targets_list_allowed_for_users():
    _, user_token = _get_tokens()
    res = client.get("/api/targets", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200
    assert "targets" in res.json()


def test_target_path_traversal_rejected():
    _, user_token = _get_tokens()
    malicious_filenames = [
        "../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "sub/folder/agent.yaml",
        "win.ini",
        "exploit.py",
        "agent.yaml;rm -rf /",
    ]
    for bad_name in malicious_filenames:
        res = client.get(f"/api/targets/{bad_name}", headers={"Authorization": f"Bearer {user_token}"})
        # Either rejected by regex validation (400) or URL routing (404)
        assert res.status_code in (400, 404), f"{bad_name} should not be allowed"


def test_target_creation_requires_admin():
    admin_token, user_token = _get_tokens()
    payload = {
        "filename": "test_temp_agent.yaml",
        "content": "version: 1\nname: Test Agent\n",
    }

    # Unauthenticated
    res_unauth = client.post("/api/targets", json=payload)
    assert res_unauth.status_code == 401

    # Standard User
    res_user = client.post(
        "/api/targets",
        json=payload,
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res_user.status_code == 403

    # Admin User
    res_admin = client.post(
        "/api/targets",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin.status_code == 200
    assert "saved successfully" in res_admin.json().get("message", "")

    # Cleanup: Admin deletes it
    del_res = client.delete(
        "/api/targets/test_temp_agent.yaml",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert del_res.status_code == 200


def test_target_creation_rejects_path_traversal():
    admin_token, _ = _get_tokens()
    payload = {
        "filename": "../malicious.yaml",
        "content": "version: 1\n",
    }
    res = client.post(
        "/api/targets",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 400
    assert "Invalid target filename format" in res.json().get("detail", "")
