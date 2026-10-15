"""Tests for Role-Based Access Control (RBAC) and IDOR protections."""
import uuid

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
    user_id = int(user_res.json()["user_id"])

    return admin_token, user_token, user_id


def test_admin_endpoints_require_auth():
    admin_endpoints = [
        "/api/admin/users",
        "/api/admin/analytics",
        "/api/admin/activity",
        "/api/admin/testing-activity",
    ]
    for endpoint in admin_endpoints:
        res = client.get(endpoint)
        assert res.status_code == 401, f"{endpoint} should require authentication"


def test_admin_endpoints_reject_standard_user():
    _, user_token, _ = _get_tokens()
    admin_endpoints = [
        "/api/admin/users",
        "/api/admin/analytics",
        "/api/admin/activity",
        "/api/admin/testing-activity",
    ]
    for endpoint in admin_endpoints:
        res = client.get(endpoint, headers={"Authorization": f"Bearer {user_token}"})
        assert res.status_code == 403, f"{endpoint} should reject non-admin users"
        assert "ADMIN" in res.json().get("detail", "") or "Administrator privileges" in res.json().get("detail", "")


def test_admin_endpoints_allow_admin_user():
    admin_token, _, _ = _get_tokens()
    res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert "users" in res.json()

    res_analytics = client.get("/api/admin/analytics", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_analytics.status_code == 200


def test_deactivated_user_token_rejected_on_next_request():
    """A JWT issued while the account was Active must stop working as soon as
    an admin deactivates the account — get_current_user re-checks the user's
    status from the database on every request, not just once at login."""
    admin_token, _, _ = _get_tokens()

    test_email = f"deactivation.test.{uuid.uuid4().hex[:8]}@certifyai.in"
    create_res = client.post(
        "/api/admin/users",
        json={
            "name": "Deactivation Test User",
            "email": test_email,
            "password": "TempPass_123!",
            "role": "USER",
            "department": "QA",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_res.status_code == 200
    new_user_id = create_res.json()["id"]

    login_res = client.post("/api/auth/login", json={"email": test_email, "password": "TempPass_123!"})
    assert login_res.status_code == 200
    token = login_res.json().get("access_token") or login_res.json().get("token")

    # Token is valid while the account is Active.
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200

    deactivate_res = client.put(
        f"/api/admin/users/{new_user_id}",
        json={"status": "Inactive"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert deactivate_res.status_code == 200

    # The same, still cryptographically valid token must now be rejected.
    me_res_after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res_after.status_code == 403
    assert "deactivated" in me_res_after.json().get("detail", "").lower()


def test_user_endpoints_require_auth():
    user_endpoints = [
        "/api/user/profile",
        "/api/user/dashboard",
        "/api/user/tests",
        "/api/user/test-history",
        "/api/user/reports",
        "/api/user/agents",
    ]
    for endpoint in user_endpoints:
        res = client.get(endpoint)
        assert res.status_code == 401, f"{endpoint} should require authentication"


def test_user_endpoints_allow_user_token():
    _, user_token, user_id = _get_tokens()
    res = client.get("/api/user/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["id"] == user_id


def test_idor_protection_ignores_spoofed_x_user_id():
    """Verify that an attacker passing X-User-Id: 1 cannot hijack user 1's profile."""
    _, user_token, user_id = _get_tokens()
    # Attempt to spoof user ID 1 (Admin) while authenticated as User (ID 2)
    res = client.get(
        "/api/user/profile",
        headers={
            "Authorization": f"Bearer {user_token}",
            "X-User-Id": "1",  # Spoofed header
        },
    )
    assert res.status_code == 200
    profile = res.json()
    # The returned profile must be the authenticated user's own profile, NOT ID 1
    assert profile["user"]["id"] == user_id


def test_user_profile_update():
    _, user_token, _ = _get_tokens()
    update_data = {
        "name": "Updated Test Engineer",
        "department": "Security QA",
    }
    res = client.put(
        "/api/user/profile",
        json=update_data,
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200

    # Verify update persisted
    verify_res = client.get("/api/user/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert verify_res.status_code == 200
    assert verify_res.json()["user"]["name"] == "Updated Test Engineer"
    assert verify_res.json()["user"]["department"] == "Security QA"
