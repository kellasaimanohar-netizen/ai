"""Tests for Authentication & Security in CertifyAI."""
import hashlib
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient

from backend import app
from security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    is_safe_url,
)
from database import get_db_connection, init_db

client = TestClient(app)


def setup_module():
    """Ensure database is initialized before running tests."""
    init_db()


def test_password_hashing_and_verification():
    pw = "SuperSecret_123!"
    hashed = hash_password(pw)
    assert hashed != pw
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    # Correct password
    assert verify_password(pw, hashed) is True

    # Incorrect password
    assert verify_password("WrongPassword!", hashed) is False


def test_legacy_sha256_password_migration():
    pw = "legacy_admin_pass"
    legacy_hash = hashlib.sha256(pw.encode()).hexdigest()

    assert verify_password(pw, legacy_hash) is True
    # Verify it is recognized as legacy 64-char hex format
    assert len(legacy_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in legacy_hash)


def test_jwt_generation_and_decoding():
    token = create_access_token(
        user_id=42,
        email="user@certifyai.in",
        role="USER",
        name="Test User",
        expires_delta=timedelta(minutes=15),
    )
    assert isinstance(token, str)
    assert len(token) > 20

    payload = decode_access_token(token)
    assert payload["sub"] == "42"
    assert payload["user_id"] == 42
    assert payload["email"] == "user@certifyai.in"
    assert payload["role"] == "USER"
    assert payload["name"] == "Test User"
    assert "exp" in payload


def test_jwt_tampering_rejected():
    token = create_access_token(
        user_id=42,
        email="user@certifyai.in",
        role="USER",
        name="Test User",
    )
    parts = token.split(".")
    tampered_token = parts[0] + "." + parts[1] + ".invalid_signature"

    with pytest.raises(Exception):
        decode_access_token(tampered_token)


def test_auth_login_endpoint_success():
    # Admin login
    res = client.post("/api/auth/login", json={"email": "admin@certifyai.in", "password": "admin"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data or "token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "ADMIN"

    # User login
    res_user = client.post("/api/auth/login", json={"email": "user@certifyai.in", "password": "user"})
    assert res_user.status_code == 200
    data_user = res_user.json()
    assert "access_token" in data_user or "token" in data_user
    assert data_user["role"] == "USER"


def test_auth_login_invalid_password():
    res = client.post("/api/auth/login", json={"email": "admin@certifyai.in", "password": "wrong_password"})
    assert res.status_code == 401
    assert "Invalid email or password" in res.json().get("detail", "")


def test_auth_login_unknown_user():
    res = client.post("/api/auth/login", json={"email": "nonexistent@certifyai.in", "password": "random_password"})
    assert res.status_code == 401


def test_auth_me_authenticated():
    login_res = client.post("/api/auth/login", json={"email": "admin@certifyai.in", "password": "admin"})
    token = login_res.json().get("access_token") or login_res.json().get("token")

    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    profile = res.json()
    assert profile["role"] == "ADMIN"
    assert "user" in profile


def test_auth_me_unauthenticated():
    res = client.get("/api/auth/me")
    assert res.status_code == 401

    res_invalid = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid_garbage_token"})
    assert res_invalid.status_code == 401
