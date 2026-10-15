"""Tests for SSRF (Server-Side Request Forgery) protection."""
import pytest
from fastapi.testclient import TestClient

from backend import app
from security import is_safe_url
from database import init_db

client = TestClient(app)


def setup_module():
    init_db()


def test_ssrf_blocks_private_and_loopback_ips():
    dangerous_urls = [
        "http://127.0.0.1/",
        "http://127.0.0.1:8000/secret",
        "http://localhost:8080/",
        "http://0.0.0.0:8000/",
        "http://10.0.0.1/internal",
        "http://10.254.254.254/api",
        "http://172.16.0.1:5000/",
        "http://172.31.255.255/",
        "http://192.168.1.1/router",
        "http://192.168.0.254/",
        "http://169.254.169.254/latest/meta-data/",  # Cloud metadata
        "http://[::1]/",                            # IPv6 loopback
        "http://[fe80::1]/",                        # IPv6 link-local
    ]
    for url in dangerous_urls:
        safe, reason = is_safe_url(url)
        assert safe is False, f"URL should be blocked by SSRF filter: {url} (reason: {reason})"


def test_ssrf_blocks_non_http_schemes():
    invalid_schemes = [
        "ftp://example.com/file.txt",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "dict://127.0.0.1:11211/",
        "ldap://localhost:389/",
        "",
        "not_a_url",
    ]
    for url in invalid_schemes:
        safe, reason = is_safe_url(url)
        assert safe is False, f"Invalid scheme should be blocked: {url} (reason: {reason})"


def test_ssrf_allows_public_domains():
    safe_urls = [
        "https://raw.githubusercontent.com/OAI/OpenAPI-Specification/main/examples/v3.0/petstore.yaml",
        "https://httpbin.org/status/200",
    ]
    for url in safe_urls:
        safe, reason = is_safe_url(url)
        assert safe is True, f"Public URL should be allowed: {url} (reason: {reason})"


def test_audit_api_rejects_ssrf_openapi_url():
    # Users run audits; admins only watch
    login_res = client.post("/api/auth/login", json={"email": "user@certifyai.in", "password": "user"})
    token = login_res.json().get("access_token") or login_res.json().get("token")

    payload = {
        "openapi_url": "http://169.254.169.254/latest/meta-data/",
        "agent_name": "SSRF Test Agent",
    }
    res = client.post("/api/audit", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 400
    assert "Disallowed openapi_url" in res.json().get("detail", "")
