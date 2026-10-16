"""Tests for the OpenAPI scan and the repository scan. Everything is read from temporary files."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from live_testing import scans


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("AA_REPO_BASE", str(tmp_path))
    r = tmp_path / "agent"
    (r / "tests").mkdir(parents=True)
    (r / "app.py").write_text('''
import psycopg2
from fastapi import FastAPI
from langchain.tools import tool

app = FastAPI()
DB_URL = "postgresql://admin:Sup3rS3cretPw@db.example.com:5432/prod"
OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"
api_password = "hunter2hunter2"
SAFE = os.environ.get("API_TOKEN", "")

@tool
def delete_customer(customer_id: str):
    cur.execute(f"DELETE FROM customers WHERE id = {customer_id}")

@tool
def calculate_loan(amount: float):
    return amount * 0.1

@app.delete("/customers/{cid}")
def remove(cid: str):
    cur.execute("DROP TABLE customers")
    cur.execute("DELETE FROM logs")
    shutil.rmtree("/data")
    os.system("rm -rf /tmp/x")
''')
    (r / "tests" / "test_x.py").write_text('password = "testpassword123"\n')
    (r / ".env").write_text("TOKEN=abc\n")
    (r / ".gitignore").write_text("__pycache__/\n")
    (r / "config.py").write_text('DB_URL = "postgresql://user:password@localhost/db"\nTOKEN_URL = "https://x/token"\nclient_secret = "your_client_secret_here"\n')
    return r


def test_repo_scan_finds_database_access_deletes_tools_and_secrets(repo):
    res = scans.scan_repo(str(repo))
    assert res["available"] and res["database"]["used"]
    assert any(t["name"] == "psycopg2" for t in res["database"]["technologies"])
    kinds = {d["kind"] for d in res["destructive_operations"] if d["severity"] != "INFO"}
    assert {"DROP", "DELETE without WHERE", "Delete files", "Run commands"} <= kinds
    names = {t["name"]: t["destructive"] for t in res["tools"]}
    assert names == {"delete_customer": True, "calculate_loan": False}
    assert any(r["method"] == "DELETE" and r["path"] == "/customers/{cid}" for r in res["routes"])
    titles = " | ".join(f["title"] for f in res["findings"])
    assert "connection string" in titles and "sk-" in titles
    assert any(f["category"] == "Hardcoded secrets" and f["severity"] == "CRITICAL" for f in res["findings"])
    assert any(f["title"].startswith("SQL is built from text") for f in res["findings"])
    assert any("environment file is not ignored" in f["title"] for f in res["findings"])


def test_secrets_are_masked_and_placeholders_ignored(repo):
    res = scans.scan_repo(str(repo))
    blob = str(res)
    assert "Sup3rS3cretPw" not in blob and "abcdefghijklmnopqrstuvwxyz123456" not in blob and "hunter2hunter2" not in blob
    # placeholder values, env lookups and url-like names are not reported
    assert not any("config.py" == s["file"] for s in res["secrets"])
    # secrets in test files are listed, but only as information
    assert any(s["file"].endswith("test_x.py") and s["severity"] == "INFO" for s in res["secrets"])


def test_repo_must_be_a_real_local_folder_inside_the_allowed_base(tmp_path, monkeypatch):
    monkeypatch.setenv("AA_REPO_BASE", str(tmp_path))
    assert scans.scan_repo("")["error"]
    assert "clone" in scans.scan_repo("https://github.com/x/y")["error"].lower()
    assert "not found" in scans.scan_repo(str(tmp_path / "missing"))["error"]
    outside = tmp_path.parent
    assert "must be inside" in scans.scan_repo(str(outside))["error"]


SPEC = {
    "openapi": "3.0.2", "servers": [{"url": "http://api.example.com"}],
    "paths": {
        "/calculate": {"post": {"summary": "Calculate"}},
        "/users/{id}": {"delete": {"summary": "Remove a user"}},
        "/admin/export": {"get": {"summary": "Export"}},
        "/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"password": {"type": "string"}}}}}}}},
    },
}


def test_openapi_scan_flags_risky_routes_and_missing_login():
    res = scans.scan_openapi(SPEC)
    by = {(r["method"], r["path"]): r for r in res["routes"]}
    assert by[("DELETE", "/users/{id}")]["risk"] == "high" and not by[("DELETE", "/users/{id}")]["login"]
    assert by[("GET", "/admin/export")]["risk"] == "medium"
    assert by[("POST", "/calculate")]["risk"] == "low"
    sev = {f["title"]: f["severity"] for f in res["findings"]}
    assert any(t.endswith("risky route(s) need no login") and s == "CRITICAL" for t, s in sev.items())
    assert "No route asks for a login" in sev
    assert any(f["category"] == "Transport security" for f in res["findings"])
    assert any(f["category"] == "Data exposure" for f in res["findings"])


def test_openapi_scan_respects_declared_security():
    spec = {"openapi": "3.0.2", "security": [{"k": []}], "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-Key"}}},
            "paths": {"/users/{id}": {"delete": {}}, "/open": {"get": {"security": []}}}}
    res = scans.scan_openapi(spec)
    by = {(r["method"], r["path"]): r for r in res["routes"]}
    assert by[("DELETE", "/users/{id}")]["login"] is True
    assert by[("GET", "/open")]["login"] is False
    assert not any(f["severity"] == "CRITICAL" for f in res["findings"])
    assert any(f["category"] == "Risky API" and f["severity"] == "WARNING" for f in res["findings"])


def test_a_plain_calculator_api_gets_only_a_warning():
    spec = {"openapi": "3.0.2", "paths": {"/calculate": {"post": {}}, "/compare": {"post": {}}}}
    res = scans.scan_openapi(spec)
    assert [f["severity"] for f in res["findings"]] == ["WARNING"]


def test_combined_findings_link_the_code_and_the_description(repo):
    repo_scan = scans.scan_repo(str(repo))
    api_scan = scans.scan_openapi(SPEC)
    combined = scans.combine(api_scan, repo_scan)
    titles = [f["title"] for f in combined]
    assert "Database-backed routes are open to anyone" in titles
    assert "The code has delete routes and the API declares no login" in titles


def test_folders_outside_the_base_stay_blocked_on_vercel(tmp_path, monkeypatch):
    monkeypatch.setenv("AA_REPO_BASE", str(tmp_path / "base"))
    monkeypatch.setenv("VERCEL", "1")
    (tmp_path / "base").mkdir()
    sneaky = tmp_path / "agent_audit_git_x"
    sneaky.mkdir()
    assert "must be inside" in scans.scan_repo(str(tmp_path))["error"]
    assert "must be inside" in scans.scan_repo(str(sneaky))["error"]
