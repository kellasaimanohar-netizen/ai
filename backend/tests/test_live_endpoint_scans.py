# no-real-database: the database is replaced by a fake below.
"""End to end: the live test endpoint with a mandatory repo and both scans, using a fake agent, a fake database
and a temporary repo folder. Nothing external is touched."""
import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi import HTTPException

import routers.user_api as api


class FakeCursor:
    lastrowid = 1

    def execute(self, *a, **k):
        return self

    def fetchone(self):
        return (0,)

    def fetchall(self):
        return []


class FakeConn:
    def cursor(self):
        return FakeCursor()

    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AA_REPO_BASE", str(tmp_path))
    monkeypatch.setattr(api, "get_db_connection", lambda: FakeConn())
    monkeypatch.setattr(api, "generate_and_store_pdf", lambda payload: "fake.pdf")
    monkeypatch.setattr(api, "_resolve_user", lambda authorization=None: {"id": 1, "email": "t@x.in", "name": "T", "role": "USER"})

    spec = {"openapi": "3.0.2", "info": {"title": "Calc"}, "paths": {"/calculate": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"required": ["amount"], "properties": {"amount": {"type": "number", "minimum": 0, "example": 100}}}}}}}}}}

    class H(BaseHTTPRequestHandler):
        def _send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            spec_with_server = {**spec, "servers": [{"url": f"http://127.0.0.1:{self.server.server_port}"}]}
            self._send(200, spec_with_server)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if "amount" not in body or not isinstance(body["amount"], (int, float)) or body["amount"] < 0:
                return self._send(422, {"detail": "bad"})
            self._send(200, {"result": round(body["amount"] * 1.1, 2)})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield tmp_path, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _req(url, repo):
    return api.LiveAgentTestRequest(openapi_url=url + "/openapi.json", repo_path=str(repo) if repo else None, agent_type="api")


def _run(req):
    return asyncio.run(api.execute_live_agent_test(req, None))


def test_repo_is_mandatory(env):
    tmp, url = env
    with pytest.raises(HTTPException) as e:
        _run(_req(url, None))
    assert e.value.status_code == 400 and "required" in e.value.detail
    with pytest.raises(HTTPException) as e:
        _run(_req(url, tmp / "missing"))
    assert "not found" in e.value.detail


def test_github_address_is_rejected_with_a_clear_message(env):
    _tmp, url = env
    with pytest.raises(HTTPException) as e:
        _run(api.LiveAgentTestRequest(openapi_url=url + "/openapi.json", repo_path="https://github.com/a/b"))
    assert "Clone" in e.value.detail


def test_clean_repo_keeps_the_live_result_and_attaches_both_scans(env):
    tmp, url = env
    repo = tmp / "clean"
    repo.mkdir()
    (repo / "app.py").write_text("def calc(x):\n    return x * 1.1\n")
    data = _run(_req(url, repo))["data"]
    scan = data["security_scan"]
    assert scan["openapi"]["available"] and scan["repo"]["available"]
    assert scan["blocking_findings"] == 0
    assert data["tier"] in ("CERTIFIED", "CONDITIONAL")
    assert scan["openapi"]["summary"]["routes"] == 1


def test_a_hardcoded_secret_blocks_certification(env):
    tmp, url = env
    repo = tmp / "leaky"
    repo.mkdir()
    (repo / "app.py").write_text('KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n')
    data = _run(_req(url, repo))["data"]
    assert data["security_scan"]["blocking_findings"] >= 1
    assert data["tier"] == "NOT_CERTIFIED" and data["trust_score"] <= 58.0
    assert any(f["category"] == "Hardcoded secrets" for f in data["all_findings"])
    assert "abcdefghijklmnopqrstuvwxyz123456" not in json.dumps(data)
