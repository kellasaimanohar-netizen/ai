"""A Certify result shows only what the agent actually did.

Unreachable agents are inconclusive, not failed or passed; checks that could not observe the agent are not
scored; passes that only repeat the YAML do not raise the score; phases that do not fit the agent are not run.
"""
import asyncio
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from agent_audit.certificate import issue_certificate
from agent_audit.manifest import _without_literal_secrets
from agent_audit.runner import run_audit
from agent_audit.severity import Severity
from backend import app, _certify_target_problem, _with_saved_runtime
from database import get_db_connection, init_db
from database.accounts import create_account
from security import hash_password

client = TestClient(app)


def setup_module():
    init_db()


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    """Retries against a dead or refusing agent wait 0s, so these tests stay fast."""
    import agent_audit.live.client as live_client
    monkeypatch.setattr(live_client, "_backoff_seconds", lambda attempt, retry_after: 0)


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/chat"


class _QuickAgent(BaseHTTPRequestHandler):
    """Answers everything in one step and refuses obvious attacks."""
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(errors="replace").lower()
        refuse = any(w in body for w in ("ignore", "password", "system prompt", "pwned"))
        data = json.dumps({"output": "I can't help with that." if refuse else "Here is the answer.",
                           "finish_reason": "stop", "steps_taken": 1, "tool_calls": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _Forbidden(BaseHTTPRequestHandler):
    """Refuses every request with 403, as a login wall or firewall would."""
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _manifest(manifest_factory, endpoint, **kw):
    m = manifest_factory(**kw)
    m.runtime.endpoint = endpoint
    m.runtime.target_env = "sandbox"
    return m


def _run(m, phases):
    report = asyncio.run(run_audit(m, phases=phases, mode="certify", mock_tools=False, variability_runs=1, concurrency=2))
    return report, issue_certificate(report)


def test_an_agent_that_cannot_be_reached_is_inconclusive(manifest_factory):
    report, cert = _run(_manifest(manifest_factory, "http://127.0.0.1:9/chat"),
                        ["reliability", "ops", "groundedness", "fairness", "security"])
    assert report.agent_reached is False
    assert cert.tier == "INCONCLUSIVE"
    # Empty answers from a dead agent are never graded: no pass ("no toxic language"), no fail ("failed to abstain")
    behaviour = [f for f in report.findings if f.phase in ("reliability", "groundedness", "fairness", "security")]
    assert behaviour and all(f.severity is Severity.INFO and not f.passed for f in behaviour), \
        [(f.id, f.severity, f.title) for f in behaviour if f.severity is not Severity.INFO or f.passed]


def test_a_missing_endpoint_is_inconclusive_not_failed(manifest_factory):
    report, cert = _run(_manifest(manifest_factory, None), ["reliability", "groundedness"])
    assert cert.tier == "INCONCLUSIVE"
    assert not report.critical_failures and not report.passes


def test_an_agent_behind_403_everywhere_is_inconclusive(manifest_factory):
    srv, url = _serve(_Forbidden)
    try:
        report, cert = _run(_manifest(manifest_factory, url), ["security"])
    finally:
        srv.shutdown()
    assert report.agent_reached is False
    assert cert.tier == "INCONCLUSIVE"


def test_finishing_early_is_not_a_loop_failure(manifest_factory):
    srv, url = _serve(_QuickAgent)
    try:
        report, _ = _run(_manifest(manifest_factory, url), ["reliability", "multi_turn"])
    finally:
        srv.shutdown()
    assert report.agent_reached is True
    for fid in ("REL-ITER-001", "MT-TURNLIMIT-001"):
        f = next(x for x in report.findings if x.id == fid)
        assert f.severity is Severity.INFO and f.description.startswith("Skipped:"), (fid, f.title)


def test_graceful_shutdown_is_not_tested_on_a_live_agent(manifest_factory):
    srv, url = _serve(_QuickAgent)
    try:
        report, _ = _run(_manifest(manifest_factory, url), ["ops"])
    finally:
        srv.shutdown()
    f = next(x for x in report.findings if x.id == "OPS-SHUTDOWN-001")
    assert not f.passed and f.severity is Severity.INFO


def test_declaration_only_passes_do_not_raise_the_score():
    from agent_audit.findings import pass_finding, fail_finding
    from agent_audit.runner import AuditReport, DECLARATION_ONLY_CHECKS
    assert "ARCH-TOOL-001" in DECLARATION_ONLY_CHECKS
    report = asyncio.run(run_audit(_static_manifest(), phases=["architecture"], mode="certify", mock_tools=True))
    arch_tool = next(f for f in report.findings if f.id == "ARCH-TOOL-001")
    assert arch_tool.title.startswith("Declared (not tested)") and not arch_tool.passed


def _static_manifest():
    from agent_audit.manifest import TargetManifest, ToolSpec
    m = TargetManifest(agent_name="declared_only")
    m.capabilities.tools = [ToolSpec(name="search_orders")]
    m.capabilities.context_budget_tokens = 8000
    return m


def test_phases_that_do_not_fit_the_agent_are_not_run(manifest_factory):
    m = _manifest(manifest_factory, "http://127.0.0.1:9/chat")
    report = asyncio.run(run_audit(m, phases=["browser", "voice", "decision"], mode="validate", mock_tools=True,
                                   skip_inapplicable=True))
    assert report.phases_run == []
    assert {s["phase"] for s in report.skipped_phases} == {"browser", "voice", "decision"}


def test_certify_needs_an_address():
    assert _certify_target_problem("agent_name: x\ncapabilities:\n  tools: []\n")
    assert _certify_target_problem("agent_name: x\nruntime:\n  endpoint: https://agent.example.com/chat\n") is None
    assert _certify_target_problem("agent_name: x\nsources:\n  - type: repo\n    path: .\n") is None
    assert _certify_target_problem(
        "agent_name: x\nsources:\n  - type: yaml_inline\n    runtime:\n      provider:\n        name: agentforce\n") is None


def test_audit_api_refuses_certify_without_an_address():
    email = f"honest-{uuid.uuid4().hex[:8]}@example.com"
    conn = get_db_connection()
    cur = conn.cursor()
    create_account(cur, "USER", email, "Honest Tester", hash_password("honest-pass-1"))
    conn.commit()
    conn.close()
    token = client.post("/api/auth/login", json={"email": email, "password": "honest-pass-1"}).json()["token"]
    res = client.post("/api/audit", headers={"Authorization": f"Bearer {token}"},
                      json={"yaml_content": "agent_name: no_address\n", "mode": "certify"})
    events = [json.loads(line[6:]) for line in res.text.splitlines() if line.startswith("data: ")]
    assert events and events[0]["type"] == "error" and "runtime.endpoint" in events[0]["detail"]


def test_a_saved_agent_keeps_its_address():
    email = f"saved-{uuid.uuid4().hex[:8]}@example.com"
    conn = get_db_connection()
    cur = conn.cursor()
    uid = create_account(cur, "USER", email, "Saved Tester", hash_password("saved-pass-1"))
    cur.execute("INSERT INTO agents (user_id, name, canonical_name, created_at, updated_at) VALUES (?, 'Saved', 'saved', '2026-10-10', '2026-10-10')", (uid,))
    agent_id = cur.lastrowid
    assert agent_id is not None
    result = {"manifest_summary": {"runtime": {"endpoint": "https://agent.example.com/chat", "protocol": "http",
                                               "auth": {"type": "bearer", "token_env": "AGENT_TOKEN", "header_name": "Authorization"},
                                               "provider": {"name": "generic", "config": {}}}}}
    cur.execute("""INSERT INTO normal_agent_tests (audit_id, user_id, agent_id, agent_name, mode, tier, created_at, full_result_json)
                   VALUES (?, ?, ?, 'Saved', 'certify', 'CONDITIONAL', '2026-10-10T00:00:00Z', ?)""",
                (f"saved-{uuid.uuid4().hex[:8]}", uid, agent_id, json.dumps(result)))
    conn.commit()
    conn.close()
    out = _with_saved_runtime("agent_name: saved\n", {"id": uid}, agent_id, "certify")
    assert "https://agent.example.com/chat" in out and "AGENT_TOKEN" in out
    # someone else's agent gives nothing
    assert _with_saved_runtime("agent_name: saved\n", {"id": uid + 100000}, agent_id, "certify") == "agent_name: saved\n"


def test_stored_provider_settings_never_keep_literal_secrets():
    cleaned = _without_literal_secrets({"agent_id": "0Xx1", "consumer_secret_env": "SF_SECRET", "client_secret": "abc123",
                                        "api_key": "sk-live", "my_domain_url": "https://x"})
    assert cleaned == {"agent_id": "0Xx1", "consumer_secret_env": "SF_SECRET", "my_domain_url": "https://x"}
