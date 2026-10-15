"""Tests for Audit Integrity, honest test reporting, and score calculation."""
from pathlib import Path

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from agent_audit.findings import Finding
from agent_audit.severity import Severity
from agent_audit.runner import AuditReport, run_audit
from agent_audit.sources.loader import load_target
from agent_audit.live.client import LiveAgentClient, LiveCallError
from agent_audit.live.budget import CallBudget


def test_trust_score_ignores_skipped_and_info_findings():
    """Verify that unexecuted/skipped checks do not inflate or skew the trust score."""
    findings = [
        # Executed pass
        Finding(
            id="SEC-001",
            phase="security",
            test_name="prompt_injection_test",
            severity=Severity.PASS,
            passed=True,
            title="Prompt Injection Defense",
            description="Agent refused prompt injection",
        ),
        # Executed failure (critical)
        Finding(
            id="SEC-002",
            phase="security",
            test_name="ssrf_test",
            severity=Severity.CRITICAL,
            passed=False,
            title="SSRF Vulnerability",
            description="Agent accessed internal network",
        ),
        # Skipped check (no repo)
        Finding(
            id="SC-DEPS-001",
            phase="supply_chain",
            test_name="deps_pin_test",
            severity=Severity.INFO,
            passed=False,
            title="Pinned Dependencies",
            description="Skipped: Repository source required",
        ),
        Finding(
            id="OBS-LOGS-001",
            phase="observability",
            test_name="logging_test",
            severity=Severity.INFO,
            passed=False,
            title="Structured Logging",
            description="Skipped: Target has no repository source",
        ),
    ]

    report = AuditReport(
        agent_name="TestAgent",
        started_at="2026-09-22T00:00:00Z",
        phases_run=["security", "supply_chain", "observability"],
        findings=findings,
    )

    # 2 executed tests: 1 pass, 1 critical failure.
    # Base pass percentage: 1/2 = 50%.
    # Penalty for 1 critical failure: -10.
    # Score should be 40.
    # If skipped tests had been counted as passes or inflated denominator:
    # (3/4 = 75% - 10 = 65%), which would be dishonest!
    assert report.trust_score == 40
    assert report.enterprise_ready is False


@pytest.mark.asyncio
async def test_skipped_checks_are_not_marked_as_passed():
    """Verify runner.run_audit itself marks file-based checks as skipped
    (passed=False, Severity.INFO, description prefixed "Skipped:") when the
    target has no repo source — by actually calling run_audit, not by
    re-implementing its filtering logic inline against a hand-built report.
    """
    target_path = (
        Path(__file__).resolve().parent.parent / "targets" / "capital_allocation_agent.yaml"
    )
    manifest = load_target(target_path)
    # This target only declares a yaml_inline source — no repo — so the
    # file-based supply_chain/observability checks below can't be satisfied.
    assert not any(k.startswith("repo") for k in manifest.provenance_trail.keys())

    report = await run_audit(
        manifest,
        phases=["supply_chain", "observability"],
        mock_tools=True,
    )

    # runner.py only rewrites findings that failed for lack of a repo source —
    # a check that legitimately passes without one (e.g. because it probes the
    # mock agent rather than static files) is untouched. So assert on the
    # actual "Skipped:" marker the runner writes, not a fixed set of IDs whose
    # pass/fail outcome depends on runtime behavior.
    skipped = [f for f in report.findings if str(f.description).startswith("Skipped:")]
    assert skipped, "expected run_audit to skip at least one file-based check without a repo source"
    for f in skipped:
        assert f.passed is False, f"{f.id}: skipped check must not be marked as passed"
        assert f.severity == Severity.INFO, f"{f.id}: skipped check must be INFO, not a real pass/fail"


@pytest.mark.asyncio
async def test_live_client_raises_on_405_and_does_not_mock_pass():
    """Verify that LiveAgentClient raises LiveCallError when the server returns 405 Method Not Allowed."""
    budget = CallBudget(max_calls=10, max_cost_usd=1.0)

    # Mock target manifest
    mock_manifest = MagicMock()
    mock_manifest.runtime.endpoint = "https://example.com/api/chat"
    mock_manifest.runtime.http_method = "POST"
    mock_manifest.runtime.request_format = None
    mock_manifest.runtime.response_format = None
    mock_manifest.runtime.timeout_s = 5.0
    mock_manifest.runtime.extra_endpoints = []
    mock_manifest.build_http_headers.return_value = {}

    client = LiveAgentClient(
        manifest=mock_manifest,
        budget=budget,
    )

    import httpx

    mock_resp = MagicMock()
    mock_resp.status_code = 405
    mock_resp.text = "Method Not Allowed"
    mock_resp.headers = {"content-type": "text/plain"}
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "405 Method Not Allowed",
        request=MagicMock(),
        response=mock_resp,
    )

    mock_http_client = AsyncMock()
    mock_http_client.request.return_value = mock_resp
    client._client = mock_http_client

    with pytest.raises(LiveCallError) as exc_info:
        await client.invoke(payload={"message": "hello", "_test_name": "method_test"})

    assert "live call failed" in str(exc_info.value).lower()
    assert client.stats["failed_requests"] > 0
