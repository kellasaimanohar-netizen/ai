"""Wave 6 — report/certificate transparency between mock and live/staging runs.

Covers:
  * AuditReport.test_environment correctly reflects mock vs. sandbox/staging.
  * AuditReport.dataset_used reflects the manifest's golden dataset (or None).
  * AuditReport's pass/fail/skip/info counts.
  * issue_certificate() refuses to present a mock-mode run as CERTIFIED or
    CONDITIONAL — it is always downgraded to FRAMEWORK_VALIDATION_ONLY,
    regardless of what the caller passes for `framework_validation_only`.
"""
from __future__ import annotations

import pytest

from agent_audit.certificate import issue_certificate
from agent_audit.exporters import export_html, export_json
from agent_audit.runner import run_audit
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestTestEnvironmentField:
    async def test_mock_tools_reports_mock_environment(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"], target_env="production", endpoint="https://prod.example.com")
        report = await run_audit(m, mode="validate", mock_tools=True, phases=["architecture"], variability_runs=2)
        assert report.test_environment == "mock"

    async def test_sandbox_endpoint_reports_sandbox_environment(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"], target_env="sandbox")
        report = await run_audit(m, mode="validate", mock_tools=False, phases=["architecture"], variability_runs=2)
        assert report.test_environment == "sandbox"


class TestDatasetUsedField:
    async def test_none_when_no_golden_dataset(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases=["architecture"], variability_runs=2)
        assert report.dataset_used is None

    async def test_reflects_declared_golden_dataset_path(self, manifest_factory, tmp_path):
        ds = tmp_path / "golden.jsonl"
        ds.write_text('{"input": "x", "expected": "y"}\n', encoding="utf-8")
        m = manifest_factory(tools=["search_kb"], golden_dataset_path=ds)
        report = await run_audit(m, mode="validate", mock_tools=True, phases=["architecture"], variability_runs=2)
        assert report.dataset_used == str(ds)


class TestStatusCounts:
    async def test_counts_partition_findings(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(
            m, mode="validate", mock_tools=True, mock_posture="secure",
            phases=["architecture", "reliability"], variability_runs=3,
        )
        assert report.pass_count == len(report.passes)
        assert report.pass_count + report.fail_count + report.info_count + report.skip_count == len(report.findings)


class TestProductionLiveAuthorizationGate:
    """A live run against a PRODUCTION-classified endpoint must be explicitly
    authorized — for every phase, not just the destructive ones (previously
    only destructive phases were gated; a non-destructive phase like
    "architecture" would silently run live against production)."""

    async def test_blocked_without_explicit_authorization(self, manifest_factory):
        m = manifest_factory(target_env="production", endpoint="https://prod.example.com")
        report = await run_audit(
            m, mode="validate", mock_tools=False, phases=["architecture"], variability_runs=1,
        )
        assert not report.findings or all(not f.passed for f in report.findings)
        blocked = {item["phase"] for item in report.skipped_phases}
        assert "architecture" in blocked

    async def test_runs_when_explicitly_authorized(self, manifest_factory):
        m = manifest_factory(target_env="production", endpoint="https://prod.example.com")
        report = await run_audit(
            m, mode="validate", mock_tools=False, live_authorized=True,
            phases=["architecture"], variability_runs=1,
        )
        blocked = {item["phase"] for item in report.skipped_phases}
        assert "architecture" not in blocked


class TestCertificateMockGuard:
    async def test_mock_run_is_never_issued_as_certified(self, manifest_factory):
        # A clean architecture-only run would normally score high enough for
        # CERTIFIED — but it came from mock_tools=True, so it must not be.
        m = manifest_factory(tools=["search_kb"], requires_hitl=False)
        report = await run_audit(
            m, mode="validate", mock_tools=True, mock_posture="secure",
            phases=["architecture"], variability_runs=2,
        )
        cert = issue_certificate(report)  # framework_validation_only defaults False
        assert cert.tier == "FRAMEWORK_VALIDATION_ONLY"
        assert cert.framework_validation_only is True

    async def test_explicit_false_does_not_override_the_mock_guard(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(
            m, mode="validate", mock_tools=True, mock_posture="secure",
            phases=["architecture"], variability_runs=2,
        )
        cert = issue_certificate(report, framework_validation_only=False)
        assert cert.tier == "FRAMEWORK_VALIDATION_ONLY"

    async def test_not_certified_stays_not_certified_even_from_mock(self, manifest_factory):
        # A critical failure is still a critical failure — the guard doesn't
        # need to relabel an already-negative verdict.
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(
            m, mode="validate", mock_tools=True, mock_posture="vulnerable",
            phases=["security"], variability_runs=5,
        )
        assert report.critical_failures  # sanity: this posture does produce criticals
        cert = issue_certificate(report)
        assert cert.tier == "NOT_CERTIFIED"


class TestExporterFieldsSurfaced:
    async def test_json_export_includes_new_fields(self, manifest_factory, tmp_path):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases=["architecture"], variability_runs=2)
        path = export_json(report, tmp_path / "report.json")
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["test_environment"] == "mock"
        assert data["capability_profile"] == {}
        assert "failed" in data["summary"] and "skipped" in data["summary"]

    async def test_html_export_shows_environment(self, manifest_factory, tmp_path):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases=["architecture"], variability_runs=2)
        path = export_html(report, tmp_path / "report.html")
        text = path.read_text(encoding="utf-8")
        assert "env-mock" in text
        assert ">mock<" in text
