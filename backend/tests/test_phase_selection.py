"""Integration coverage for run_audit(phases="auto") — capability-driven
phase selection end-to-end, and backward compatibility of the existing
phases=[...] / phases=None call shapes."""
from __future__ import annotations

import pytest

from agent_audit.phases import PHASE_MAP
from agent_audit.runner import run_audit

pytestmark = pytest.mark.asyncio


class TestRunAuditAutoMode:
    async def test_auto_populates_capability_profile(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases="auto", variability_runs=3)
        assert report.capability_profile
        assert "archetypes" in report.capability_profile

    async def test_auto_records_skip_reasons_for_omitted_phases(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])  # no browser/voice/mcp signals
        report = await run_audit(m, mode="validate", mock_tools=True, phases="auto", variability_runs=3)
        skipped_ids = {item["phase"] for item in report.skipped_phases}
        assert "browser" in skipped_ids
        assert "voice" in skipped_ids
        for item in report.skipped_phases:
            assert item["reason"]
            assert item["remediation"]

    async def test_auto_only_runs_selected_phases(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases="auto", variability_runs=3)
        phases_seen = {f.phase for f in report.findings}
        assert "browser" not in phases_seen
        assert "voice" not in phases_seen
        assert "architecture" in phases_seen

    async def test_auto_runs_browser_phase_for_browser_agent(self, manifest_factory):
        m = manifest_factory(tools=["navigate_page", "click_element"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases="auto", variability_runs=3)
        phases_seen = {f.phase for f in report.findings}
        assert "browser" in phases_seen
        skipped_ids = {item["phase"] for item in report.skipped_phases}
        assert "browser" not in skipped_ids


class TestBackwardCompatibility:
    """phases=None and an explicit phases=[...] list must behave exactly as
    before Wave 2 — "auto" is strictly additive, opt-in."""

    async def test_none_still_runs_every_phase(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        report = await run_audit(m, mode="validate", mock_tools=True, phases=None, variability_runs=2)
        assert set(report.phases_run) == set(PHASE_MAP.keys())
        assert report.capability_profile == {}

    async def test_explicit_list_is_unaffected_by_capability_profile(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])  # would auto-skip browser
        report = await run_audit(
            m, mode="validate", mock_tools=True, phases=["browser"], variability_runs=2,
        )
        assert report.phases_run == ["browser"]
        phases_seen = {f.phase for f in report.findings}
        assert "browser" in phases_seen
        assert report.capability_profile == {}
