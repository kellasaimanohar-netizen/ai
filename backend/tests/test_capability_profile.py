"""Tests for agent_audit.capability_profile — derivation heuristics, explicit
YAML-override precedence, and capability-driven phase selection."""
from __future__ import annotations

from agent_audit.capability_profile import (
    AgentCapabilityProfile,
    derive_profile,
    select_phases,
)


class TestDeriveProfile:
    def test_no_tools_is_conversational_api_based(self, manifest_factory):
        m = manifest_factory(tools=[], endpoint="https://example.test/chat")
        p = derive_profile(m)
        assert "conversational" in p.archetypes or "api_based" in p.archetypes
        assert p.browser_access is False
        assert p.mcp_servers == []
        assert p.data_mode == "static"

    def test_tools_present_implies_tool_calling(self, manifest_factory):
        m = manifest_factory(tools=["search_kb", "send_email"])
        p = derive_profile(m)
        assert "tool_calling" in p.archetypes

    def test_browser_tools_set_browser_access(self, manifest_factory):
        m = manifest_factory(tools=["navigate_page", "click_element", "screenshot"])
        p = derive_profile(m)
        assert p.browser_access is True
        assert "browser_use" in p.archetypes

    def test_mcp_tools_detected(self, manifest_factory):
        m = manifest_factory(tools=["mcp_filesystem_read", "search_kb"])
        p = derive_profile(m)
        assert "mcp_based" in p.archetypes
        assert "mcp_filesystem_read" in p.mcp_servers

    def test_financial_tools_are_critical_risk(self, manifest_factory):
        m = manifest_factory(tools=["approve_loan", "transfer_funds"])
        p = derive_profile(m)
        assert "financial_decision" in p.archetypes
        assert p.decision_making is True
        assert p.risk_level == "critical"

    def test_destructive_tools_raise_risk_without_financial(self, manifest_factory):
        m = manifest_factory(tools=["delete_account"], destructive_tools=["delete_account"])
        p = derive_profile(m)
        assert p.risk_level == "high"

    def test_pii_fields_set_sensitive_data_handling(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"], pii_fields=["email", "ssn"])
        p = derive_profile(m)
        assert p.sensitive_data_handling is True

    def test_dynamic_data_hints_set_data_mode(self, manifest_factory):
        m = manifest_factory(tools=["get_live_order_status", "check_current_price"])
        p = derive_profile(m)
        assert p.data_mode == "dynamic"

    def test_dynamic_plus_golden_dataset_is_hybrid(self, manifest_factory, tmp_path):
        ds = tmp_path / "golden.jsonl"
        ds.write_text('{"input": "hi", "expected": "hello"}\n', encoding="utf-8")
        m = manifest_factory(tools=["get_live_order_status"], golden_dataset_path=ds)
        p = derive_profile(m)
        assert p.data_mode == "hybrid"

    def test_static_only_agent_has_static_data_mode(self, manifest_factory):
        m = manifest_factory(tools=["summarise_document"])
        p = derive_profile(m)
        assert p.data_mode == "static"

    def test_requires_hitl_propagates(self, manifest_factory):
        m = manifest_factory(tools=["approve_loan"], requires_hitl=True)
        p = derive_profile(m)
        assert p.requires_human_approval is True

    def test_auth_required_reflects_manifest(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        p = derive_profile(m)
        assert p.auth_required is False  # build_manifest defaults to auth type "none"


class TestExplicitOverridePrecedence:
    def test_explicit_data_mode_wins_over_heuristic(self, manifest_factory):
        # No dynamic-data-hint tools -> heuristic alone would say "static".
        m = manifest_factory(tools=["summarise_document"])
        m.capability_profile_raw = {"data_mode": "dynamic"}
        p = derive_profile(m)
        assert p.data_mode == "dynamic"

    def test_explicit_archetypes_wins_over_heuristic(self, manifest_factory):
        m = manifest_factory(tools=[])
        m.capability_profile_raw = {"archetypes": ["financial_decision"]}
        p = derive_profile(m)
        assert p.archetypes == ["financial_decision"]

    def test_explicit_risk_level_wins(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        m.capability_profile_raw = {"risk_level": "critical"}
        p = derive_profile(m)
        assert p.risk_level == "critical"

    def test_unknown_override_key_is_ignored_not_raised(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        m.capability_profile_raw = {"not_a_real_field": "whatever"}
        p = derive_profile(m)  # must not raise
        assert not hasattr(p, "not_a_real_field")


class TestSelectPhases:
    def test_conversational_agent_skips_voice_browser_mcp(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        p = derive_profile(m)
        selected, skipped = select_phases(p)
        assert "voice" in skipped
        assert "browser" in skipped
        assert "mcp" in skipped
        assert "data_analysis" in skipped
        assert "decision" in skipped
        assert "security_agent" in skipped
        # Universally-applicable phases still run
        for always_on in ("architecture", "reliability", "security", "data_governance"):
            assert always_on in selected

    def test_skip_reasons_are_non_empty_strings(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        p = derive_profile(m)
        _, skipped = select_phases(p)
        for phase, reason in skipped.items():
            assert isinstance(reason, str) and len(reason) > 10

    def test_browser_agent_runs_browser_phase(self, manifest_factory):
        m = manifest_factory(tools=["navigate_page", "click_element"])
        p = derive_profile(m)
        selected, skipped = select_phases(p)
        assert "browser" in selected
        assert "browser" not in skipped

    def test_voice_io_type_runs_voice_phase(self, manifest_factory):
        m = manifest_factory(tools=["search_kb"])
        p = derive_profile(m)
        p.io_type = "voice"
        selected, skipped = select_phases(p)
        assert "voice" in selected

    def test_mcp_agent_runs_mcp_phase(self, manifest_factory):
        m = manifest_factory(tools=["mcp_filesystem_read"])
        p = derive_profile(m)
        selected, skipped = select_phases(p)
        assert "mcp" in selected

    def test_decision_agent_runs_decision_phase(self, manifest_factory):
        m = manifest_factory(tools=["approve_loan"])
        p = derive_profile(m)
        selected, skipped = select_phases(p)
        assert "decision" in selected

    def test_security_agent_tools_run_security_agent_phase(self, manifest_factory):
        m = manifest_factory(tools=["query_threat_intel", "raise_alert"])
        p = derive_profile(m)
        selected, skipped = select_phases(p)
        assert "security_agent" in selected

    def test_every_phase_map_entry_is_classified(self, manifest_factory):
        """Regression: select_phases must classify every registered phase —
        one that falls through unclassified would silently always-run,
        which is safe but should be an explicit, deliberate default."""
        from agent_audit.phases import PHASE_MAP

        m = manifest_factory(tools=["search_kb"])
        p = derive_profile(m)
        selected, skipped = select_phases(p)
        assert set(selected) | set(skipped) == set(PHASE_MAP.keys())
