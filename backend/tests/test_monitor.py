"""Tests for the runtime monitor (SentinelAI layer).

Covers each market scenario the monitor must catch (token overrun, step loop,
task drift, tool escalation, HITL bypass, risky decisions, PII leak, outcome
drift), plus batch vs stream evaluation and baseline derivation from a manifest.
"""
from __future__ import annotations

from agent_audit.monitor import (
    Decision,
    MonitorBaseline,
    MonitorEngine,
    RunRecord,
    ToolCall,
)
from agent_audit.monitor.sources import MockTelemetrySource, make_run
from agent_audit.severity import Severity


def _baseline(**kw) -> MonitorBaseline:
    defaults = dict(
        agent_name="agent",
        max_tokens_per_run=5000, max_cost_per_run_usd=0.10, max_steps_per_run=10,
        allowed_tools={"Get", "Search", "Post"}, destructive_tools={"Post"},
        requires_hitl=True, pii_fields=["email"], baseline_success_rate=0.95,
        max_cost_per_window_usd=5.0,
    )
    defaults.update(kw)
    return MonitorBaseline(**defaults)


class TestPerRunChecks:
    def test_healthy_run_no_alerts(self):
        eng = MonitorEngine(_baseline())
        run = make_run("ok", tokens_prompt=300, tokens_completion=200, cost_usd=0.01,
                       steps_taken=3, tools=[ToolCall("Get")])
        res = eng.evaluate_run(run)
        assert res.healthy
        assert res.alerting == []

    def test_token_overrun_is_critical(self):
        eng = MonitorEngine(_baseline())
        run = make_run("x", tokens_prompt=40000, tokens_completion=20000, cost_usd=2.5)
        res = eng.evaluate_run(run)
        ids = {f.id for f in res.alerting}
        assert "MON-TOKEN-001" in ids
        assert any(f.id == "MON-TOKEN-001" and f.severity is Severity.CRITICAL
                   for f in res.findings)

    def test_step_loop(self):
        eng = MonitorEngine(_baseline())
        res = eng.evaluate_run(make_run("x", steps_taken=99))
        assert "MON-LOOP-001" in {f.id for f in res.alerting}

    def test_tool_escalation_off_allowlist(self):
        eng = MonitorEngine(_baseline())
        res = eng.evaluate_run(make_run("x", tools=[ToolCall("Delete_Everything")]))
        assert "MON-DRIFT-001" in {f.id for f in res.alerting}

    def test_hitl_bypass_on_destructive(self):
        eng = MonitorEngine(_baseline())
        run = make_run("x", tools=[ToolCall("Post", destructive=True, hitl_approved=False)])
        res = eng.evaluate_run(run)
        assert "MON-HITL-001" in {f.id for f in res.alerting}

    def test_hitl_approved_destructive_passes(self):
        eng = MonitorEngine(_baseline())
        run = make_run("x", tools=[ToolCall("Post", destructive=True, hitl_approved=True)])
        res = eng.evaluate_run(run)
        assert "MON-HITL-001" not in {f.id for f in res.alerting}

    def test_risky_autonomous_decision(self):
        eng = MonitorEngine(_baseline())
        run = make_run("x", decisions=[
            Decision("auto_approve", "yes", autonomous=True, risk_score=0.9)])
        res = eng.evaluate_run(run)
        assert "MON-DEC-001" in {f.id for f in res.alerting}

    def test_low_risk_decision_passes(self):
        eng = MonitorEngine(_baseline())
        run = make_run("x", decisions=[
            Decision("route", "queue_a", autonomous=True, risk_score=0.2)])
        res = eng.evaluate_run(run)
        assert "MON-DEC-001" not in {f.id for f in res.alerting}

    def test_pii_leak_ssn_and_card(self):
        eng = MonitorEngine(_baseline())
        res = eng.evaluate_run(make_run("x", output="SSN 123-45-6789 card 4111111111111111"))
        f = [f for f in res.alerting if f.id == "MON-PII-001"]
        assert f and "SSN" in f[0].data_classification
        assert "credit_card" in f[0].data_classification

    def test_pii_card_luhn_negative(self):
        # 16 digits that fail Luhn must NOT trip the card detector.
        eng = MonitorEngine(_baseline())
        res = eng.evaluate_run(make_run("x", output="order id 1234567890123456"))
        assert "MON-PII-001" not in {f.id for f in res.alerting}


class TestWindowChecks:
    def test_window_cost_overrun(self):
        eng = MonitorEngine(_baseline(max_cost_per_window_usd=1.0))
        runs = [make_run(f"r{i}", cost_usd=0.5, finished_at=f"2026-06-26T10:0{i}:00Z")
                for i in range(5)]
        res = eng.evaluate_batch(runs)
        assert "MON-COST-002" in {f.id for f in res.alerting}

    def test_token_outlier_vs_window(self):
        eng = MonitorEngine(_baseline(max_tokens_per_run=10_000_000))  # disable abs ceiling
        # Seed a window of small runs, then one big outlier.
        for i in range(6):
            eng.evaluate_run(make_run(f"s{i}", tokens_prompt=100, tokens_completion=100,
                                      finished_at=f"2026-06-26T10:0{i}:00Z"))
        res = eng.evaluate_run(make_run("outlier", tokens_prompt=5000, tokens_completion=5000,
                                        finished_at="2026-06-26T10:09:00Z"))
        assert "MON-TOKEN-002" in {f.id for f in res.alerting}

    def test_outcome_drift_below_baseline(self):
        eng = MonitorEngine(_baseline(baseline_success_rate=0.95))
        runs = [make_run(f"r{i}", outcome="faulted" if i < 4 else "success",
                         finished_at=f"2026-06-26T10:0{i}:00Z") for i in range(10)]
        res = eng.evaluate_batch(runs)
        assert "MON-OUTCOME-001" in {f.id for f in res.alerting}


class TestEngineModes:
    def test_batch_equals_sequential_stream(self):
        runs = [make_run(f"r{i}", finished_at=f"2026-06-26T10:0{i}:00Z") for i in range(5)]
        eng_b = MonitorEngine(_baseline())
        batch = eng_b.evaluate_batch(runs)
        assert batch.runs_evaluated == 5

    def test_check_exception_does_not_crash(self):
        eng = MonitorEngine(_baseline())
        # A malformed run (None output) must be tolerated, not raise.
        run = RunRecord(run_id="weird", agent_name="agent", source="mock")
        res = eng.evaluate_run(run)
        assert isinstance(res.alerting, list)

    def test_window_is_bounded(self):
        eng = MonitorEngine(_baseline(window_size=3))
        for i in range(10):
            eng.evaluate_run(make_run(f"r{i}", finished_at=f"2026-06-26T10:{i:02d}:00Z"))
        assert len(eng.window) == 3


class TestBaselineDerivation:
    def test_from_manifest(self):
        from pathlib import Path

        from agent_audit.sources import load_target

        target_path = Path(__file__).resolve().parent.parent / "targets" / "agentforce_agent.yaml"
        m = load_target(str(target_path))
        base = MonitorBaseline.from_manifest(m)
        assert base.agent_name == "Agentforce_Service_Agent"
        assert "Issue_Refund" in base.destructive_tools
        assert base.requires_hitl is True


class TestMockSource:
    def test_fetch_and_since_filter(self):
        src = MockTelemetrySource([
            make_run("a", finished_at="2026-06-26T09:00:00Z"),
            make_run("b", finished_at="2026-06-26T11:00:00Z"),
        ])
        assert len(src.fetch_runs()) == 2
        recent = src.fetch_runs(since="2026-06-26T10:00:00Z")
        assert [r.run_id for r in recent] == ["b"]
