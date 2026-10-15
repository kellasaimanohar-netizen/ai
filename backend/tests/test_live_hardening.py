"""Verification suite for the v8 live-hardening layer.

Rewritten to use real ``assert`` statements so pytest actually fails when a
behaviour regresses. (The previous version only printed PASS/FAIL via a helper
that never raised, so every check passed under pytest regardless of outcome.)

Covers: adapters (incl. registry isolation), budget (incl. refund-on-failure),
safety gate, and an end-to-end LiveAgentClient run against a fake HTTP agent
via httpx.MockTransport — no real network.

Run: python -m pytest tests/test_live_hardening.py -v
"""
from __future__ import annotations

import httpx
import pytest

from agent_audit.live.adapters import (
    CanonicalResponse,
    ResponseAdapter,
    detect_and_normalize,
    register_adapter,
    restore_adapters,
    snapshot_adapters,
)
from agent_audit.live.budget import BudgetExceededError, CallBudget
from agent_audit.live.client import LiveAgentClient, LiveCallError
from agent_audit.live.safety import (
    DESTRUCTIVE_PHASES,
    SafetyGate,
    SandboxViolationError,
    TargetEnv,
)


@pytest.fixture(autouse=True)
def _isolate_adapter_registry():
    """Snapshot the global adapter registry and restore it after each test, so
    adapters registered in one test never leak into another (or into a live
    audit running in the same process)."""
    saved = snapshot_adapters()
    yield
    restore_adapters(saved)


# ───────────────────────── adapters ─────────────────────────
class TestAdapters:
    def test_native(self):
        r = detect_and_normalize({"output": "hi", "finish_reason": "complete", "cost_usd": 0.01})
        assert r["output"] == "hi"
        assert r["finish_reason"] == "complete"
        assert r["cost_usd"] == 0.01

    def test_openai_chat(self):
        r = detect_and_normalize({
            "id": "chatcmpl-1",
            "choices": [{"message": {"content": "answer", "tool_calls": [
                {"function": {"name": "search", "arguments": '{"q": "x"}'}}]},
                "finish_reason": "stop"}],
            "usage": {"total_cost": 0.02},
        })
        assert r["output"] == "answer"
        assert r["finish_reason"] == "complete"
        assert r["tool_calls"][0]["tool"] == "search"
        assert r["tool_calls"][0]["args"] == {"q": "x"}
        assert r["cost_usd"] == 0.02

    def test_openai_bad_tool_args_dont_crash(self):
        r = detect_and_normalize({
            "choices": [{"message": {"content": "x", "tool_calls": [
                {"function": {"name": "f", "arguments": "{not json"}}]},
                "finish_reason": "stop"}],
        })
        assert r["tool_calls"][0]["args"] == {"_raw": "{not json"}

    def test_anthropic_messages(self):
        r = detect_and_normalize({
            "type": "message", "id": "msg_1",
            "content": [{"type": "text", "text": "hello "}, {"type": "text", "text": "world"}],
            "stop_reason": "end_turn", "usage": {"cost_usd": 0.03},
        })
        assert r["output"] == "hello world"
        assert r["finish_reason"] == "complete"
        assert r["cost_usd"] == 0.03

    def test_anthropic_tool_use(self):
        r = detect_and_normalize({
            "type": "message",
            "content": [{"type": "tool_use", "name": "calc", "input": {"a": 1}}],
            "stop_reason": "tool_use",
        })
        assert r["tool_calls"][0]["tool"] == "calc"
        assert r["finish_reason"] == "tool_calls"

    def test_langserve_nested(self):
        r = detect_and_normalize({"output": {"output": "nested answer"}, "run_id": "r1"})
        assert r["output"] == "nested answer"

    def test_raw_fallbacks(self):
        assert detect_and_normalize("just text")["output"] == "just text"
        assert detect_and_normalize({"response": "r"})["output"] == "r"
        assert detect_and_normalize({"answer": "a"})["output"] == "a"
        assert "foo" in detect_and_normalize({"foo": "bar"})["output"]
        assert detect_and_normalize(None)["output"] == ""

    def test_custom_adapter_wins(self):
        class EchoAdapter(ResponseAdapter):
            name = "echo"
            def matches(self, body):
                return isinstance(body, dict) and body.get("kind") == "echo"
            def normalize(self, body):
                return CanonicalResponse(output="ECHO:" + body.get("msg", ""))
        register_adapter(EchoAdapter())
        assert detect_and_normalize({"kind": "echo", "msg": "x"})["output"] == "ECHO:x"

    def test_buggy_adapter_skipped(self):
        class BrokenAdapter(ResponseAdapter):
            name = "broken"
            def matches(self, body):
                raise RuntimeError("boom")
            def normalize(self, body):
                return CanonicalResponse()
        register_adapter(BrokenAdapter())
        # A raising adapter must not kill normalization.
        assert detect_and_normalize("safe")["output"] == "safe"

    def test_registry_isolation(self):
        # The custom adapters from the two tests above must NOT have leaked here,
        # thanks to the autouse restore fixture.
        assert not any(a.name in {"echo", "broken"} for a in snapshot_adapters())


# ───────────────────────── budget ─────────────────────────
class TestBudget:
    async def test_per_test_cap(self):
        b = CallBudget(max_calls=10, max_cost_usd=100.0, max_per_test=2)
        await b.reserve("t1"); await b.settle(0.1)
        await b.reserve("t1"); await b.settle(0.1)
        with pytest.raises(BudgetExceededError):
            await b.reserve("t1")

    async def test_call_count_cap(self):
        b = CallBudget(max_calls=2, max_cost_usd=100.0, max_per_test=100)
        await b.reserve("a"); await b.settle(0.0)
        await b.reserve("b"); await b.settle(0.0)
        with pytest.raises(BudgetExceededError):
            await b.reserve("c")

    async def test_spend_cap_blocks_next_reserve(self):
        # BUG-1 fix: settle() records cost and never raises — the call that just
        # completed has been paid for and its result must be kept. The spend
        # ceiling is enforced on the NEXT reserve() instead.
        b = CallBudget(max_calls=100, max_cost_usd=0.5, max_per_test=100)
        await b.reserve("x")
        await b.settle(0.6)                      # crossing call completes cleanly
        assert b.snapshot()["cost_spent_usd"] == 0.6
        with pytest.raises(BudgetExceededError):
            await b.reserve("x")                 # next call is blocked

    async def test_release_refunds_slot(self):
        # Regression: a failed call must refund its reserved slot, or transient
        # failures silently exhaust the budget and abort a legitimate audit.
        b = CallBudget(max_calls=2, max_cost_usd=100.0, max_per_test=100)
        await b.reserve("x")
        await b.release("x")          # call failed all retries
        assert b.calls_made == 0
        # Budget fully available again.
        await b.reserve("y"); await b.reserve("z")
        assert b.calls_made == 2

    async def test_release_never_negative(self):
        b = CallBudget()
        await b.release("never-reserved")
        assert b.calls_made == 0


# ───────────────────────── safety gate ─────────────────────────
class TestSafety:
    def test_mock_allows_all(self):
        g = SafetyGate(env=TargetEnv.UNKNOWN, live=False)
        for p in DESTRUCTIVE_PHASES:
            g.authorize(p)  # must not raise

    def test_live_sandbox_allows_destructive(self):
        g = SafetyGate(env=TargetEnv.SANDBOX, live=True)
        for p in DESTRUCTIVE_PHASES:
            g.authorize(p)

    def test_live_prod_blocks_destructive(self):
        g = SafetyGate(env=TargetEnv.PRODUCTION, live=True, live_authorized=True)
        with pytest.raises(SandboxViolationError):
            g.authorize("adversarial")
        g.authorize("architecture")  # non-destructive is fine once live_authorized=True

    def test_live_prod_blocks_everything_without_explicit_authorization(self):
        # v10.4: ANY live phase against PRODUCTION — not just destructive
        # ones — requires live_authorized=True. A non-destructive phase like
        # "architecture" must not silently run against a real production
        # system just because mock_tools=False was passed.
        g = SafetyGate(env=TargetEnv.PRODUCTION, live=True)
        with pytest.raises(SandboxViolationError):
            g.authorize("architecture")
        with pytest.raises(SandboxViolationError):
            g.authorize("adversarial")

    def test_live_unknown_fails_closed(self):
        g = SafetyGate(env=TargetEnv.UNKNOWN, live=True)
        with pytest.raises(SandboxViolationError):
            g.authorize("browser")

    def test_staging_override_allows(self):
        g = SafetyGate(env=TargetEnv.STAGING, live=True, allow_destructive_override=True)
        g.authorize("multi_turn")

    def test_production_override_still_blocks(self):
        g = SafetyGate(env=TargetEnv.PRODUCTION, live=True, allow_destructive_override=True)
        with pytest.raises(SandboxViolationError):
            g.authorize("multi_turn")


# ───────────────────────── LiveAgentClient (end-to-end, fake HTTP) ─────────────────────────
class _StubRuntime:
    endpoint = "https://fake-agent.local/invoke"


class _StubManifest:
    """Minimal stand-in for TargetManifest — only what LiveAgentClient touches."""
    def __init__(self):
        self.runtime = _StubRuntime()

    def build_http_headers(self):
        return {"authorization": "Bearer test"}


def _make_client(handler, budget=None):
    """Build a LiveAgentClient whose httpx client uses a MockTransport handler."""
    client = LiveAgentClient(_StubManifest(), budget=budget)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


class TestLiveClientE2E:
    async def test_openai_shaped_call_normalizes_and_strips_keys(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json
            seen["body"] = _json.loads(request.content)
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={
                "id": "chatcmpl-9",
                "choices": [{"message": {"content": "live answer"}, "finish_reason": "stop"}],
                "usage": {"total_cost": 0.05},
            })

        client = _make_client(handler)
        try:
            resp, latency_ms = await client.invoke(
                {"input": "hi", "_test_name": "probe1", "_internal": "secret"}
            )
        finally:
            await client.aclose()

        # Normalized to canonical shape.
        assert resp["output"] == "live answer"
        assert resp["finish_reason"] == "complete"
        assert resp["cost_usd"] == 0.05
        assert latency_ms >= 0
        # Internal underscore keys stripped before hitting the agent.
        assert "_test_name" not in seen["body"]
        assert "_internal" not in seen["body"]
        assert seen["body"] == {"input": "hi"}
        # Auth header forwarded.
        assert seen["auth"] == "Bearer test"

    async def test_cost_tracked_against_budget(self):
        def handler(request):
            return httpx.Response(200, json={"output": "x", "finish_reason": "stop", "cost_usd": 0.10})

        budget = CallBudget(max_calls=10, max_cost_usd=100.0)
        client = _make_client(handler, budget=budget)
        try:
            await client.invoke({"input": "a", "_test_name": "t"})
        finally:
            await client.aclose()
        assert budget.calls_made == 1
        assert budget.cost_spent_usd == 0.10

    async def test_4xx_fails_fast_and_refunds_budget(self):
        def handler(request):
            return httpx.Response(400, text="bad request")

        budget = CallBudget(max_calls=2, max_cost_usd=100.0)
        client = _make_client(handler, budget=budget)
        try:
            with pytest.raises(LiveCallError):
                await client.invoke({"input": "a", "_test_name": "t"})
        finally:
            await client.aclose()
        # Slot refunded — a non-retryable failure must not consume budget.
        assert budget.calls_made == 0

    async def test_production_block_short_circuits_before_any_call(self):
        # The gate is what protects production; confirm a blocked phase never
        # reaches the client. (Pairs with the gate unit tests above.)
        g = SafetyGate(env=TargetEnv.PRODUCTION, live=True)
        called = False

        def handler(request):
            nonlocal called
            called = True
            return httpx.Response(200, json={"output": "should not happen"})

        with pytest.raises(SandboxViolationError):
            g.authorize("adversarial")
        assert called is False


class TestBugfixRegressions:
    """Regression tests for the v8 bug-fix pass."""

    async def test_successful_call_kept_when_spend_crossed(self):
        # BUG-1: a successful, paid-for response must be RETURNED even when its
        # cost crosses max_cost_usd. The next call is the one that gets blocked.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "output": "real answer", "finish_reason": "complete", "cost_usd": 0.6,
            })

        budget = CallBudget(max_calls=100, max_cost_usd=0.5, max_per_test=100)
        client = _make_client(handler, budget=budget)
        try:
            resp, _ = await client.invoke({"input": "hi", "_test_name": "p"})
            assert resp["output"] == "real answer"          # result kept, not discarded
            with pytest.raises(BudgetExceededError):
                await client.invoke({"input": "again", "_test_name": "p"})  # next blocked
        finally:
            await client.aclose()

    async def test_single_owner_accounting_no_double_refund(self):
        # BUG-3: exactly one of settle()/release() runs per reservation. A 4xx
        # refunds once (calls_made back to 0), never below zero.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"error": "bad"})

        budget = CallBudget(max_calls=5, max_cost_usd=100.0)
        client = _make_client(handler, budget=budget)
        try:
            with pytest.raises(LiveCallError):
                await client.invoke({"input": "x", "_test_name": "t"})
        finally:
            await client.aclose()
        assert budget.calls_made == 0          # refunded exactly once
        assert budget._per_test_counts.get("t", 0) == 0
