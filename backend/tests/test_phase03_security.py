"""Dedicated PASS/FAIL pytest coverage for Phase 3 — Security checks.

Convention (see test_phase02_reliability.py for the canonical description):
  * One test class per check ID, `test_pass` / `test_fail` methods.
  * SEC-INJ-DIRECT-001, SEC-SECRET-001 and SEC-PII-001 have named async
    `_test_*` helpers — call them directly with `mock_ctx(...)`.
  * SEC-PERM-001's helper (`_test_tool_permissions`) is a static,
    *synchronous* function — it must not be awaited.
  * SEC-SECRET-001 / SEC-PII-001 are posture-aware (Wave 0 fix): posture
    "secure" -> clean scenario, "vulnerable" -> leaky scenario.
  * SEC-PERM-001 is a static manifest-only check — no posture involved.
"""
from __future__ import annotations

from agent_audit.manifest import ToolSpec
from agent_audit.phases.phase3_security import (
    _test_direct_injection,
    _test_pii_in_output,
    _test_secret_leakage,
    _test_tool_permissions,
)
from agent_audit.severity import Severity

# NOTE: no module-level `pytestmark = pytest.mark.asyncio` here (unlike the
# other test_phaseNN_*.py files) — this module mixes async tests (most
# checks) with plain sync tests (SEC-PERM-001, whose helper is sync). The
# project's pytest-asyncio is configured in `asyncio_mode = auto`
# (see pyproject.toml), which already auto-detects `async def test_*`
# functions without needing an explicit mark, so leaving the mark off here
# avoids a PytestWarning on the sync tests while async ones still run fine.


class TestSecInjDirect001:
    """SEC-INJ-DIRECT-001 — resistance to direct prompt-injection attempts.

    Fixed after this file was first written: `_test_direct_injection`'s
    trial() now picks "injection_blocked" vs "injection_success" from
    `ctx.mock_posture` instead of alternating 50/50 by trial index (which
    pinned mean_score at exactly 0.5 and made PASS structurally
    unreachable). Both branches are covered below like every other check.
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=20)
        f = await _test_direct_injection(ctx)
        assert f.id == "SEC-INJ-DIRECT-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable", variability_runs=20)
        f = await _test_direct_injection(ctx)
        assert f.id == "SEC-INJ-DIRECT-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestSecSecret001:
    """SEC-SECRET-001 — auth headers/secrets must not leak into tool args."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_secret_leakage(ctx)
        assert f.id == "SEC-SECRET-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_secret_leakage(ctx)
        assert f.id == "SEC-SECRET-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestSecPii001:
    """SEC-PII-001 — SSN / credit card / email must not leak into output."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_pii_in_output(ctx)
        assert f.id == "SEC-PII-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_pii_in_output(ctx)
        assert f.id == "SEC-PII-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestSecPerm001:
    """SEC-PERM-001 — every tool the agent exposes is declared in YAML.

    Static/sync check — `_test_tool_permissions` is not a coroutine, and
    (per the module-level note above) there's no asyncio pytestmark here to
    conflict with that.
    """

    def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["search_kb"])
        ctx = ctx_factory(m, posture="secure")
        f = _test_tool_permissions(ctx)
        assert f.id == "SEC-PERM-001"
        assert f.passed is True
        assert f.severity is Severity.PASS

    def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["search_kb"])
        # build_manifest's `tools=[...]` kwarg always stamps
        # declared_in=["yaml"]; the FAIL branch needs a tool whose
        # provenance is NOT "yaml", so it's added by hand via ToolSpec.
        m.capabilities.tools.append(
            ToolSpec(name="undeclared_tool", declared_in=["repo"], source_location="app.py:99")
        )
        ctx = ctx_factory(m, posture="secure")
        f = _test_tool_permissions(ctx)
        assert f.id == "SEC-PERM-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL
