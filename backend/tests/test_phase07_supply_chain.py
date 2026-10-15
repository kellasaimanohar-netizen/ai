"""Dedicated PASS/FAIL pytest coverage for Phase 7 — Supply Chain checks.

All three checks in phase7_supply_chain.py are implemented inline inside
`run_phase()` (no per-check helper functions) and are purely static —
manifest-only, no `ctx.call_agent` calls — so `posture` is irrelevant here.
Every test calls `run_phase(ctx)` and picks the specific finding out of the
returned list by `.id`.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase7_supply_chain import _is_unpinned, run_phase
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


def _find(findings, finding_id):
    return next(f for f in findings if f.id == finding_id)


class TestScDeps001:
    """SC-DEPS-001 — at least one dependency discovered."""

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(dependencies=[("httpx", "0.27.0")])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-DEPS-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail_no_dependencies(self, manifest_factory, ctx_factory):
        m = manifest_factory(dependencies=[])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-DEPS-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestScPin001:
    """SC-PIN-001 — every dependency declares a concrete version pin.

    Wave-0-fixed via the module-level `_is_unpinned()` helper and
    `_PLACEHOLDER_VERSIONS` / `_PLACEHOLDER_VERSION_PATTERN` constants.
    """

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(dependencies=[
            ("httpx", "0.27.0"),
            ("foo", ">=1.0,<2.0"),
        ])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-PIN-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail(self, manifest_factory, ctx_factory):
        m = manifest_factory(dependencies=[
            ("bar", "latest"),
            ("baz", "*"),
        ])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-PIN-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestIsUnpinnedUnit:
    """Direct unit coverage of `_is_unpinned()`'s edge cases."""

    @pytest.mark.parametrize("version", [None, "", "latest", "*", "1.*"])
    async def test_flagged_as_unpinned(self, version):
        assert _is_unpinned(version) is True

    @pytest.mark.parametrize("version", [
        "^0.0",           # legitimate semver caret range — must NOT be flagged
        "0.27.0",          # concrete pin
        ">=0.27,<1.0",     # concrete range
    ])
    async def test_not_flagged_as_unpinned(self, version):
        assert _is_unpinned(version) is False


class TestScModel001:
    """SC-MODEL-001 — models have a known (non-"unknown") provider."""

    async def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(models=[("anthropic", "claude-3-5-sonnet-20241022")])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-MODEL-001")
        assert f.passed is True
        assert f.severity is Severity.PASS

    async def test_fail_unknown_provider(self, manifest_factory, ctx_factory):
        m = manifest_factory(models=[("unknown", "some-model")])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-MODEL-001")
        assert f.passed is False
        assert f.severity is Severity.WARNING

    async def test_fail_no_models_discovered(self, manifest_factory, ctx_factory):
        m = manifest_factory(models=[])
        ctx = ctx_factory(m)
        findings = await run_phase(ctx)
        f = _find(findings, "SC-MODEL-001")
        assert f.passed is False
        assert f.severity is Severity.INFO
