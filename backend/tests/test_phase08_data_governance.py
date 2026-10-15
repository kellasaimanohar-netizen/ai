"""Dedicated PASS/FAIL pytest coverage for Phase 8 — Data Governance checks.

Follows the convention established in test_phase02_reliability.py:
  * One test class per check ID.
  * `test_pass` drives the check into its PASS branch, `test_fail` into FAIL.
  * Static checks (all of DG-CONSENT-001/DG-RETENTION-001/DG-ERASURE-001/
    DG-XBORDER-001) are manifest-only — no posture toggle, just different
    `build_manifest(...)` shapes via `manifest_factory`.
  * DG-MINIMISE-001 is the one dynamic check in this phase; it was made
    posture-aware in Wave 0 via the mock client's `pii_probe` scenario, so
    it toggles `posture="secure"|"vulnerable"` via `ctx_factory` like the
    phase2 checks do.
  * Every test asserts `finding.id` and `finding.passed` at minimum; severity
    is asserted on FAIL branches where the source clearly assigns one.
"""
from __future__ import annotations

import pytest

from agent_audit.phases.phase8_data_governance import (
    _check_consent_declaration,
    _check_cross_border_transfer,
    _check_erasure_path,
    _check_pii_minimisation,
    _check_retention_policy,
)
from agent_audit.severity import Severity

pytestmark = pytest.mark.asyncio


class TestDgConsent001:
    """DG-CONSENT-001 — consent capture mechanism must be declared."""

    async def test_not_applicable_no_personal_data(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = _check_consent_declaration(ctx)
        assert f.id == "DG-CONSENT-001"
        assert f.passed is True
        assert "not applicable" in f.title.lower()

    async def test_pass_consent_declared(self, manifest_factory, ctx_factory):
        m = manifest_factory(
            pii_fields=["email"],
            prompts=[("system_prompt", "Our consent policy: we ask for explicit consent before processing personal data.")],
        )
        ctx = ctx_factory(m, posture="secure")
        f = _check_consent_declaration(ctx)
        assert f.id == "DG-CONSENT-001"
        assert f.passed is True

    async def test_fail_no_consent_declared(self, manifest_factory, ctx_factory):
        m = manifest_factory(pii_fields=["email"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_consent_declaration(ctx)
        assert f.id == "DG-CONSENT-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestDgRetention001:
    """DG-RETENTION-001 — a data-retention period must be declared."""

    async def test_not_applicable_no_personal_data(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = _check_retention_policy(ctx)
        assert f.id == "DG-RETENTION-001"
        assert f.passed is True
        assert "not applicable" in f.title.lower()

    async def test_pass_retention_declared(self, manifest_factory, ctx_factory):
        m = manifest_factory(
            pii_fields=["email"],
            prompts=[("system_prompt", "We retain personal data for 90 days, then purge it automatically (TTL).")],
        )
        ctx = ctx_factory(m, posture="secure")
        f = _check_retention_policy(ctx)
        assert f.id == "DG-RETENTION-001"
        assert f.passed is True

    async def test_fail_no_retention_declared(self, manifest_factory, ctx_factory):
        m = manifest_factory(pii_fields=["email"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_retention_policy(ctx)
        assert f.id == "DG-RETENTION-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestDgErasure001:
    """DG-ERASURE-001 — a right-to-erasure endpoint or runbook must exist."""

    async def test_not_applicable_no_personal_data(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = _check_erasure_path(ctx)
        assert f.id == "DG-ERASURE-001"
        assert f.passed is True
        assert "not applicable" in f.title.lower()

    async def test_pass_erasure_tool_declared(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["delete_user"], pii_fields=["email"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_erasure_path(ctx)
        assert f.id == "DG-ERASURE-001"
        assert f.passed is True

    async def test_fail_no_erasure_path(self, manifest_factory, ctx_factory):
        m = manifest_factory(tools=["search_kb"], pii_fields=["email"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_erasure_path(ctx)
        assert f.id == "DG-ERASURE-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestDgXborder001:
    """DG-XBORDER-001 — DPDP personal data must stay in India-approved regions."""

    async def test_not_applicable_no_dpdp_classification(self, manifest_factory, ctx_factory):
        m = manifest_factory(data_classification=["general"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_cross_border_transfer(ctx)
        assert f.id == "DG-XBORDER-001"
        assert f.passed is True
        assert "not applicable" in f.title.lower()

    async def test_fail_no_regions_declared(self, manifest_factory, ctx_factory):
        m = manifest_factory(data_classification=["dpdp_personal"], allowed_data_regions=[])
        ctx = ctx_factory(m, posture="secure")
        f = _check_cross_border_transfer(ctx)
        assert f.id == "DG-XBORDER-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING

    async def test_fail_non_india_region(self, manifest_factory, ctx_factory):
        m = manifest_factory(data_classification=["dpdp_personal"], allowed_data_regions=["us-east-1"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_cross_border_transfer(ctx)
        assert f.id == "DG-XBORDER-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL

    async def test_pass_india_only_regions(self, manifest_factory, ctx_factory):
        m = manifest_factory(data_classification=["dpdp_personal"], allowed_data_regions=["ap-south-1"])
        ctx = ctx_factory(m, posture="secure")
        f = _check_cross_border_transfer(ctx)
        assert f.id == "DG-XBORDER-001"
        assert f.passed is True


class TestDgMinimise001:
    """DG-MINIMISE-001 — no raw PII in benign responses (Wave-0 posture-aware)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _check_pii_minimisation(ctx)
        assert f.id == "DG-MINIMISE-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _check_pii_minimisation(ctx)
        assert f.id == "DG-MINIMISE-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL
