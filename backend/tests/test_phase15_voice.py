"""Dedicated PASS/FAIL pytest coverage for Phase 15 — Voice Agent Safety checks.

Follows the convention established in test_phase02_reliability.py:
  * One test class per check ID.
  * `test_pass` drives the check into its PASS branch, `test_fail` into FAIL.
  * Checks call their `_test_*` helper directly (imported from the phase
    module) with a `mock_ctx(...)` built via the shared `manifest_factory` /
    `ctx_factory` fixtures from conftest.py.
  * Every test asserts `finding.id` and `finding.passed` at minimum; severity
    is asserted where the source clearly assigns one on that branch.

Reachability notes (read the actual phase15_voice.py source before touching
this file — do not assume the below without re-verifying):

  * VOICE-INJ-001 (`_test_asr_injection`) runs `_ASR_INJECTION_PAYLOADS`
    through `run_variability`, alternating the mock scenario by trial index
    parity (`"injection_blocked"` for even `i`, `"injection_success"` for
    odd `i`) — independent of posture. With `variability_runs=1` only i=0
    runs ("injection_blocked" → trial passes), and `classify()`'s small-N
    special case (`runs == passes and runs < 5` → ROBUST) yields a PASS
    finding. With runs >= 2 the alternation always produces a mixed
    pass/fail result whose wide Wilson CI classifies as HIGH_UNCERTAINTY,
    which is not in (ROBUST, STABLE) and always yields FAIL. So
    `variability_runs=1` drives PASS, the conftest default (5) drives FAIL.
  * VOICE-PII-001 (`_test_transcript_pii`) is Wave-0-fixed: it always
    requests the posture-aware `"pii_probe"` mock scenario, so `posture=`
    alone toggles PASS/FAIL.
  * VOICE-ESC-001, VOICE-TTS-001, VOICE-DISF-001 were fixed after this file
    was first written: each now uses a dedicated posture-aware mock scenario
    ("voice_escalation_probe", "tts_safety_probe", "disfluency_probe")
    instead of a single hardcoded one, so `posture=` toggles PASS/FAIL for
    all three now.
  * VOICE-CONSENT-001 (`_test_consent_declaration`) is a synchronous,
    static, manifest-only check (no mock scenario involved at all) — both
    branches are driven purely by `data_classification`.
"""
from __future__ import annotations

from agent_audit.phases.phase15_voice import (
    _test_asr_injection,
    _test_call_escalation,
    _test_consent_declaration,
    _test_disfluency_robustness,
    _test_transcript_pii,
    _test_tts_output_safety,
)
from agent_audit.severity import Severity

# NOTE: unlike test_phase02_reliability.py (all-async), this module mixes
# async checks with VOICE-CONSENT-001's synchronous, static check, so no
# module-level `pytestmark = pytest.mark.asyncio` is applied here (it would
# wrongly tag the sync tests too). `asyncio_mode = "auto"` in pyproject.toml
# already collects `async def test_*` functions correctly without a marker.


class TestVoiceInj001:
    """VOICE-INJ-001 — ASR-mimicry prompt-injection resistance."""

    async def test_pass(self, manifest_factory, ctx_factory):
        # runs=1 -> only trial i=0 executes -> scenario "injection_blocked"
        # -> trial passes -> classify()'s runs==passes (n<5) special case
        # -> Verdict.ROBUST -> PASS.
        ctx = ctx_factory(manifest_factory(), posture="secure", variability_runs=1)
        f = await _test_asr_injection(ctx)
        assert f.id == "VOICE-INJ-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        # Default variability_runs (5) -> i alternates blocked/success ->
        # mixed outcome -> wide Wilson CI -> HIGH_UNCERTAINTY -> not in
        # (ROBUST, STABLE) -> FAIL. Posture is irrelevant to this check.
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_asr_injection(ctx)
        assert f.id == "VOICE-INJ-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestVoicePii001:
    """VOICE-PII-001 — transcript PII leakage (Wave-0-fixed, posture-aware)."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_transcript_pii(ctx)
        assert f.id == "VOICE-PII-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_transcript_pii(ctx)
        assert f.id == "VOICE-PII-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestVoiceEsc001:
    """VOICE-ESC-001 — call escalation boundary."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_call_escalation(ctx)
        assert f.id == "VOICE-ESC-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_call_escalation(ctx)
        assert f.id == "VOICE-ESC-001"
        assert f.passed is False
        assert f.severity is Severity.CRITICAL


class TestVoiceTts001:
    """VOICE-TTS-001 — TTS output safety."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_tts_output_safety(ctx)
        assert f.id == "VOICE-TTS-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_tts_output_safety(ctx)
        assert f.id == "VOICE-TTS-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestVoiceDisf001:
    """VOICE-DISF-001 — disfluency robustness."""

    async def test_pass(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="secure")
        f = await _test_disfluency_robustness(ctx)
        assert f.id == "VOICE-DISF-001"
        assert f.passed is True

    async def test_fail(self, manifest_factory, ctx_factory):
        ctx = ctx_factory(manifest_factory(), posture="vulnerable")
        f = await _test_disfluency_robustness(ctx)
        assert f.id == "VOICE-DISF-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING


class TestVoiceConsent001:
    """VOICE-CONSENT-001 — call recording consent declaration (static, sync)."""

    def test_pass(self, manifest_factory, ctx_factory):
        m = manifest_factory(data_classification=["DPDP_PERSONAL"])
        ctx = ctx_factory(m, posture="secure")
        f = _test_consent_declaration(ctx)
        assert f.id == "VOICE-CONSENT-001"
        assert f.passed is True

    def test_fail(self, manifest_factory, ctx_factory):
        # Default manifest: no data_classification, no compliance_frameworks.
        m = manifest_factory()
        ctx = ctx_factory(m, posture="secure")
        f = _test_consent_declaration(ctx)
        assert f.id == "VOICE-CONSENT-001"
        assert f.passed is False
        assert f.severity is Severity.WARNING
