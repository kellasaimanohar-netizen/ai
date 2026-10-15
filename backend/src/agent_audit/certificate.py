"""Certificate — Ed25519-signed verdict that anyone can verify offline.

Embeds the public key in every certificate. Verification requires no secret.

Tiers:
  CERTIFIED    — 0 critical, trust_score >= 80, validity 90 days
  CONDITIONAL  — 0 critical but warnings or score < 80, validity 60 days
  NOT_CERTIFIED — any critical: not issued (14-day observation window)
  INCONCLUSIVE — a live audit where the agent never answered: nothing was observed to judge
  A live audit with phases that could not be tested is at most CONDITIONAL.

v4.1: trust_score now uses the same formula as AuditReport.trust_score
(critical failures carry a 10-point penalty each) for consistency.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from agent_audit import __version__
from agent_audit.exceptions import CertificateError
from agent_audit.runner import AuditReport

log = logging.getLogger(__name__)

CERT_VERSION = "4.2"
VALIDITY_CERTIFIED_DAYS = 90
VALIDITY_CONDITIONAL_DAYS = 60
VALIDITY_OBSERVATION_DAYS = 14

# Badge grade bands (spec §11). The grade is a *presentation* layer derived
# purely from trust_score + critical count — both already part of the signed
# payload — so it is tamper-evident without needing its own signed field.
# A critical failure caps the grade at FAILED regardless of score, mirroring the
# "critical security failures prevent certification" rule.
GRADE_BANDS = [
    (95, "PLATINUM"),
    (90, "GOLD"),
    (80, "SILVER"),
    (70, "BRONZE"),
]


def grade_for(trust_score: int, critical: int) -> str:
    """Map (score, critical) → badge grade. Critical failures force FAILED."""
    if critical > 0:
        return "FAILED"
    for threshold, name in GRADE_BANDS:
        if trust_score >= threshold:
            return name
    return "FAILED"

# Environment variable holding the base64 raw Ed25519 *private* key the issuer
# signs with. Set this in CI / the signing service so every certificate is
# signed by the same, pinnable key instead of a throwaway per-run key.
ISSUER_KEY_ENV = "AGENT_AUDIT_SIGNING_KEY"


def load_issuer_key(*, env: str = ISSUER_KEY_ENV) -> Ed25519PrivateKey | None:
    """Load the persistent issuer signing key from ``$AGENT_AUDIT_SIGNING_KEY``
    (base64 raw 32-byte Ed25519 seed). Returns ``None`` if unset, so callers can
    fall back to an ephemeral key for local/dev use."""
    import os

    raw = os.environ.get(env)
    if not raw:
        return None
    try:
        seed = base64.b64decode(raw)
        return Ed25519PrivateKey.from_private_bytes(seed)
    except Exception as exc:  # noqa: BLE001
        raise CertificateError(
            f"{env} is set but is not a valid base64 Ed25519 private key: {exc}"
        ) from exc


def generate_issuer_key_b64() -> str:
    """Generate a fresh issuer key, returned as base64 to store in the env/secret
    manager. (Helper for operators bootstrapping a signing identity.)"""
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


@dataclass(slots=True)
class Certificate:
    """Signed certification of an audit report."""

    agent_name: str
    tier: str                       # CERTIFIED | CONDITIONAL | NOT_CERTIFIED | FRAMEWORK_VALIDATION_ONLY
    trust_score: int
    issued_at: str
    expires_at: str
    audit_version: str
    cert_version: str
    audit_id: str
    content_hash: str               # sha256 of the signed payload
    public_key_b64: str             # Ed25519 public key, base64
    signature_b64: str              # signature over content_hash, base64
    findings_summary: dict[str, int] = field(default_factory=dict)
    suppressions_embedded: list[dict[str, Any]] = field(default_factory=list)
    framework_validation_only: bool = False
    key_fingerprint: str = ""

    @property
    def grade(self) -> str:
        """Badge grade (Platinum/Gold/Silver/Bronze/Failed), derived from the
        signed trust_score + critical count. Tamper-evident: changing the score
        to inflate the grade breaks the signature."""
        return grade_for(self.trust_score, self.findings_summary.get("critical", 0))

    @property
    def badges(self) -> list[str]:
        """Capability badges the agent qualifies for (spec §11), derived from the
        findings summary. Conservative: only awarded on a clean, non-critical run."""
        out: list[str] = []
        crit = self.findings_summary.get("critical", 0)
        if crit == 0 and self.trust_score >= 80:
            out.append("Production Ready")
        if crit == 0 and self.trust_score >= 90:
            out.append("Enterprise Ready")
        if crit == 0:
            out.append("Secure Agent")
        return out

    @property
    def days_remaining(self) -> int:
        # Parse as aware UTC (the 'Z' suffix denotes UTC). Computing in aware UTC
        # keeps this consistent with load_and_verify's expiry check; a naive
        # local-time comparison drifts by a day in non-UTC zones.
        exp = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        return max(0, (exp - now).days)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # surface the derived badge layer in the exported certificate
        d["grade"] = self.grade
        d["badges"] = self.badges
        return d

    def save(self, path: str | Path) -> Path:
        out = Path(path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        log.info("certificate saved → %s  tier=%s  score=%d  expires=%s",
                 out, self.tier, self.trust_score, self.expires_at[:10])
        return out


def _key_fingerprint(public_bytes: bytes) -> str:
    """Short, stable fingerprint of an Ed25519 public key (sha256, hex, 16 bytes).
    Verifiers pin against this so a forged cert signed by an attacker's key —
    even with all fields and content_hash recomputed — is rejected."""
    return hashlib.sha256(public_bytes).hexdigest()[:32]


def _canonical_payload(
    *,
    agent_name: str,
    tier: str,
    trust_score: int,
    issued_at: str,
    expires_at: str,
    audit_version: str,
    cert_version: str,
    audit_id: str,
    findings_summary: dict[str, Any],
    suppressions_embedded: list[dict[str, Any]],
    framework_validation_only: bool,
    key_fingerprint: str = "",
) -> bytes:
    """The exact bytes that ``content_hash`` is computed over. Used by BOTH
    ``issue_certificate`` and ``load_and_verify`` so the hash is bound to the
    certificate's visible fields and the two paths can never drift.

    ``key_fingerprint`` is included so the signing key's identity is part of the
    signed content — an attacker cannot swap in their own key without changing
    the hash, and a verifier pinning a fingerprint detects the swap."""
    payload = {
        "agent_name": agent_name,
        "tier": tier,
        "trust_score": trust_score,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "audit_version": audit_version,
        "cert_version": cert_version,
        "audit_id": audit_id,
        "findings_summary": findings_summary,
        "suppressions_embedded": suppressions_embedded or [],
        "framework_validation_only": framework_validation_only,
        "key_fingerprint": key_fingerprint,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_certificate(
    report: AuditReport,
    *,
    suppressions_embedded: list[dict[str, Any]] | None = None,
    signing_key: Ed25519PrivateKey | None = None,
    framework_validation_only: bool = False,
) -> Certificate:
    """Compute the tier, score, sign and return the certificate."""
    # Use the canonical trust_score from AuditReport (includes critical penalty)
    score = report.trust_score
    critical = len(report.critical_failures)
    warnings = len(report.warnings)
    passes = len(report.passes)
    total = len(report.findings)

    if critical > 0:
        tier = "NOT_CERTIFIED"
    elif score >= 90 and warnings <= 3:
        tier = "CERTIFIED"
    else:
        tier = "CONDITIONAL"
    # Only what the agent actually did can certify it
    if getattr(report, "agent_reached", None) is False:
        tier = "INCONCLUSIVE"
    elif tier == "CERTIFIED" and getattr(report, "untested_phases", None):
        tier = "CONDITIONAL"

    # A mock-mode report must never be presentable as an equivalent-to-live
    # certification — force FRAMEWORK_VALIDATION_ONLY whenever the report's
    # own test_environment says "mock", regardless of what the caller passed
    # for `framework_validation_only`. A NOT_CERTIFIED verdict is left as-is
    # even from mock — it doesn't claim anything positive that needs guarding.
    mock_run = getattr(report, "test_environment", None) == "mock"
    if framework_validation_only or (mock_run and tier != "NOT_CERTIFIED"):
        tier = "FRAMEWORK_VALIDATION_ONLY"
        framework_validation_only = True

    issued = dt.datetime.now(dt.timezone.utc)
    validity_map = {
        "CERTIFIED": VALIDITY_CERTIFIED_DAYS,
        "CONDITIONAL": VALIDITY_CONDITIONAL_DAYS,
    }
    expires = issued + dt.timedelta(days=validity_map.get(tier, VALIDITY_OBSERVATION_DAYS))

    findings_summary = {
        "total": total,
        "passes": passes,
        "critical": critical,
        "warnings": warnings,
        "suppressed": len(report.suppressed),
    }

    if signing_key is None:
        signing_key = load_issuer_key()
    ephemeral = signing_key is None
    if signing_key is None:
        signing_key = Ed25519PrivateKey.generate()

    public_bytes = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_fingerprint = _key_fingerprint(public_bytes)

    payload = {
        "agent_name": report.agent_name,
        "tier": tier,
        "trust_score": score,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audit_version": __version__,
        "cert_version": CERT_VERSION,
        "audit_id": report.audit_id,
        "findings_summary": findings_summary,
        "suppressions_embedded": suppressions_embedded or [],
        "framework_validation_only": framework_validation_only,
        "key_fingerprint": key_fingerprint,
    }
    canonical = _canonical_payload(**payload)
    content_hash = hashlib.sha256(canonical).hexdigest()

    signature = signing_key.sign(content_hash.encode("ascii"))

    if ephemeral:
        gen_cmd = 'python -c "import base64, cryptography.hazmat.primitives.asymmetric.ed25519 as ed; k = ed.Ed25519PrivateKey.generate(); print(base64.b64encode(k.private_bytes(1, 1, ed.NoEncryption())).decode())"'
        log.warning(
            "\n"
            "================================================================================\n"
            "WARNING: AGENT_AUDIT_SIGNING_KEY environment variable is missing.\n"
            "The certificate was signed with an EPHEMERAL throwaway key.\n"
            "This certificate cannot be pinned or verified offline by clients.\n\n"
            "To generate a persistent signing key, run this command:\n"
            f"  {gen_cmd}\n\n"
            "Set the output as AGENT_AUDIT_SIGNING_KEY in your environment variables:\n"
            "  Windows (cmd): set AGENT_AUDIT_SIGNING_KEY=your_base64_key\n"
            "  Windows (ps):  $env:AGENT_AUDIT_SIGNING_KEY=\"your_base64_key\"\n"
            "  Linux/macOS:   export AGENT_AUDIT_SIGNING_KEY=\"your_base64_key\"\n"
            "================================================================================"
        )
    log.info("certificate issued — agent=%s tier=%s score=%d expires=%s fp=%s",
             report.agent_name, tier, score, expires.strftime("%Y-%m-%d"), key_fingerprint)

    return Certificate(
        agent_name=report.agent_name,
        tier=tier,
        trust_score=score,
        issued_at=payload["issued_at"],
        expires_at=payload["expires_at"],
        audit_version=__version__,
        cert_version=CERT_VERSION,
        audit_id=report.audit_id,
        content_hash=content_hash,
        public_key_b64=base64.b64encode(public_bytes).decode("ascii"),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        findings_summary=findings_summary,
        suppressions_embedded=suppressions_embedded or [],
        framework_validation_only=framework_validation_only,
        key_fingerprint=key_fingerprint,
    )


def load_and_verify(
    path: str | Path,
    *,
    trusted_keys: "set[str] | list[str] | None" = None,
    trusted_fingerprints: "set[str] | list[str] | None" = None,
    allow_untrusted: bool = False,
) -> Certificate:
    """Load a certificate and verify it.

    Security model: an Ed25519 signature only proves *some* key signed the
    content. Because the public key travels *inside* the certificate, a signature
    alone is meaningless — an attacker can forge every field, sign with their own
    key, and embed their own public key. Real assurance requires pinning the
    issuer's key. Callers therefore SHOULD pass one of:

      * ``trusted_keys``        — base64 raw Ed25519 public keys you trust, or
      * ``trusted_fingerprints``— 32-hex-char fingerprints (``_key_fingerprint``)

    If neither is given and ``allow_untrusted`` is False, verification still
    checks signature + hash integrity but raises unless you explicitly opt into
    trust-on-first-use by setting ``allow_untrusted=True`` (dev/local only).
    """
    p = Path(path).expanduser()
    if not p.is_file():
        raise CertificateError(f"certificate file not found: {p}")

    data = json.loads(p.read_text(encoding="utf-8"))
    required = {
        "agent_name", "tier", "trust_score", "issued_at", "expires_at",
        "audit_version", "cert_version", "content_hash",
        "public_key_b64", "signature_b64",
    }
    missing = required - set(data.keys())
    if missing:
        raise CertificateError(f"malformed certificate — missing fields: {sorted(missing)}")

    try:
        pub_bytes = base64.b64decode(data["public_key_b64"])
        sig_bytes = base64.b64decode(data["signature_b64"])
    except Exception as exc:
        raise CertificateError(f"malformed base64 fields: {exc}") from exc

    fingerprint = _key_fingerprint(pub_bytes)

    # ── trust anchor: is this issuer key one we accept? ────────────────────
    pinned = bool(trusted_keys) or bool(trusted_fingerprints)
    if pinned:
        trusted_fp = set(trusted_fingerprints or [])
        for k in (trusted_keys or []):
            try:
                trusted_fp.add(_key_fingerprint(base64.b64decode(k)))
            except Exception as exc:
                raise CertificateError(f"malformed trusted key: {exc}") from exc
        if fingerprint not in trusted_fp:
            raise CertificateError(
                f"certificate signed by an UNTRUSTED key (fingerprint {fingerprint}). "
                f"This is the signature a forged certificate would carry. Expected one "
                f"of: {sorted(trusted_fp)}."
            )
    elif not allow_untrusted:
        raise CertificateError(
            "no trust anchor supplied — pass trusted_keys / trusted_fingerprints to "
            "pin the issuer, or allow_untrusted=True to accept any embedded key "
            "(trust-on-first-use; NOT secure against forgery)."
        )

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, data["content_hash"].encode("ascii"))
    except InvalidSignature as exc:
        raise CertificateError("certificate signature is invalid") from exc
    except Exception as exc:
        raise CertificateError(f"certificate verification failed: {exc}") from exc

    # CRITICAL: the signature only proves content_hash was signed by this key.
    # We must also prove content_hash actually corresponds to the certificate's
    # visible fields — otherwise an attacker can edit trust_score / tier while
    # leaving content_hash + signature untouched and still verify. The key
    # fingerprint is part of the signed payload, so a key swap also breaks this.
    recomputed = hashlib.sha256(_canonical_payload(
        agent_name=data["agent_name"],
        tier=data["tier"],
        trust_score=data["trust_score"],
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        audit_version=data["audit_version"],
        cert_version=data["cert_version"],
        audit_id=data.get("audit_id", ""),
        findings_summary=data.get("findings_summary", {}),
        suppressions_embedded=data.get("suppressions_embedded", []),
        framework_validation_only=data.get("framework_validation_only", False),
        key_fingerprint=data.get("key_fingerprint", fingerprint),
    )).hexdigest()
    if recomputed != data["content_hash"]:
        raise CertificateError(
            "certificate content_hash does not match its fields — the certificate "
            "has been tampered with (e.g. trust_score, tier, or signing key was altered)."
        )

    # The badge grade is a *derived* value (grade_for(score, critical)) and is not
    # part of the signed payload. If a certificate ships a standalone "grade"
    # string, an attacker could alter that display value while leaving the signed
    # score/tier/findings honest. Re-derive it and reject any mismatch so the
    # human-readable badge cannot be inflated independently of the signed content.
    if "grade" in data:
        expected_grade = grade_for(
            data["trust_score"], data.get("findings_summary", {}).get("critical", 0)
        )
        if str(data["grade"]).upper() != expected_grade:
            raise CertificateError(
                "certificate grade does not match its signed score/findings — the "
                f"badge was altered (claims {data['grade']}, derives {expected_grade})."
            )

    try:
        exp = dt.datetime.fromisoformat(data["expires_at"].rstrip("Z"))
    except ValueError as exc:
        raise CertificateError(f"malformed expires_at: {exc}") from exc
    if exp.replace(tzinfo=dt.timezone.utc) < dt.datetime.now(dt.timezone.utc):
        raise CertificateError(f"certificate expired on {data['expires_at']}")

    return Certificate(
        **{k: data[k] for k in [
            "agent_name", "tier", "trust_score", "issued_at", "expires_at",
            "audit_version", "cert_version", "content_hash",
            "public_key_b64", "signature_b64",
        ]},
        audit_id=data.get("audit_id", ""),
        findings_summary=data.get("findings_summary", {}),
        suppressions_embedded=data.get("suppressions_embedded", []),
        framework_validation_only=data.get("framework_validation_only", False),
        key_fingerprint=data.get("key_fingerprint", fingerprint),
    )
