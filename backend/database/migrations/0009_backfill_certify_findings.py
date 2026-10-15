"""Save the findings of CertifyAI tests that ran before their findings were stored as rows.

Each normal test kept its findings in full_result_json; tests that have no rows in audit_findings get them now.
"""
import json
import re

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[2] / "src")   # the audit library, for its phase names
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    from agent_audit.phases import PHASE_LABELS
except ImportError:
    PHASE_LABELS = {}


def _phase_name(phase):
    if not phase:
        return "Architecture & Security"
    label = PHASE_LABELS.get(phase)
    if label:
        label = re.sub(r"^Phase\s+\d+\s*·\s*", "", label)
        return re.sub(r"\s*\[[^\]]*\]\s*$", "", label).strip()
    return phase.replace("_", " ").title()


def run(cur) -> None:
    cur.execute("""SELECT n.id, n.audit_id, n.full_result_json, n.created_at FROM normal_agent_tests n
                   WHERE NOT EXISTS (SELECT 1 FROM audit_findings f WHERE f.normal_test_id = n.id)""")
    for test_id, audit_id, raw, created_at in cur.fetchall():
        try:
            findings = (json.loads(raw or "{}") or {}).get("findings") or []
        except ValueError:
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            phase = f.get("phase") or f.get("phase_id")
            cur.execute(
                """INSERT INTO audit_findings (normal_test_id, audit_id, rule_id, phase_id, phase_name, title, description,
                                               severity, remediation, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (test_id, audit_id, f.get("id") or f.get("rule_id") or "UNKNOWN", phase, _phase_name(phase),
                 f.get("title") or f.get("test_name") or "Check", f.get("description") or None,
                 (f.get("severity") or "INFO").upper(), f.get("remediation") or None, created_at),
            )
