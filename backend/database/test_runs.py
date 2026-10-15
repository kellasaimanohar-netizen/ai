"""Test records for the two kinds of agent.

Normal (CertifyAI) tests are rows in `normal_agent_tests`; live-agent tests are rows in `live_agent_tests`.
Test ids come from one shared sequence, so an id names exactly one test of either kind. The view
`all_agent_tests` lists both for history, dashboards and reports; write to the tables, never the view.
"""
from __future__ import annotations

import re
from typing import Any

NORMAL = "normal_agent_tests"
LIVE = "live_agent_tests"

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[1] / "src")   # the audit library, for its phase names
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    from agent_audit.phases import PHASE_LABELS as _PHASE_LABELS
except ImportError:   # src/ not on the path (for example when migrations run on their own)
    _PHASE_LABELS = {}


def certify_source(yaml_content: str | None, repo_path: str | None, openapi_url: str | None) -> str | None:
    """What a CertifyAI audit read: a pasted YAML file, a repository folder or an OpenAPI link."""
    if yaml_content:
        return "yaml"
    if repo_path:
        return "repo"
    if openapi_url:
        return "openapi"
    return None


def record_certify_details(cursor, test_id: int, *, source: str | None = None,
                           repo_path: str | None = None, openapi_url: str | None = None) -> None:
    cursor.execute(f"UPDATE {NORMAL} SET source = ?, repo_path = ?, openapi_url = ? WHERE id = ?",
                   (source, repo_path or None, openapi_url or None, test_id))


def record_live_details(cursor, test_id: int, *, target_env: str | None, endpoint_url: str | None,
                        openapi_url: str | None, repo_path: str | None, agent_type: str | None,
                        tests_total: int | None, could_not_run: int | None, live_agent_id: int | None = None) -> None:
    cursor.execute(
        f"""UPDATE {LIVE} SET target_env = ?, endpoint_url = ?, openapi_url = ?, repo_path = ?, agent_type = ?,
                              tests_total = ?, could_not_run = ?, live_agent_id = COALESCE(?, live_agent_id)
            WHERE id = ?""",
        (target_env, endpoint_url, openapi_url or None, repo_path or None, agent_type, tests_total, could_not_run,
         live_agent_id, test_id),
    )


def test_table(cursor, test_id: int) -> str | None:
    """Which table holds this test id."""
    for table in (NORMAL, LIVE):
        cursor.execute(f"SELECT 1 FROM {table} WHERE id = ?", (test_id,))
        if cursor.fetchone():
            return table
    return None


def set_pdf_path(cursor, test_id: int, pdf_path: str) -> None:
    table = test_table(cursor, test_id)
    if table:
        cursor.execute(f"UPDATE {table} SET pdf_path = ? WHERE id = ?", (pdf_path, test_id))


def phase_name(phase_id: str | None) -> str:
    """A readable category for a CertifyAI phase id, such as 'supply_chain' -> 'Supply Chain'."""
    if not phase_id:
        return "Architecture & Security"
    label = _PHASE_LABELS.get(phase_id)
    if label:
        label = re.sub(r"^Phase\s+\d+\s*·\s*", "", label)
        return re.sub(r"\s*\[[^\]]*\]\s*$", "", label).strip()
    return phase_id.replace("_", " ").title()


def record_certify_findings(cursor, test_id: int, audit_id: str, findings: list[dict[str, Any]], created_at: str) -> int:
    """Saves a CertifyAI test's findings, one row each. Returns how many were saved."""
    saved = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        phase = f.get("phase") or f.get("phase_id")
        cursor.execute(
            """INSERT INTO audit_findings (normal_test_id, audit_id, rule_id, phase_id, phase_name, title, description,
                                           severity, remediation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (test_id, audit_id, f.get("id") or f.get("rule_id") or "UNKNOWN", phase, phase_name(phase),
             f.get("title") or f.get("test_name") or "Check", f.get("description") or None,
             (f.get("severity") or "INFO").upper(), f.get("remediation") or None, created_at),
        )
        saved += 1
    return saved


def record_live_findings(cursor, test_id: int, audit_id: str, findings: list[dict[str, Any]], created_at: str) -> int:
    """Saves a live test's findings, one row each. Returns how many were saved."""
    saved = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        cursor.execute(
            """INSERT INTO audit_findings (live_test_id, audit_id, rule_id, phase_id, phase_name, title, description,
                                           severity, remediation, created_at)
               VALUES (?, ?, ?, 'live_probe', ?, ?, ?, ?, ?, ?)""",
            (test_id, audit_id, f.get("id") or "UNKNOWN", f.get("category", "Behavioral Security"),
             f.get("title") or "Check", f.get("description"), f.get("severity", "INFO"), f.get("remediation"), created_at),
        )
        saved += 1
    return saved
