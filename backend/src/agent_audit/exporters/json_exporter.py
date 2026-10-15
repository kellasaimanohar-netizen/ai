"""JSON exporter — machine-readable full report with all metadata."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_audit.runner import AuditReport

log = logging.getLogger(__name__)


def export_json(report: AuditReport, path: str | Path) -> Path:
    """Write the full report to disk as UTF-8 JSON and return the path."""
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "audit_version": report.audit_version,
        "audit_id": report.audit_id,
        "agent_name": report.agent_name,
        "mode": report.mode,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "total_duration_ms": round(report.total_duration_ms, 1),
        "phases_run": report.phases_run,
        "enterprise_ready": report.enterprise_ready,
        "trust_score": report.trust_score,
        "test_environment": getattr(report, "test_environment", "unknown"),
        "dataset_used": getattr(report, "dataset_used", None),
        "capability_profile": getattr(report, "capability_profile", {}),
        "summary": {
            "total": len(report.findings),
            "passed": report.pass_count,
            "failed": report.fail_count,
            "skipped": report.skip_count,
            "info": report.info_count,
            "critical_failures": len(report.critical_failures),
            "warnings": len(report.warnings),
            "suppressed": len(report.suppressed),
        },
        "manifest": report.manifest_summary,
        "audit_summary": getattr(report, "audit_summary", {}),
        "diagnostics": getattr(report, "diagnostics", []),
        "skipped_phases": getattr(report, "skipped_phases", []),
        "findings": [f.to_dict() for f in report.sorted_findings()],
    }

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("JSON report → %s  (%d findings)", out_path, len(report.findings))
    return out_path
