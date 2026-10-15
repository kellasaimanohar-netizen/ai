"""HTML exporter — single self-contained file for auditor readouts.

No external dependencies, no JS bundle, no network calls. Dark-mode aware.

v4.1 additions:
  - Trust score gauge in the header
  - Per-finding variability detail (CI, runs, verdict)
  - Per-finding duration column
  - Audit metadata strip (audit_id, mode, elapsed)
  - Certification-readiness banner
  - Standards coverage now shows control IDs, not just framework names
"""
from __future__ import annotations

import html
import logging
from collections import defaultdict
from pathlib import Path

from agent_audit.findings import Finding
from agent_audit.runner import AuditReport
from agent_audit.severity import Severity

log = logging.getLogger(__name__)


def export_html(report: AuditReport, path: str | Path) -> Path:
    """Write an HTML dashboard of the report."""
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    coverage = _standards_coverage(report.findings)
    by_phase = _findings_by_phase(report.sorted_findings())
    elapsed = f"{report.total_duration_ms / 1000:.1f}s" if report.total_duration_ms else "—"
    score = report.trust_score
    score_colour = "#2ea44f" if score >= 80 else "#e0a800" if score >= 60 else "#d32f2f"

    doc = _HTML_TMPL.format(
        title=html.escape(f"Agent Audit — {report.agent_name}"),
        agent=html.escape(report.agent_name),
        mode=html.escape(report.mode),
        audit_id=html.escape(report.audit_id or "—"),
        started=html.escape(report.started_at),
        finished=html.escape(report.finished_at),
        elapsed=html.escape(elapsed),
        verdict_class="ok" if report.enterprise_ready else "fail",
        verdict_text="ENTERPRISE READY" if report.enterprise_ready else "NOT ENTERPRISE READY",
        test_environment=html.escape(getattr(report, "test_environment", "unknown")),
        env_class="env-mock" if getattr(report, "test_environment", "") == "mock" else "env-live",
        trust_score=score,
        score_colour=score_colour,
        n_critical=len(report.critical_failures),
        n_warnings=len(report.warnings),
        n_passed=len(report.passes),
        n_total=len(report.findings),
        n_suppressed=len(report.suppressed),
        coverage_rows=_render_coverage(coverage),
        findings_sections=_render_findings(by_phase),
    )
    out_path.write_text(doc, encoding="utf-8")
    log.info("HTML report → %s", out_path)
    return out_path


def _findings_by_phase(findings: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        out[f.phase].append(f)
    return dict(out)


def _standards_coverage(findings: list[Finding]) -> dict[str, list[dict]]:
    """Returns {framework: [{id, name, pass_count, fail_count}]}."""
    fw_controls: dict[str, dict[str, dict]] = defaultdict(dict)
    for f in findings:
        bucket = "pass" if f.passed else "fail"
        for s in f.standards:
            ctrl = fw_controls[s.framework].setdefault(
                s.identifier,
                {"identifier": s.identifier, "name": s.name, "pass": 0, "fail": 0},
            )
            ctrl[bucket] += 1
    result: dict[str, list[dict]] = {}
    for fw, controls in sorted(fw_controls.items()):
        result[fw] = sorted(controls.values(), key=lambda c: c["identifier"])
    return result


def _render_coverage(coverage: dict[str, list[dict]]) -> str:
    if not coverage:
        return "<tr><td colspan=4><em>No standards mapped.</em></td></tr>"
    rows: list[str] = []
    for framework, controls in coverage.items():
        for ctrl in controls:
            rows.append(
                f"<tr>"
                f"<td>{html.escape(framework)}</td>"
                f"<td class='mono'>{html.escape(ctrl['identifier'])}</td>"
                f"<td>{html.escape(ctrl['name'])}</td>"
                f"<td class='ok'>{ctrl['pass']}</td>"
                f"<td class='fail'>{ctrl['fail']}</td>"
                f"</tr>"
            )
    return "\n".join(rows)


def _render_findings(by_phase: dict[str, list[Finding]]) -> str:
    sections: list[str] = []
    for phase, items in sorted(by_phase.items()):
        rows = [_render_finding_row(f) for f in items]
        sections.append(
            f"<section>"
            f"<h2>{html.escape(phase.replace('_', ' ').title())}</h2>"
            f"<table class='findings'>"
            f"<thead><tr>"
            f"<th>Status</th><th>ID</th><th>Title / Detail</th>"
            f"<th>Standards</th><th class='dur'>ms</th>"
            f"</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            f"</table></section>"
        )
    return "\n".join(sections)


def _render_finding_row(f: Finding) -> str:
    if f.suppressed:
        status_class, status_text = "suppressed", "suppressed"
    elif f.passed:
        status_class, status_text = "ok", "pass"
    elif f.severity is Severity.CRITICAL:
        status_class, status_text = "fail", "critical"
    elif f.severity is Severity.HIGH_UNCERTAINTY:
        status_class, status_text = "warn", "uncertain"
    else:
        status_class, status_text = "warn", f.severity.value.lower()

    stds = ", ".join(f"{s.framework}/{s.identifier}" for s in f.standards) or "—"
    dur = f"{f.duration_ms:.0f}" if f.duration_ms else "—"

    detail_parts: list[str] = []
    if f.description:
        detail_parts.append(f"<div class='desc'>{html.escape(f.description)}</div>")
    if f.variability:
        v = f.variability
        detail_parts.append(
            f"<div class='var'>variability: {v.passes}/{v.runs} runs · "
            f"CI [{v.ci_lower:.2f}, {v.ci_upper:.2f}] · verdict: {v.verdict}</div>"
        )
    if f.remediation and not f.passed and not f.suppressed:
        detail_parts.append(
            f"<div class='remediation'>"
            f"<strong>Fix:</strong> {html.escape(f.remediation)}"
            f"</div>"
        )

    detail = "".join(detail_parts)
    return (
        f"<tr class='{status_class}'>"
        f"<td class='status'>{status_text}</td>"
        f"<td class='id mono'>{html.escape(f.id)}</td>"
        f"<td><strong>{html.escape(f.title)}</strong>{detail}</td>"
        f"<td class='stds mono'>{html.escape(stds)}</td>"
        f"<td class='dur'>{dur}</td>"
        f"</tr>"
    )


_HTML_TMPL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  :root {{
    --bg: #0f1115; --fg: #e6e6e6; --muted: #8a8f98;
    --ok: #2ea44f; --fail: #d32f2f; --warn: #e0a800; --sup: #6c757d;
    --card: #181b22; --border: #2a2f3a;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg: #f7f8fa; --fg: #1a1a1a; --muted: #555c66; --card: #fff; --border: #dde1e7; }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font: 14px/1.6 system-ui,-apple-system,sans-serif; color: var(--fg); background: var(--bg); }}
  header {{ padding: 20px 28px; border-bottom: 1px solid var(--border); display: flex; gap: 24px; align-items: flex-start; flex-wrap: wrap; }}
  .header-main {{ flex: 1; min-width: 220px; }}
  header h1 {{ font-size: 18px; font-weight: 600; margin-bottom: 4px; }}
  header .meta {{ color: var(--muted); font-size: 12px; line-height: 1.8; }}
  header .meta code {{ font-family: ui-monospace,"SF Mono",monospace; }}
  .verdict {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 13px; margin-top: 8px; }}
  .verdict.ok {{ background: rgba(46,164,79,.15); color: var(--ok); }}
  .verdict.fail {{ background: rgba(211,47,47,.15); color: var(--fail); }}
  .env-mock {{ color: var(--warn, #e0a800); }}
  .env-live {{ color: var(--ok); }}
  .score-ring {{ text-align: center; min-width: 90px; }}
  .score-ring svg {{ display: block; margin: 0 auto; }}
  .score-ring .score-num {{ font-size: 20px; font-weight: 700; }}
  .score-ring .score-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}
  main {{ padding: 20px 28px; max-width: 1300px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(120px,1fr)); gap: 10px; margin-bottom: 20px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; }}
  .card .n {{ font-size: 20px; font-weight: 600; }}
  .card .l {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; margin-top: 2px; }}
  .card.critical .n {{ color: var(--fail); }}
  .card.warn .n {{ color: var(--warn); }}
  .card.ok .n {{ color: var(--ok); }}
  .card.sup .n {{ color: var(--sup); }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0 20px; background: var(--card); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; font-size: 13px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 500; }}
  tr:last-child td {{ border-bottom: none; }}
  tr.ok .status {{ color: var(--ok); }}
  tr.fail .status {{ color: var(--fail); font-weight: 700; }}
  tr.warn .status {{ color: var(--warn); }}
  tr.suppressed {{ opacity: .55; }}
  td.id, td.stds, td.mono, .mono {{ font-family: ui-monospace,"SF Mono",monospace; font-size: 11px; color: var(--muted); }}
  td.dur {{ text-align: right; font-family: ui-monospace,"SF Mono",monospace; font-size: 11px; color: var(--muted); white-space: nowrap; }}
  .desc {{ color: var(--muted); font-size: 12px; margin-top: 3px; }}
  .var {{ color: var(--muted); font-size: 11px; margin-top: 3px; font-family: ui-monospace,"SF Mono",monospace; }}
  .remediation {{ font-size: 12px; margin-top: 5px; padding: 5px 9px; background: rgba(0,0,0,.04); border-radius: 4px; border-left: 3px solid var(--warn); }}
  h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin: 20px 0 6px; font-weight: 500; }}
  section {{ margin-bottom: 8px; }}
</style>
</head>
<body>
<header>
  <div class="header-main">
    <h1>Agent Audit — {agent}</h1>
    <div class="meta">
      mode <code>{mode}</code> &middot;
      audit <code>{audit_id}</code> &middot;
      {started} → {finished} &middot;
      elapsed {elapsed} &middot;
      environment <code class="{env_class}">{test_environment}</code>
    </div>
    <div class="verdict {verdict_class}">{verdict_text}</div>
  </div>
  <div class="score-ring">
    <svg width="72" height="72" viewBox="0 0 72 72">
      <circle cx="36" cy="36" r="30" fill="none" stroke="#2a2f3a" stroke-width="6"/>
      <circle cx="36" cy="36" r="30" fill="none" stroke="{score_colour}" stroke-width="6"
              stroke-dasharray="{trust_score_dash} 189" stroke-dashoffset="47"
              stroke-linecap="round"/>
    </svg>
    <div class="score-num" style="color:{score_colour}">{trust_score}</div>
    <div class="score-label">trust score</div>
  </div>
</header>
<main>
  <section class="cards">
    <div class="card critical"><div class="n">{n_critical}</div><div class="l">Critical</div></div>
    <div class="card warn"><div class="n">{n_warnings}</div><div class="l">Warnings</div></div>
    <div class="card ok"><div class="n">{n_passed}/{n_total}</div><div class="l">Passed</div></div>
    <div class="card sup"><div class="n">{n_suppressed}</div><div class="l">Suppressed</div></div>
  </section>

  <h2>Standards coverage</h2>
  <table>
    <thead><tr><th>Framework</th><th>Control</th><th>Name</th><th>Passed</th><th>Failed</th></tr></thead>
    <tbody>{coverage_rows}</tbody>
  </table>

  {findings_sections}
</main>
</body>
</html>
"""

# Pre-compute the SVG dash for the score ring (circumference = 2π×30 ≈ 188.5)
_CIRC = 188.5
import agent_audit.exporters.html_exporter as _self_ref  # noqa: E402


def _patch_template() -> None:
    """Replace the {trust_score_dash} placeholder with a computed value at render time."""
    pass  # handled inline in export_html via format()


# Override export_html to inject the computed dash value
_orig_export = export_html


def export_html(report: AuditReport, path: str | Path) -> Path:  # type: ignore[misc]
    """Write an HTML dashboard of the report."""
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    coverage = _standards_coverage(report.findings)
    by_phase = _findings_by_phase(report.sorted_findings())
    elapsed = f"{report.total_duration_ms / 1000:.1f}s" if report.total_duration_ms else "—"
    score = report.trust_score
    score_colour = "#2ea44f" if score >= 80 else "#e0a800" if score >= 60 else "#d32f2f"
    dash = round(_CIRC * score / 100, 1)

    doc = _HTML_TMPL.format(
        title=html.escape(f"Agent Audit — {report.agent_name}"),
        agent=html.escape(report.agent_name),
        mode=html.escape(report.mode),
        audit_id=html.escape(report.audit_id or "—"),
        started=html.escape(report.started_at),
        finished=html.escape(report.finished_at),
        elapsed=html.escape(elapsed),
        verdict_class="ok" if report.enterprise_ready else "fail",
        verdict_text="ENTERPRISE READY" if report.enterprise_ready else "NOT ENTERPRISE READY",
        test_environment=html.escape(getattr(report, "test_environment", "unknown")),
        env_class="env-mock" if getattr(report, "test_environment", "") == "mock" else "env-live",
        trust_score=score,
        trust_score_dash=dash,
        score_colour=score_colour,
        n_critical=len(report.critical_failures),
        n_warnings=len(report.warnings),
        n_passed=len(report.passes),
        n_total=len(report.findings),
        n_suppressed=len(report.suppressed),
        coverage_rows=_render_coverage(coverage),
        findings_sections=_render_findings(by_phase),
    )
    out_path.write_text(doc, encoding="utf-8")
    log.info("HTML report → %s", out_path)
    return out_path
