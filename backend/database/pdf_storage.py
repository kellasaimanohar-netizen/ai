import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# ReportLab imports with graceful fallback
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
        KeepTogether
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    logging.warning("ReportLab is not installed in the active Python environment. Full PDF generation requires: pip install reportlab")

# Report PDFs are kept on this computer under storage/reports/<kind>/ (REPORTS_DIR overrides the folder).
# The database stores each path relative to that folder, such as "live/live-605837b20f.pdf".
BACKEND_DIR = Path(__file__).resolve().parent.parent
default_reports = Path("/tmp/storage/reports") if os.getenv("VERCEL") else (BACKEND_DIR / "storage" / "reports")
REPORTS_DIR = Path(os.getenv("REPORTS_DIR") or default_reports)
PDF_DIR = REPORTS_DIR
for _kind in ("certify", "live"):
    try:
        (REPORTS_DIR / _kind).mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def _clean_id(audit_id: Any) -> str:
    return str(audit_id).strip().replace("/", "_").replace("\\", "_")


def report_kind(test_data: Dict[str, Any]) -> str:
    """'live' or 'certify': which folder a test's report belongs in."""
    if test_data.get("test_type") in ("certify", "live"):
        return test_data["test_type"]
    if test_data.get("mode") == "live_probe" or str(test_data.get("audit_id", "")).startswith("live-"):
        return "live"
    return "certify"


def resolve_pdf_path(stored: Optional[str]) -> Optional[Path]:
    """The file for a stored pdf_path, or None when it is not on disk."""
    if not stored:
        return None
    p = Path(stored)
    for candidate in ((p,) if p.is_absolute() else (REPORTS_DIR / p,)):
        if candidate.is_file():
            return candidate
    return None


def get_pdf_path(audit_id: str) -> Optional[Path]:
    """Returns path to locally stored PDF if it exists."""
    name = f"{_clean_id(audit_id)}.pdf"
    for folder in (REPORTS_DIR / "certify", REPORTS_DIR / "live"):
        if (folder / name).is_file():
            return folder / name
    return None


def relative_pdf_path(path: Path) -> str:
    """What to store in the database for a file inside REPORTS_DIR."""
    try:
        return path.resolve().relative_to(REPORTS_DIR.resolve()).as_posix()
    except ValueError:
        return str(path)


def _certificate_of(test_data: Dict[str, Any]) -> Dict[str, Any]:
    """The signed certificate from the audit result, if it has one (fresh results carry it; stored ones keep it in JSON)."""
    cert = test_data.get("cert")
    if not cert and test_data.get("full_result_json"):
        try:
            cert = (json.loads(test_data["full_result_json"]) or {}).get("cert")
        except (ValueError, TypeError):
            cert = None
    return cert if isinstance(cert, dict) else {}


def generate_and_store_pdf(test_data: Dict[str, Any]) -> str:
    """
    Generates the AI agent audit report PDF
    and stores it locally in storage/reports/<certify|live>/{audit_id}.pdf.
    Returns the path relative to REPORTS_DIR, which is what the database keeps.
    """
    audit_id = str(test_data.get("audit_id") or "aud-unknown").strip()
    clean_id = _clean_id(audit_id)
    kind = report_kind(test_data)
    pdf_file_path = REPORTS_DIR / kind / f"{clean_id}.pdf"
    stored_path = f"{kind}/{clean_id}.pdf"

    if not HAS_REPORTLAB:
        logging.warning("ReportLab is not installed; writing fallback PDF report.")
        minimal_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\n0000000101 00000 n\n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n185\n%%EOF\n"
        )
        pdf_file_path.write_bytes(minimal_pdf)
        return stored_path

    # Extract test details
    agent_name = test_data.get("agent_name", "AI Agent")
    trust_score = float(test_data.get("trust_score", 0.0))
    tier = str(test_data.get("tier", "NOT_CERTIFIED")).upper()
    tested_by = test_data.get("tested_by_name") or test_data.get("tested_by_email") or "CertifyAI Security Platform"
    tested_date = test_data.get("created_at") or test_data.get("started_at") or datetime.utcnow().isoformat()
    mode = str(test_data.get("mode", "certify")).upper()
    # Validate runs use a built-in simulator; a shared report must never pass that off as the agent's real behaviour
    mode_label = {"VALIDATE": "VALIDATE (SIMULATED: the agent was not contacted)", "LIVE_PROBE": "LIVE"}.get(mode, mode)
    duration_s = round(float(test_data.get("duration_ms", 0) or test_data.get("total_duration_ms", 0)) / 1000, 2)
    
    crit_count = int(test_data.get("critical_count", 0))
    warn_count = int(test_data.get("warning_count", 0))
    pass_count = int(test_data.get("pass_count", 0))
    total_evals = crit_count + warn_count + pass_count

    findings = test_data.get("findings") or []
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []

    # Configure ReportLab document
    doc = SimpleDocTemplate(
        str(pdf_file_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom palette
    primary_color = colors.HexColor("#1e1b4b")  # Deep Indigo
    accent_blue = colors.HexColor("#4f46e5")    # Indigo-600
    color_green = colors.HexColor("#16a34a")    # Emerald
    color_amber = colors.HexColor("#d97706")    # Amber
    color_red = colors.HexColor("#dc2626")      # Crimson
    tier_color = color_green if tier == "CERTIFIED" else (color_amber if tier == "CONDITIONAL" else (colors.grey if tier == "INCONCLUSIVE" else color_red))

    # Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    score_style = ParagraphStyle(
        'ScoreStyle',
        fontName='Helvetica-Bold',
        fontSize=32,
        leading=36,
        alignment=1, # Center
        textColor=tier_color
    )

    elements = []

    # --- 1. HEADER BRANDING & REPORT TITLE ---
    elements.append(Paragraph("CertifyAI Autonomous Agent Audit & Trust Report", title_style))
    elements.append(Paragraph(
        f"Generated by CertifyAI Platform Engine • Cryptographic Trust Verification Standard • {tested_date[:10]}",
        subtitle_style
    ))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceBefore=4, spaceAfter=14))

    # --- 2. EXECUTIVE METADATA & COMPOSITE SCORE BOX ---
    meta_table_data = [
        [
            Paragraph(f"<b>Agent Target:</b> {agent_name}", body_style),
            Paragraph(f"<b>Audit Run ID:</b> {audit_id}", body_style)
        ],
        [
            Paragraph(f"<b>Audited By:</b> {tested_by}", body_style),
            Paragraph(f"<b>Execution Mode:</b> {mode_label}", body_style)
        ],
        [
            Paragraph(f"<b>Execution Time:</b> {duration_s}s", body_style),
            Paragraph(f"<b>Timestamp:</b> {tested_date}", body_style)
        ]
    ]
    meta_table = Table(meta_table_data, colWidths=[270, 270])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    # --- 3. TRUST SCORE & FINDINGS KPI CARDS ---
    score_box_data = [
        [
            Paragraph(f"{trust_score}%", score_style),
            Paragraph(f"<b>Critical Failures:</b> <font color='#dc2626'>{crit_count}</font><br/>"
                      f"<b>Warnings:</b> <font color='#d97706'>{warn_count}</font><br/>"
                      f"<b>Passed Checks:</b> <font color='#16a34a'>{pass_count}</font><br/>"
                      f"<b>Total Evaluated Rules:</b> {total_evals}", body_style)
        ],
        [
            Paragraph(f"<b>TIER STATUS: {tier}</b>", ParagraphStyle('T', parent=body_bold, alignment=1, textColor=tier_color)),
            Paragraph(f"<b>Enterprise Readiness:</b> {'APPROVED FOR PRODUCTION DEPLOYMENT' if tier == 'CERTIFIED' else ('NOT ENOUGH TESTS COULD RUN TO DECIDE' if tier == 'INCONCLUSIVE' else 'REQUIRES GUARDRAIL OR POLICY REMEDIATION')}", body_bold)
        ]
    ]
    score_table = Table(score_box_data, colWidths=[180, 360])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#ffffff")),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1.5, tier_color),
        ('LINEBEFORE', (1, 0), (1, -1), 1, colors.HexColor("#e2e8f0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 16))

    # --- 4. DETAILED AUDIT FINDINGS TABLE ---
    elements.append(Paragraph("Evaluated Diagnostic Checks & Findings", section_heading))

    if findings:
        findings_table_data = [
            [
                Paragraph("<b>Severity</b>", body_bold),
                Paragraph("<b>Rule ID</b>", body_bold),
                Paragraph("<b>Title / Description</b>", body_bold),
                Paragraph("<b>Remediation Guidance</b>", body_bold)
            ]
        ]

        for f in findings[:25]:  # Include up to top 25 findings
            sev = str(f.get("severity", "PASS")).upper()
            rule_id = f.get("rule_id") or f.get("id") or "RULE"
            title = f.get("title") or f.get("description") or "Compliance Rule"
            remediation = f.get("remediation") or "Maintain configured safety bounds."

            s_color = color_green if sev == "PASS" else (color_amber if sev == "WARNING" else color_red)
            sev_p = Paragraph(f"<b><font color='{s_color.hexval()}'>{sev}</font></b>", body_style)
            rule_p = Paragraph(f"<font color='#4f46e5'><b>{rule_id}</b></font>", body_style)
            title_p = Paragraph(title, body_style)
            rem_p = Paragraph(remediation, body_style)

            findings_table_data.append([sev_p, rule_p, title_p, rem_p])

        findings_table = Table(findings_table_data, colWidths=[65, 85, 200, 190])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(findings_table)
    else:
        elements.append(Paragraph("<i>No diagnostic defect findings recorded.</i>", body_style))

    elements.append(Spacer(1, 16))

    # --- 5. CERTIFICATE ---
    # Only what the audit engine really produced: its signed certificate, or a plain statement that there is none.
    cert = _certificate_of(test_data)
    if cert.get("content_hash") and cert.get("signature_b64"):
        left = (f"<b>Content hash (SHA-256):</b> {cert['content_hash']}<br/>"
                f"<b>Signature:</b> Ed25519, made by the audit engine{(' v' + str(cert['audit_version'])) if cert.get('audit_version') else ''}")
        right = (f"<b>Issued:</b> {cert.get('issued_at', '-')}<br/>"
                 f"<b>Expires:</b> {cert.get('expires_at', '-')}<br/>"
                 f"<b>Check it with:</b> the certificate file, not this PDF")
    else:
        left = "<b>No signed certificate.</b> This kind of test does not issue one."
        right = f"<b>Report file:</b> {pdf_file_path.name}"
    cert_info = [
        [Paragraph("<b>Certificate</b>", body_bold),
         Paragraph("This report summarises automated tests. It is not a certification of compliance with any standard or law.", body_style)],
        [Paragraph(left, body_style), Paragraph(right, body_style)],
    ]
    cert_table = Table(cert_info, colWidths=[270, 270])
    cert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(cert_table)

    # Build document to disk
    try:
        doc.build(elements)
        logging.info(f"Successfully generated audit report PDF at {pdf_file_path}")
        return stored_path
    except Exception as e:
        logging.error(f"Failed to compile PDF document: {e}")
        return ""
