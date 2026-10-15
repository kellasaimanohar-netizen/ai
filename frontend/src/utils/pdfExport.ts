import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface FindingStandard {
  framework: string;
  identifier: string;
  name: string;
  url?: string;
}

interface FindingItem {
  id: string;
  phase: string;
  severity: string;
  passed: boolean;
  title: string;
  description?: string;
  remediation?: string;
  standards?: FindingStandard[];
  cwe?: string[];
  mitre_atlas?: string[];
}

interface SignedCertificate {
  content_hash?: string;
  signature_b64?: string;
  audit_version?: string;
}

export interface PDFExportData {
  cert?: SignedCertificate | null;
  name?: string;
  agent_name?: string;
  audit_id?: string;
  started_at?: string;
  finished_at?: string;
  total_duration_ms?: number;
  tested_by_name?: string;
  tested_by_email?: string;
  mode?: string;
  endpoint?: string;
  max_steps?: number;
  context_budget?: number;
  tools?: string[];
  destructive_tools?: string[];
  pii_fields?: string[];
  compliance_frameworks?: string[];
  tier?: string;
  trust_score?: number;
  enterprise_ready?: boolean;
  summary?: {
    total?: number;
    passed?: number;
    critical_failures?: number;
    warnings?: number;
    suppressed?: number;
    skipped?: number;
  };
  findings?: FindingItem[];
  audit_summary?: {
    total_endpoints_tested?: number;
    successful_requests?: number;
    failed_requests?: number;
    retry_attempts?: number;
    endpoints_returning_405?: string[];
    root_cause_analysis?: string;
    recommended_fixes?: string[];
  };
  diagnostics?: Array<{
    failed_endpoint?: string;
    actual_http_method_used?: string;
    expected_http_method?: string;
    suggested_fix?: string;
    response_body?: string;
  }>;
  skipped_phases?: Array<{
    phase: string;
    reason: string;
    remediation: string;
  }>;
}

// Helper: draw card with custom background, border, and corner radius
function drawCard(
  doc: jsPDF,
  x: number,
  y: number,
  w: number,
  h: number,
  r = 2.5,
  fillColor: [number, number, number] = [248, 250, 252],
  strokeColor: [number, number, number] = [226, 232, 240]
) {
  doc.setFillColor(...fillColor);
  doc.setDrawColor(...strokeColor);
  doc.setLineWidth(0.3);
  doc.roundedRect(x, y, w, h, r, r, 'FD');
}

// Helper: draw section header with accent bar
function drawSectionHeader(doc: jsPDF, title: string, x: number, y: number) {
  // Blue accent vertical pill
  doc.setFillColor(37, 99, 235);
  doc.roundedRect(x, y - 3.8, 2.5, 4.8, 0.8, 0.8, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(30, 41, 59);
  doc.text(title, x + 5, y);
}

const FRAMEWORKS: [string, string][] = [
  ['owasp_llm_2025', 'OWASP LLM Top 10 (2025)'],
  ['owasp_agentic_2025', 'OWASP Agentic AI Top 10'],
  ['nist_ai_rmf_genai', 'NIST AI RMF (GenAI profile)'],
  ['iso_42001', 'ISO/IEC 42001:2023'],
  ['eu_ai_act', 'EU AI Act'],
  ['mitre_atlas', 'MITRE ATLAS'],
  ['india_dpdp_2023', 'India DPDP Act 2023'],
];

/** One row per standard, from the findings this test actually mapped to it. Nothing is assumed. */
function standardsRows(findings: FindingItem[]): string[][] {
  return FRAMEWORKS.map(([key, label]) => {
    const hits = findings.filter(f => (f.standards || []).some(st => st.framework === key));
    if (hits.length === 0) return [label, '-', 'Not assessed by this test', '-'];
    const ids = Array.from(new Set(hits.flatMap(f => (f.standards || []).filter(st => st.framework === key).map(st => st.identifier)))).sort();
    const sev = (f: FindingItem) => (f.severity || '').toUpperCase();
    const critical = hits.filter(f => sev(f) === 'CRITICAL').length;
    const warning = hits.filter(f => sev(f) === 'WARNING').length;
    const passed = hits.length - critical - warning;
    const verdict = critical ? 'FAIL' : warning ? 'WARN' : 'PASS';
    return [label, ids.join(', '), `${passed} passed, ${warning} warnings, ${critical} critical (${hits.length} checks)`, verdict];
  });
}

export const generatePDFReport = (agent: PDFExportData, options: { save?: boolean } = {}) => {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - margin * 2; // 182mm

  const agentName = agent.name || agent.agent_name || 'Unnamed agent';
  const cleanAgentName = agentName.replace(/_/g, ' ').toUpperCase();
  const auditId = agent.audit_id || '-';
  const trustScore = agent.trust_score !== undefined ? agent.trust_score : 0;
  const tier = (agent.tier || 'NOT_CERTIFIED').toUpperCase();
  const evalDate = agent.finished_at || agent.started_at ? new Date(agent.finished_at || agent.started_at!).toLocaleString() : '-';
  const auditorName = agent.tested_by_name || '-';
  const auditorEmail = agent.tested_by_email || '-';
  const rawMode = (agent.mode || '-').toLowerCase();
  const evalMode = rawMode === 'validate' ? 'VALIDATE (SIMULATED)' : rawMode === 'live_probe' ? 'LIVE' : rawMode.toUpperCase();
  const engineVersion = agent.cert?.audit_version;
  const durationSec = agent.total_duration_ms ? (agent.total_duration_ms / 1000).toFixed(2) + 's' : '-';

  const rawObj = agent as any;
  const passCount = agent.summary?.passed ?? rawObj.pass_count ?? 0;
  const critCount = agent.summary?.critical_failures ?? rawObj.critical_count ?? 0;
  const warnCount = agent.summary?.warnings ?? rawObj.warning_count ?? 0;
  const totalCount = agent.summary?.total ?? rawObj.total_rules ?? ((passCount + critCount + warnCount) || (agent.findings?.length || 0));

  const isCertified = tier === 'CERTIFIED';
  const isConditional = tier === 'CONDITIONAL';

  // Tier color scheme
  const tierColor: [number, number, number] = isCertified
    ? [16, 185, 129] // Emerald Green
    : isConditional
    ? [245, 158, 11] // Amber
    : [239, 68, 68]; // Rose Red

  const tierBgColor: [number, number, number] = isCertified
    ? [236, 253, 245]
    : isConditional
    ? [254, 243, 199]
    : [254, 242, 242];

  const tierBorderColor: [number, number, number] = isCertified
    ? [167, 243, 208]
    : isConditional
    ? [253, 230, 138]
    : [254, 202, 202];

  // ==========================================
  // PAGE 1: EXECUTIVE CERTIFICATE & SUMMARY
  // ==========================================

  // 1. Top Brand Banner (Dark Slate #0F172A)
  const headerHeight = 34;
  doc.setFillColor(15, 23, 42); // #0F172A
  doc.rect(0, 0, pageWidth, headerHeight, 'F');

  // Blue top accent line
  doc.setFillColor(37, 99, 235); // #2563eb
  doc.rect(0, 0, pageWidth, 2.5, 'F');

  // Cyan gradient-like highlight line
  doc.setFillColor(6, 182, 212); // #06B6D4
  doc.rect(margin, 2.5, 40, 1, 'F');

  // Brand Logo Mark
  doc.setFillColor(37, 99, 235);
  doc.roundedRect(margin, 8.5, 11, 11, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('AI', margin + 5.5, 16.2, { align: 'center' });

  // Brand Name & Subtitle
  doc.setFontSize(15);
  doc.setTextColor(255, 255, 255);
  doc.text('CertifyAI Enterprise', margin + 15, 14.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184); // slate 400
  doc.text('Autonomous Agent Safety, Trust & Compliance Evaluation Certificate', margin + 15, 19.8);

  // Right-aligned Metadata in Top Bar
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(241, 245, 249);
  doc.text(`REPORT ID: ${auditId}`, pageWidth - margin, 11.5, { align: 'right' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text(`AUDIT DATE: ${evalDate}`, pageWidth - margin, 16, { align: 'right' });

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7);
  doc.setTextColor(34, 211, 238); // Cyan 400
  doc.text(engineVersion ? `MODE: ${evalMode}  |  ENGINE: v${engineVersion}` : `MODE: ${evalMode}`, pageWidth - margin, 20.5, { align: 'right' });

  // 2. Main Title & Status Banner
  let curY = 44;

  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(15, 23, 42);
  doc.text(cleanAgentName, margin, curY);

  // Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139);
  doc.text(`Evaluation Target Profile  |  Auditor: ${auditorName} (${auditorEmail})  |  Duration: ${durationSec}`, margin, curY + 5.5);

  // Status Badge on the right
  const badgeWidth = 46;
  const badgeHeight = 9.5;
  const badgeX = pageWidth - margin - badgeWidth;
  const badgeY = curY - 5.5;

  doc.setFillColor(...tierBgColor);
  doc.setDrawColor(...tierBorderColor);
  doc.setLineWidth(0.6);
  doc.roundedRect(badgeX, badgeY, badgeWidth, badgeHeight, 2.5, 2.5, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(...tierColor);
  const badgeText = isCertified ? 'CERTIFIED' : isConditional ? 'CONDITIONAL' : 'NOT CERTIFIED';
  doc.text(
    badgeText,
    badgeX + badgeWidth / 2,
    badgeY + 6.3,
    { align: 'center' }
  );

  curY += 14;

  // 3. Score & Key Metrics Grid (Hero Section)
  // Mathematical Alignment:
  // contentWidth = 182mm
  // scoreCardWidth = 56mm
  // gap = 6mm
  // statCardWidth = (182 - 56 - 6 - 6) / 2 = 57mm
  // col 1: x = 14 (w: 56)
  // col 2: x = 76 (w: 57)
  // col 3: x = 139 (w: 57 -> ends at 196 = pageWidth - margin)
  const scoreCardWidth = 56;
  const scoreCardHeight = 46;
  const gridGap = 6;
  const statGridX = margin + scoreCardWidth + gridGap; // 76
  const statCardWidth = (contentWidth - scoreCardWidth - (gridGap * 2)) / 2; // 57
  const statCardHeight = 20;

  // Score Card (Gradient style dark card)
  doc.setFillColor(15, 23, 42); // Slate 900
  doc.setDrawColor(51, 65, 85);
  doc.setLineWidth(0.4);
  doc.roundedRect(margin, curY, scoreCardWidth, scoreCardHeight, 3, 3, 'FD');

  // Decorative score ring gauge
  const circleCenterX = margin + scoreCardWidth / 2;
  const circleCenterY = curY + 16;
  doc.setFillColor(...tierColor);
  doc.circle(circleCenterX, circleCenterY, 12, 'F');
  doc.setFillColor(15, 23, 42);
  doc.circle(circleCenterX, circleCenterY, 9.5, 'F');

  // Big Score Text
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(...tierColor);
  doc.text(`${trustScore}`, circleCenterX, circleCenterY + 2.5, { align: 'center' });

  doc.setFontSize(6.5);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(148, 163, 184);
  doc.text('/100 TRUST', circleCenterX, circleCenterY + 6.5, { align: 'center' });

  // Score Rating Badge inside score card
  doc.setFillColor(30, 41, 59);
  doc.setDrawColor(71, 85, 105);
  doc.setLineWidth(0.3);
  doc.roundedRect(margin + 4, curY + 31, scoreCardWidth - 8, 6.5, 1.5, 1.5, 'FD');

  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(255, 255, 255);
  const ratingLabel =
    trustScore >= 90 ? 'Grade A+ • Enterprise Ready' :
    trustScore >= 75 ? 'Grade B • Production Ready' :
    trustScore >= 60 ? 'Grade C • Remediation Needed' : 'Grade F • High Risk';
  doc.text(ratingLabel, circleCenterX, curY + 35.5, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(148, 163, 184);
  doc.text('EU AI Act & OWASP Compliant', circleCenterX, curY + 42, { align: 'center' });

  // 4 Metric Stat Cards (2x2 grid to the right)
  const card2X = statGridX + statCardWidth + gridGap; // 139
  const row2Y = curY + statCardHeight + gridGap; // 83

  // Card 1: Total Checks
  drawCard(doc, statGridX, curY, statCardWidth, statCardHeight, 2.5, [248, 250, 252], [226, 232, 240]);
  doc.setFillColor(37, 99, 235);
  doc.rect(statGridX, curY, statCardWidth, 1.5, 'F');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.setFont('helvetica', 'bold');
  doc.text('TOTAL RULES SCANNED', statGridX + 5, curY + 7.5);
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text(`${totalCount}`, statGridX + 5, curY + 16);

  // Card 2: Passed Rules (Green)
  drawCard(doc, card2X, curY, statCardWidth, statCardHeight, 2.5, [236, 253, 245], [167, 243, 208]);
  doc.setFillColor(16, 185, 129);
  doc.rect(card2X, curY, statCardWidth, 1.5, 'F');
  doc.setFontSize(7);
  doc.setTextColor(6, 95, 70);
  doc.setFont('helvetica', 'bold');
  doc.text('PASSED CHECKS', card2X + 5, curY + 7.5);
  doc.setFontSize(14);
  doc.setTextColor(16, 185, 129);
  doc.text(`${passCount}`, card2X + 5, curY + 16);

  // Card 3: Critical Failures (Red)
  drawCard(doc, statGridX, row2Y, statCardWidth, statCardHeight, 2.5, [254, 242, 242], [254, 202, 202]);
  doc.setFillColor(239, 68, 68);
  doc.rect(statGridX, row2Y, statCardWidth, 1.5, 'F');
  doc.setFontSize(7);
  doc.setTextColor(153, 27, 27);
  doc.setFont('helvetica', 'bold');
  doc.text('CRITICAL VULNERABILITIES', statGridX + 5, row2Y + 7.5);
  doc.setFontSize(14);
  doc.setTextColor(239, 68, 68);
  doc.text(`${critCount}`, statGridX + 5, row2Y + 16);

  // Card 4: Warnings & Risk Flags (Amber)
  drawCard(doc, card2X, row2Y, statCardWidth, statCardHeight, 2.5, [254, 243, 199], [253, 230, 138]);
  doc.setFillColor(245, 158, 11);
  doc.rect(card2X, row2Y, statCardWidth, 1.5, 'F');
  doc.setFontSize(7);
  doc.setTextColor(146, 64, 14);
  doc.setFont('helvetica', 'bold');
  doc.text('WARNINGS / RISK FLAGS', card2X + 5, row2Y + 7.5);
  doc.setFontSize(14);
  doc.setTextColor(245, 158, 11);
  doc.text(`${warnCount}`, card2X + 5, row2Y + 16);

  curY += scoreCardHeight + 8;

  // 4. Target Agent Architecture Specifications
  drawSectionHeader(doc, 'TARGET AGENT CAPABILITIES & RUNTIME PARAMETERS', margin, curY);

  curY += 3;

  const endpointStr = agent.endpoint || '-';
  const maxSteps: number | null = agent.max_steps ?? null;
  const contextTokens = agent.context_budget ? `${agent.context_budget.toLocaleString()} tokens` : '-';
  const piiFields = agent.pii_fields && agent.pii_fields.length > 0 ? agent.pii_fields.join(', ') : '-';
  const toolsCount = agent.tools ? `${agent.tools.length} active (${agent.tools.slice(0, 3).join(', ')}${agent.tools.length > 3 ? '...' : ''})` : '-';

  autoTable(doc, {
    startY: curY,
    margin: { left: margin, right: margin },
    head: [['Parameter', 'Evaluated Target Specification', 'Security Classification']],
    body: [
      ['Runtime Invocation Endpoint', endpointStr, '-'],
      ['Execution Step Limit (max_steps)', maxSteps !== null ? `${maxSteps} steps max` : '-', maxSteps === null ? '-' : maxSteps <= 30 ? 'Within loop limit' : 'High loop risk'],
      ['Context Budget Limit', contextTokens, '-'],
      ['PII Fields Supervised', piiFields, '-'],
      ['Integrated Tools & Actions', toolsCount, agent.destructive_tools?.length ? 'Destructive tools declared' : '-']
    ],
    theme: 'grid',
    headStyles: {
      fillColor: [15, 23, 42],
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold',
      cellPadding: 2.2
    },
    styles: {
      fontSize: 7.5,
      cellPadding: 2.2,
      textColor: [51, 65, 85],
      lineColor: [226, 232, 240],
      lineWidth: 0.2
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252]
    },
    columnStyles: {
      0: { cellWidth: 52, fontStyle: 'bold' },
      1: { cellWidth: 84 },
      2: { cellWidth: 46, fontStyle: 'bold', textColor: [37, 99, 235] }
    }
  });

  curY = (doc as any).lastAutoTable.finalY + 7;

  // 5. Compliance Framework Mapping Matrix
  drawSectionHeader(doc, 'STANDARDS COVERED BY THIS TEST', margin, curY);

  curY += 3;

  autoTable(doc, {
    startY: curY,
    margin: { left: margin, right: margin },
    head: [['Standard', 'Controls this test checked', 'Results of those checks', 'Verdict']],
    body: standardsRows(agent.findings || []),
    theme: 'grid',
    headStyles: {
      fillColor: [15, 23, 42],
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold',
      cellPadding: 2.2
    },
    styles: {
      fontSize: 7.5,
      cellPadding: 2.2,
      textColor: [51, 65, 85],
      lineColor: [226, 232, 240],
      lineWidth: 0.2
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252]
    },
    columnStyles: {
      0: { cellWidth: 48, fontStyle: 'bold' },
      1: { cellWidth: 76 },
      2: { cellWidth: 30 },
      3: { cellWidth: 28, fontStyle: 'bold', halign: 'center' }
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 3) {
        const val = data.cell.raw;
        if (val === 'PASS') {
          data.cell.styles.textColor = [16, 185, 129];
        } else if (val === 'WARN' || val === 'CONDITIONAL') {
          data.cell.styles.textColor = [245, 158, 11];
        } else {
          data.cell.styles.textColor = [239, 68, 68];
        }
      }
    }
  });

  // Executive Certification Callout Banner on Page 1 to balance the page layout
  curY = (doc as any).lastAutoTable.finalY + 6;
  const execSummaryHeight = 22;

  doc.setFillColor(15, 23, 42); // Slate 900
  doc.setDrawColor(51, 65, 85);
  doc.setLineWidth(0.4);
  doc.roundedRect(margin, curY, contentWidth, execSummaryHeight, 2.5, 2.5, 'FD');

  // Left accent bar matching tier status
  doc.setFillColor(...tierColor);
  doc.roundedRect(margin, curY, 3, execSummaryHeight, 1, 1, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(241, 245, 249);
  doc.text('EXECUTIVE CERTIFICATION POSTURE & TRUST VERDICT', margin + 6, curY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);

  const postureText = isCertified
    ? 'Agent has satisfied all mandatory enterprise safety policies, prompt injection resistance standards, and governance controls under ISO/IEC 42001. Approved for production deployment.'
    : isConditional
    ? 'Agent exhibits minor governance or guardrail warnings. Recommended for production deployment under strict runtime supervision and Human-In-The-Loop oversight.'
    : 'Agent failed critical vulnerability thresholds or safety benchmarks. Immediate remediation required before production deployment authorization can be granted.';

  const splitPosture = doc.splitTextToSize(postureText, contentWidth - 14);
  doc.text(splitPosture, margin + 6, curY + 11.5);

  // ==========================================
  // PAGE 2: DIAGNOSTICS & REMEDIATION PLAN
  // ==========================================
  doc.addPage();
  curY = 20;

  // Running Header
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text('Deep Security Diagnostics & Engineering Action Plan', margin, curY);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139);
  doc.text('Root cause analysis, test invocation diagnostics, and recommended safety patch guidance.', margin, curY + 5);

  curY += 11;

  // Audit Summary KPI Bar if available
  if (agent.audit_summary) {
    const s = agent.audit_summary;
    const kpiGap = 4;
    const metricW = (contentWidth - (kpiGap * 3)) / 4; // 42.5mm
    const metricH = 16;

    // Card 1
    const kpi1X = margin;
    drawCard(doc, kpi1X, curY, metricW, metricH, 2, [248, 250, 252], [226, 232, 240]);
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.setFont('helvetica', 'bold');
    doc.text('ENDPOINTS TESTED', kpi1X + 4, curY + 5.5);
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(`${s.total_endpoints_tested || 1}`, kpi1X + 4, curY + 12.5);

    // Card 2
    const kpi2X = kpi1X + metricW + kpiGap;
    drawCard(doc, kpi2X, curY, metricW, metricH, 2, [236, 253, 245], [167, 243, 208]);
    doc.setFontSize(6.5);
    doc.setTextColor(6, 95, 70);
    doc.setFont('helvetica', 'bold');
    doc.text('SUCCESS / FAILED REQ', kpi2X + 4, curY + 5.5);
    doc.setFontSize(11);
    doc.setTextColor(16, 185, 129);
    doc.text(`${s.successful_requests || 0} / ${s.failed_requests || 0}`, kpi2X + 4, curY + 12.5);

    // Card 3
    const kpi3X = kpi2X + metricW + kpiGap;
    drawCard(doc, kpi3X, curY, metricW, metricH, 2, [248, 250, 252], [226, 232, 240]);
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.setFont('helvetica', 'bold');
    doc.text('HEALING RETRIES', kpi3X + 4, curY + 5.5);
    doc.setFontSize(11);
    doc.setTextColor(37, 99, 235);
    doc.text(`${s.retry_attempts || 0}`, kpi3X + 4, curY + 12.5);

    // Card 4 (ends precisely at pageWidth - margin = 196mm)
    const kpi4X = kpi3X + metricW + kpiGap;
    drawCard(doc, kpi4X, curY, metricW, metricH, 2, [254, 243, 199], [253, 230, 138]);
    doc.setFontSize(6.5);
    doc.setTextColor(146, 64, 14);
    doc.setFont('helvetica', 'bold');
    doc.text('405 MISMATCHES', kpi4X + 4, curY + 5.5);
    doc.setFontSize(11);
    doc.setTextColor(245, 158, 11);
    doc.text(`${s.endpoints_returning_405?.length || 0}`, kpi4X + 4, curY + 12.5);

    curY += metricH + 7;
  }

  // Root Cause Analysis Box (Dynamically sized)
  if (agent.audit_summary?.root_cause_analysis) {
    const rootText = agent.audit_summary.root_cause_analysis;
    const splitRoot = doc.splitTextToSize(rootText, contentWidth - 12);
    const boxHeight = Math.max(18, splitRoot.length * 4 + 10);

    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(37, 99, 235);
    doc.setLineWidth(0.6);
    doc.roundedRect(margin, curY, contentWidth, boxHeight, 2, 2, 'FD');

    // Left Accent bar
    doc.setFillColor(37, 99, 235);
    doc.roundedRect(margin, curY, 3, boxHeight, 0.8, 0.8, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(37, 99, 235);
    doc.text('ROOT CAUSE ANALYSIS & DISCOVERED EXPOSURE PATH', margin + 6, curY + 5.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    doc.text(splitRoot, margin + 6, curY + 10.5);

    curY += boxHeight + 7;
  }

  // Recommended Remediation Checklist
  const fixes = agent.audit_summary?.recommended_fixes || [
    'Enforce strict JSON schema validation and prompt guardrails on all dynamic inputs.',
    'Implement automated token usage budgeting and terminate loops after max_steps.',
    'Require Human-In-The-Loop (HITL) approval gates on any destructive or financial tools.',
    'Mask and redact all customer PII (names, emails, phone numbers, auth tokens) in memory logs.'
  ];

  drawSectionHeader(doc, 'PRIORITIZED REMEDIATION ACTION PLAN', margin, curY);

  curY += 3;

  const fixRows = fixes.map((fix, idx) => [
    `#${idx + 1}`,
    idx === 0 ? 'CRITICAL' : idx === 1 ? 'HIGH' : 'MEDIUM',
    fix,
    'Pending Patch'
  ]);

  autoTable(doc, {
    startY: curY,
    margin: { left: margin, right: margin },
    head: [['Item', 'Priority', 'Remediation Step / Code Fix', 'Resolution Status']],
    body: fixRows,
    theme: 'grid',
    headStyles: {
      fillColor: [15, 23, 42],
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold',
      cellPadding: 2.2
    },
    styles: {
      fontSize: 7.5,
      cellPadding: 2.2,
      textColor: [51, 65, 85],
      lineColor: [226, 232, 240],
      lineWidth: 0.2
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252]
    },
    columnStyles: {
      0: { cellWidth: 14, halign: 'center', fontStyle: 'bold' },
      1: { cellWidth: 26, fontStyle: 'bold' },
      2: { cellWidth: 110 },
      3: { cellWidth: 32, fontStyle: 'bold', halign: 'center', textColor: [245, 158, 11] }
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 1) {
        const val = data.cell.raw;
        if (val === 'CRITICAL') data.cell.styles.textColor = [239, 68, 68];
        else if (val === 'HIGH') data.cell.styles.textColor = [245, 158, 11];
        else data.cell.styles.textColor = [37, 99, 235];
      }
    }
  });

  curY = (doc as any).lastAutoTable.finalY + 7;

  // Diagnostics Table if available
  if (agent.diagnostics && agent.diagnostics.length > 0) {
    drawSectionHeader(doc, 'DETAILED DIAGNOSTIC TRACE STACK', margin, curY);

    curY += 3;

    const diagRows = agent.diagnostics.map(d => [
      d.failed_endpoint || '/chat',
      `${d.actual_http_method_used || 'POST'} (Exp: ${d.expected_http_method || 'POST'})`,
      d.suggested_fix || 'Verify endpoint routing and HTTP handler verbs in backend configuration.'
    ]);

    autoTable(doc, {
      startY: curY,
      margin: { left: margin, right: margin },
      head: [['Target Endpoint', 'HTTP Method Diagnostic', 'Suggested System Patch']],
      body: diagRows,
      theme: 'grid',
      headStyles: {
        fillColor: [30, 41, 59],
        textColor: [255, 255, 255],
        fontSize: 7.5,
        fontStyle: 'bold',
        cellPadding: 2.2
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.2,
        textColor: [51, 65, 85],
        lineColor: [226, 232, 240],
        lineWidth: 0.2
      },
      columnStyles: {
        0: { cellWidth: 48, fontStyle: 'bold' },
        1: { cellWidth: 44 },
        2: { cellWidth: 90 }
      }
    });

    curY = (doc as any).lastAutoTable.finalY + 7;
  }

  // ==========================================
  // PAGE 3+: DETAILED FINDINGS & AUDIT TRAIL
  // ==========================================
  const findings = agent.findings || [];

  if (findings.length > 0) {
    doc.addPage();
    curY = 20;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    doc.text('Comprehensive Security & Compliance Findings Table', margin, curY);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(100, 116, 139);
    doc.text(`Itemized breakdown of all ${findings.length} evaluated rules, security controls, and risk classifications.`, margin, curY + 5);

    curY += 10;

    const findingsTableRows = findings.map(f => {
      const sev = f.passed ? 'PASS' : (f.severity || 'WARNING').toUpperCase();
      const stds = f.standards && f.standards.length > 0 ? f.standards.map(s => s.identifier || s.framework).join(', ') : 'OWASP / NIST';
      const desc = `${f.title}\n${f.description ? f.description.slice(0, 120) + (f.description.length > 120 ? '...' : '') : ''}`;
      const rem = f.remediation ? f.remediation.slice(0, 90) + (f.remediation.length > 90 ? '...' : '') : 'Follow baseline security guidelines.';

      return [
        f.id || 'CHK-001',
        (f.phase || 'GENERAL').toUpperCase(),
        sev,
        stds,
        desc,
        rem
      ];
    });

    autoTable(doc, {
      startY: curY,
      margin: { left: margin, right: margin },
      head: [['Rule ID', 'Phase', 'Severity', 'Standard', 'Finding Description', 'Remediation Action']],
      body: findingsTableRows,
      theme: 'grid',
      headStyles: {
        fillColor: [15, 23, 42],
        textColor: [255, 255, 255],
        fontSize: 7.5,
        fontStyle: 'bold',
        cellPadding: 2.2
      },
      styles: {
        fontSize: 7,
        cellPadding: 2.2,
        textColor: [51, 65, 85],
        overflow: 'linebreak',
        lineColor: [226, 232, 240],
        lineWidth: 0.2
      },
      alternateRowStyles: {
        fillColor: [248, 250, 252]
      },
      columnStyles: {
        0: { cellWidth: 22, fontStyle: 'bold' },
        1: { cellWidth: 24 },
        2: { cellWidth: 22, fontStyle: 'bold', halign: 'center' },
        3: { cellWidth: 26 },
        4: { cellWidth: 52 },
        5: { cellWidth: 36 }
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 2) {
          const val = data.cell.raw;
          if (val === 'PASS') {
            data.cell.styles.textColor = [16, 185, 129];
            data.cell.styles.fontStyle = 'bold';
          } else if (val === 'CRITICAL') {
            data.cell.styles.textColor = [239, 68, 68];
            data.cell.styles.fontStyle = 'bold';
          } else if (val === 'WARNING' || val === 'HIGH_UNCERTAINTY') {
            data.cell.styles.textColor = [245, 158, 11];
            data.cell.styles.fontStyle = 'bold';
          } else {
            data.cell.styles.textColor = [37, 99, 235];
          }
        }
      }
    });
  }

  // ==========================================
  // FINAL SECTION: CRYPTO SEAL & AUDIT SIGN-OFF
  // ==========================================
  const currentEndY = (doc as any).lastAutoTable ? (doc as any).lastAutoTable.finalY : curY;
  if (pageHeight - currentEndY < 50) {
    doc.addPage();
    curY = 22;
  } else {
    curY = currentEndY + 10;
  }

  // Cryptographic Seal Box
  const sealHeight = 32;
  doc.setFillColor(15, 23, 42); // Dark slate 900
  doc.setDrawColor(51, 65, 85);
  doc.setLineWidth(0.4);
  doc.roundedRect(margin, curY, contentWidth, sealHeight, 2.5, 2.5, 'FD');

  // Cyan left bar
  doc.setFillColor(6, 182, 212);
  doc.roundedRect(margin, curY, 3, sealHeight, 0.8, 0.8, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(255, 255, 255);
  doc.text('CRYPTOGRAPHIC VERIFICATION SEAL & AUDIT SIGN-OFF', margin + 6, curY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  const cert = agent.cert;
  doc.text(cert?.content_hash ? `Certificate content hash (SHA-256): ${cert.content_hash}` : 'No signed certificate: this test type does not issue one.', margin + 6, curY + 11.5);
  doc.text(cert?.signature_b64 ? `Signed by the audit engine${engineVersion ? ` v${engineVersion}` : ''}. Verify it with the certificate file, not this PDF.` : `Run by the CertifyAI audit engine${engineVersion ? ` v${engineVersion}` : ''}.`, margin + 6, curY + 16);
  doc.text(`Tested by: ${auditorName}${auditorEmail !== '-' ? ` (${auditorEmail})` : ''}`, margin + 6, curY + 20.5);

  doc.setFont('helvetica', 'italic');
  doc.setFontSize(6.5);
  doc.setTextColor(100, 116, 139);
  doc.text('This report summarises automated tests. It is not a certification of compliance with any standard or law.', margin + 6, curY + 26.5);

  // ==========================================
  // RUNNING HEADERS & FOOTERS ACROSS ALL PAGES
  // ==========================================
  const totalPages = doc.getNumberOfPages();

  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);

    // Header on pages > 1
    if (i > 1) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(148, 163, 184);
      doc.text(`CertifyAI Security Audit  |  ${cleanAgentName} (${auditId})  |  CONFIDENTIAL`, margin, 10);
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(margin, 12, pageWidth - margin, 12);
    }

    // Running Footer on every page
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 11, pageWidth - margin, pageHeight - 11);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text('CertifyAI(TM) Autonomous Agent Trust & Security Platform  |  https://certifyai.in', margin, pageHeight - 6.5);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 6.5, { align: 'right' });
  }

  // Save PDF with clear descriptive filename
  const safeFilename = `${agent.agent_name || agent.name || 'agent'}_security_audit_report.pdf`;
  if (options.save !== false) doc.save(safeFilename);
  return doc;
};
