/**
 * Markdown version of a test report. Same data as the PDF, but nothing is shortened, so the whole
 * report can be read by a person or pasted into an AI assistant for review.
 * Works with both certify results (`findings`) and live results (`all_findings`, `test_results`).
 */

type Any = Record<string, any>;

const TIER_LABEL: Record<string, string> = {
  CERTIFIED: 'Certified',
  CONDITIONAL: 'Conditional',
  NOT_CERTIFIED: 'Not certified',
  INCONCLUSIVE: 'Inconclusive',
};

const FRAMEWORKS: [string, string][] = [
  ['owasp_llm_2025', 'OWASP LLM Top 10 (2025)'],
  ['owasp_agentic_2025', 'OWASP Agentic AI Top 10'],
  ['nist_ai_rmf_genai', 'NIST AI RMF (GenAI profile)'],
  ['iso_42001', 'ISO/IEC 42001:2023'],
  ['eu_ai_act', 'EU AI Act'],
  ['mitre_atlas', 'MITRE ATLAS'],
  ['india_dpdp_2023', 'India DPDP Act 2023'],
];

const num = (v: unknown) => String(Math.round((Number(v) || 0) * 100) / 100);
const when = (iso?: string) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
};
/** Text safe inside a table cell: pipes escaped, line breaks kept as <br>. */
const cell = (v: unknown) => String(v ?? '-').replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>') || '-';
/** Text inside a fenced block cannot close the fence. */
const fence = (v: unknown) => String(v ?? '').replace(/```/g, '`​``');
const table = (head: string[], rows: unknown[][]) =>
  [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map(r => `| ${r.map(cell).join(' | ')} |`)].join('\n');

const severityOf = (f: Any) => (f.passed || String(f.severity).toUpperCase() === 'PASS' ? 'PASS' : String(f.severity || 'WARNING').toUpperCase());
const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, WARNING: 2, INFO: 3, PASS: 4 };

export function buildMarkdownReport(r: Any): string {
  const name = r.agent_name || r.name || 'Unnamed agent';
  const tier = String(r.tier || 'NOT_CERTIFIED').toUpperCase();
  const findings: Any[] = r.findings?.length ? r.findings : r.all_findings || [];
  const tests: Any[] = r.test_results || [];
  const critical = r.summary?.critical_failures ?? r.critical_count ?? findings.filter(f => severityOf(f) === 'CRITICAL').length;
  const warnings = r.summary?.warnings ?? r.warning_count ?? findings.filter(f => ['WARNING', 'HIGH'].includes(severityOf(f))).length;
  const passed = r.summary?.passed ?? r.pass_count ?? findings.filter(f => severityOf(f) === 'PASS').length;
  const total = r.summary?.total ?? r.tests_count ?? r.total_rules ?? (critical + warnings + passed || findings.length);
  const mode = String(r.mode || (tests.length ? 'live_probe' : '')).toLowerCase();
  const modeLabel = mode === 'validate' ? 'Validate (simulated agent, not your real agent)' : mode === 'live_probe' ? 'Live' : mode ? mode.replace(/_/g, ' ') : '-';

  const out: string[] = [];
  out.push(`# Agent test report: ${name}`);
  out.push('');
  out.push(`> **Result:** ${TIER_LABEL[tier] || tier} · **Trust score:** ${num(r.trust_score)}/100 · **Findings:** ${critical} critical, ${warnings} warnings, ${passed} passed`);
  if (r.tier_note) out.push(`>\n> ${r.tier_note}`);
  out.push('');

  out.push('## Summary');
  out.push('');
  const meta: [string, unknown][] = [
    ['Agent', name],
    ['Version', r.version],
    ['Report ID', r.audit_id],
    ['Result', TIER_LABEL[tier] || tier],
    ['Trust score', `${num(r.trust_score)} / 100`],
    ['Checks', total],
    ['Critical', critical],
    ['Warnings', warnings],
    ['Passed', passed],
    ['Could not run', r.could_not_run],
    ['Mode', modeLabel],
    ['Agent type', r.agent_type],
    ['Endpoint', r.endpoint_url || r.endpoint],
    ['Environment', r.target_env],
    ['OpenAPI', r.openapi_url],
    ['Repository', r.repo_path],
    ['Started', r.started_at ? when(r.started_at) : undefined],
    ['Finished', r.finished_at ? when(r.finished_at) : undefined],
    ['Duration', r.total_duration_ms ? `${(r.total_duration_ms / 1000).toFixed(1)} s` : undefined],
    ['Average latency', r.avg_latency_ms ? `${Math.round(r.avg_latency_ms)} ms` : undefined],
    ['Tested by', r.tested_by_name ? `${r.tested_by_name}${r.tested_by_email ? ` (${r.tested_by_email})` : ''}` : undefined],
    ['AI judge', r.ai_judge_used === undefined ? undefined : r.ai_judge_used ? 'Used' : 'Not used'],
  ];
  out.push(table(['Field', 'Value'], meta.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => [k, v])));
  out.push('');

  const tools: string[] = r.tools || r.capabilities || r.repo_summary?.tools_detected || [];
  if (tools.length || r.destructive_tools?.length || r.pii_fields?.length || r.max_steps || r.context_budget) {
    out.push('## Agent capabilities');
    out.push('');
    if (tools.length) out.push(`- **Tools (${tools.length}):** ${tools.join(', ')}`);
    if (r.destructive_tools?.length) out.push(`- **Destructive tools:** ${r.destructive_tools.join(', ')}`);
    if (r.pii_fields?.length) out.push(`- **Personal data fields:** ${r.pii_fields.join(', ')}`);
    if (r.max_steps) out.push(`- **Step limit:** ${r.max_steps}`);
    if (r.context_budget) out.push(`- **Context budget:** ${Number(r.context_budget).toLocaleString()} tokens`);
    out.push('');
  }

  const problems = findings.filter(f => severityOf(f) !== 'PASS').sort((a, b) => (SEV_ORDER[severityOf(a)] ?? 9) - (SEV_ORDER[severityOf(b)] ?? 9));
  out.push(`## Issues to fix (${problems.length})`);
  out.push('');
  if (problems.length === 0) out.push('No failed checks.');
  problems.forEach((f, i) => {
    out.push(`### ${i + 1}. [${severityOf(f)}] ${f.title || f.id || 'Finding'}`);
    out.push('');
    const facts = [
      f.id && `**ID:** \`${f.id}\``,
      (f.phase || f.category) && `**Area:** ${f.phase || f.category}`,
      f.standards?.length && `**Standards:** ${f.standards.map((s: Any) => s.identifier || s.framework).join(', ')}`,
      f.cwe?.length && `**CWE:** ${f.cwe.join(', ')}`,
      f.mitre_atlas?.length && `**MITRE ATLAS:** ${f.mitre_atlas.join(', ')}`,
    ].filter(Boolean);
    if (facts.length) out.push(facts.join(' · '), '');
    if (f.description) out.push(String(f.description).trim(), '');
    if (f.remediation) out.push(`**How to fix:** ${String(f.remediation).trim()}`, '');
  });

  if (tests.length) {
    out.push(`## Test prompts and answers (${tests.length})`);
    out.push('');
    out.push(table(['Test', 'Category', 'Status', 'HTTP', 'Latency'], tests.map(t => [t.name || t.test_id, t.category, t.status, t.status_code || '-', t.latency_ms ? `${Math.round(t.latency_ms)} ms` : '-'])));
    out.push('');
    tests.filter(t => t.status !== 'PASSED').forEach(t => {
      out.push(`### ${t.name || t.test_id} (${t.status})`);
      out.push('');
      if (t.expected_behavior) out.push(`**Expected:** ${t.expected_behavior}`, '');
      if (t.prompt) out.push('**Prompt sent:**', '', '```text', fence(t.prompt), '```', '');
      if (t.response) out.push('**Agent answer:**', '', '```text', fence(String(t.response).slice(0, 4000)), '```', '');
      const checks = (t.checks || []).filter((c: Any) => c.passed !== true);
      if (checks.length) out.push(...checks.map((c: Any) => `- ${c.passed === false ? 'Failed' : 'Undecided'}: ${c.name}${c.detail ? `, ${c.detail}` : ''}`), '');
      if (t.judge_note) out.push(`**AI judge:** ${t.judge_note}`, '');
    });
  }

  const summaryBox = r.audit_summary;
  if (summaryBox?.root_cause_analysis || summaryBox?.recommended_fixes?.length) {
    out.push('## Root cause and recommended fixes');
    out.push('');
    if (summaryBox.root_cause_analysis) out.push(summaryBox.root_cause_analysis, '');
    (summaryBox.recommended_fixes || []).forEach((fix: string, i: number) => out.push(`${i + 1}. ${fix}`));
    out.push('');
  }

  if (r.diagnostics?.length) {
    out.push('## Request diagnostics');
    out.push('');
    out.push(table(['Endpoint', 'Method used', 'Expected', 'Suggested fix'], r.diagnostics.map((d: Any) => [d.failed_endpoint, d.actual_http_method_used, d.expected_http_method, d.suggested_fix])));
    out.push('');
  }

  if (r.skipped_phases?.length) {
    out.push('## Skipped phases');
    out.push('');
    out.push(table(['Phase', 'Why', 'What to do'], r.skipped_phases.map((s: Any) => [s.phase, s.reason, s.remediation])));
    out.push('');
  }

  if (findings.some(f => f.standards?.length)) {
    out.push('## Standards covered');
    out.push('');
    out.push(table(['Standard', 'Controls checked', 'Results', 'Verdict'], FRAMEWORKS.map(([key, label]) => {
      const hits = findings.filter(f => (f.standards || []).some((s: Any) => s.framework === key));
      if (!hits.length) return [label, '-', 'Not assessed by this test', '-'];
      const ids = Array.from(new Set(hits.flatMap(f => f.standards.filter((s: Any) => s.framework === key).map((s: Any) => s.identifier)))).sort().join(', ');
      const c = hits.filter(f => severityOf(f) === 'CRITICAL').length;
      const w = hits.filter(f => ['WARNING', 'HIGH'].includes(severityOf(f))).length;
      return [label, ids, `${hits.length - c - w} passed, ${w} warnings, ${c} critical`, c ? 'FAIL' : w ? 'WARN' : 'PASS'];
    })));
    out.push('');
  }

  const passedChecks = findings.filter(f => severityOf(f) === 'PASS');
  if (passedChecks.length) {
    out.push(`## Passed checks (${passedChecks.length})`);
    out.push('');
    passedChecks.forEach(f => out.push(`- ${f.title || f.id}${f.id && f.title ? ` (\`${f.id}\`)` : ''}`));
    out.push('');
  }

  if (r.cert?.content_hash) {
    out.push('## Certificate');
    out.push('');
    out.push(`- **Content hash (SHA-256):** \`${r.cert.content_hash}\``);
    if (r.cert.audit_version) out.push(`- **Audit engine:** v${r.cert.audit_version}`);
    out.push('- Verify the signature with the certificate file, not this report.');
    out.push('');
  }

  out.push('---');
  out.push('');
  out.push(`Generated by CertifyAI on ${when(new Date().toISOString())}. This report summarises automated tests. It is not a certification of compliance with any standard or law.`);
  out.push('');
  return out.join('\n');
}

const safeName = (s: string) => (s || 'agent').replace(/[^\w.-]+/g, '_').replace(/^_+|_+$/g, '') || 'agent';

export function downloadMarkdownReport(r: Any, baseName?: string): void {
  const blob = new Blob([buildMarkdownReport(r)], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${safeName(baseName || `${r.agent_name || r.name}_audit_report${r.version ? `_${r.version}` : ''}`)}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
