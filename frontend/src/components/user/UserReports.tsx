import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Bot, ChevronDown, ChevronRight, Download, Eye, FileText, RefreshCw, ShieldCheck } from 'lucide-react';
import { generatePDFReport } from '../../utils/pdfExport';
import { apiFetch } from '../../utils/apiClient';
import {
  Alert, Button, EmptyState, Modal, PageHeader, Pagination, Panel, SearchInput, Segmented, SortHeader, Stat, TableSkeleton, TierBadge, Tooltip,
  scoreColor, scoreTone, useSort, fmtScore,
} from '../ui';
import { findingsText } from '../FindingCounts';
import { ReportDownloadMenu } from '../ReportDownload';
import { CertificateView } from '../CertificateView';
import { fetchTestResult } from '../../utils/reportPdf';

interface UserReportsProps {
  user: { id: number | string; name: string; email: string; role: string };
  onViewReportDetail: (testId: number) => void;
}

const formatDate = (iso?: string | null) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
};

/** Date on the first line, local time underneath. */
const DateTime: React.FC<{ iso?: string | null }> = ({ iso }) => {
  const d = new Date(iso || '');
  if (!iso || Number.isNaN(d.getTime())) return <>-</>;
  return (
    <time dateTime={iso}>
      <div>{d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</div>
      <div className="cell-sub">{d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: true })}</div>
    </time>
  );
};

const saveBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
};

type SortKey = 'agent' | 'date' | 'score';

/** Runs of the same agent are grouped by name, ignoring case, spaces, dashes and underscores. */
const agentKey = (name?: string) => (name || '').trim().toLowerCase().replace(/[\s_-]+/g, ' ');
const timeOf = (iso?: string) => { const t = new Date(iso || '').getTime(); return Number.isNaN(t) ? 0 : t; };

interface ReportGroup {
  key: string;
  latest: any;
  runs: any[]; // newest first
}
const PAGE = 25;

export const UserReports: React.FC<UserReportsProps> = ({ user, onViewReportDetail }) => {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [cert, setCert] = useState<any | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/user/reports');
      if (!res.ok) throw new Error('The reports could not be loaded.');
      setReports((await res.json()).reports || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The reports could not be loaded.');
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, user?.id]);

  const downloadPdf = async (id: number, agent: string) => {
    setBusy(`pdf-${id}`);
    try {
      const res = await apiFetch(`/api/user/tests/${id}/pdf`);
      if (res.ok) {
        saveBlob(await res.blob(), `${agent.replace(/\s+/g, '_')}_audit_report_${id}.pdf`);
        return;
      }
      const detail = await apiFetch(`/api/user/tests/${id}`);
      if (!detail.ok) throw new Error('not available');
      const data = await detail.json();
      generatePDFReport(data.test.full_result || data.test, { save: false }).save(`${agent}_audit_report.pdf`);
    } catch {
      setError(`The PDF for ${agent} could not be created. Try again.`);
    } finally {
      setBusy(null);
    }
  };

  // One entry per agent: its newest run on top, every run kept as its history
  const groups = useMemo<ReportGroup[]>(() => {
    const byAgent = new Map<string, any[]>();
    for (const r of reports) {
      const k = agentKey(r.agent_name);
      const list = byAgent.get(k);
      if (list) list.push(r); else byAgent.set(k, [r]);
    }
    return Array.from(byAgent.entries()).map(([key, runs]) => {
      const sortedRuns = [...runs].sort((a, b) => timeOf(b.created_at) - timeOf(a.created_at));
      return { key, latest: sortedRuns[0], runs: sortedRuns };
    });
  }, [reports]);

  type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');

  const filtered = useMemo(() => {
    let res = groups;
    if (agentTypeFilter === 'LIVE') {
      res = res.filter(g => g.runs.some(r => r.mode === 'live_probe' || r.test_type === 'LIVE' || (r.notes || '').toLowerCase().includes('live')));
    } else if (agentTypeFilter === 'TESTING') {
      res = res.filter(g => g.runs.some(r => r.mode !== 'live_probe' && r.test_type !== 'LIVE' && !(r.notes || '').toLowerCase().includes('live')));
    }
    const q = search.trim().toLowerCase();
    if (!q) return res;
    return res.filter(g => g.runs.some(r => (r.agent_name || '').toLowerCase().includes(q) || (r.audit_id || '').toLowerCase().includes(q)));
  }, [groups, search, agentTypeFilter]);

  const { sorted, sort, toggle } = useSort<ReportGroup, SortKey>(filtered, {
    agent: g => g.latest.agent_name,
    date: g => timeOf(g.latest.created_at) || null,
    score: g => g.latest.trust_score,
  }, { key: 'date', dir: 'desc' });

  useEffect(() => setPage(1), [search, agentTypeFilter, sort]);
  const pageRows = sorted.slice((page - 1) * PAGE, page * PAGE);

  const actions = (r: any) => (
    <div style={{ display: 'inline-flex', gap: 2 }}>
      <Tooltip label="View result">
        <Button size="sm" variant="ghost" iconOnly icon={Eye} aria-label={`View result for ${r.agent_name} ${r.version || ''}`} onClick={() => onViewReportDetail(r.id)} />
      </Tooltip>
      <ReportDownloadMenu size="sm" variant="ghost" iconOnly name={`${r.agent_name} ${r.version || ''}`.trim()}
        onPdf={() => downloadPdf(r.id, r.agent_name)} getReport={() => fetchTestResult(r.id)} onError={setError} />
      {r.certificate && (
        <Tooltip label="Signed certificate">
          <Button size="sm" variant="ghost" iconOnly icon={ShieldCheck} aria-label={`View signed certificate for ${r.agent_name} ${r.version || ''}`} onClick={() => setCert(r.certificate)} />
        </Tooltip>
      )}
    </div>
  );

  const scoreCell = (r: any) => (
    <>
      <span style={{ fontWeight: 600, color: scoreColor(r.trust_score) }}>{fmtScore(r.trust_score)}%</span>
      {typeof r.score_delta === 'number' && r.score_delta !== 0 && (
        <span style={{ marginLeft: 8, fontSize: 12, color: r.score_delta > 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>
          {r.score_delta > 0 ? `+${r.score_delta}` : r.score_delta}
        </span>
      )}
    </>
  );

  const mono = (v?: string) => <code style={{ wordBreak: 'break-all' }}>{v || '-'}</code>;
  const certRows: [string, React.ReactNode][] = cert ? [
    ['Agent', cert.agent_name],
    ['Result', <TierBadge key="t" tier={cert.tier} />],
    ['Trust score', `${fmtScore(cert.trust_score)}%`],
    ['Grade', cert.grade || '-'],
    ['Issued', formatDate(cert.issued_at)],
    ['Expires', formatDate(cert.expires_at)],
    ['Audit ID', mono(cert.audit_id)],
    ['Signing key', mono(cert.key_fingerprint)],
    ['Content hash', mono(cert.content_hash)],
    ['Signature', mono(cert.signature_b64)],
  ] : [];

  const kpis = useMemo(() => {
    const totalReports = reports.length;
    const certifiedCount = reports.filter(r => r.tier === 'CERTIFIED').length;
    const certifiedRate = totalReports > 0 ? Math.round((certifiedCount / totalReports) * 100) : 0;
    const avgScore = totalReports > 0 ? Math.round(reports.reduce((acc, r) => acc + (r.trust_score || 0), 0) / totalReports) : 0;
    const totalCritical = reports.reduce((acc, r) => acc + (r.critical_count || 0), 0);
    return { totalReports, certifiedRate, avgScore, totalCritical, uniqueAgents: groups.length };
  }, [reports, groups]);

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Reports & Compliance Vault"
        subtitle="Download audit reports as PDF or Markdown, and view signed certificates."
        actions={
          <>
            <Segmented<AgentTypeFilter> label="Agent Type" value={agentTypeFilter} onChange={setAgentTypeFilter} items={[
              { value: 'ALL', label: 'All Agents' },
              { value: 'LIVE', label: 'Live Agents' },
              { value: 'TESTING', label: 'Testing Agents' },
            ]} />
            <SearchInput value={search} onChange={setSearch} placeholder="Search agent or audit ID" label="Search reports" width={240} />
            <Button icon={RefreshCw} onClick={load} loading={loading && loaded}>Refresh</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={() => { setError(null); load(); }}>Try again</Button>} />}

      {loaded && reports.length > 0 && (
        <div className="stat-grid" style={{ marginBottom: 12 }}>
          <Stat label="Total Audits" value={kpis.totalReports} tone="neutral" note={`${kpis.uniqueAgents} distinct agent fleets evaluated`} />
          <Stat label="Certified Compliance" value={`${kpis.certifiedRate}%`} tone={kpis.certifiedRate >= 80 ? 'pass' : kpis.certifiedRate >= 60 ? 'warning' : 'critical'} note="Full safety criteria verified" />
          <Stat label="Average Trust Score" value={`${fmtScore(kpis.avgScore)}%`} tone={scoreTone(kpis.avgScore)} note="Fleet-wide safety index" />
          <Stat label="Critical Vulnerabilities" value={kpis.totalCritical} tone={kpis.totalCritical === 0 ? 'pass' : 'critical'} note={kpis.totalCritical === 0 ? 'Zero critical issues detected' : 'Requires security attention'} />
        </div>
      )}

      <Panel
        flush
        title="Agents"
        subtitle={loaded ? `${groups.length} agent${groups.length === 1 ? '' : 's'}, ${reports.length} report${reports.length === 1 ? '' : 's'}. Open an agent to see every version.` : undefined}
      >
        {loaded && filtered.length === 0 ? (
          <EmptyState
            icon={FileText}
            title={reports.length === 0 ? 'No reports yet' : 'No reports match your search'}
            hint={reports.length === 0 ? 'A report is created for every test you run.' : undefined}
            action={reports.length > 0 ? <Button size="sm" onClick={() => setSearch('')}>Clear search</Button> : undefined}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col" style={{ width: 44 }}><span className="sr-only">Show versions</span></th>
                    <SortHeader label="Agent" column="agent" sort={sort} onSort={toggle} />
                    <SortHeader label="Last tested" column="date" sort={sort} onSort={toggle} />
                    <SortHeader label="Latest score" column="score" sort={sort} onSort={toggle} numeric />
                    <th scope="col">Result</th>
                    <th scope="col">Findings</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {!loaded ? <TableSkeleton columns={7} rows={6} /> : pageRows.map(g => {
                    const r = g.latest;
                    const isOpen = open === g.key;
                    const count = g.runs.length;
                    return (
                      <React.Fragment key={g.key}>
                        <tr className={isOpen ? 'row-open' : undefined}>
                          <td>
                            <button
                              type="button"
                              className="icon-btn"
                              style={{ height: 28, minWidth: 28, padding: 0 }}
                              onClick={() => setOpen(isOpen ? null : g.key)}
                              aria-expanded={isOpen}
                              aria-label={isOpen ? `Hide versions of ${r.agent_name}` : `Show all ${count} versions of ${r.agent_name}`}
                            >
                              {isOpen ? <ChevronDown /> : <ChevronRight />}
                            </button>
                          </td>
                          <td style={{ minWidth: 220 }}>
                            <div className="cell-with-icon">
                              <Bot aria-hidden="true" />
                              <span className="cell-strong cell-truncate" title={r.agent_name}>{r.agent_name}</span>
                              {r.version && <span className="badge mono" title="Latest version">{r.version}</span>}
                            </div>
                            <div className="cell-sub" style={{ marginLeft: 24 }}>
                              <button type="button" className="link-btn" style={{ fontWeight: 500 }} onClick={() => setOpen(isOpen ? null : g.key)}>
                                {count} version{count === 1 ? '' : 's'}
                              </button>
                            </div>
                          </td>
                          <td style={{ whiteSpace: 'nowrap' }}><DateTime iso={r.created_at} /></td>
                          <td className="num" style={{ whiteSpace: 'nowrap' }}>{scoreCell(r)}</td>
                          <td><TierBadge tier={r.tier} /></td>
                          <td style={{ whiteSpace: 'nowrap' }}>{findingsText(r)}</td>
                          <td className="cell-actions">{actions(r)}</td>
                        </tr>
                        {isOpen && (
                          <tr className="row-detail">
                            <td colSpan={7}>
                              <div className="table-wrap" style={{ border: '1px solid var(--color-border)', borderRadius: 8, background: 'var(--color-surface)' }}>
                                <table className="data-table nested-table">
                                  <thead>
                                    <tr>
                                      <th scope="col">Version</th>
                                      <th scope="col">Tested</th>
                                      <th scope="col" className="num">Score</th>
                                      <th scope="col">Result</th>
                                      <th scope="col">Findings</th>
                                      <th scope="col">Audit ID</th>
                                      <th scope="col"><span className="sr-only">Actions</span></th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {g.runs.map((run, i) => (
                                      <tr key={run.id}>
                                        <td>
                                          <span className="cell-strong">{run.version || `#${count - i}`}</span>
                                          {i === 0 && <span className="badge info" style={{ marginLeft: 8 }}>Latest</span>}
                                        </td>
                                        <td style={{ whiteSpace: 'nowrap' }}><DateTime iso={run.created_at} /></td>
                                        <td className="num" style={{ whiteSpace: 'nowrap' }}>{scoreCell(run)}</td>
                                        <td><TierBadge tier={run.tier} /></td>
                                        <td style={{ whiteSpace: 'nowrap' }}>{findingsText(run)}</td>
                                        <td className="cell-mono" style={{ whiteSpace: 'nowrap' }}>{run.audit_id}</td>
                                        <td className="cell-actions">{actions(run)}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {sorted.length > PAGE && <Pagination page={page} pageSize={PAGE} total={sorted.length} onPage={setPage} />}
          </>
        )}
      </Panel>

      <Modal open={!!cert} onClose={() => setCert(null)} title="Certificate" description="Signed by the CertifyAI audit engine." size="lg"
        footer={<Button onClick={() => setCert(null)}>Close</Button>}>
        {cert && <CertificateView cert={cert} />}
      </Modal>
    </div>
  );
};
