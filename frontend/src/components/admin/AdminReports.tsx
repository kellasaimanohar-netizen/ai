import React, { useEffect, useMemo, useState } from 'react';
import { Bot, Download, Eye, FileText, RefreshCw } from 'lucide-react';
import { generatePDFReport } from '../../utils/pdfExport';
import { apiFetch } from '../../utils/apiClient';
import { ReportDownloadMenu } from '../ReportDownload';
import {
  Alert, Badge, Button, EmptyState, PageHeader, Pagination, Panel, SearchInput, Segmented, SortHeader, Stat, TableSkeleton, TierBadge, Tooltip,
  scoreColor, scoreTone, useSort, fmtScore,
} from '../ui';

interface AdminReportsProps {
  onViewTestDetails: (testId: number) => void;
}

type Period = 'all' | 'today' | '7d' | '30d';
type SortKey = 'agent' | 'person' | 'date' | 'score';
const PAGE = 25;

const RESULT_FILTERS = [
  { value: 'all', label: 'All' },
  { value: 'CERTIFIED', label: 'Certified' },
  { value: 'CONDITIONAL', label: 'Conditional' },
  { value: 'NOT_CERTIFIED', label: 'Not certified' },
  { value: 'FRAMEWORK_VALIDATION_ONLY', label: 'Validation only' },
];

const saveBlob = (blob: Blob, name: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
};

export const AdminReports: React.FC<AdminReportsProps> = ({ onViewTestDetails }) => {
  const [reports, setReports] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedUserFilter, setSelectedUserFilter] = useState('all');
  const [selectedStatusFilter, setSelectedStatusFilter] = useState('all');
  const [exportDateFilter, setExportDateFilter] = useState<Period>('all');
  const [exporting, setExporting] = useState<'csv' | null>(null);
  const [busyRow, setBusyRow] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const fetchReports = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/admin/reports');
      if (!res.ok) throw new Error('The reports could not be loaded.');
      const data = await res.json();
      setReports(data.reports || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The reports could not be loaded.');
    } finally {
      setIsLoading(false);
      setLoaded(true);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchFull = async (reportId: number) => {
    const res = await apiFetch(`/api/admin/tests/${reportId}`);
    if (!res.ok) throw new Error('not found');
    const data = await res.json();
    return data.test.full_result || data.test;
  };

  const handleDownloadPDF = async (reportId: number, agentName: string) => {
    setBusyRow(`pdf-${reportId}`);
    try {
      generatePDFReport(await fetchFull(reportId), { save: false }).save(`${agentName}_audit_report.pdf`);
    } catch {
      setError(`The PDF for ${agentName} could not be created.`);
    } finally {
      setBusyRow(null);
    }
  };

  const handleExportAll = async (format: 'csv') => {
    let exportUrl = `/api/admin/reports/export?format=${format}`;
    if (exportDateFilter !== 'all') exportUrl += `&date_filter=${exportDateFilter}`;
    if (selectedUserFilter !== 'all') exportUrl += `&user=${encodeURIComponent(selectedUserFilter)}`;
    if (selectedStatusFilter !== 'all') exportUrl += `&status=${encodeURIComponent(selectedStatusFilter)}`;

    // window.open() can't attach an Authorization header, and this endpoint
    // requires admin auth - fetch it via apiFetch (which does attach the
    // token) and hand the browser a blob to download instead.
    setExporting(format);
    setError(null);
    try {
      const res = await apiFetch(exportUrl);
      if (!res.ok) throw new Error();
      saveBlob(await res.blob(), `certifyai_audit_export.${format}`);
    } catch {
      setError('The export could not be created. Try again.');
    } finally {
      setExporting(null);
    }
  };

  const testers = useMemo(() => Array.from(new Set(reports.map(r => r.tested_by_name).filter(Boolean))).sort(), [reports]);

  type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');

  const filteredReports = useMemo(() => reports.filter(r => {
    const q = searchTerm.toLowerCase();
    const matchSearch = (r.agent_name || '').toLowerCase().includes(q) ||
                        (r.tested_by_name || '').toLowerCase().includes(q) ||
                        (r.audit_id || '').toLowerCase().includes(q);
    const matchUser = selectedUserFilter === 'all' || (r.tested_by_name || '').toLowerCase() === selectedUserFilter.toLowerCase();
    const matchStatus = selectedStatusFilter === 'all' || r.tier === selectedStatusFilter;
    const isLive = r.mode === 'live_probe' || r.test_type === 'LIVE' || (r.notes || '').toLowerCase().includes('live');
    const matchType = agentTypeFilter === 'ALL' || (agentTypeFilter === 'LIVE' && isLive) || (agentTypeFilter === 'TESTING' && !isLive);
    return matchSearch && matchUser && matchStatus && matchType;
  }), [reports, searchTerm, selectedUserFilter, selectedStatusFilter, agentTypeFilter]);

  const { sorted, sort, toggle } = useSort<any, SortKey>(filteredReports, {
    agent: r => r.agent_name,
    person: r => r.tested_by_name,
    date: r => { const t = new Date(r.created_at).getTime(); return Number.isNaN(t) ? null : t; },
    score: r => r.trust_score,
  }, { key: 'date', dir: 'desc' });

  useEffect(() => setPage(1), [searchTerm, selectedUserFilter, selectedStatusFilter, agentTypeFilter, sort]);
  const pageRows = sorted.slice((page - 1) * PAGE, page * PAGE);
  const filtered = searchTerm !== '' || selectedUserFilter !== 'all' || selectedStatusFilter !== 'all' || agentTypeFilter !== 'ALL';
  const clearFilters = () => { setSearchTerm(''); setSelectedUserFilter('all'); setSelectedStatusFilter('all'); setAgentTypeFilter('ALL'); };

  const kpis = useMemo(() => {
    const totalReports = reports.length;
    const certifiedCount = reports.filter(r => r.tier === 'CERTIFIED').length;
    const certifiedRate = totalReports > 0 ? Math.round((certifiedCount / totalReports) * 100) : 0;
    const avgScore = totalReports > 0 ? Math.round(reports.reduce((acc, r) => acc + (r.trust_score || 0), 0) / totalReports) : 0;
    const totalCritical = reports.reduce((acc, r) => acc + (r.critical_count || 0), 0);
    const uniqueAgents = new Set(reports.map(r => r.agent_name)).size;
    return { totalReports, certifiedRate, avgScore, totalCritical, uniqueAgents };
  }, [reports]);

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Organization Reports & Audit Vault"
        subtitle="Download or export every cryptographic certification report in the organization. Complete administrative control."
        actions={
          <>
            <Button icon={RefreshCw} variant="ghost" onClick={fetchReports} loading={isLoading && loaded}>Refresh</Button>
            <Button icon={Download} variant="primary" onClick={() => handleExportAll('csv')} loading={exporting === 'csv'} disabled={!!exporting}>Export CSV</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={() => { setError(null); fetchReports(); }}>Try again</Button>} />}

      {loaded && reports.length > 0 && (
        <div className="stat-grid" style={{ marginBottom: 16 }}>
          <Stat label="Total Organization Reports" value={kpis.totalReports} tone="neutral" note={`${kpis.uniqueAgents} monitored agent fleets`} />
          <Stat label="Certification Compliance" value={`${kpis.certifiedRate}%`} tone={kpis.certifiedRate >= 80 ? 'pass' : kpis.certifiedRate >= 60 ? 'warning' : 'critical'} note="Organization policy standard" />
          <Stat label="System Average Score" value={`${fmtScore(kpis.avgScore)}%`} tone={scoreTone(kpis.avgScore)} note="Fleet-wide security index" />
          <Stat label="Critical Vulnerabilities" value={kpis.totalCritical} tone={kpis.totalCritical === 0 ? 'pass' : 'critical'} note={kpis.totalCritical === 0 ? 'Zero critical exposures' : 'Requires administrative review'} />
        </div>
      )}

      <div className="filter-bar">
        <SearchInput value={searchTerm} onChange={setSearchTerm} placeholder="Search report, agent or tester" width="auto" />
        <select className="form-input" value={agentTypeFilter} onChange={e => setAgentTypeFilter(e.target.value as AgentTypeFilter)} aria-label="Filter by agent type">
          <option value="ALL">All Agents</option>
          <option value="LIVE">Live Agents</option>
          <option value="TESTING">Testing Agents</option>
        </select>
        <select className="form-input" value={selectedUserFilter} onChange={e => setSelectedUserFilter(e.target.value)} aria-label="Filter by tester">
          <option value="all">All testers</option>
          {testers.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <Segmented<string> label="Filter by result" value={selectedStatusFilter} onChange={setSelectedStatusFilter} items={RESULT_FILTERS} />
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)', marginLeft: 'auto' }}>Export period</span>
        <Segmented<Period> label="Export period" value={exportDateFilter} onChange={setExportDateFilter} items={[
          { value: 'all', label: 'All time' }, { value: 'today', label: 'Today' }, { value: '7d', label: '7 days' }, { value: '30d', label: '30 days' },
        ]} />
      </div>

      <Panel flush>
        {loaded && filteredReports.length === 0 ? (
          <EmptyState
            icon={FileText}
            title={reports.length === 0 ? 'No reports yet' : 'No reports match these filters'}
            hint={reports.length === 0 ? 'A report is created for every test.' : undefined}
            action={filtered ? <Button size="sm" onClick={clearFilters}>Clear filters</Button> : undefined}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Report ID</th>
                    <SortHeader label="Agent" column="agent" sort={sort} onSort={toggle} />
                    <SortHeader label="Tested by" column="person" sort={sort} onSort={toggle} />
                    <SortHeader label="Date" column="date" sort={sort} onSort={toggle} />
                    <SortHeader label="Score" column="score" sort={sort} onSort={toggle} numeric />
                    <th scope="col">Result</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {!loaded ? <TableSkeleton columns={7} rows={8} /> : pageRows.map(report => (
                    <tr key={report.id}>
                      <td className="cell-mono" style={{ whiteSpace: 'nowrap' }}>{report.audit_id}</td>
                      <td style={{ minWidth: 200 }}>
                        <div className="cell-with-icon">
                          <Bot aria-hidden="true" />
                          <span className="cell-strong cell-truncate" style={{ maxWidth: 220 }} title={report.agent_name}>{report.agent_name}</span>
                          {report.version && <span className="badge mono">{report.version}</span>}
                          {report.is_latest && <Badge tone="info">Latest</Badge>}
                        </div>
                      </td>
                      <td>
                        <div className="cell-strong">{report.tested_by_name}</div>
                        <div className="cell-sub">{report.tested_by_email}</div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {new Date(report.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                      </td>
                      <td className="num" style={{ whiteSpace: 'nowrap' }}>
                        <span style={{ fontWeight: 600, color: scoreColor(report.trust_score) }}>{fmtScore(report.trust_score)}%</span>
                        {typeof report.score_delta === 'number' && report.score_delta !== 0 && (
                          <span style={{ marginLeft: 8, fontSize: 12, color: report.score_delta > 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>
                            {report.score_delta > 0 ? `+${report.score_delta}` : report.score_delta}
                          </span>
                        )}
                      </td>
                      <td><TierBadge tier={report.tier} /></td>
                      <td className="cell-actions">
                        <div style={{ display: 'inline-flex', gap: 2 }}>
                          <Tooltip label="View test details">
                            <Button size="sm" variant="ghost" iconOnly icon={Eye} aria-label={`View details for ${report.agent_name}`} onClick={() => onViewTestDetails(report.id)} />
                          </Tooltip>
                          <ReportDownloadMenu size="sm" variant="ghost" iconOnly name={report.agent_name}
                            onPdf={() => handleDownloadPDF(report.id, report.agent_name)}
                            getReport={async () => ({ ...report, ...(await fetchFull(report.id)) })}
                            onError={setError} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {sorted.length > PAGE && <Pagination page={page} pageSize={PAGE} total={sorted.length} onPage={setPage} />}
          </>
        )}
      </Panel>
    </div>
  );
};
