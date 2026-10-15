import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Bot, ChevronDown, ChevronRight, Clock, Download, Eye, Play, RefreshCw, Trash2, X } from 'lucide-react';
import { generatePDFReport } from '../../utils/pdfExport';
import { PdfHoverPreview } from '../PdfHoverPreview';
import { apiFetch } from '../../utils/apiClient';
import {
  Alert, Badge, Button, EmptyState, PageHeader, Pagination, Panel, SearchInput, Segmented, SimulatedNotice, SortHeader, TableSkeleton,
  TierBadge, Tooltip, isSimulated, modeLabel, scoreColor, useFocusTrap, type SortDir, type Tone, fmtScore,
} from '../ui';
import { FindingBadges } from '../FindingCounts';
import { ReportDownloadMenu } from '../ReportDownload';
import { fetchTestResult } from '../../utils/reportPdf';
import { DeleteTestDialog } from '../DeleteTestDialog';

interface UserTestHistoryProps {
  user: {
    id: number | string;
    name: string;
    email: string;
    role: string;
  };
  initialSelectedTestId?: number | null;
  onViewTestResult?: (testId: number) => void;
  onStartNewTest: () => void;
}

type SortField = 'agent_name' | 'status' | 'created_at' | 'trust_score';
type DateFilter = 'all' | 'today' | '7d' | '30d';
type StatusFilter = 'ALL' | 'CERTIFIED' | 'NOT_CERTIFIED';
type FindingFilter = 'ALL' | 'CRITICAL' | 'WARNING' | 'PASS';

const PAGE_SIZE = 10;

const formatDuration = (ms: number) => {
  if (!ms) return '-';
  const totalSec = Math.round(ms / 1000);
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
};

const formatDateTime = (isoStr: string) => {
  if (!isoStr) return { date: '-', time: '' };
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return { date: isoStr, time: '' };
  return {
    date: d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
    time: d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false }),
  };
};

const sevTone = (sev: string): Tone => (sev === 'CRITICAL' ? 'critical' : sev === 'WARNING' ? 'warning' : sev === 'PASS' ? 'pass' : 'neutral');

const verdict = (t: any) => {
  if (t.tier === 'FRAMEWORK_VALIDATION_ONLY') return 'Run against a mock target, so this result does not certify the agent.';
  if (t.tier === 'CERTIFIED') return 'No critical findings, a score of 90 or more and at most 3 warnings.';
  if ((t.critical_count || 0) > 0) return `${t.critical_count} critical finding${t.critical_count === 1 ? '' : 's'} to fix before deployment.`;
  return 'Review the warnings before deployment.';
};

export const UserTestHistory: React.FC<UserTestHistoryProps> = ({
  user,
  initialSelectedTestId,
  onViewTestResult,
  onStartNewTest
}) => {
  const [tests, setTests] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [dateFilter, setDateFilter] = useState<DateFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL');

  const [sort, setSort] = useState<{ key: SortField; dir: SortDir }>({ key: 'created_at', dir: 'desc' });
  const [currentPage, setCurrentPage] = useState<number>(1);

  const [selectedTestDetail, setSelectedTestDetail] = useState<any | null>(null);
  const [deleting, setDeleting] = useState<any | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState<number | null>(null);

  const fetchHistory = async () => {
    setIsLoading(true);
    setError(null);
    try {
      let url = `/api/user/tests?limit=100`;
      if (searchTerm) url += `&search=${encodeURIComponent(searchTerm)}`;
      if (statusFilter !== 'ALL') url += `&status=${encodeURIComponent(statusFilter)}`;
      if (dateFilter !== 'all') url += `&date_filter=${encodeURIComponent(dateFilter)}`;

      const res = await apiFetch(url);
      if (!res.ok) throw new Error('Your test history could not be loaded.');
      const data = await res.json();
      setTests(data.tests || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Your test history could not be loaded.');
    } finally {
      setIsLoading(false);
      setLoaded(true);
    }
  };

  const handleOpenTestDetail = async (testId: number) => {
    setIsDetailLoading(true);
    if (onViewTestResult) onViewTestResult(testId);
    try {
      const res = await apiFetch(`/api/user/tests/${testId}`);
      if (res.ok) {
        const data = await res.json();
        const testData = data.test;
        const fullObj = (testData.full_result && Object.keys(testData.full_result).length > 0) ? testData.full_result : testData;
        setSelectedTestDetail({
          ...fullObj,
          ...testData,
          findings: fullObj.findings || testData.findings || [],
          audit_summary: fullObj.audit_summary || testData.audit_summary || null
        });
      } else {
        const local = tests.find(t => t.id === testId);
        if (local) setSelectedTestDetail(local);
        else setError('That test could not be opened.');
      }
    } catch {
      const local = tests.find(t => t.id === testId);
      if (local) setSelectedTestDetail(local);
      else setError('That test could not be opened.');
    } finally {
      setIsDetailLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [user?.id, dateFilter, statusFilter]);

  useEffect(() => {
    if (initialSelectedTestId) handleOpenTestDetail(initialSelectedTestId);
  }, [initialSelectedTestId]);

  const handleDownloadPDF = async (test: any) => {
    try {
      setDownloadingId(test.id);
      // Prefer the PDF stored on the server
      try {
        const res = await apiFetch(`/api/user/tests/${test.id}/pdf`);
        if (res.ok) {
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${(test.agent_name || 'Agent').replace(/\s+/g, '_')}_audit_report_${test.audit_id || test.id}.pdf`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
          return;
        }
      } catch {
        /* fall back to building the PDF in the browser */
      }

      let findingsList = test.findings || [];
      if (!findingsList.length && test.full_result && test.full_result.findings) findingsList = test.full_result.findings;

      // generatePDFReport saves the file itself
      generatePDFReport({
        agent_name: test.agent_name,
        trust_score: test.trust_score || 0,
        tier: test.tier || 'NOT_CERTIFIED',
        audit_id: test.audit_id || `AUD-${test.id}`,
        findings: findingsList,
        summary: {
          critical_failures: test.critical_count || 0,
          warnings: test.warning_count || 0,
          passed: test.pass_count || 0,
          total: (test.pass_count || 0) + (test.critical_count || 0) + (test.warning_count || 0)
        }
      });
    } catch {
      setError('The PDF could not be created. Try again.');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleSort = (field: SortField) => {
    setSort(s => (s.key === field ? { key: field, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key: field, dir: 'desc' }));
    setCurrentPage(1);
  };

  type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';

  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');

  const filteredAndSortedTests = useMemo(() => {
    let result = [...tests];
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      result = result.filter(t =>
        (t.agent_name || '').toLowerCase().includes(term) ||
        (t.audit_id || '').toLowerCase().includes(term) ||
        (t.notes || '').toLowerCase().includes(term)
      );
    }
    if (agentTypeFilter === 'LIVE') {
      result = result.filter(t => t.mode === 'live_probe' || t.test_type === 'LIVE' || (t.notes || '').toLowerCase().includes('live'));
    } else if (agentTypeFilter === 'TESTING') {
      result = result.filter(t => t.mode !== 'live_probe' && t.test_type !== 'LIVE' && !(t.notes || '').toLowerCase().includes('live'));
    }

    if (statusFilter === 'CERTIFIED') result = result.filter(t => t.tier === 'CERTIFIED');
    else if (statusFilter === 'NOT_CERTIFIED') result = result.filter(t => t.tier !== 'CERTIFIED');

    result.sort((a, b) => {
      let comparison: number;
      if (sort.key === 'agent_name') comparison = (a.agent_name || '').localeCompare(b.agent_name || '');
      else if (sort.key === 'status') comparison = (a.tier === 'CERTIFIED' ? 0 : 1) - (b.tier === 'CERTIFIED' ? 0 : 1);
      else if (sort.key === 'trust_score') comparison = (a.trust_score || 0) - (b.trust_score || 0);
      else comparison = new Date(a.created_at || 0).getTime() - new Date(b.created_at || 0).getTime();
      return sort.dir === 'asc' ? comparison : -comparison;
    });
    return result;
  }, [tests, searchTerm, agentTypeFilter, statusFilter, sort]);

  const totalTests = filteredAndSortedTests.length;
  const totalPages = Math.max(1, Math.ceil(totalTests / PAGE_SIZE));
  const validCurrentPage = Math.min(currentPage, totalPages);
  const paginatedTests = filteredAndSortedTests.slice((validCurrentPage - 1) * PAGE_SIZE, validCurrentPage * PAGE_SIZE);

  const summaryMetrics = useMemo(() => ({
    total: totalTests,
    certified: filteredAndSortedTests.filter(t => t.tier === 'CERTIFIED').length,
    notCertified: filteredAndSortedTests.filter(t => t.tier === 'NOT_CERTIFIED').length,
    validationOnly: filteredAndSortedTests.filter(t => t.tier === 'FRAMEWORK_VALIDATION_ONLY').length,
    criticals: filteredAndSortedTests.reduce((acc, t) => acc + (t.critical_count || 0), 0),
  }), [filteredAndSortedTests, totalTests]);

  const filtered = searchTerm.trim() !== '' || dateFilter !== 'all' || statusFilter !== 'ALL' || agentTypeFilter !== 'ALL';
  const clearFilters = () => { setSearchTerm(''); setDateFilter('all'); setStatusFilter('ALL'); setAgentTypeFilter('ALL'); setCurrentPage(1); };

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Test history"
        subtitle="Every test you have run, with its score, findings and downloadable reports."
        actions={
          <>
            <Button icon={RefreshCw} onClick={fetchHistory} loading={isLoading && loaded}>Refresh</Button>
            <Button variant="primary" icon={Play} onClick={onStartNewTest}>Test an agent</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={() => { setError(null); fetchHistory(); }}>Try again</Button>} />}

      <form className="filter-bar" onSubmit={e => { e.preventDefault(); setCurrentPage(1); fetchHistory(); }}>
        <SearchInput value={searchTerm} onChange={v => { setSearchTerm(v); setCurrentPage(1); }} placeholder="Search agent name or audit ID" label="Search tests" width="auto" />
        {/* No "All" option: clicking the selected type or result again shows everything */}
        <Segmented<AgentTypeFilter> label="Agent type, click again to show all" value={agentTypeFilter} onChange={v => { setAgentTypeFilter(v === agentTypeFilter ? 'ALL' : v); setCurrentPage(1); }} items={[
          { value: 'LIVE', label: 'Live Agents' },
          { value: 'TESTING', label: 'Testing Agents' },
        ]} />
        <Segmented<DateFilter> label="Date" value={dateFilter} onChange={v => { setDateFilter(v); setCurrentPage(1); }} items={[
          { value: 'all', label: 'All time' }, { value: 'today', label: 'Today' }, { value: '7d', label: '7 days' }, { value: '30d', label: '30 days' },
        ]} />
        <Segmented<StatusFilter> label="Result, click again to show all" value={statusFilter} onChange={v => { setStatusFilter(v === statusFilter ? 'ALL' : v); setCurrentPage(1); }} items={[
          { value: 'CERTIFIED', label: 'Certified' }, { value: 'NOT_CERTIFIED', label: 'Not certified' },
        ]} />
        {filtered && <Button variant="ghost" onClick={clearFilters}>Clear filters</Button>}
      </form>

      <Panel
        flush
        footer={loaded && totalTests > 0 ? (
          <span style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <span>{summaryMetrics.total} test{summaryMetrics.total === 1 ? '' : 's'}</span>
            <span>{summaryMetrics.certified} certified</span>
            <span>{summaryMetrics.notCertified} not certified</span>
            <span>{summaryMetrics.validationOnly} validation only</span>
            <span style={{ color: summaryMetrics.criticals > 0 ? 'var(--color-danger)' : undefined }}>{summaryMetrics.criticals} critical finding{summaryMetrics.criticals === 1 ? '' : 's'}</span>
          </span>
        ) : undefined}
      >
        {loaded && !isLoading && totalTests === 0 ? (
          <EmptyState
            icon={Clock}
            title={filtered ? 'No tests match these filters' : 'No tests yet'}
            hint={filtered ? undefined : 'Run your first test and it appears here with its score and report.'}
            action={filtered
              ? <Button size="sm" onClick={clearFilters}>Clear filters</Button>
              : <Button variant="primary" icon={Play} onClick={onStartNewTest}>Test an agent</Button>}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <SortHeader label="Agent" column="agent_name" sort={sort} onSort={handleSort} />
                    <SortHeader label="Result" column="status" sort={sort} onSort={handleSort} />
                    <SortHeader label="Tested" column="created_at" sort={sort} onSort={handleSort} />
                    <SortHeader label="Score" column="trust_score" sort={sort} onSort={handleSort} numeric />
                    <th scope="col">Findings</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {!loaded || (isLoading && tests.length === 0) ? <TableSkeleton columns={6} rows={8} /> : paginatedTests.map(test => {
                    const score = test.trust_score !== undefined && test.trust_score !== null ? Math.round(test.trust_score) : 0;
                    const { date, time } = formatDateTime(test.created_at);
                    return (
                      <tr key={test.id}>
                        <td style={{ minWidth: 240 }}>
                          <div className="cell-with-icon">
                            <Bot aria-hidden="true" />
                            <div style={{ minWidth: 0 }}>
                              <div className="cell-strong cell-truncate" title={test.agent_name}>{test.agent_name}</div>
                              <div className="cell-sub" style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                                {isSimulated(test.mode) ? <Badge tone="warning">{modeLabel(test.mode)}</Badge> : <span>{test.mode ? modeLabel(test.mode) : 'Audit'}</span>}
                                <span aria-hidden="true">·</span>
                                <span>{formatDuration(test.duration_ms)}</span>
                                {test.audit_id && <><span aria-hidden="true">·</span><span className="cell-mono">{test.audit_id}</span></>}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td><TierBadge tier={test.tier} /></td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <div>{date}</div>
                          <div className="cell-sub">{time}</div>
                        </td>
                        <td className="num" style={{ fontWeight: 600, color: scoreColor(score) }}>{fmtScore(score)}%</td>
                        <td>
                          <FindingBadges counts={test} />
                        </td>
                        <td className="cell-actions">
                          <div style={{ display: 'inline-flex', gap: 2, alignItems: 'center' }}>
                            <PdfHoverPreview testId={test.id}>
                              <Button size="sm" variant="ghost" icon={Eye} onClick={() => handleOpenTestDetail(test.id)} aria-label={`View result for ${test.agent_name}`}>View</Button>
                            </PdfHoverPreview>
                            <ReportDownloadMenu size="sm" variant="ghost" iconOnly name={test.agent_name}
                              onPdf={() => handleDownloadPDF(test)} getReport={() => fetchTestResult(test.id)} onError={setError} />
                            <Tooltip label="Delete test">
                              <Button size="sm" variant="ghost" iconOnly icon={Trash2} className="btn-delete" onClick={() => setDeleting(test)} aria-label={`Delete test of ${test.agent_name}`} />
                            </Tooltip>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {totalTests > PAGE_SIZE && <Pagination page={validCurrentPage} pageSize={PAGE_SIZE} total={totalTests} onPage={setCurrentPage} />}
          </>
        )}
      </Panel>

      {(selectedTestDetail || isDetailLoading) && (
        <ResultModal
          test={selectedTestDetail}
          loading={isDetailLoading && !selectedTestDetail}
          user={user}
          downloading={selectedTestDetail ? downloadingId === selectedTestDetail.id : false}
          onClose={() => setSelectedTestDetail(null)}
          onPdf={() => handleDownloadPDF(selectedTestDetail)}
        />
      )}

      <DeleteTestDialog
        test={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={t => {
          setTests(prev => prev.filter(x => x.id !== t.id));
          if (selectedTestDetail?.id === t.id) setSelectedTestDetail(null);
        }}
      />
    </div>
  );
};

/** Full result of one test: score, verdict, counts and every finding with its evidence and fix. */
const ResultModal: React.FC<{
  test: any | null;
  loading: boolean;
  user: UserTestHistoryProps['user'];
  downloading: boolean;
  onClose: () => void;
  onPdf: () => void;
}> = ({ test, loading, user, downloading, onClose, onPdf }) => {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const [filter, setFilter] = useState<FindingFilter>('ALL');
  const [expanded, setExpanded] = useState<number | null>(null);
  useFocusTrap(ref, true);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  const findings: any[] = test?.findings || [];
  const count = (sev: string) => findings.filter(f => (f.severity || 'PASS').toUpperCase() === sev).length;
  const shown = findings.filter(f => filter === 'ALL' || (f.severity || 'PASS').toUpperCase() === filter);
  const total = test ? (test.critical_count || 0) + (test.warning_count || 0) + (test.pass_count || 0) : 0;
  const tester = test ? (test.tested_by_name || user?.name) : '';

  return createPortal(
    <div className="modal-layer" style={{ paddingTop: '4vh' }} onPointerDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-busy={loading} style={{ maxWidth: 920, maxHeight: '92vh' }}>
        {loading || !test ? (
          <div style={{ padding: 32 }} role="status" aria-label="Loading result">
            <h2 id={titleId} className="sr-only">Loading result</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <span className="skeleton" style={{ height: 28, width: '50%' }} />
              <span className="skeleton" style={{ height: 96 }} />
              <span className="skeleton" style={{ height: 200 }} />
            </div>
          </div>
        ) : (
          <>
            <div className="modal-head" style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
              <div style={{ minWidth: 0 }}>
                <h2 id={titleId} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  {test.agent_name}
                  <TierBadge tier={test.tier || 'NOT_CERTIFIED'} />
                </h2>
                <p>
                  Completed in {test.duration_ms ? `${(test.duration_ms / 1000).toFixed(1)}s` : '-'}
                  {tester ? `, tested by ${tester}` : ''}
                </p>
              </div>
              <div style={{ display: 'flex', gap: 8, flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                <ReportDownloadMenu name={test.agent_name} onPdf={onPdf} getReport={() => fetchTestResult(test.id)} />
                <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>
              </div>
            </div>

            <div className="modal-body" style={{ paddingTop: 20, display: 'flex', flexDirection: 'column', gap: 24 }}>
              <SimulatedNotice mode={test.mode} />

              <div className="result-summary">
                <div className="result-score">
                  <span className="stat-label">Trust score</span>
                  <span className="result-score-value" style={{ color: scoreColor(test.trust_score) }}>{fmtScore(test.trust_score)}%</span>
                  <div className="meter" style={{ width: '100%' }}>
                    <span style={{ width: `${Math.max(0, Math.min(100, test.trust_score || 0))}%`, background: scoreColor(test.trust_score) }} />
                  </div>
                  <span style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>{verdict(test)}</span>
                </div>
                <div className="result-counts">
                  {([
                    ['Critical', test.critical_count || 0, (test.critical_count || 0) > 0 ? 'var(--color-danger)' : undefined],
                    ['Warnings', test.warning_count || 0, (test.warning_count || 0) > 0 ? 'var(--color-warning)' : undefined],
                    ['Passed', test.pass_count || 0, undefined],
                    ['Total checks', total, undefined],
                  ] as [string, number, string | undefined][]).map(([label, value, color]) => (
                    <div key={label} className="result-count">
                      <span>{label}</span>
                      <strong className="num" style={{ color }}>{value}</strong>
                    </div>
                  ))}
                </div>
              </div>

              <dl className="detail-list">
                <div className="detail-row"><dt>Audit ID</dt><dd><code>{test.audit_id || '-'}</code></dd></div>
                <div className="detail-row"><dt>Mode</dt><dd>{modeLabel(test.mode)}</dd></div>
                <div className="detail-row"><dt>Run time</dt><dd>{test.duration_ms ? `${(test.duration_ms / 1000).toFixed(2)}s` : '-'}</dd></div>
              </dl>

              <section>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 12 }}>
                  <div>
                    <h3 style={{ fontSize: 16 }}>Findings <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({shown.length})</span></h3>
                    <p style={{ fontSize: 13, color: 'var(--color-text-muted)', marginTop: 2 }}>Open a finding to see what was expected, what happened and how to fix it.</p>
                  </div>
                  <Segmented<FindingFilter> label="Filter findings" value={filter} onChange={v => { setFilter(v); setExpanded(null); }} items={[
                    { value: 'ALL', label: 'All' },
                    { value: 'CRITICAL', label: `Critical (${count('CRITICAL')})` },
                    { value: 'WARNING', label: `Warning (${count('WARNING')})` },
                    { value: 'PASS', label: `Pass (${count('PASS')})` },
                  ]} />
                </div>
                {shown.length === 0 ? (
                  <EmptyState title={findings.length === 0 ? 'No findings were stored for this test' : 'No findings in this category'} />
                ) : (
                  <div className="accordion">
                    {shown.map((f, idx) => {
                      const sev = (f.severity || 'PASS').toUpperCase();
                      const isOpen = expanded === idx;
                      return (
                        <div key={idx} className="accordion-item">
                          <button className="accordion-trigger" onClick={() => setExpanded(isOpen ? null : idx)} aria-expanded={isOpen}>
                            {isOpen ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
                            <Badge tone={sevTone(sev)}>{sev.charAt(0) + sev.slice(1).toLowerCase()}</Badge>
                            <span className="accordion-title cell-truncate" style={{ maxWidth: 'none' }}>{f.title || f.description || 'Compliance check'}</span>
                            <span className="accordion-meta cell-mono">{f.rule_id || f.id || f.check_id || `RULE-${idx + 1}`}</span>
                          </button>
                          {isOpen && (
                            <div className="accordion-panel">
                              {f.description && <p>{f.description}</p>}
                              {f.expected && <p><strong>Expected: </strong>{f.expected}</p>}
                              {f.actual && <p><strong>Observed: </strong>{f.actual}</p>}
                              {f.remediation && <p><strong>How to fix: </strong>{f.remediation}</p>}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>
            </div>
          </>
        )}
      </div>
    </div>,
    document.body,
  );
};
