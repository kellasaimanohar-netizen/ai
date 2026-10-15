import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, Bot, RefreshCw } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { generatePDFReport } from '../../utils/pdfExport';
import {
  Alert, Badge, Button, EmptyState, KindBadge, PageHeader, Pagination, Panel, SearchInput, Segmented, SortHeader, TableSkeleton, TierBadge,
  isSimulated, scoreColor, useSort, fmtScore,
} from '../ui';
import { TestDetailModal } from '../TestDetailModal';
import { FindingBadges } from '../FindingCounts';

interface Props {
  initialSelectedTestId?: number | null;
}

const formatDateTime = (iso?: string) => {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '-';
  return `${d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}, ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
};

const DAY = 86400000;
const PAGE = 25;
type Period = 'all' | 'today' | '7d' | '30d';
type SortKey = 'person' | 'agent' | 'when' | 'score';

export const AdminTestingActivity: React.FC<Props> = ({ initialSelectedTestId }) => {
  const [tests, setTests] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const [search, setSearch] = useState('');
  const [person, setPerson] = useState('ALL');
  const [agent, setAgent] = useState('ALL');
  const [tier, setTier] = useState('ALL');
  const [kind, setKind] = useState<'ALL' | 'live' | 'certify'>('ALL');
  const [period, setPeriod] = useState<Period>('all');
  const [loadedAt, setLoadedAt] = useState(0);
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/admin/activity?limit=500');
      if (!res.ok) throw new Error('The testing activity could not be loaded.');
      setTests((await res.json()).tests || []);
      setLoadedAt(Date.now());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The testing activity could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  const openDetail = useCallback(async (id: number) => {
    try {
      const res = await apiFetch(`/api/admin/tests/${id}`);
      if (!res.ok) throw new Error('not found');
      setDetail((await res.json()).test);
    } catch {
      setError('That test could not be opened.');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (initialSelectedTestId) openDetail(initialSelectedTestId);
  }, [initialSelectedTestId, openDetail]);

  const people = useMemo(() => Array.from(new Set(tests.map(t => t.tested_by_name).filter(Boolean))).sort(), [tests]);
  const agents = useMemo(() => Array.from(new Set(tests.map(t => t.agent_name).filter(Boolean))).sort(), [tests]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const now = loadedAt;
    const startOfToday = new Date(loadedAt).setHours(0, 0, 0, 0);
    return tests.filter(t => {
      if (person !== 'ALL' && t.tested_by_name !== person) return false;
      if (agent !== 'ALL' && t.agent_name !== agent) return false;
      if (kind !== 'ALL' && (t.mode === 'live_probe' ? 'live' : 'certify') !== kind) return false;
      if (tier !== 'ALL' && (t.tier || '').toUpperCase() !== tier) return false;
      const when = new Date(t.created_at).getTime();
      if (period === 'today' && when < startOfToday) return false;
      if (period === '7d' && when < now - 7 * DAY) return false;
      if (period === '30d' && when < now - 30 * DAY) return false;
      return !q || (t.agent_name || '').toLowerCase().includes(q) || (t.audit_id || '').toLowerCase().includes(q) || (t.tested_by_name || '').toLowerCase().includes(q);
    });
  }, [tests, person, agent, tier, kind, period, search, loadedAt]);

  const { sorted, sort, toggle } = useSort<any, SortKey>(rows, {
    person: t => t.tested_by_name,
    agent: t => t.agent_name,
    when: t => { const v = new Date(t.created_at).getTime(); return Number.isNaN(v) ? null : v; },
    score: t => t.trust_score,
  }, { key: 'when', dir: 'desc' });

  useEffect(() => setPage(1), [search, person, agent, tier, kind, period, sort]);
  const pageRows = sorted.slice((page - 1) * PAGE, page * PAGE);

  const filtered = search.trim() !== '' || person !== 'ALL' || agent !== 'ALL' || tier !== 'ALL' || kind !== 'ALL' || period !== 'all';
  const clearFilters = () => { setSearch(''); setPerson('ALL'); setAgent('ALL'); setTier('ALL'); setKind('ALL'); setPeriod('all'); };

  const downloadPdf = (t: any) => {
    try {
      generatePDFReport(t.full_result && Object.keys(t.full_result).length ? t.full_result : t, { save: false }).save(`${t.agent_name}_audit_report.pdf`);
    } catch {
      setError('The PDF could not be created. Try again.');
    }
  };

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Testing activity"
        subtitle="Every agent evaluation across the organization, and who ran it."
        actions={<Button icon={RefreshCw} onClick={load} loading={loading && loadedAt > 0}>Refresh</Button>}
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={() => { setError(null); load(); }}>Try again</Button>} />}

      <div className="filter-bar">
        <SearchInput value={search} onChange={setSearch} placeholder="Search agent, audit ID or person" label="Search runs" width="auto" />
        <select className="form-input" value={person} onChange={e => setPerson(e.target.value)} aria-label="Person">
          <option value="ALL">All people</option>
          {people.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select className="form-input" value={agent} onChange={e => setAgent(e.target.value)} aria-label="Agent">
          <option value="ALL">All agents</option>
          {agents.map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <select className="form-input" style={{ flexBasis: 170 }} value={kind} onChange={e => setKind(e.target.value as 'ALL' | 'live' | 'certify')} aria-label="Type">
          <option value="ALL">All Agents</option>
          <option value="live">Live Agents</option>
          <option value="certify">Testing Agents</option>
        </select>
        <select className="form-input" style={{ flexBasis: 170 }} value={tier} onChange={e => setTier(e.target.value)} aria-label="Result">
          <option value="ALL">All results</option>
          <option value="CERTIFIED">Certified</option>
          <option value="CONDITIONAL">Conditional</option>
          <option value="NOT_CERTIFIED">Not certified</option>
          <option value="FRAMEWORK_VALIDATION_ONLY">Validation only</option>
        </select>
        <Segmented<Period> label="Period" value={period} onChange={setPeriod} items={[
          { value: 'all', label: 'All time' }, { value: 'today', label: 'Today' }, { value: '7d', label: '7 days' }, { value: '30d', label: '30 days' },
        ]} />
        {filtered && <Button variant="ghost" onClick={clearFilters}>Clear filters</Button>}
      </div>

      <Panel title="Runs" subtitle={loadedAt ? `${rows.length.toLocaleString()} of ${tests.length.toLocaleString()} shown` : undefined} flush>
        {loadedAt > 0 && rows.length === 0 ? (
          <EmptyState
            icon={Activity}
            title={tests.length === 0 ? 'No tests yet' : 'No runs match the filters'}
            hint={tests.length === 0 ? 'Runs appear here as soon as someone tests an agent.' : undefined}
            action={filtered ? <Button size="sm" onClick={clearFilters}>Clear filters</Button> : undefined}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <SortHeader label="Person" column="person" sort={sort} onSort={toggle} />
                    <SortHeader label="Agent" column="agent" sort={sort} onSort={toggle} />
                    <SortHeader label="When" column="when" sort={sort} onSort={toggle} />
                    <SortHeader label="Score" column="score" sort={sort} onSort={toggle} numeric />
                    <th scope="col">Result</th>
                    <th scope="col">Findings</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {loadedAt === 0 ? <TableSkeleton columns={7} rows={8} /> : pageRows.map(t => (
                    <tr
                      key={t.id}
                      className="clickable"
                      tabIndex={0}
                      onClick={() => openDetail(t.id)}
                      onKeyDown={e => { if (e.key === 'Enter') openDetail(t.id); }}
                    >
                      <td>
                        <div className="cell-strong">{t.tested_by_name || '-'}</div>
                        <div className="cell-sub">{t.tested_by_email}</div>
                      </td>
                      <td style={{ minWidth: 260 }}>
                        <div className="cell-with-icon">
                          <Bot aria-hidden="true" />
                          <span className="cell-strong cell-truncate" style={{ maxWidth: 220 }} title={t.agent_name}>{t.agent_name}</span>
                          {t.version && <span className="badge mono">{t.version}</span>}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4, marginLeft: 24 }}>
                          <KindBadge live={t.mode === 'live_probe'} />
                          {isSimulated(t.mode) && <Badge tone="warning" title="Validate mode: the agent was not contacted">Simulated</Badge>}
                          <span className="cell-mono">{t.audit_id}</span>
                        </div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>{formatDateTime(t.created_at)}</td>
                      <td className="num" style={{ whiteSpace: 'nowrap' }}>
                        <span style={{ fontWeight: 600, color: scoreColor(t.trust_score) }}>{fmtScore(t.trust_score)}%</span>
                        {typeof t.score_delta === 'number' && t.score_delta !== 0 && (
                          <span style={{ marginLeft: 8, fontSize: 12, color: t.score_delta > 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>
                            {t.score_delta > 0 ? `+${t.score_delta}` : t.score_delta}
                          </span>
                        )}
                      </td>
                      <td><TierBadge tier={t.tier} /></td>
                      <td>
                        <FindingBadges counts={t} showPassed={false} />
                      </td>
                      <td className="cell-actions">
                        <Button size="sm" variant="ghost" onClick={e => { e.stopPropagation(); openDetail(t.id); }} aria-label={`View test of ${t.agent_name}`}>View</Button>
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

      {detail && <TestDetailModal test={detail} onClose={() => setDetail(null)} onDownloadPdf={downloadPdf} />}
    </div>
  );
};
