import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { BadgeCheck, Bot, ClipboardList, FileSearch, Gauge, Layers, Play, Radio, RefreshCw, Search } from 'lucide-react';
import { ResponsiveContainer, ComposedChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts';
import { apiFetch } from '../../utils/apiClient';
import { ScrollChart } from '../ScrollChart';
import { ordinalDay } from '../../utils/dateLabel';
import { PdfHoverPreview, PdfViewerModal } from '../PdfHoverPreview';
import {
  Alert, Button, EmptyState, PageHeader, Panel, Segmented, SortHeader, Stat, TableSkeleton, TierBadge, Tooltip as Tip,
  scoreColor, scoreTone, useSort, fmtScore,
} from '../ui';
import { ChartLegend, ChartTooltip, PercentAxis, SERIES, axisProps, hiddenPercentAxis, lineProps, weekOverWeek } from '../charts';
import { greeting } from '../../utils/greeting';

interface UserDashboardProps {
  onStartNewTest: () => void;
  onViewTestResult: (testId: number) => void;
  onNavigate: (tab: string) => void;
  user: { id: number | string; name: string; email: string; role: string; avatar_url?: string };
}

interface Kpis {
  total_tests: number;
  tests_this_week: number;
  agents_tested: number;
  live_agents?: number;
  certify_agents?: number;
  average_score: number;
  certified_count: number;
  pass_count?: number;
  fail_count?: number;
}

interface DashboardData {
  kpis: Kpis;
  recent_tests: any[];
  score_trends: { '7d': any[]; '30d': any[]; '90d': any[] };
  categories: { category: string; score: number; tests: number }[];
  phase_matrix: { phase_num: number; name: string; pass_rate: number; status: string }[];
  vulnerabilities: { critical: number; warning: number; low: number; passed: number };
}

const EMPTY: DashboardData = {
  kpis: { total_tests: 0, tests_this_week: 0, agents_tested: 0, average_score: 0, certified_count: 0 },
  recent_tests: [],
  score_trends: { '7d': [], '30d': [], '90d': [] },
  categories: [],
  phase_matrix: [],
  vulnerabilities: { critical: 0, warning: 0, low: 0, passed: 0 },
};

const formatDuration = (ms?: number) => {
  if (!ms) return '-';
  const total = Math.round(ms / 1000);
  const m = Math.floor(total / 60);
  return m > 0 ? `${m}m ${total % 60}s` : `${total}s`;
};

const formatDate = (iso?: string) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
};

const timeOf = (iso?: string) => {
  const t = iso ? new Date(iso).getTime() : NaN;
  return Number.isNaN(t) ? null : t;
};

type View = 'trend' | 'categories' | 'phases';
type Range = '7d' | '30d' | '90d';
type SortKey = 'agent' | 'date' | 'score' | 'duration';

const VIEW_COPY: Record<View, { title: string; subtitle: string }> = {
  trend: { title: 'Trust score over time', subtitle: 'Daily average score. The dashed line is the certification threshold (90).' },
  categories: { title: 'Score by category', subtitle: 'Share of checks passed, from your audit findings.' },
  phases: { title: 'Pass rate by phase', subtitle: 'Share of checks passed in each audit phase.' },
};

export const UserDashboard: React.FC<UserDashboardProps> = ({ onStartNewTest, onNavigate, user }) => {
  const [data, setData] = useState<DashboardData>(EMPTY);
  const [viewing, setViewing] = useState<{ id: number; name?: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [range, setRange] = useState<Range>('30d');
  const [view, setView] = useState<View>('trend');
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('ALL');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/user/dashboard');
      if (!res.ok) throw new Error('The dashboard could not be loaded.');
      const body = await res.json();
      setData({
        ...EMPTY,
        ...body,
        kpis: { ...EMPTY.kpis, ...(body.kpis || {}) },
        score_trends: { ...EMPTY.score_trends, ...(body.score_trends || {}) },
        vulnerabilities: { ...EMPTY.vulnerabilities, ...(body.vulnerabilities || {}) },
        recent_tests: body.recent_tests || [],
        categories: body.categories || [],
        phase_matrix: body.phase_matrix || [],
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The dashboard could not be loaded.');
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, user?.id]);

  const firstLoad = loading && !loaded;

  // The server adds two empty days after today so the latest point is not squeezed against the edge.
  const trend = data.score_trends[range] || [];
  const hasTrend = trend.some((d: any) => d.live_score != null || d.certify_score != null);
  const { kpis, vulnerabilities: vuln } = data;
  const scoreDelta = useMemo(() => weekOverWeek(data.score_trends['30d'] || []), [data.score_trends]);
  const certifiedShare = kpis.total_tests ? Math.round((kpis.certified_count / kpis.total_tests) * 100) : 0;

  type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');

  const filtered = useMemo(() => data.recent_tests.filter(t => {
    const q = search.trim().toLowerCase();
    const matchesText = !q || (t.agent_name || '').toLowerCase().includes(q) || (t.audit_id || '').toLowerCase().includes(q);
    const matchesTier = tierFilter === 'ALL' || (t.tier || '').toUpperCase() === tierFilter;
    const isLive = t.mode === 'live_probe' || t.test_type === 'LIVE' || (t.notes || '').toLowerCase().includes('live');
    const matchesType = agentTypeFilter === 'ALL' || (agentTypeFilter === 'LIVE' && isLive) || (agentTypeFilter === 'TESTING' && !isLive);
    return matchesText && matchesTier && matchesType;
  }), [data.recent_tests, search, tierFilter, agentTypeFilter]);

  const { sorted: tests, sort, toggle } = useSort<any, SortKey>(filtered, {
    agent: t => t.agent_name,
    date: t => timeOf(t.created_at),
    score: t => t.trust_score,
    duration: t => t.duration_ms,
  }, { key: 'date', dir: 'desc' });

  const findingTotal = vuln.critical + vuln.warning + vuln.low + vuln.passed;
  const findingRows = [
    { label: 'Critical', count: vuln.critical, color: 'var(--color-danger)' },
    { label: 'Warnings', count: vuln.warning, color: 'var(--color-warning)' },
    { label: 'Informational', count: vuln.low, color: 'var(--color-info)' },
    { label: 'Passed checks', count: vuln.passed, color: 'var(--color-success)' },
  ];

  const filtersActive = search.trim() !== '' || tierFilter !== 'ALL' || agentTypeFilter !== 'ALL';

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Dashboard"
        subtitle={`${greeting()}${user?.name ? `, ${user.name.split(' ')[0]}` : ''}. These results cover your own tests.`}
        actions={
          <>
            <Tip label="Reload dashboard data" placement="bottom">
              <Button variant="secondary" icon={RefreshCw} onClick={load} loading={loading && loaded}>Refresh</Button>
            </Tip>
            <Button variant="primary" icon={Play} onClick={onStartNewTest}>Test an agent</Button>
          </>
        }
      />

      {error && (
        <Alert tone="critical" title={error} action={<Button size="sm" onClick={load}>Try again</Button>}>
          {loaded && data !== EMPTY ? 'Showing the last data that loaded.' : 'Check your connection and try again.'}
        </Alert>
      )}

      <div className="stat-grid kpi-5">
        <Stat
          label="Average trust score" icon={Gauge} loading={firstLoad}
          value={kpis.total_tests ? `${fmtScore(kpis.average_score)}%` : '-'}
          tone={scoreTone(kpis.average_score, !!kpis.total_tests)}
          trend={scoreDelta !== null ? { delta: scoreDelta, label: 'pts vs prior 7 days' } : null}
          note={kpis.total_tests ? 'Across all your tests' : 'No tests yet'}
        />
        <Stat label="Total tests" icon={ClipboardList} loading={firstLoad} value={kpis.total_tests} note={`${kpis.tests_this_week} in the last 7 days`} onClick={() => onNavigate('tests')} />
        <Stat
          label="Certified" icon={BadgeCheck} loading={firstLoad}
          value={kpis.certified_count}
          note={kpis.total_tests ? `${certifiedShare}% of ${kpis.total_tests} tests` : 'No tests yet'}
        />
        <Stat label="Live agents" icon={Radio} loading={firstLoad} value={kpis.live_agents ?? 0} note="Tested against live endpoints" onClick={() => onNavigate('live-agents')} />
        <Stat label="Certify agents" icon={Layers} loading={firstLoad} value={kpis.certify_agents ?? 0} note="Tested for certification" onClick={() => onNavigate('agents')} />
      </div>

      <div className="dash-split">
        <Panel
          title={VIEW_COPY[view].title}
          subtitle={VIEW_COPY[view].subtitle}
          actions={
            <>
              <Segmented<View> label="Chart view" value={view} onChange={setView} items={[
                { value: 'trend', label: 'Trend' }, { value: 'categories', label: 'Categories' }, { value: 'phases', label: 'Phases' },
              ]} />
              {view === 'trend' && (
                <Segmented<Range> label="Time range" value={range} onChange={setRange} items={[
                  { value: '7d', label: '7D' }, { value: '30d', label: '30D' }, { value: '90d', label: '90D' },
                ]} />
              )}
            </>
          }
        >
          {view === 'trend' && hasTrend && (
            <div style={{ marginBottom: 12 }}>
              <ChartLegend items={[{ name: SERIES.live.name, color: SERIES.live.color }, { name: SERIES.certify.name, color: SERIES.certify.color }]} />
            </div>
          )}
          <div style={{ height: 280 }}>
            {firstLoad ? (
              <span className="skeleton" style={{ height: '100%' }} aria-hidden="true" />
            ) : view === 'trend' ? (hasTrend ? (
              <ScrollChart count={trend.length} axis={<PercentAxis />}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={trend} margin={{ top: 8, right: 12, left: 56, bottom: 0 }}>
                    <CartesianGrid vertical={false} />
                    <ReferenceLine y={90} stroke="var(--color-text-muted)" strokeDasharray="4 4" />
                    <XAxis dataKey="date" {...axisProps} interval={0} tickFormatter={ordinalDay} tick={{ ...axisProps.tick, fontSize: 11 }} />
                    <YAxis {...hiddenPercentAxis} />
                    <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--color-border-strong)', strokeWidth: 1 }} />
                    <Line dataKey={SERIES.live.key} name={SERIES.live.name} {...lineProps(SERIES.live.color)} />
                    <Line dataKey={SERIES.certify.key} name={SERIES.certify.name} {...lineProps(SERIES.certify.color)} />
                  </ComposedChart>
                </ResponsiveContainer>
              </ScrollChart>
            ) : (
              <EmptyState icon={FileSearch} title="No tests in this period" hint="Run a test and its score appears here." action={<Button size="sm" icon={Play} onClick={onStartNewTest}>Test an agent</Button>} />
            )) : view === 'categories' ? (data.categories.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.categories} margin={{ top: 8, right: 12, left: -12, bottom: 32 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="category" {...axisProps} interval={0} angle={-20} textAnchor="end" />
                  <YAxis domain={[0, 100]} {...axisProps} tickFormatter={v => `${v}%`} width={48} />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--color-surface-hover)' }} />
                  <Bar dataKey="score" name="Score" fill="var(--chart-1)" radius={[4, 4, 0, 0]} maxBarSize={40} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState icon={FileSearch} title="No category data yet" hint="Categories fill in once a test has findings." />
            )) : (data.phase_matrix.length ? (
              <div style={{ height: '100%', overflowY: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 8, alignContent: 'start' }}>
                {data.phase_matrix.map(p => {
                  const color = p.pass_rate >= 80 ? 'var(--color-success)' : p.pass_rate >= 60 ? 'var(--color-warning)' : 'var(--color-danger)';
                  return (
                    <div key={p.phase_num} style={{ padding: '10px 12px', border: '1px solid var(--color-border)', borderRadius: 6, display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 13 }}>
                        <span style={{ color: 'var(--color-text)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.name}>{p.name}</span>
                        <span className="num" style={{ color: 'var(--color-text)', fontWeight: 600 }}>{p.pass_rate}%</span>
                      </div>
                      <div className="meter"><span style={{ width: `${Math.max(0, Math.min(100, p.pass_rate))}%`, background: color }} /></div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState icon={FileSearch} title="No phase data yet" hint="Phases fill in once a test has findings." />
            ))}
          </div>
        </Panel>

        <Panel
          title="Findings"
          subtitle="Totals across every stored audit."
          footer="Certified needs a score of 90 or more, no critical findings and at most 3 warnings."
        >
          {firstLoad ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <span className="skeleton" style={{ height: 10 }} />
              {[0, 1, 2, 3].map(i => <span key={i} className="skeleton" style={{ height: 16 }} />)}
            </div>
          ) : findingTotal === 0 ? (
            <EmptyState title="No findings yet" hint="Findings from your tests are counted here." />
          ) : (
            <div className="panel-fill">
              <div className="stack-bar" role="img" aria-label={findingRows.map(r => `${r.label} ${r.count}`).join(', ')}>
                {findingRows.filter(r => r.count > 0).map(r => (
                  <span key={r.label} style={{ flexGrow: r.count, background: r.color }} />
                ))}
              </div>
              <div className="legend-list">
                {findingRows.map(r => (
                  <div className="legend-row" key={r.label}>
                    <span className="legend-swatch" style={{ background: r.color }} aria-hidden="true" />
                    {r.label}
                    <span className="legend-value num">{r.count.toLocaleString()}</span>
                    <span className="legend-share num">{Math.round((r.count / findingTotal) * 100)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent tests"
        subtitle={loaded ? `Your latest ${data.recent_tests.length} test${data.recent_tests.length === 1 ? '' : 's'}.` : undefined}
        flush
        actions={
          <>
            <div className="input-icon" style={{ width: 240 }}>
              <Search aria-hidden="true" />
              <input className="form-input" placeholder="Search agent or audit ID" value={search} onChange={e => setSearch(e.target.value)} aria-label="Search recent tests" />
            </div>
            <select className="form-input" value={agentTypeFilter} onChange={e => setAgentTypeFilter(e.target.value as AgentTypeFilter)} aria-label="Filter by agent type">
              <option value="ALL">All Agents</option>
              <option value="LIVE">Live Agents</option>
              <option value="TESTING">Testing Agents</option>
            </select>
            <select className="form-input" value={tierFilter} onChange={e => setTierFilter(e.target.value)} aria-label="Filter by result">
              <option value="ALL">All results</option>
              <option value="CERTIFIED">Certified</option>
              <option value="CONDITIONAL">Conditional</option>
              <option value="NOT_CERTIFIED">Not certified</option>
              <option value="FRAMEWORK_VALIDATION_ONLY">Validation only</option>
            </select>
            <Button variant="ghost" onClick={() => onNavigate('tests')}>View all</Button>
          </>
        }
      >
        {loaded && data.recent_tests.length === 0 ? (
          <EmptyState
            icon={ClipboardList}
            title="No tests yet"
            hint="Run your first test to see results here."
            action={<Button variant="primary" icon={Play} onClick={onStartNewTest}>Test an agent</Button>}
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <SortHeader label="Agent" column="agent" sort={sort} onSort={toggle} />
                  <SortHeader label="Date" column="date" sort={sort} onSort={toggle} />
                  <SortHeader label="Score" column="score" sort={sort} onSort={toggle} numeric />
                  <th scope="col">Result</th>
                  <SortHeader label="Duration" column="duration" sort={sort} onSort={toggle} numeric />
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {firstLoad ? <TableSkeleton columns={6} /> : tests.map(t => (
                  <tr key={t.id}>
                    <td>
                      <div className="cell-with-icon cell-strong">
                        <Bot aria-hidden="true" />
                        <span className="cell-truncate" title={t.agent_name}>{t.agent_name}</span>
                        {t.version && <span className="badge mono">{t.version}</span>}
                      </div>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatDate(t.created_at)}</td>
                    <td className="num" style={{ whiteSpace: 'nowrap' }}>
                      <span style={{ color: scoreColor(t.trust_score), fontWeight: 600 }}>{fmtScore(t.trust_score)}%</span>
                      {typeof t.score_delta === 'number' && t.score_delta !== 0 && (
                        <span style={{ marginLeft: 8, fontSize: 12, color: t.score_delta > 0 ? 'var(--color-success)' : 'var(--color-danger)' }} aria-label={`${t.score_delta > 0 ? 'up' : 'down'} ${Math.abs(t.score_delta)} from previous run`}>
                          {t.score_delta > 0 ? `+${t.score_delta}` : t.score_delta}
                        </span>
                      )}
                    </td>
                    <td><TierBadge tier={t.tier} /></td>
                    <td className="num">{formatDuration(t.duration_ms)}</td>
                    <td className="cell-actions">
                      <PdfHoverPreview testId={t.id}>
                        <Button size="sm" variant="ghost" onClick={() => setViewing({ id: t.id, name: t.agent_name })} aria-label={`View result for ${t.agent_name}`}>View result</Button>
                      </PdfHoverPreview>
                    </td>
                  </tr>
                ))}
                {!firstLoad && tests.length === 0 && (
                  <tr>
                    <td colSpan={6} className="table-empty">
                      No tests match these filters.{' '}
                      {filtersActive && <button type="button" className="link-btn" onClick={() => { setSearch(''); setTierFilter('ALL'); }}>Clear filters</button>}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {viewing && <PdfViewerModal testId={viewing.id} title={viewing.name} onClose={() => setViewing(null)} />}
    </div>
  );
};
