import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, Bot, ClipboardList, Gauge, Layers, Radio, RefreshCw, ShieldAlert, Zap } from 'lucide-react';
import { ResponsiveContainer, Tooltip, LineChart, Line, ReferenceLine, XAxis, YAxis, CartesianGrid } from 'recharts';
import { apiFetch } from '../../utils/apiClient';
import { ScrollChart } from '../ScrollChart';
import { ordinalDay } from '../../utils/dateLabel';
import {
  Alert, Button, EmptyState, PageHeader, Panel, SortHeader, Stat, TableSkeleton, TierBadge, Tooltip as Tip,
  scoreColor, scoreTone, useSort, fmtScore,
} from '../ui';
import { ChartLegend, ChartTooltip, PercentAxis, SERIES, axisProps, hiddenPercentAxis, lineProps, weekOverWeek } from '../charts';
import { greeting } from '../../utils/greeting';

interface AdminDashboardProps {
  user: { id: number | string; name: string; email: string; role: string };
  onNavigate: (tab: string) => void;
  onViewTestDetails: (testId: number) => void;
}

interface Kpis {
  tests_today: number;
  agents_today: number;
  live_agents?: number;
  certify_agents?: number;
  total_tests: number;
  average_score: number;
  certified_count: number;
  conditional_count: number;
  not_certified_count: number;
  critical_findings_count: number;
}

const EMPTY_KPIS: Kpis = {
  tests_today: 0, agents_today: 0, total_tests: 0, average_score: 0,
  certified_count: 0, conditional_count: 0, not_certified_count: 0, critical_findings_count: 0,
};

const formatDateTime = (iso?: string) => {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '-';
  return `${d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}, ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
};

type SortKey = 'person' | 'agent' | 'when' | 'score';

export const AdminDashboard: React.FC<AdminDashboardProps> = ({ user, onNavigate, onViewTestDetails }) => {
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kpis, setKpis] = useState<Kpis>(EMPTY_KPIS);
  const [activity, setActivity] = useState<any[]>([]);
  const [volume, setVolume] = useState<any[]>([]);
  const [rankings, setRankings] = useState<any[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/admin/dashboard');
      if (!res.ok) throw new Error('The dashboard could not be loaded.');
      const body = await res.json();
      setKpis({ ...EMPTY_KPIS, ...(body.kpis || {}) });
      setActivity(body.recent_activity || []);
      // The charts below are extra. If they cannot load, the rest of the page still works.
      try {
        const ar = await apiFetch('/api/admin/analytics?days=14&pad=2');
        if (ar.ok) {
          const a = await ar.json();
          setVolume(a.volume_trend || []);
          setRankings((a.agent_rankings || []).slice(0, 5));
        }
      } catch {
        /* ignore */
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The dashboard could not be loaded.');
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const firstLoad = loading && !loaded;
  const scoreDelta = useMemo(() => weekOverWeek(volume), [volume]);
  const hasVolume = volume.some(v => v.live_score != null || v.certify_score != null);

  const classified = kpis.certified_count + kpis.conditional_count + kpis.not_certified_count;
  const validationOnly = Math.max(0, kpis.total_tests - classified);
  const distribution = [
    { name: 'Certified', value: kpis.certified_count, color: 'var(--color-success)' },
    { name: 'Conditional', value: kpis.conditional_count, color: 'var(--color-warning)' },
    { name: 'Not certified', value: kpis.not_certified_count, color: 'var(--color-danger)' },
    { name: 'Validation only', value: validationOnly, color: 'var(--color-info)' },
  ];

  type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');

  const filteredActivity = useMemo(() => {
    let list = activity || [];
    if (agentTypeFilter === 'LIVE') {
      list = list.filter(t => t.mode === 'live_probe' || t.test_type === 'LIVE' || (t.notes || '').toLowerCase().includes('live'));
    } else if (agentTypeFilter === 'TESTING') {
      list = list.filter(t => t.mode !== 'live_probe' && t.test_type !== 'LIVE' && !(t.notes || '').toLowerCase().includes('live'));
    }
    return list;
  }, [activity, agentTypeFilter]);

  const { sorted: rows, sort, toggle } = useSort<any, SortKey>(filteredActivity, {
    person: r => r.tested_by_name,
    agent: r => r.agent_name,
    when: r => { const t = new Date(r.created_at).getTime(); return Number.isNaN(t) ? null : t; },
    score: r => r.trust_score,
  }, { key: 'when', dir: 'desc' });

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Dashboard"
        subtitle={`${greeting()}${user?.name ? `, ${user.name.split(' ')[0]}` : ''}. Testing across the whole organization.`}
        actions={
          <>
            <Tip label="Reload dashboard data" placement="bottom">
              <Button variant="secondary" icon={RefreshCw} onClick={load} loading={loading && loaded}>Refresh</Button>
            </Tip>
            <Button variant="primary" icon={Activity} onClick={() => onNavigate('activity')}>Review testing activity</Button>
          </>
        }
      />

      {error && (
        <Alert tone="critical" title={error} action={<Button size="sm" onClick={load}>Try again</Button>}>
          Check your connection and try again.
        </Alert>
      )}

      <div className="stat-grid kpi-6">
        <Stat
          label="Average trust score" icon={Gauge} loading={firstLoad}
          value={kpis.total_tests ? `${fmtScore(kpis.average_score)}%` : '-'}
          tone={scoreTone(kpis.average_score, !!kpis.total_tests)}
          trend={scoreDelta !== null ? { delta: scoreDelta, label: 'pts vs prior 7 days' } : null}
          note="Organization average"
        />
        <Stat
          label="Critical findings" icon={ShieldAlert} loading={firstLoad}
          value={kpis.critical_findings_count}
          tone={kpis.critical_findings_count ? 'critical' : 'neutral'}
          note={kpis.critical_findings_count ? 'Across all tests, needs review' : 'None across all tests'}
        />
        <Stat label="Tests today" icon={Zap} loading={firstLoad} value={kpis.tests_today} note={`${kpis.agents_today} distinct agent${kpis.agents_today === 1 ? '' : 's'}`} />
        <Stat label="Total tests" icon={ClipboardList} loading={firstLoad} value={kpis.total_tests.toLocaleString()} note="All time" onClick={() => onNavigate('activity')} />
        <Stat label="Live agents" icon={Radio} loading={firstLoad} value={kpis.live_agents ?? 0} note="Tested against live endpoints" onClick={() => onNavigate('admin-live-agents')} />
        <Stat label="Certify agents" icon={Layers} loading={firstLoad} value={kpis.certify_agents ?? 0} note="Tested for certification" onClick={() => onNavigate('admin-agents')} />
      </div>

      <div className="dash-split">
        <Panel
          title="Recent testing activity"
          subtitle="The latest evaluations and who ran them."
          flush
          actions={
            <>
              <select className="form-input" style={{ width: 140 }} value={agentTypeFilter} onChange={e => setAgentTypeFilter(e.target.value as AgentTypeFilter)} aria-label="Filter by agent type">
                <option value="ALL">All Agents</option>
                <option value="LIVE">Live Agents</option>
                <option value="TESTING">Testing Agents</option>
              </select>
              <Button variant="ghost" onClick={() => onNavigate('activity')}>View all</Button>
            </>
          }
        >
          {loaded && activity.length === 0 ? (
            <EmptyState icon={Activity} title="No testing activity yet" hint="Runs appear here as soon as someone tests an agent." />
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <SortHeader label="Person" column="person" sort={sort} onSort={toggle} />
                    <SortHeader label="Agent" column="agent" sort={sort} onSort={toggle} />
                    <SortHeader label="When" column="when" sort={sort} onSort={toggle} />
                    <SortHeader label="Score" column="score" sort={sort} onSort={toggle} numeric />
                    <th scope="col">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {firstLoad ? <TableSkeleton columns={5} /> : rows.map(item => (
                    <tr
                      key={item.id}
                      className="clickable"
                      tabIndex={0}
                      onClick={() => onViewTestDetails(item.id)}
                      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onViewTestDetails(item.id); } }}
                      aria-label={`Open test of ${item.agent_name} by ${item.tested_by_name || 'unknown'}`}
                    >
                      <td className="cell-strong"><span className="cell-truncate" style={{ maxWidth: 140 }} title={item.tested_by_name || undefined}>{item.tested_by_name || '-'}</span></td>
                      <td>
                        <span className="cell-with-icon">
                          <Bot aria-hidden="true" />
                          <span className="cell-truncate" style={{ maxWidth: 180 }} title={item.agent_name}>{item.agent_name}</span>
                        </span>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>{formatDateTime(item.created_at)}</td>
                      <td className="num" style={{ color: scoreColor(item.trust_score), fontWeight: 600 }}>{fmtScore(item.trust_score)}%</td>
                      <td><TierBadge tier={item.tier} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Results by outcome" subtitle="All tests, grouped by certification result.">
          {firstLoad ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <span className="skeleton" style={{ height: 10 }} />
              {[0, 1, 2, 3].map(i => <span key={i} className="skeleton" style={{ height: 16 }} />)}
            </div>
          ) : kpis.total_tests === 0 ? (
            <EmptyState title="No tests yet" hint="Results are grouped here once tests run." />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="stack-bar" role="img" aria-label={distribution.map(d => `${d.name} ${d.value}`).join(', ')}>
                {distribution.filter(d => d.value > 0).map(d => <span key={d.name} style={{ flexGrow: d.value, background: d.color }} />)}
              </div>
              <div className="legend-list">
                {distribution.map(d => (
                  <div className="legend-row" key={d.name}>
                    <span className="legend-swatch" style={{ background: d.color }} aria-hidden="true" />
                    {d.name}
                    <span className="legend-value num">{d.value.toLocaleString()}</span>
                    <span className="legend-share num">{Math.round((d.value / kpis.total_tests) * 100)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>

      {(hasVolume || rankings.length > 0) && (
        <div className="dash-split">
          <Panel title="Trust score per day" subtitle="Daily average over the last 14 days. The dashed line is the certification threshold (90).">
            {hasVolume ? (
              <>
                <div style={{ marginBottom: 12 }}>
                  <ChartLegend items={[{ name: SERIES.live.name, color: SERIES.live.color }, { name: SERIES.certify.name, color: SERIES.certify.color }]} />
                </div>
                <div style={{ height: 220 }}>
                  <ScrollChart count={volume.length} axis={<PercentAxis />}>
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={volume} margin={{ top: 8, right: 12, left: 56, bottom: 0 }}>
                        <CartesianGrid vertical={false} />
                        <ReferenceLine y={90} stroke="var(--color-text-muted)" strokeDasharray="4 4" />
                        <XAxis dataKey="date" {...axisProps} interval={0} tickFormatter={ordinalDay} tick={{ ...axisProps.tick, fontSize: 11 }} />
                        <YAxis {...hiddenPercentAxis} />
                        <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--color-border-strong)', strokeWidth: 1 }} />
                        <Line dataKey={SERIES.live.key} name={SERIES.live.name} {...lineProps(SERIES.live.color)} />
                        <Line dataKey={SERIES.certify.key} name={SERIES.certify.name} {...lineProps(SERIES.certify.color)} />
                      </LineChart>
                    </ResponsiveContainer>
                  </ScrollChart>
                </div>
              </>
            ) : (
              <EmptyState title="No scores in the last 14 days" />
            )}
          </Panel>
          <Panel title="Top agents" subtitle="Highest average trust score.">
            {rankings.length === 0 ? <EmptyState title="No agents tested yet" /> : (
              <ol style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 16 }}>
                {rankings.map(a => (
                  <li key={a.agent_name}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 14, marginBottom: 6 }}>
                      <span style={{ color: 'var(--color-text)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.agent_name}>{a.agent_name}</span>
                      <span className="num" style={{ color: 'var(--color-text)', fontWeight: 600 }}>{fmtScore(a.avg_score)}%</span>
                    </div>
                    <div className="meter"><span style={{ width: `${Math.max(0, Math.min(100, a.avg_score))}%`, background: 'var(--chart-1)' }} /></div>
                  </li>
                ))}
              </ol>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
};
