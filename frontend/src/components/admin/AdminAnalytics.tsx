import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { BarChart3, RefreshCw } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts';
import { apiFetch } from '../../utils/apiClient';
import { ScrollChart } from '../ScrollChart';
import { ordinalDay } from '../../utils/dateLabel';
import { Alert, Button, EmptyState, PageHeader, Panel, Segmented, tierInfo, fmtScore } from '../ui';
import {
  Breakdown, ChartLegend, MeterRow, PercentAxis, PinnedAxis, SERIES, axisProps, countTicks, hiddenPercentAxis, lineProps,
} from '../charts';

const TIER_COLOR: Record<string, string> = {
  CERTIFIED: 'var(--color-success)',
  CONDITIONAL: 'var(--color-warning)',
  NOT_CERTIFIED: 'var(--color-danger)',
  FRAMEWORK_VALIDATION_ONLY: 'var(--color-info)',
};

const LEGEND = [{ name: SERIES.live.name, color: SERIES.live.color }, { name: SERIES.certify.name, color: SERIES.certify.color }];

/** Tooltip for the score chart: each series with its score and how many tests it averages. */
const ScoreTooltip: React.FC<{ active?: boolean; payload?: any[]; label?: string }> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const row = payload[0]?.payload || {};
  const rows = payload.filter(p => p.value != null);
  if (!rows.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{label}</div>
      {rows.map(p => {
        const n = row[p.dataKey === SERIES.live.key ? 'live_count' : 'certify_count'] ?? 0;
        return (
          <div className="chart-tooltip-row" key={p.dataKey}>
            <span className="legend-swatch" style={{ background: p.color }} />
            {p.name}
            <strong>{p.value}% <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({n} test{n === 1 ? '' : 's'})</span></strong>
          </div>
        );
      })}
    </div>
  );
};

const CountTooltip: React.FC<{ active?: boolean; payload?: any[]; label?: string }> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((a, p) => a + (Number(p.value) || 0), 0);
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{label}</div>
      {payload.map(p => (
        <div className="chart-tooltip-row" key={p.dataKey}>
          <span className="legend-swatch" style={{ background: p.color }} />
          {p.name}
          <strong>{p.value ?? 0}</strong>
        </div>
      ))}
      <div className="chart-tooltip-row" style={{ borderTop: '1px solid var(--color-border)', marginTop: 4, paddingTop: 4 }}>
        Total<strong>{total}</strong>
      </div>
    </div>
  );
};

export const AdminAnalytics: React.FC = () => {
  const [days, setDays] = useState<number>(30);
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(`/api/admin/analytics?days=${days}`);
      if (!res.ok) throw new Error('The analytics could not be loaded.');
      setData(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The analytics could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    load();
  }, [load]);

  const firstLoad = loading && !data;
  const volume: any[] = data?.volume_trend || [];
  const kinds = ((data?.type_distribution || []) as any[]).map(d => ({
    name: d.type === 'live' ? SERIES.live.name : SERIES.certify.name,
    value: d.count,
    color: d.type === 'live' ? SERIES.live.color : SERIES.certify.color,
  }));
  const distribution = ((data?.certification_distribution || []) as any[]).map(d => ({
    name: tierInfo(d.tier).label,
    value: d.count,
    color: TIER_COLOR[d.tier] || 'var(--color-text-muted)',
  }));
  const agentRankings: any[] = data?.agent_rankings || [];
  const userRankings: any[] = data?.user_rankings || [];
  const hasScores = volume.some(v => v.avg_score !== null && v.avg_score !== undefined);
  const ticks = useMemo(() => countTicks(Math.max(0, ...volume.map(v => (v.live_count || 0) + (v.certify_count || 0)))), [volume]);

  const chartBox = (child: React.ReactNode) => (
    <div style={{ height: 240 }}>{firstLoad ? <span className="skeleton" style={{ height: '100%' }} aria-hidden="true" /> : child}</div>
  );

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Analytics"
        subtitle="Audit volume, certification results and agent performance across the organization."
        actions={
          <>
            <Segmented<string> label="Period" value={String(days)} onChange={v => setDays(Number(v))} items={[7, 30, 90].map(d => ({ value: String(d), label: `${d} days` }))} />
            <Button icon={RefreshCw} onClick={load} loading={loading && !!data}>Refresh</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={load}>Try again</Button>} />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(420px, 100%), 1fr))', gap: 24 }}>
        <Panel title="Tests per day" subtitle={`Last ${days} days, split by test type.`}>
          {volume.some(v => v.test_count > 0) && <div style={{ marginBottom: 12 }}><ChartLegend items={LEGEND} /></div>}
          {chartBox(volume.some(v => v.test_count > 0) ? (
            <ScrollChart count={volume.length} axis={<PinnedAxis ticks={ticks} />}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={volume} margin={{ top: 8, right: 12, left: 56, bottom: 0 }} barCategoryGap="30%">
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" {...axisProps} interval={0} tickFormatter={ordinalDay} tick={{ ...axisProps.tick, fontSize: 11 }} />
                  <YAxis hide domain={[0, ticks[ticks.length - 1]]} ticks={ticks} />
                  <Tooltip content={<CountTooltip />} cursor={{ fill: 'var(--color-surface-hover)' }} />
                  <Bar dataKey="live_count" name={SERIES.live.name} stackId="t" fill={SERIES.live.color} stroke="var(--color-surface)" strokeWidth={1} maxBarSize={28} isAnimationActive={false} />
                  <Bar dataKey="certify_count" name={SERIES.certify.name} stackId="t" fill={SERIES.certify.color} stroke="var(--color-surface)" strokeWidth={1} radius={[4, 4, 0, 0]} maxBarSize={28} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </ScrollChart>
          ) : <EmptyState icon={BarChart3} title="No tests in this period" hint="Try a longer period." />)}
        </Panel>

        <Panel title="Average trust score" subtitle="Daily average. The dashed line is the certification threshold (90).">
          {hasScores && <div style={{ marginBottom: 12 }}><ChartLegend items={LEGEND} /></div>}
          {chartBox(hasScores ? (
            <ScrollChart count={volume.length} axis={<PercentAxis />}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={volume} margin={{ top: 8, right: 12, left: 56, bottom: 0 }}>
                  <CartesianGrid vertical={false} />
                  <ReferenceLine y={90} stroke="var(--color-text-muted)" strokeDasharray="4 4" />
                  <XAxis dataKey="date" {...axisProps} interval={0} tickFormatter={ordinalDay} tick={{ ...axisProps.tick, fontSize: 11 }} />
                  <YAxis {...hiddenPercentAxis} />
                  <Tooltip content={<ScoreTooltip />} cursor={{ stroke: 'var(--color-border-strong)', strokeWidth: 1 }} />
                  <Line dataKey={SERIES.live.key} name={SERIES.live.name} {...lineProps(SERIES.live.color)} />
                  <Line dataKey={SERIES.certify.key} name={SERIES.certify.name} {...lineProps(SERIES.certify.color)} />
                </LineChart>
              </ResponsiveContainer>
            </ScrollChart>
          ) : <EmptyState icon={BarChart3} title="No scores in this period" hint="Try a longer period." />)}
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(320px, 100%), 1fr))', gap: 24, alignItems: 'start' }}>
        <Panel title="Results by outcome" subtitle={`Tests in the last ${days} days.`}>
          {firstLoad ? <span className="skeleton" style={{ height: 160 }} /> : distribution.length === 0 ? <EmptyState title="No results yet" /> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <div>
                <div className="field-label" style={{ marginBottom: 8 }}>Certification result</div>
                <Breakdown items={distribution} label="Certification result" />
              </div>
              {kinds.length > 0 && (
                <div>
                  <div className="field-label" style={{ marginBottom: 8 }}>Test type</div>
                  <Breakdown items={kinds} label="Test type" />
                </div>
              )}
            </div>
          )}
        </Panel>

        <Panel title="Agents by average score" subtitle="Highest first.">
          {firstLoad ? <span className="skeleton" style={{ height: 160 }} /> : agentRankings.length === 0 ? <EmptyState title="No agents tested yet" /> : (
            <ol style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {agentRankings.map(a => (
                <MeterRow key={a.agent_name} label={a.agent_name} value={a.avg_score} meta={`${fmtScore(a.avg_score)}% · ${a.test_count} test${a.test_count === 1 ? '' : 's'}`} />
              ))}
            </ol>
          )}
        </Panel>

        <Panel title="People by testing volume" subtitle="Bar shows each person's average score.">
          {firstLoad ? <span className="skeleton" style={{ height: 160 }} /> : userRankings.length === 0 ? <EmptyState title="No tests yet" /> : (
            <ol style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {userRankings.map(u => (
                <MeterRow key={u.email || u.name} label={u.name} sub={u.email} value={u.avg_score} meta={`${u.test_count} test${u.test_count === 1 ? '' : 's'} · avg ${fmtScore(u.avg_score)}%`} />
              ))}
            </ol>
          )}
        </Panel>
      </div>
    </div>
  );
};
