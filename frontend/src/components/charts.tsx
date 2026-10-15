import React from 'react';
import { Line, LineChart, ResponsiveContainer, XAxis, YAxis } from 'recharts';

/**
 * Chart conventions shared by every Recharts chart:
 * hairline solid grid, muted axis text, 2px lines, 8px markers with a surface ring,
 * series colors from --chart-1 / --chart-2, text always in text colors (never the series color).
 */

export const SERIES = {
  live: { key: 'live_score', name: 'Live agents', color: 'var(--chart-1)' },
  certify: { key: 'certify_score', name: 'Certify agents', color: 'var(--chart-2)' },
} as const;

export const axisProps = {
  stroke: 'var(--chart-grid)',
  tick: { fill: 'var(--chart-axis)', fontSize: 12 },
  tickLine: false,
  axisLine: false,
} as const;

export const lineProps = (color: string) => ({
  type: 'monotone' as const,
  stroke: color,
  strokeWidth: 2,
  dot: { r: 4, fill: color, stroke: 'var(--color-surface)', strokeWidth: 2 },
  activeDot: { r: 5, fill: color, stroke: 'var(--color-surface)', strokeWidth: 2 },
  connectNulls: true,
  isAnimationActive: false,
});

interface TooltipEntry { name?: string | number; value?: number | string | null; color?: string; dataKey?: string | number }

/** Recharts tooltip content in the design system's style. */
export const ChartTooltip: React.FC<{
  active?: boolean;
  payload?: TooltipEntry[];
  label?: string | number;
  labelFormatter?: (l: string) => string;
  unit?: string;
}> = ({ active, payload, label, labelFormatter, unit = '%' }) => {
  if (!active || !payload || payload.length === 0) return null;
  const rows = payload.filter(p => p.value !== null && p.value !== undefined);
  if (rows.length === 0) return null;
  return (
    <div className="chart-tooltip">
      {label !== undefined && <div className="chart-tooltip-title">{labelFormatter ? labelFormatter(String(label)) : label}</div>}
      {rows.map(p => (
        <div className="chart-tooltip-row" key={String(p.dataKey ?? p.name)}>
          <span className="legend-swatch" style={{ background: p.color }} />
          {p.name}
          <strong>{p.value}{unit}</strong>
        </div>
      ))}
    </div>
  );
};

export const ChartLegend: React.FC<{ items: { name: string; color: string }[]; extra?: React.ReactNode }> = ({ items, extra }) => (
  <div className="chart-legend">
    {items.map(i => (
      <span key={i.name}><i style={{ background: i.color }} aria-hidden="true" />{i.name}</span>
    ))}
    {extra}
  </div>
);

type TrendRow = { score?: number | null; avg_score?: number | null; live_score?: number | null; certify_score?: number | null };

/**
 * Change in the average daily score between the last 7 days and the 7 days before, from a daily
 * trend series in date order. The API appends `padDays` empty future days to its trends, which are
 * dropped first. Returns null when either window has no scored days, so no trend is invented.
 */
export function weekOverWeek(rows: TrendRow[], padDays = 2): number | null {
  const past = padDays > 0 ? rows.slice(0, -padDays) : rows;
  const dayScore = (r: TrendRow) => {
    if (typeof r.score === 'number') return r.score;
    if (typeof r.avg_score === 'number') return r.avg_score;
    const vals = [r.live_score, r.certify_score].filter((v): v is number => typeof v === 'number');
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
  };
  const avg = (list: TrendRow[]) => {
    const vals = list.map(dayScore).filter((v): v is number => v !== null);
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
  };
  const recent = avg(past.slice(-7));
  const prior = avg(past.slice(-14, -7));
  if (recent === null || prior === null) return null;
  return Math.round(recent - prior);
}

const PERCENT_TICKS = [0, 25, 50, 75, 90, 100];
const AXIS_DATA = [{ x: 0 }, { x: 1 }];

/** A 0-100% y-axis drawn on its own, pinned beside a scrolling chart. Margins match the charts that use it. */
export const PercentAxis: React.FC = () => (
  <ResponsiveContainer width="100%" height="100%">
    <LineChart data={AXIS_DATA} margin={{ top: 8, right: 0, left: 0, bottom: 0 }}>
      <XAxis dataKey="x" hide />
      <YAxis domain={[0, 100]} ticks={PERCENT_TICKS} {...axisProps} tickFormatter={v => `${v}%`} width={48} />
      {/* Recharts only draws axes for a chart with a series, so this one is invisible */}
      <Line dataKey="x" stroke="transparent" dot={false} isAnimationActive={false} />
    </LineChart>
  </ResponsiveContainer>
);

/** Props for the hidden y-axis of a chart whose visible axis is a pinned PercentAxis. */
export const hiddenPercentAxis = { domain: [0, 100] as [number, number], ticks: PERCENT_TICKS, hide: true };

/** Rounded axis ticks for a count chart: 0 up to a tidy top value, about four steps. */
export function countTicks(max: number): number[] {
  const top = Math.max(1, max);
  const raw = top / 4;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = Math.max(1, [1, 2, 5, 10].map(m => m * mag).find(s => s >= raw) || mag * 10);
  const ticks: number[] = [];
  for (let v = 0; v < top + step; v += step) ticks.push(Math.round(v));
  return ticks;
}

/** A y-axis drawn on its own for any tick list, pinned beside a scrolling chart. */
export const PinnedAxis: React.FC<{ ticks: number[]; format?: (v: number) => string }> = ({ ticks, format }) => (
  <ResponsiveContainer width="100%" height="100%">
    <LineChart data={[{ x: 0, y: ticks[0] }, { x: 1, y: ticks[ticks.length - 1] }]} margin={{ top: 8, right: 0, left: 0, bottom: 0 }}>
      <XAxis dataKey="x" hide />
      <YAxis domain={[ticks[0], ticks[ticks.length - 1]]} ticks={ticks} {...axisProps} tickFormatter={format} width={48} allowDecimals={false} />
      <Line dataKey="y" stroke="transparent" dot={false} isAnimationActive={false} />
    </LineChart>
  </ResponsiveContainer>
);

/** Single-series horizontal bar row used for rankings. */
export const MeterRow: React.FC<{ label: string; sub?: string; value: number; meta: string; color?: string }> = ({ label, sub, value, meta, color = 'var(--chart-1)' }) => (
  <li style={{ listStyle: 'none' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 12, marginBottom: 6 }}>
      <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 14, fontWeight: 500, color: 'var(--color-text)' }} title={sub ? `${label} ${sub}` : label}>
        {label}{sub && <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}> {sub}</span>}
      </span>
      <span className="num" style={{ whiteSpace: 'nowrap', fontSize: 12, color: 'var(--color-text-secondary)' }}>{meta}</span>
    </div>
    <div className="meter"><span style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: color }} /></div>
  </li>
);

/** Part-to-whole bar plus a legend list with counts and shares. */
export const Breakdown: React.FC<{ items: { name: string; value: number; color: string }[]; label: string }> = ({ items, label }) => {
  const total = items.reduce((a, b) => a + b.value, 0);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="stack-bar" role="img" aria-label={`${label}: ${items.map(i => `${i.name} ${i.value}`).join(', ')}`}>
        {items.filter(i => i.value > 0).map(i => <span key={i.name} style={{ flexGrow: i.value, background: i.color }} />)}
      </div>
      <div className="legend-list">
        {items.map(i => (
          <div className="legend-row" key={i.name}>
            <span className="legend-swatch" style={{ background: i.color }} aria-hidden="true" />
            {i.name}
            <span className="legend-value num">{i.value.toLocaleString()}</span>
            <span className="legend-share num">{total ? Math.round((i.value / total) * 100) : 0}%</span>
          </div>
        ))}
      </div>
    </div>
  );
};
