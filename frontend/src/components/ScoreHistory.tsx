import React, { useLayoutEffect, useRef, useState } from 'react';
import { fmtScore, tierInfo } from './ui';

export interface ScorePoint {
  score: number;
  version?: string | null;
  tier?: string | null;
  date?: string | null;
}

/** Each point is colored by its result, so a pass or fail reads at a glance. */
const TONE_COLOR: Record<string, string> = {
  pass: 'var(--color-success)',
  warning: 'var(--color-warning)',
  critical: 'var(--color-danger)',
  info: 'var(--color-info)',
  neutral: 'var(--color-text-muted)',
};
const pointColor = (p: ScorePoint) => TONE_COLOR[tierInfo(p.tier).tone] || TONE_COLOR.neutral;
const clamp = (v: number) => Math.max(0, Math.min(100, Number(v) || 0));

const shortDate = (iso?: string | null) => {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
};

const describe = (p: ScorePoint) =>
  [p.version, `${fmtScore(clamp(p.score))}%`, tierInfo(p.tier).label, shortDate(p.date)].filter(Boolean).join(' · ');

/** A small score line for table rows: a dot per test, the latest score labelled, details on hover. */
export const ScoreSparkline: React.FC<{ points: ScorePoint[] }> = ({ points }) => {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length < 2) return <span className="cell-sub" style={{ margin: 0 }}>One test</span>;

  const w = 120;
  const h = 34;
  const padX = 5;
  const step = (w - padX * 2) / (points.length - 1);
  const x = (i: number) => padX + i * step;
  const y = (v: number) => 4 + (1 - clamp(v) / 100) * (h - 8);
  const line = points.map((p, i) => `${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join(' ');
  const last = points[points.length - 1];
  const active = hover ?? points.length - 1;

  return (
    <div className="spark" onMouseLeave={() => setHover(null)}>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img"
        aria-label={`Score history: ${points.map(p => `${p.version || ''} ${fmtScore(clamp(p.score))}%`.trim()).join(', ')}`}>
        <line x1={padX} x2={w - padX} y1={y(50)} y2={y(50)} className="spark-mid" />
        <polyline points={line} fill="none" stroke="var(--color-accent)" strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" />
        {points.map((p, i) => (
          <g key={i} onMouseEnter={() => setHover(i)}>
            <circle cx={x(i)} cy={y(p.score)} r={10} fill="transparent" />
            <circle cx={x(i)} cy={y(p.score)} r={i === active ? 3.5 : 2.5} fill={pointColor(p)}
              stroke="var(--color-surface)" strokeWidth="1.25" className="spark-dot" />
          </g>
        ))}
      </svg>
      <span className="spark-value" style={{ color: pointColor(last) }}>{fmtScore(clamp(last.score))}%</span>
      {hover !== null && (
        <span className="spark-tip" role="tooltip" style={{ left: x(hover) }}>{describe(points[hover])}</span>
      )}
    </div>
  );
};

/** The full score history: every test is a labelled point, with its version underneath. */
export const ScoreHistoryChart: React.FC<{ points: ScorePoint[] }> = ({ points }) => {
  const [hover, setHover] = useState<number | null>(null);
  const [width, setWidth] = useState(0);
  const boxRef = useRef<HTMLDivElement>(null);

  // The chart fills its panel; with many tests it keeps a readable spacing and scrolls sideways.
  useLayoutEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const measure = () => setWidth(el.clientWidth);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  if (points.length === 0) return null;

  const padL = 36;
  const padR = 24;
  const slot = Math.max(56, Math.min(160, (width - padL - padR) / Math.max(1, points.length - 1)));
  const top = 26;
  const plotH = 120;
  const w = padL + padR + Math.max(1, points.length - 1) * slot;
  const h = top + plotH + 34;
  const x = (i: number) => (points.length === 1 ? padL + (w - padL - padR) / 2 : padL + i * slot);
  const y = (v: number) => top + (1 - clamp(v) / 100) * plotH;
  const line = points.map((p, i) => `${x(i)},${y(p.score)}`).join(' ');
  const area = points.length > 1 ? `${x(0)},${y(0)} ${line} ${x(points.length - 1)},${y(0)}` : '';

  return (
    <figure className="score-chart">
      <figcaption className="score-chart-head">
        <span>Score by version</span>
        <span className="score-chart-legend">
          {(['pass', 'warning', 'critical', 'neutral'] as const).map(t => (
            <span key={t}><i style={{ background: TONE_COLOR[t] }} />{t === 'pass' ? 'Certified' : t === 'warning' ? 'Conditional' : t === 'critical' ? 'Not certified' : 'Inconclusive'}</span>
          ))}
        </span>
      </figcaption>
      <div className="score-chart-scroll" ref={boxRef}>
        <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img"
          aria-label={`Score by version: ${points.map(describe).join('; ')}`}>
          {[0, 50, 100].map(v => (
            <g key={v}>
              <line x1={padL} x2={w - padR + 8} y1={y(v)} y2={y(v)} className="score-chart-grid" />
              <text x={padL - 8} y={y(v) + 4} textAnchor="end" className="score-chart-axis">{v}</text>
            </g>
          ))}
          {area && <polygon points={area} className="score-chart-area" />}
          {points.length > 1 && <polyline points={line} fill="none" stroke="var(--color-accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />}
          {points.map((p, i) => {
            const on = hover === i;
            return (
              <g key={i} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} className="score-chart-point">
                <title>{describe(p)}</title>
                <line x1={x(i)} x2={x(i)} y1={top} y2={y(0)} className="score-chart-guide" style={{ opacity: on ? 1 : 0 }} />
                <rect x={x(i) - slot / 2} y={0} width={slot} height={h} fill="transparent" />
                <circle cx={x(i)} cy={y(p.score)} r={on ? 6 : 4.5} fill={pointColor(p)} stroke="var(--color-surface)" strokeWidth="2" />
                <text x={x(i)} y={y(p.score) - 11} textAnchor="middle" className="score-chart-value" style={{ fill: on ? 'var(--color-text)' : undefined }}>
                  {fmtScore(clamp(p.score))}%
                </text>
                <text x={x(i)} y={y(0) + 18} textAnchor="middle" className="score-chart-version">{p.version || `#${i + 1}`}</text>
                <text x={x(i)} y={y(0) + 31} textAnchor="middle" className="score-chart-date">{shortDate(p.date)}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </figure>
  );
};
