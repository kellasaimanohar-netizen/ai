import React from 'react';
import { Badge } from './ui';

interface Counts {
  critical_count?: number | null;
  warning_count?: number | null;
  pass_count?: number | null;
}

/** The non-zero finding counts, most serious first. A zero count is left out. */
const parts = (c: Counts): { n: number; tone: 'critical' | 'warning' | 'pass'; label: string }[] => {
  const critical = Number(c.critical_count) || 0;
  const warnings = Number(c.warning_count) || 0;
  const passed = Number(c.pass_count) || 0;
  return [
    { n: critical, tone: 'critical' as const, label: 'critical' },
    { n: warnings, tone: 'warning' as const, label: warnings === 1 ? 'warning' : 'warnings' },
    { n: passed, tone: 'pass' as const, label: 'passed' },
  ].filter(p => p.n > 0);
};

/** "8 warnings, 18 passed", or a dash when every count is zero. */
export const findingsText = (c: Counts): string =>
  parts(c).map(p => `${p.n} ${p.label}`).join(', ') || '-';

/** The same counts as badges. */
export const FindingBadges: React.FC<{ counts: Counts; showPassed?: boolean }> = ({ counts, showPassed = true }) => {
  const shown = parts(counts).filter(p => showPassed || p.tone !== 'pass');
  if (shown.length === 0) return <span style={{ color: 'var(--color-text-muted)' }}>-</span>;
  return (
    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
      {shown.map(p => <Badge key={p.tone} tone={p.tone}>{p.n} {p.label}</Badge>)}
    </div>
  );
};
