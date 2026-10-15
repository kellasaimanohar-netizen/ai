import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, ChevronRight, X } from 'lucide-react';
import { Badge, Button, EmptyState, Segmented, TierBadge, modeLabel, scoreColor, useFocusTrap, type Tone, fmtScore } from './ui';
import { ReportDownloadMenu } from './ReportDownload';

interface Finding {
  id?: string;
  rule_id?: string;
  title?: string;
  description?: string;
  remediation?: string;
  phase?: string;
  severity?: string;
  passed?: boolean;
  suppressed?: boolean;
}

interface Props {
  test: any;
  onClose: () => void;
  onDownloadPdf?: (test: any) => void;
}

type Filter = 'ALL' | 'CRITICAL' | 'WARNING' | 'PASS';

const severityTone = (s: string): Tone => (s === 'CRITICAL' ? 'critical' : s === 'WARNING' || s === 'HIGH_UNCERTAINTY' ? 'warning' : s === 'PASS' ? 'pass' : 'neutral');
const severityLabel = (s: string) => (s === 'HIGH_UNCERTAINTY' ? 'Uncertain' : s.charAt(0) + s.slice(1).toLowerCase());

const normalize = (f: Finding) => {
  const sev = String(f.severity || (f.passed ? 'PASS' : 'INFO')).toUpperCase();
  return { ...f, sev };
};

/** Read-only view of one stored audit: summary numbers and every finding with its remediation. */
export const TestDetailModal: React.FC<Props> = ({ test, onClose, onDownloadPdf }) => {
  const findings = useMemo(() => ((test.full_result?.findings || test.findings || []) as Finding[]).map(normalize), [test]);
  const [filter, setFilter] = useState<Filter>('ALL');
  const [open, setOpen] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useFocusTrap(ref, true);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  const counts = {
    CRITICAL: findings.filter(f => f.sev === 'CRITICAL').length,
    WARNING: findings.filter(f => f.sev === 'WARNING' || f.sev === 'HIGH_UNCERTAINTY').length,
    PASS: findings.filter(f => f.sev === 'PASS').length,
  };
  const shown = findings.filter(f => filter === 'ALL' || (filter === 'WARNING' ? f.sev === 'WARNING' || f.sev === 'HIGH_UNCERTAINTY' : f.sev === filter));
  const duration = test.duration_ms ?? test.total_duration_ms;

  const summary: [string, React.ReactNode][] = [
    ['Trust score', <span key="s" style={{ color: scoreColor(test.trust_score) }}>{fmtScore(test.trust_score)}%</span>],
    ['Result', <TierBadge key="t" tier={test.tier} />],
    ['Mode', modeLabel(test.mode)],
    ['Critical', test.critical_count ?? counts.CRITICAL],
    ['Warnings', test.warning_count ?? counts.WARNING],
    ['Passed', test.pass_count ?? counts.PASS],
    ['Duration', duration ? `${(duration / 1000).toFixed(1)}s` : '-'],
  ];

  return createPortal(
    <div className="modal-layer" style={{ paddingTop: '5vh' }} onPointerDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} style={{ maxWidth: 900, maxHeight: '90vh' }}>
        <div className="modal-head" style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
          <div style={{ minWidth: 0 }}>
            <h2 id={titleId} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {test.agent_name}
              {test.version && <span className="badge mono">{test.version}</span>}
            </h2>
            <p className="cell-mono" style={{ marginTop: 4 }}>
              {test.audit_id}{test.tested_by_name ? <span style={{ fontFamily: 'var(--font-sans)' }}>, run by {test.tested_by_name}</span> : ''}
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            {onDownloadPdf && (
              <ReportDownloadMenu name={test.agent_name} onPdf={() => onDownloadPdf(test)}
                getReport={() => ({ ...test, ...(test.full_result && Object.keys(test.full_result).length ? test.full_result : {}) })} />
            )}
            <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>
          </div>
        </div>

        <div className="modal-body" style={{ paddingTop: 20 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 8, marginBottom: 24 }}>
            {summary.map(([label, value]) => (
              <div key={label} style={{ border: '1px solid var(--color-border)', borderRadius: 8, padding: '10px 12px', background: 'var(--color-surface-subtle)' }}>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{label}</div>
                <div className="num" style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text)', marginTop: 4 }}>{value}</div>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
            <h3 style={{ fontSize: 16 }}>Findings <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({findings.length})</span></h3>
            <Segmented<Filter> label="Filter findings" value={filter} onChange={v => { setFilter(v); setOpen(null); }} items={[
              { value: 'ALL', label: 'All' },
              { value: 'CRITICAL', label: `Critical (${counts.CRITICAL})` },
              { value: 'WARNING', label: `Warning (${counts.WARNING})` },
              { value: 'PASS', label: `Pass (${counts.PASS})` },
            ]} />
          </div>

          {findings.length === 0 ? (
            <EmptyState title="No findings were stored for this test" />
          ) : shown.length === 0 ? (
            <EmptyState title="No findings in this category" />
          ) : (
            <div className="accordion">
              {shown.map((f, i) => {
                const isOpen = open === i;
                return (
                  <div key={`${f.id || f.rule_id}-${i}`} className="accordion-item">
                    <button className="accordion-trigger" onClick={() => setOpen(isOpen ? null : i)} aria-expanded={isOpen}>
                      {isOpen ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
                      <Badge tone={severityTone(f.sev)}>{severityLabel(f.sev)}</Badge>
                      <span className="accordion-title">{f.title || f.id || f.rule_id}</span>
                      {f.phase && <span className="accordion-meta">{f.phase}</span>}
                    </button>
                    {isOpen && (
                      <div className="accordion-panel" style={{ padding: '12px 16px', background: 'var(--color-surface)', display: 'flex', flexDirection: 'column', gap: 10 }}>
                        {f.description && <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>{f.description}</p>}
                        {f.remediation && (
                          <div style={{ background: 'var(--color-surface-subtle)', borderLeft: '3px solid var(--color-accent)', padding: '10px 14px', borderRadius: '0 6px 6px 0' }}>
                            <strong style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--color-accent)', display: 'block', marginBottom: 4 }}>Recommended Remediation:</strong>
                            <span style={{ fontSize: 13, color: 'var(--color-text)', lineHeight: 1.5 }}>{f.remediation}</span>
                          </div>
                        )}
                        {f.suppressed && <div className="badge warning">Accepted Risk (Suppressed)</div>}
                        {(f.rule_id || f.id) && (
                          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)', marginTop: 4 }}>
                            RULE IDENTIFIER: {f.rule_id || f.id}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
};
