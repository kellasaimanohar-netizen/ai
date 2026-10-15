import React, { useCallback, useEffect, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Clock, Pause, Play, RefreshCw, Trash2, XCircle } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { Button, EmptyState, Modal, TableSkeleton, TierBadge, scoreColor, type Tone, fmtScore } from '../ui';
import { findingsText } from '../FindingCounts';

interface Issue { severity: 'CRITICAL' | 'WARNING' | 'INFO'; title: string; detail: string }
interface Health {
  status: 'UP' | 'DEGRADED' | 'DOWN';
  checked_at: string;
  latency_ms: number | null;
  http_status: number | null;
  cert_days: number | null;
  issues: Issue[];
}
interface Monitor {
  id: number;
  name: string;
  active: number;
  health_minutes: number;
  frequency_minutes: number;
  health: Health | null;
  uptime_24h: number | null;
  uptime_7d: number | null;
  avg_latency_ms: number | null;
  history: { at: string; status: string }[];
  last_run_at: string | null;
  last_score: number | null;
  last_tier: string | null;
  owner?: { name: string; email: string } | null;
  live_agent_id?: number | null;
  request?: { openapi_url?: string; endpoint_url?: string; target_env?: string };
}

export const STATUS: Record<string, { label: string; tone: Tone; color: string }> = {
  UP: { label: 'Online', tone: 'pass', color: 'var(--color-pass)' },
  DEGRADED: { label: 'Needs attention', tone: 'warning', color: 'var(--color-warning)' },
  DOWN: { label: 'Down', tone: 'critical', color: 'var(--color-critical)' },
};

export const ago = (iso?: string | null) => {
  if (!iso) return 'not yet';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};

const every = (m: number) => (m % 1440 === 0 ? `${m / 1440} day` : m % 60 === 0 ? `${m / 60} h` : `${m} min`);
export const pct = (v: number | null) => (v === null ? '-' : `${v}%`);

export type { Monitor };

export interface Monitors {
  monitors: Monitor[] | null;
  failed: boolean;
  busy: number | null;
  load: () => void;
  checkNow: (id: number) => void;
  setActive: (id: number, active: boolean) => void;
  remove: (m: Monitor) => void;
}

/** Loads every monitor from the server and refreshes it every 30 seconds. */
export const useMonitors = (): Monitors => {
  const [monitors, setMonitors] = useState<Monitor[] | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch('/api/user/live/monitors');
      if (!res.ok) throw new Error('bad status');
      setMonitors((await res.json()).monitors || []);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    load();
    const t = window.setInterval(load, 30000);
    return () => window.clearInterval(t);
  }, [load]);

  const act = async (id: number, fn: () => Promise<Response>) => {
    setBusy(id);
    try {
      await fn();
    } finally {
      setBusy(null);
      load();
    }
  };
  const checkNow = (id: number) => act(id, () => apiFetch(`/api/user/live/monitors/${id}/check-now`, { method: 'POST' }));
  const setActive = (id: number, active: boolean) => act(id, () => apiFetch(`/api/user/live/schedules/${id}/active?active=${active}`, { method: 'POST' }));
  /** Deletes without asking; callers confirm first (MonitorDetail shows a dialog). */
  const remove = (m: Monitor) => act(m.id, () => apiFetch(`/api/user/live/schedules/${m.id}`, { method: 'DELETE' }));

  return { monitors, failed, busy, load, checkNow, setActive, remove };
};

/** Full details of one monitored agent: status, uptime, recent checks, problems and controls. */
export const MonitorDetail: React.FC<{ m: Monitor; mon: Monitors; readOnly?: boolean }> = ({ m, mon, readOnly }) => {
  const { busy, checkNow, setActive, remove } = mon;
  const h = m.health;
  const st = !m.active ? { label: 'Paused', tone: 'neutral' as Tone, color: 'var(--text-muted)' } : h ? (STATUS[h.status] ?? { label: h.status, tone: 'neutral' as Tone, color: 'var(--text-muted)' }) : { label: 'Checking', tone: 'neutral' as Tone, color: 'var(--text-muted)' };
  const issues = h?.issues || [];
  const [confirming, setConfirming] = useState(false);
  return (
    <div className="monitor-card">
      <div className="monitor-head">
        <span className="status-text"><span className="status-dot" style={{ background: st.color }} aria-hidden="true" />{st.label}</span>
        {h && <span className="monitor-sub" style={{ margin: 0 }}>Checked {ago(h.checked_at)}</span>}
      </div>
      <div className="monitor-sub">Checked every {every(m.health_minutes || 5)}{m.frequency_minutes ? `, full test every ${every(m.frequency_minutes)}` : ''}</div>

      <div className="monitor-stats">
        <div><span>Uptime 24 h</span><strong>{pct(m.uptime_24h)}</strong></div>
        <div><span>Uptime 7 days</span><strong>{pct(m.uptime_7d)}</strong></div>
        <div><span>Answer time</span><strong>{h?.latency_ms != null ? `${h.latency_ms} ms` : '-'}</strong></div>
        <div><span>Last full test</span><strong>{m.last_score != null ? `${fmtScore(m.last_score)}%` : '-'}</strong></div>
      </div>

      <div className="monitor-bars" role="img" aria-label={`Recent checks: ${m.history.filter(c => c.status === 'UP').length} of ${m.history.length} online`}>
        {m.history.length === 0 && <span className="monitor-sub">No checks yet.</span>}
        {m.history.map((c, i) => (
          <span key={i} title={`${STATUS[c.status]?.label || c.status}, ${ago(c.at)}`} style={{ background: STATUS[c.status]?.color || 'var(--border-strong)' }} />
        ))}
      </div>

      <div className="monitor-issues">
        {!h ? (
          <div className="monitor-sub">The first check is running.</div>
        ) : issues.length === 0 ? (
          <div className="monitor-ok"><CheckCircle2 size={16} aria-hidden="true" />No problems found.</div>
        ) : issues.map((i, n) => (
          <div key={n} className={`monitor-issue ${i.severity.toLowerCase()}`}>
            {i.severity === 'CRITICAL' ? <XCircle size={15} /> : i.severity === 'WARNING' ? <AlertTriangle size={15} /> : <Activity size={15} />}
            <div>
              <strong>{i.title}</strong>
              {i.detail && <span>{i.detail}</span>}
            </div>
          </div>
        ))}
        {h?.cert_days != null && h.cert_days >= 14 && <div className="monitor-sub">Security certificate: {h.cert_days} days left.</div>}
        {m.last_tier && <div className="monitor-sub" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>Last full test: <TierBadge tier={m.last_tier} /> {ago(m.last_run_at)}</div>}
      </div>

      {!readOnly && (
        <div className="monitor-actions">
          <Button size="sm" icon={RefreshCw} onClick={() => checkNow(m.id)} loading={busy === m.id}>Check now</Button>
          <Button size="sm" icon={m.active ? Pause : Play} onClick={() => setActive(m.id, !m.active)} disabled={busy === m.id}>{m.active ? 'Pause' : 'Resume'}</Button>
          <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setConfirming(true)} disabled={busy === m.id} style={{ marginLeft: 'auto' }}>Stop monitoring</Button>
        </div>
      )}
      <Modal
        open={confirming}
        onClose={() => setConfirming(false)}
        title={`Stop monitoring ${m.name}?`}
        description="Health checks and scheduled tests stop, and its health history is removed. Past test results stay in your history."
        footer={
          <>
            <Button onClick={() => setConfirming(false)}>Cancel</Button>
            <Button variant="danger" onClick={() => { setConfirming(false); remove(m); }}>Stop monitoring</Button>
          </>
        }
      />
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* Test history                                                        */
/* ------------------------------------------------------------------ */

export interface LiveTestRun {
  id: number;
  audit_id: string;
  agent_name: string;
  mode: string;
  trust_score: number;
  tier: string;
  critical_count: number;
  warning_count: number;
  pass_count: number;
  duration_ms: number;
  created_at: string;
}

const formatDateTime = (iso?: string) => {
  const d = new Date(iso || '');
  if (!iso || Number.isNaN(d.getTime())) return '-';
  return `${d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}, ${d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`;
};

const formatRunDuration = (ms?: number) => {
  if (!ms) return '-';
  const s = ms / 1000;
  return s >= 60 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${s.toFixed(1)}s`;
};

/**
 * Loads the real, most recent test runs of one live agent from the server — the same runs that make
 * up its score history, whether started by hand or by the scheduled monitor. Nothing here is sample
 * data: an agent with no runs yet shows as empty rather than placeholder rows.
 */
export function useAgentHistory(liveAgentId: number | null | undefined, limit = 10) {
  const [history, setHistory] = useState<LiveTestRun[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (liveAgentId == null) return;
    setLoading(true);
    try {
      const res = await apiFetch(`/api/user/live/agents/${liveAgentId}/history?limit=${limit}`);
      if (!res.ok) throw new Error('bad status');
      setHistory((await res.json()).history || []);
      setFailed(false);
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, [liveAgentId, limit]);

  useEffect(() => {
    setHistory(null);
    load();
  }, [load]);

  return { history, failed, loading, reload: load };
}

/** The agent's last 10 real test runs, fetched live from the server. Shown to the owning user and,
 * read-only, to admins — same data, same endpoint, same component either way. */
export const AgentHistory: React.FC<{ liveAgentId: number | null | undefined; limit?: number }> = ({ liveAgentId, limit = 10 }) => {
  const { history, failed, loading, reload } = useAgentHistory(liveAgentId, limit);

  return (
    <div className="monitor-card">
      <div className="monitor-head">
        <span className="status-text"><Clock size={15} aria-hidden="true" />Recent tests</span>
        <Button size="sm" variant="ghost" icon={RefreshCw} onClick={reload} loading={loading}>Refresh</Button>
      </div>
      <div className="monitor-sub">The last {limit} real test runs of this agent, newest first.</div>

      {liveAgentId == null ? (
        <EmptyState title="Not saved as a live agent yet" hint="Test history appears once this agent has a saved record." />
      ) : loading && history === null ? (
        <div className="table-wrap">
          <table className="data-table nested-table">
            <tbody><TableSkeleton columns={5} rows={3} /></tbody>
          </table>
        </div>
      ) : failed && (history === null || history.length === 0) ? (
        <EmptyState title="The test history could not be loaded" action={<Button size="sm" onClick={reload}>Try again</Button>} />
      ) : !history || history.length === 0 ? (
        <EmptyState title="No tests run yet" hint="Every manual test and scheduled full test appears here." />
      ) : (
        <div className="table-wrap" style={{ border: '1px solid var(--color-border)', borderRadius: 8, background: 'var(--color-surface)' }}>
          <table className="data-table nested-table">
            <thead>
              <tr>
                <th scope="col">Tested</th>
                <th scope="col" className="num">Score</th>
                <th scope="col">Result</th>
                <th scope="col">Findings</th>
                <th scope="col" className="num">Duration</th>
                <th scope="col">Audit ID</th>
              </tr>
            </thead>
            <tbody>
              {history.map(run => (
                <tr key={run.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatDateTime(run.created_at)}</td>
                  <td className="num" style={{ fontWeight: 600, color: scoreColor(run.trust_score) }}>{Math.round(run.trust_score * 10) / 10}%</td>
                  <td><TierBadge tier={run.tier} /></td>
                  <td style={{ whiteSpace: 'nowrap' }}>{findingsText(run)}</td>
                  <td className="num">{formatRunDuration(run.duration_ms)}</td>
                  <td className="cell-mono" style={{ whiteSpace: 'nowrap' }}>{run.audit_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
