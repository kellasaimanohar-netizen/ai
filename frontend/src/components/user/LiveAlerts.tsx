import React, { useCallback, useEffect, useState } from 'react';
import { AlertCircle, AlertTriangle, Bell, Info, RefreshCw, X } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { Badge, Button, EmptyState, Panel, type Tone } from '../ui';

export interface LiveAlert {
  id: number;
  agent_name: string;
  kind: string;
  severity: string;
  message: string;
  created_at: string;
  read_at: string | null;
}

interface LiveAlertsProps {
  onClose?: () => void;
  isOpen?: boolean;
  /**
   * Controlled mode: pass the already-fetched list (and its refresh/mark-all actions) so this panel
   * shares one poll with the rest of the page instead of fetching on its own. Omit all three to let
   * the panel fetch and poll for itself.
   */
  alerts?: LiveAlert[];
  onRefresh?: () => Promise<unknown> | void;
  onMarkAll?: () => Promise<unknown> | void;
}

const TONE: Record<string, Tone> = {
  CRITICAL: 'critical',
  WARNING: 'warning',
  INFO: 'neutral',
};

const ICON: Record<string, React.ElementType> = { CRITICAL: AlertCircle, WARNING: AlertTriangle };

/** Icon and badge tone for a severity, as a pair so callers destructure rather than call-and-assign
 * straight into a capitalized `Icon` binding (which some tooling flags as creating a component in render). */
const alertMeta = (severity: string): [React.ElementType, Tone] => [ICON[severity] || Info, TONE[severity] || 'neutral'];

export const alertWhen = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
};

const AlertRow: React.FC<{ a: LiveAlert; showAgent?: boolean }> = ({ a, showAgent = true }) => {
  const [Icon, tone] = alertMeta(a.severity);
  return (
    <li className={`notif-item ${tone === 'neutral' ? 'info' : tone}${a.read_at ? ' read' : ''}`}>
      <Icon aria-hidden="true" />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="notif-msg">{a.message}</div>
        <div className="notif-meta">
          {(showAgent ? [a.agent_name, alertWhen(a.created_at)] : [alertWhen(a.created_at)]).filter(Boolean).join(' · ')}
          {!a.read_at && <span className="sr-only">, unread</span>}
        </div>
      </div>
      <Badge tone={tone}>{a.severity.charAt(0) + a.severity.slice(1).toLowerCase()}</Badge>
    </li>
  );
};

/** Changes found by the scheduled live tests: score drops, worse results, new critical findings, agents that stopped answering. */
export const LiveAlerts: React.FC<LiveAlertsProps> = ({ onClose, alerts: controlledAlerts, onRefresh, onMarkAll }) => {
  const controlled = controlledAlerts !== undefined;
  const [ownAlerts, setOwnAlerts] = useState<LiveAlert[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/user/live/alerts');
      if (!res.ok) throw new Error();
      const d = await res.json();
      setOwnAlerts(d.alerts || []);
      setFailed(false);
    } catch {
      setFailed(true);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (controlled) return;
    load();
    const t = window.setInterval(() => { if (!document.hidden) load(); }, 60000);
    return () => window.clearInterval(t);
  }, [controlled, load]);

  const alerts = controlled ? controlledAlerts : ownAlerts;
  const unread = alerts.filter(a => !a.read_at).length;

  const refresh = async () => {
    if (controlled) { await onRefresh?.(); return; }
    await load();
  };
  const markAll = async () => {
    if (controlled) { await onMarkAll?.(); return; }
    await apiFetch('/api/user/live/alerts/read-all', { method: 'POST' });
    await load();
  };

  return (
    <Panel
      title="Alerts"
      subtitle={unread ? `${unread} unread` : alerts.length ? 'All alerts reviewed' : 'Nothing needs attention'}
      flush
      actions={
        <>
          {unread > 0 && <Button size="sm" variant="ghost" onClick={markAll}>Mark all as read</Button>}
          <Button size="sm" icon={RefreshCw} onClick={refresh} loading={isLoading}>Refresh</Button>
          {onClose && <button type="button" className="icon-btn" onClick={onClose} aria-label="Close alerts"><X /></button>}
        </>
      }
    >
      {!controlled && failed && alerts.length === 0 ? (
        <EmptyState title="Alerts could not be loaded" action={<Button size="sm" onClick={refresh}>Try again</Button>} />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={Bell}
          title="No alerts"
          hint="Score drops, unreachable endpoints and new critical findings from your monitored agents appear here."
        />
      ) : (
        <ul style={{ listStyle: 'none' }}>
          {alerts.slice(0, 10).map(a => <AlertRow key={a.id} a={a} />)}
        </ul>
      )}
    </Panel>
  );
};

