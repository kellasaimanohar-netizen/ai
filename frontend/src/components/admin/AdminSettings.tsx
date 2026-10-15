import React, { useCallback, useEffect, useState } from 'react';
import { Clock, Cpu, Database, Globe, Layers, RefreshCw, Server, Tag } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { BACKEND_URL } from '../../utils/apiConfig';
import { Alert, Badge, Button, PageHeader, Panel, Stat, Toggle, type Tone } from '../ui';

interface Health {
  status: string;
  service?: string;
  version?: string;
  engine?: string;
  database?: { status: 'ok' | 'error'; latency_ms: number | null; schema_version: string | null; pending_migrations: number | null };
}

const REFRESH_SECONDS = 30;

const latencyTone = (ms: number | null): Tone => (ms === null ? 'neutral' : ms < 500 ? 'pass' : ms < 1500 ? 'warning' : 'critical');

const timeOf = (d: Date | null) => (d ? d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-');

/** Read-only system information taken from the running API. There are no editable settings yet. */
export const AdminSettings: React.FC = () => {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [latency, setLatency] = useState<number | null>(null);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [auto, setAuto] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const t0 = performance.now();
    try {
      const res = await apiFetch('/api/health');
      // 503 means the API answered but something it depends on (the database) did not; its body says what
      if (!res.ok && res.status !== 503) throw new Error('The API did not respond correctly.');
      setHealth(await res.json());
      setLatency(Math.round(performance.now() - t0));
    } catch (err) {
      setHealth(null);
      setLatency(null);
      setError(err instanceof Error ? err.message : 'The API could not be reached.');
    } finally {
      setCheckedAt(new Date());
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!auto) return;
    const t = window.setInterval(load, REFRESH_SECONDS * 1000);
    return () => window.clearInterval(t);
  }, [auto, load]);

  const up = !!health && !error;
  const healthy = up && health?.status === 'healthy';
  const address = BACKEND_URL || window.location.origin;

  const details: [React.ElementType, string, React.ReactNode][] = [
    [Tag, 'Service', health?.service || '-'],
    [Layers, 'Version', health?.version ? `v${health.version}` : '-'],
    [Cpu, 'Runtime', health?.engine || '-'],
    [Database, 'Database schema', health?.database?.schema_version
      ? `Version ${health.database.schema_version}${health.database.pending_migrations ? `, ${health.database.pending_migrations} update(s) pending` : ', up to date'}`
      : '-'],
    [Globe, 'API address', <code key="a">{address}</code>],
    [Server, 'Console mode', import.meta.env.DEV ? 'Development' : 'Production'],
  ];

  const bannerTone: Tone = loading && !health && !error ? 'info' : healthy ? 'pass' : up ? 'warning' : 'critical';
  const bannerTitle = loading && !health && !error ? 'Checking the API' : healthy ? 'All systems operational' : up ? `API reports: ${health?.status}` : 'The API is unreachable';
  const bannerText = error || (healthy ? 'The API and the database are answering normally.'
    : health?.database?.status === 'error' ? 'The API answered, but it cannot reach the database.'
    : health?.database?.pending_migrations ? `The database is missing ${health.database.pending_migrations} schema update(s). Restart the backend or run python -m database.migrate.`
    : loading && !health ? 'Contacting the health endpoint.' : 'The API answered, but did not report healthy.');

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="System"
        subtitle="Live status of the CertifyAI API this console is connected to."
        actions={
          <>
            <span className="toggle-row" style={{ gap: 10, fontSize: 13, color: 'var(--color-text-secondary)' }}>
              <Toggle checked={auto} onChange={setAuto} label={`Refresh every ${REFRESH_SECONDS} seconds`} />
              Refresh every {REFRESH_SECONDS}s
            </span>
            <Button icon={RefreshCw} onClick={load} loading={loading && !!checkedAt}>Refresh</Button>
          </>
        }
      />

      <Alert tone={bannerTone} title={bannerTitle}>{bannerText}</Alert>

      <div className="stat-grid">
        <Stat label="API status" value={up ? (health?.status === 'healthy' ? 'Healthy' : health?.status || 'Unknown') : 'Down'} tone={healthy ? 'pass' : up ? 'warning' : 'critical'} note="From the health endpoint" loading={loading && !checkedAt} />
        <Stat label="Database" value={!up ? '-' : health?.database?.status === 'ok' ? 'Connected' : 'Unreachable'}
          tone={!up ? 'neutral' : health?.database?.status === 'ok' ? 'pass' : 'critical'} loading={loading && !checkedAt}
          note={health?.database?.latency_ms != null ? `Answered in ${health.database.latency_ms} ms` : 'Checked by the API'} />
        <Stat label="Version" value={health?.version ? `v${health.version}` : '-'} note={health?.service || 'Not reported'} loading={loading && !checkedAt} />
        <Stat label="Response time" value={latency === null ? '-' : `${latency} ms`} tone={latencyTone(latency)} note="Measured from this browser" loading={loading && !checkedAt} />
        <Stat label="Last checked" value={timeOf(checkedAt)} note={auto ? `Next check in under ${REFRESH_SECONDS}s` : 'Automatic refresh is off'} loading={loading && !checkedAt} />
      </div>

      <Panel title="API details" subtitle="Reported by the health endpoint." actions={<Badge tone={healthy ? 'pass' : up ? 'warning' : 'critical'} dot>{up ? health?.status : 'unreachable'}</Badge>}>
        <dl className="detail-list">
          {details.map(([Icon, label, value]) => (
            <div key={label} className="detail-row">
              <dt><Icon size={16} aria-hidden="true" />{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      </Panel>

      <p style={{ fontSize: 13, color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Clock size={14} aria-hidden="true" />
        There are no editable system settings yet. This page only shows what the API reports.
      </p>
    </div>
  );
};
