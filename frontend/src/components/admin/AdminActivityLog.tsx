import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw, ScrollText } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { Alert, Badge, Button, EmptyState, PageHeader, Pagination, Panel, SearchInput, TableSkeleton, type Tone } from '../ui';

interface Entry {
  id: number;
  timestamp: string;
  event_type: string;
  user_id: number | null;
  user_email: string;
  user_name: string;
  user_role: string | null;
  details: string;
  status: string;
  ip_address: string | null;
  entity_type: string | null;
  entity_id: string | null;
}

const PAGE = 50;

/** Readable names for the recorded actions; anything new falls back to its code. */
const EVENT_LABELS: Record<string, string> = {
  USER_LOGIN: 'Signed in',
  LOGIN_FAILURE: 'Failed sign-in',
  PASSWORD_RESET_REQUESTED: 'Asked for a password reset',
  PASSWORD_RESET: 'Reset password',
  CERTIFY_TEST_RUN: 'Ran a CertifyAI test',
  AUDIT_RUN: 'Ran a CertifyAI test',
  LIVE_TEST_RUN: 'Ran a live test',
  LIVE_AGENT_CREATED: 'Added a live agent',
  LIVE_AGENT_UPDATED: 'Changed a live agent',
  LIVE_AGENT_DELETED: 'Removed a live agent',
  MONITOR_CREATED: 'Turned on monitoring',
  MONITOR_DELETED: 'Stopped monitoring',
  MONITOR_PAUSED: 'Paused monitoring',
  MONITOR_RESUMED: 'Resumed monitoring',
  REPORT_DOWNLOADED: 'Downloaded a report',
  ACCOUNT_CREATED: 'Created an account',
  ACCOUNT_UPDATED: 'Changed an account',
};

const STATUS_TONE: Record<string, Tone> = { SUCCESS: 'pass', WARNING: 'warning', FAILED: 'critical' };

const when = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
};

/** Everything users did, for admins: sign-ins, tests, live agents, monitors, downloads and account changes. */
export const AdminActivityLog: React.FC = () => {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [total, setTotal] = useState(0);
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [users, setUsers] = useState<{ id: number; name: string; email: string }[]>([]);
  const [userId, setUserId] = useState('');
  const [eventType, setEventType] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch('/api/admin/users')
      .then(r => (r.ok ? r.json() : { users: [] }))
      .then(d => setUsers(d.users || []))
      .catch(() => setUsers([]));
  }, []);

  // Search waits for a pause in typing
  useEffect(() => {
    const t = window.setTimeout(() => setQuery(search.trim()), 300);
    return () => window.clearTimeout(t);
  }, [search]);

  useEffect(() => setOffset(0), [userId, eventType, status, query]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    if (userId) params.set('user_id', userId);
    if (eventType) params.set('event_type', eventType);
    if (status) params.set('status', status);
    if (query) params.set('q', query);
    try {
      const res = await apiFetch(`/api/admin/activity-log?${params}`);
      if (!res.ok) throw new Error('The activity log could not be loaded.');
      const d = await res.json();
      setEntries(d.entries || []);
      setTotal(d.total || 0);
      setEventTypes(d.event_types || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The activity log could not be loaded.');
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, [userId, eventType, status, query, offset]);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = !!(userId || eventType || status || query);
  const clearFilters = () => { setUserId(''); setEventType(''); setStatus(''); setSearch(''); };

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Activity log"
        subtitle="What every user did and when: sign-ins, tests, live agents, monitors, downloads and account changes. Entries cannot be edited or deleted."
        actions={<Button icon={RefreshCw} onClick={load} loading={loading && loaded}>Refresh</Button>}
      />

      <div className="filter-bar">
        <SearchInput value={search} onChange={setSearch} placeholder="Search details, name or email" label="Search the activity log" width="auto" />
        <select className="form-input" value={userId} onChange={e => setUserId(e.target.value)} aria-label="Filter by person">
          <option value="">Everyone</option>
          {users.map(u => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
        </select>
        <select className="form-input" value={eventType} onChange={e => setEventType(e.target.value)} aria-label="Filter by action">
          <option value="">All actions</option>
          {eventTypes.map(t => <option key={t} value={t}>{EVENT_LABELS[t] || t}</option>)}
        </select>
        <select className="form-input" style={{ flexBasis: 150 }} value={status} onChange={e => setStatus(e.target.value)} aria-label="Filter by result">
          <option value="">Any result</option>
          <option value="SUCCESS">Success</option>
          <option value="WARNING">Warning</option>
          <option value="FAILED">Failed</option>
        </select>
        {filtered && <Button variant="ghost" onClick={clearFilters}>Clear filters</Button>}
      </div>

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={load}>Try again</Button>} />}

      <Panel flush>
        {loaded && !loading && entries.length === 0 ? (
          <EmptyState
            icon={ScrollText}
            title={total === 0 && !filtered ? 'No activity yet' : 'Nothing matches these filters'}
            action={filtered ? <Button size="sm" onClick={clearFilters}>Clear filters</Button> : undefined}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    {['When', 'Who', 'Action', 'Details', 'Result', 'From'].map(h => <th key={h} scope="col">{h}</th>)}
                  </tr>
                </thead>
                <tbody style={{ opacity: loading && loaded ? 0.6 : 1, transition: 'opacity 150ms' }}>
                  {!loaded ? <TableSkeleton columns={6} rows={8} /> : entries.map(e => (
                    <tr key={e.id}>
                      <td style={{ whiteSpace: 'nowrap' }}>{when(e.timestamp)}</td>
                      <td style={{ minWidth: 170 }}>
                        <div className="cell-strong">{e.user_name || '-'}</div>
                        <div className="cell-sub">{e.user_email}{e.user_role ? ` · ${e.user_role === 'ADMIN' ? 'Admin' : 'User'}` : ''}</div>
                      </td>
                      <td className="cell-strong" style={{ whiteSpace: 'nowrap' }}>{EVENT_LABELS[e.event_type] || e.event_type}</td>
                      <td style={{ minWidth: 260 }}>{e.details}</td>
                      <td><Badge tone={STATUS_TONE[e.status] || 'neutral'} dot>{e.status.charAt(0) + e.status.slice(1).toLowerCase()}</Badge></td>
                      <td className="cell-mono" style={{ whiteSpace: 'nowrap' }}>{e.ip_address || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {total > PAGE && (
              <Pagination page={Math.floor(offset / PAGE) + 1} pageSize={PAGE} total={total} onPage={p => setOffset((p - 1) * PAGE)} />
            )}
          </>
        )}
      </Panel>
    </div>
  );
};
