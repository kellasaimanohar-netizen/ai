import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Radio, RefreshCw } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { Alert, Button, EmptyState, PageHeader, Panel, SearchInput, StatusText, TableSkeleton, TierBadge } from '../ui';
import { AgentHistory, MonitorDetail, STATUS, ago, pct, useMonitors, type Monitor } from '../user/LiveMonitors';

interface AdminLiveAgent {
  id: number;
  name: string;
  openapi_url: string;
  target_env: string;
  owner_name: string;
  owner_email: string;
  last_result: { trust_score?: number; tier?: string } | null;
  last_tested_at: string | null;
  last_error: string | null;
}

/** One row: a user's live agent, its monitor when it has one, or a monitor from before live agents were stored. */
interface Row {
  key: string;
  liveAgentId: number | null;
  name: string;
  url: string;
  env: string | null;
  ownerName: string;
  ownerEmail: string;
  score: number | null;
  tier: string | null;
  testedAt: string | null;
  monitor: Monitor | null;
}

const MUTED = 'var(--color-text-muted)';

/** Read-only view of every user's live agents. Admins watch here; only the owning user tests or changes an agent. */
export const AdminLiveAgents: React.FC = () => {
  const mon = useMonitors();
  const [agents, setAgents] = useState<AdminLiveAgent[] | null>(null);
  const [agentsFailed, setAgentsFailed] = useState(false);
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState<string | null>(null);

  const loadAgents = useCallback(async () => {
    try {
      const res = await apiFetch('/api/user/live/agents');
      if (!res.ok) throw new Error('bad status');
      setAgents((await res.json()).agents || []);
      setAgentsFailed(false);
    } catch {
      setAgentsFailed(true);
    }
  }, []);

  useEffect(() => {
    loadAgents();
  }, [loadAgents]);

  const rows = useMemo<Row[]>(() => {
    const monitors = mon.monitors || [];
    const fromAgents: Row[] = (agents || []).map(a => ({
      key: `agent-${a.id}`,
      liveAgentId: a.id,
      name: a.name,
      url: a.openapi_url,
      env: a.target_env,
      ownerName: a.owner_name,
      ownerEmail: a.owner_email,
      score: a.last_result?.trust_score ?? null,
      tier: a.last_result?.tier ?? null,
      testedAt: a.last_tested_at,
      monitor: monitors.find(m => m.live_agent_id === a.id) || null,
    }));
    const unlinked: Row[] = monitors.filter(m => !m.live_agent_id).map(m => ({
      key: `monitor-${m.id}`,
      liveAgentId: null,
      name: m.name,
      url: m.request?.openapi_url || m.request?.endpoint_url || '',
      env: m.request?.target_env || null,
      ownerName: m.owner?.name || '-',
      ownerEmail: m.owner?.email || '',
      score: m.last_score,
      tier: m.last_tier,
      testedAt: m.last_run_at,
      monitor: m,
    }));
    const q = search.trim().toLowerCase();
    return [...fromAgents, ...unlinked].filter(r => !q
      || r.name.toLowerCase().includes(q)
      || r.ownerName.toLowerCase().includes(q)
      || r.ownerEmail.toLowerCase().includes(q)
      || r.url.toLowerCase().includes(q));
  }, [agents, mon.monitors, search]);

  const loading = (agents === null && !agentsFailed) || (mon.monitors === null && !mon.failed);
  const refresh = () => {
    loadAgents();
    mon.load();
  };

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Live agents"
        subtitle="Every user's live agents, with their health and latest test. Only the owning user can test or change an agent."
        actions={
          <>
            <SearchInput value={search} onChange={setSearch} placeholder="Search agent or user" label="Search live agents" />
            <Button icon={RefreshCw} onClick={refresh} loading={loading && (agents !== null || mon.monitors !== null)}>Refresh</Button>
          </>
        }
      />

      {(agentsFailed || mon.failed) && (
        <Alert tone="critical" title="The live agents could not be loaded" action={<Button size="sm" onClick={refresh}>Try again</Button>}>
          Some rows may be missing until the next successful refresh.
        </Alert>
      )}

      <Panel flush>
        {!loading && rows.length === 0 ? (
          <EmptyState
            icon={Radio}
            title={search.trim() ? 'No live agents match your search' : 'No live agents yet'}
            hint={search.trim() ? undefined : 'An agent appears here when a user adds it on their Live agents page.'}
            action={search.trim() ? <Button size="sm" onClick={() => setSearch('')}>Clear search</Button> : undefined}
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Agent</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="num">Uptime 24 h</th>
                  <th scope="col" className="num">Answer time</th>
                  <th scope="col">Last test</th>
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {loading ? <TableSkeleton columns={7} /> : rows.map(r => {
                  const m = r.monitor;
                  const h = m?.health;
                  const st = !m ? { label: 'Not monitored', color: MUTED }
                    : !m.active ? { label: 'Paused', color: MUTED }
                    : h ? (STATUS[h.status] ?? { label: h.status, color: MUTED })
                    : { label: 'Checking', color: MUTED };
                  const isOpen = open === r.key;
                  return (
                    <React.Fragment key={r.key}>
                      <tr className={isOpen ? 'row-open' : undefined}>
                        <td style={{ minWidth: 220 }}>
                          <div className="cell-strong">{r.name}</div>
                          <div className="cell-mono" style={{ marginTop: 2 }}>
                            {r.url.replace(/^https?:\/\//, '')}{r.env ? ` · ${r.env}` : ''}
                          </div>
                        </td>
                        <td>
                          <div>{r.ownerName}</div>
                          {r.ownerEmail && <div className="cell-sub">{r.ownerEmail}</div>}
                        </td>
                        <td>
                          <StatusText color={st.color}>{st.label}</StatusText>
                          {m && <div className="cell-sub">Checked {ago(h?.checked_at)}</div>}
                        </td>
                        <td className="num">{m ? pct(m.uptime_24h) : '-'}</td>
                        <td className="num">{h?.latency_ms != null ? `${h.latency_ms} ms` : '-'}</td>
                        <td>
                          {r.score != null ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span className="num cell-strong">{Math.round(r.score * 10) / 10}%</span>
                              {r.tier && <TierBadge tier={r.tier} />}
                            </div>
                          ) : 'Not tested'}
                          {r.testedAt && <div className="cell-sub">{ago(r.testedAt)}</div>}
                        </td>
                        <td className="cell-actions">
                          <Button size="sm" variant="ghost" icon={isOpen ? ChevronDown : ChevronRight} onClick={() => setOpen(isOpen ? null : r.key)} aria-expanded={isOpen}>
                            Details
                          </Button>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="row-detail">
                          <td colSpan={7}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                              <AgentHistory liveAgentId={r.liveAgentId} />
                              {m && <MonitorDetail m={m} mon={mon} readOnly />}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
};
