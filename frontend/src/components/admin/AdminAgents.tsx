import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Bot, ChevronDown, ChevronRight, RefreshCw } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { Alert, Badge, Button, EmptyState, PageHeader, Panel, SearchInput, Segmented, SortHeader, TableSkeleton, TierBadge, useSort, fmtScore } from '../ui';
import { findingsText } from '../FindingCounts';
import { ScoreSparkline } from '../ScoreHistory';

const formatDate = (iso?: string | null) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
};

const findings = (v: any) => findingsText(v);

const delta = (d: unknown) => (typeof d === 'number' && d !== 0 ? (
  <span style={{ marginLeft: 8, fontSize: 12, color: d > 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>{d > 0 ? `+${fmtScore(d)}` : fmtScore(d)}</span>
) : null);

type SortKey = 'name' | 'score' | 'tested';
type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';

export const AdminAgents: React.FC = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/admin/agents');
      if (!res.ok) throw new Error('The agent fleet could not be loaded.');
      setAgents((await res.json()).agents || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The agent fleet could not be loaded.');
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter(a => {
      const versions = a.version_progression || a.versions || [];
      const latestMode = versions.length ? (versions[versions.length - 1].mode || '') : (a.mode || '');
      const isLive = latestMode === 'live_probe' || a.is_live || (a.name || '').toLowerCase().includes('live');
      if (agentTypeFilter === 'LIVE' && !isLive) return false;
      if (agentTypeFilter === 'TESTING' && isLive) return false;

      return !q || (a.name || '').toLowerCase().includes(q) || (a.description || '').toLowerCase().includes(q);
    });
  }, [agents, search, agentTypeFilter]);

  const versionsOf = (ag: any): any[] => ag.version_progression || ag.versions || [];
  const { sorted, sort, toggle } = useSort<any, SortKey>(filtered, {
    name: a => a.name,
    score: a => { const v = versionsOf(a); return v.length ? Number(v[v.length - 1].score) : null; },
    tested: a => { const v = versionsOf(a); const t = new Date(a.last_tested || v[v.length - 1]?.created_at || '').getTime(); return Number.isNaN(t) ? null : t; },
  }, { key: 'tested', dir: 'desc' });

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Agent fleet"
        subtitle="Every agent in the organization with its latest result and version history."
        actions={
          <>
            <Segmented<AgentTypeFilter> label="Agent Type" value={agentTypeFilter} onChange={setAgentTypeFilter} items={[
              { value: 'ALL', label: 'All Agents' },
              { value: 'LIVE', label: 'Live Agents' },
              { value: 'TESTING', label: 'Testing Agents' },
            ]} />
            <SearchInput value={search} onChange={setSearch} placeholder="Search agents" width={220} />
            <Button icon={RefreshCw} onClick={load} loading={loading && loaded}>Refresh</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={load}>Try again</Button>} />}

      <Panel flush>
        {loaded && filtered.length === 0 ? (
          <EmptyState
            icon={Bot}
            title={agents.length === 0 ? 'No agents yet' : 'No agents match your search'}
            hint={agents.length === 0 ? 'Agents appear here after their first test.' : undefined}
            action={agents.length > 0 ? <Button size="sm" onClick={() => setSearch('')}>Clear search</Button> : undefined}
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <SortHeader label="Agent" column="name" sort={sort} onSort={toggle} />
                  <SortHeader label="Latest result" column="score" sort={sort} onSort={toggle} />
                  <th scope="col">Findings</th>
                  <th scope="col">History</th>
                  <SortHeader label="Last tested" column="tested" sort={sort} onSort={toggle} />
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {!loaded ? <TableSkeleton columns={6} /> : sorted.map(ag => {
                  const versions = versionsOf(ag);
                  const tested = versions.length > 0;
                  const latest = versions[versions.length - 1];
                  const isOpen = open === ag.name;
                  return (
                    <React.Fragment key={ag.id || ag.name}>
                      <tr className={isOpen ? 'row-open' : undefined}>
                        <td style={{ minWidth: 220 }}>
                          <div className="cell-with-icon">
                            <Bot aria-hidden="true" />
                            <div style={{ minWidth: 0 }}>
                              <div className="cell-strong cell-truncate" title={ag.name}>{ag.name}</div>
                              <div className="cell-sub">{versions.length} test{versions.length === 1 ? '' : 's'}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          {tested ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                              <span className="num cell-strong">{fmtScore(latest.score)}%</span>
                              {delta(latest.score_delta)}
                              <TierBadge tier={latest.tier || latest.status} />
                              {latest.version && <span className="badge mono">{latest.version}</span>}
                            </div>
                          ) : <Badge>Not tested</Badge>}
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>{tested ? findings(latest) : '-'}</td>
                        <td>{tested ? <ScoreSparkline points={versions.map((v: any) => ({ score: Number(v.score) || 0, version: v.version, tier: v.tier || v.status, date: v.created_at }))} /> : '-'}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          {tested ? (
                            <>
                              <div>{formatDate(ag.last_tested || latest.created_at)}</div>
                              {ag.last_tested_by && <div className="cell-sub">by {ag.last_tested_by}</div>}
                            </>
                          ) : '-'}
                        </td>
                        <td className="cell-actions">
                          {tested && (
                            <Button size="sm" variant="ghost" icon={isOpen ? ChevronDown : ChevronRight} onClick={() => setOpen(isOpen ? null : ag.name)} aria-expanded={isOpen}>
                              Versions
                            </Button>
                          )}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="row-detail">
                          <td colSpan={6}>
                            <div className="table-wrap" style={{ border: '1px solid var(--color-border)', borderRadius: 8, background: 'var(--color-surface)' }}>
                              <table className="data-table nested-table">
                                <thead>
                                  <tr>{['Version', 'Score', 'Change', 'Result', 'Findings', 'Date'].map(h => <th key={h} scope="col" className={h === 'Score' ? 'num' : undefined}>{h}</th>)}</tr>
                                </thead>
                                <tbody>
                                  {[...versions].reverse().map(v => (
                                    <tr key={v.audit_id || v.version}>
                                      <td className="cell-strong">{v.version}</td>
                                      <td className="num">{fmtScore(v.score)}%</td>
                                      <td style={{ color: v.score_delta > 0 ? 'var(--color-success)' : v.score_delta < 0 ? 'var(--color-danger)' : undefined }}>
                                        {v.score_delta ? (v.score_delta > 0 ? `+${fmtScore(v.score_delta)}` : fmtScore(v.score_delta)) : '-'}
                                      </td>
                                      <td><TierBadge tier={v.tier || v.status} /></td>
                                      <td>{findings(v)}</td>
                                      <td style={{ whiteSpace: 'nowrap' }}>{formatDate(v.created_at)}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
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
