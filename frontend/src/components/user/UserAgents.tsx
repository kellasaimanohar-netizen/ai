import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowDownRight, ArrowUpRight, Bot, ChevronDown, ChevronRight, FileText, Layers, Minus, Play, RefreshCw, Trash2 } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { Alert, Badge, Button, EmptyState, PageHeader, Panel, SearchInput, Segmented, SortHeader, TableSkeleton, TierBadge, Tooltip, scoreColor, useSort, fmtScore } from '../ui';
import { FindingBadges } from '../FindingCounts';
import { ScoreHistoryChart, ScoreSparkline, type ScorePoint } from '../ScoreHistory';
import { DeleteTestDialog, type DeletableTest } from '../DeleteTestDialog';

interface UserAgentsProps {
  user: { id: number | string; name: string; email: string; role: string };
  onSelectAgentForTest: (agentName: string) => void;
  onViewReport?: (testId: number) => void;
}

const formatDate = (iso?: string | null) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
};

const formatTime = (iso?: string | null) => {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
};

const pointsOf = (versions: any[]): ScorePoint[] =>
  versions.map(v => ({ score: Number(v.score) || 0, version: v.version, tier: v.tier || v.status, date: v.created_at }));

/** Score change from the previous version, with a direction arrow. */
const Change: React.FC<{ delta?: number | null; first: boolean }> = ({ delta, first }) => {
  if (first) return <span className="cell-sub" style={{ margin: 0 }}>First test</span>;
  if (!delta || Math.abs(delta) < 0.005) return <span className="change-chip flat"><Minus aria-hidden="true" />No change</span>;
  const up = delta > 0;
  return (
    <span className={`change-chip ${up ? 'up' : 'down'}`}>
      {up ? <ArrowUpRight aria-hidden="true" /> : <ArrowDownRight aria-hidden="true" />}
      {up ? `+${fmtScore(delta)}` : fmtScore(delta)} pts
    </span>
  );
};

type SortKey = 'name' | 'score' | 'tested';
type AgentTypeFilter = 'ALL' | 'LIVE' | 'TESTING';

export const UserAgents: React.FC<UserAgentsProps> = ({ user, onSelectAgentForTest, onViewReport }) => {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentTypeFilter>('ALL');
  const [open, setOpen] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<DeletableTest | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/user/agents');
      if (!res.ok) throw new Error('The agent list could not be loaded.');
      const body = await res.json();
      setAgents(body.agents || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The agent list could not be loaded.');
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, user?.id]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter(a => {
      const versions = a.version_progression || a.versions || [];
      const latestMode = versions.length ? (versions[versions.length - 1].mode || '') : (a.mode || '');
      const isLive = latestMode === 'live_probe' || a.is_live || (a.name || '').toLowerCase().includes('live');
      if (agentTypeFilter === 'LIVE' && !isLive) return false;
      if (agentTypeFilter === 'TESTING' && isLive) return false;

      return !q || (a.name || '').toLowerCase().includes(q) || (a.description || '').toLowerCase().includes(q) ||
        (Array.isArray(a.capabilities) ? a.capabilities : []).some((c: string) => String(c).toLowerCase().includes(q));
    });
  }, [agents, search, agentTypeFilter]);

  const versionsOf = (ag: any): any[] => ag.version_progression || ag.versions || [];
  const { sorted, sort, toggle } = useSort<any, SortKey>(filtered, {
    name: a => a.name,
    score: a => { const v = versionsOf(a); return v.length ? Number(v[v.length - 1].score) : null; },
    tested: a => { const v = versionsOf(a); const t = new Date(v[v.length - 1]?.created_at || '').getTime(); return Number.isNaN(t) ? null : t; },
  }, { key: 'tested', dir: 'desc' });

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Agents"
        subtitle="Trust score, findings and version history for each agent."
        actions={
          <>
            <Segmented<AgentTypeFilter> label="Agent Type" value={agentTypeFilter} onChange={setAgentTypeFilter} items={[
              { value: 'ALL', label: 'All Agents' },
              { value: 'LIVE', label: 'Live Agents' },
              { value: 'TESTING', label: 'Testing Agents' },
            ]} />
            <SearchInput value={search} onChange={setSearch} placeholder="Search by name or tool" label="Search agents" width={220} />
            <Button icon={RefreshCw} onClick={load} loading={loading && loaded}>Refresh</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={load}>Try again</Button>} />}

      <Panel flush>
        {loaded && filtered.length === 0 ? (
          <EmptyState
            icon={Layers}
            title={agents.length === 0 ? 'No agents yet' : 'No agents match your search'}
            hint={agents.length === 0 ? 'Agents appear here after their first test.' : undefined}
            action={agents.length === 0
              ? <Button variant="primary" icon={Play} onClick={() => onSelectAgentForTest('')}>Test an agent</Button>
              : <Button size="sm" onClick={() => setSearch('')}>Clear search</Button>}
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
                  const tools: string[] = Array.isArray(ag.capabilities) ? ag.capabilities : [];
                  return (
                    <React.Fragment key={ag.id || ag.name}>
                      <tr className={isOpen ? 'row-open' : undefined}>
                        <td style={{ minWidth: 260, paddingTop: 12, paddingBottom: 12 }}>
                          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                            <Bot size={16} aria-hidden="true" style={{ color: 'var(--color-text-muted)', marginTop: 2 }} />
                            <div style={{ minWidth: 0 }}>
                              <div className="cell-strong">{ag.name}</div>
                              {ag.description && <div className="cell-sub" style={{ maxWidth: 380 }}>{ag.description}</div>}
                              {tools.length > 0 && (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                                  {tools.slice(0, 4).map(t => <span key={t} className="badge mono">{t}</span>)}
                                  {tools.length > 4 && <span className="badge" title={tools.slice(4).join(', ')}>+{tools.length - 4}</span>}
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td>
                          {tested ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                              <span className="num cell-strong" style={{ fontSize: 15, color: scoreColor(Number(latest.score)) }}>{fmtScore(latest.score)}%</span>
                              {typeof latest.score_delta === 'number' && latest.score_delta !== 0 && (
                                <span style={{ fontSize: 12, color: latest.score_delta > 0 ? 'var(--color-success)' : 'var(--color-danger)' }}>
                                  {latest.score_delta > 0 ? `+${fmtScore(latest.score_delta)}` : fmtScore(latest.score_delta)}
                                </span>
                              )}
                              <TierBadge tier={latest.tier || latest.status} />
                              {latest.version && <span className="badge mono">{latest.version}</span>}
                            </div>
                          ) : <Badge>Not tested</Badge>}
                        </td>
                        <td>
                          {tested ? (
                            <FindingBadges counts={latest} />
                          ) : '-'}
                        </td>
                        <td>{tested ? <ScoreSparkline points={pointsOf(versions)} /> : '-'}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{tested ? formatDate(latest.created_at) : '-'}</td>
                        <td className="cell-actions">
                          <div style={{ display: 'inline-flex', gap: 4 }}>
                            {tested && (
                              <Button size="sm" variant="ghost" icon={isOpen ? ChevronDown : ChevronRight} onClick={() => setOpen(isOpen ? null : ag.name)} aria-expanded={isOpen}>
                                Versions
                              </Button>
                            )}
                            <Button size="sm" icon={Play} onClick={() => onSelectAgentForTest(ag.name)} aria-label={`Test ${ag.name}`}>Test</Button>
                          </div>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="row-detail">
                          <td colSpan={6}>
                            <div className="version-panel">
                              <div className="version-panel-head">
                                <div>
                                  <h4>Version history</h4>
                                  <p>{versions.length} test{versions.length === 1 ? '' : 's'} of {ag.name}, newest first</p>
                                </div>
                              </div>
                              <ScoreHistoryChart points={pointsOf(versions)} />
                              <div className="table-wrap">
                                <table className="data-table nested-table version-table">
                                  <thead>
                                    <tr>
                                      <th scope="col">Version</th>
                                      <th scope="col">Score</th>
                                      <th scope="col">Change</th>
                                      <th scope="col">Result</th>
                                      <th scope="col">Findings</th>
                                      <th scope="col">Tested</th>
                                      <th scope="col"><span className="sr-only">Actions</span></th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {[...versions].reverse().map((v, i) => {
                                      const score = Number(v.score) || 0;
                                      return (
                                        <tr key={v.audit_id || v.version} className={i === 0 ? 'is-latest' : undefined}>
                                          <td>
                                            <span className="version-tag">{v.version}</span>
                                            {i === 0 && <span className="version-latest">Latest</span>}
                                          </td>
                                          <td>
                                            <div className="score-cell">
                                              <span style={{ color: scoreColor(score) }}>{fmtScore(score)}%</span>
                                              <span className="meter" aria-hidden="true"><span style={{ width: `${Math.max(0, Math.min(100, score))}%`, background: scoreColor(score) }} /></span>
                                            </div>
                                          </td>
                                          <td><Change delta={v.score_delta} first={i === versions.length - 1} /></td>
                                          <td><TierBadge tier={v.tier || v.status} /></td>
                                          <td><FindingBadges counts={v} /></td>
                                          <td style={{ whiteSpace: 'nowrap' }}>
                                            <div>{formatDate(v.created_at)}</div>
                                            <div className="cell-sub">{formatTime(v.created_at)}</div>
                                          </td>
                                          <td className="cell-actions">
                                            <div style={{ display: 'inline-flex', gap: 4 }}>
                                              {onViewReport && <Button size="sm" variant="secondary" icon={FileText} onClick={() => onViewReport(v.test_id ?? v.id)}>Report</Button>}
                                              <Tooltip label="Delete this test">
                                                <Button size="sm" variant="ghost" iconOnly icon={Trash2} className="btn-delete"
                                                  onClick={() => setDeleting({ id: v.test_id ?? v.id, agent_name: ag.name, version: v.version, audit_id: v.audit_id })}
                                                  aria-label={`Delete ${ag.name} ${v.version || ''}`} />
                                              </Tooltip>
                                            </div>
                                          </td>
                                        </tr>
                                      );
                                    })}
                                  </tbody>
                                </table>
                              </div>
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

      {/* Versions are numbered from the remaining tests, so the list reloads after a delete */}
      <DeleteTestDialog test={deleting} onClose={() => setDeleting(null)} onDeleted={() => load()} />
    </div>
  );
};
