import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  Bell,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  FolderGit2,
  Globe,
  Key,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Server,
  Trash2,
  XCircle,
} from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import {
  Alert, Badge, Button, EmptyState, Field, Modal, PageHeader, Panel, SearchInput, Segmented, StatusText, TierBadge, Tooltip, scoreColor,
  type Tone,
  fmtScore,
} from '../ui';
import { LiveTestSettings, DEFAULT_LIVE_CONFIG, type LiveTestConfig } from './LiveTestSettings';
import { LiveAlerts, type LiveAlert } from './LiveAlerts';
import { useMonitors, MonitorDetail, AgentHistory, STATUS, ago } from './LiveMonitors';
import { LiveSecurityScan, type SecurityScan } from './LiveSecurityScan';
import { generatePDFReport } from '../../utils/pdfExport';
import { ReportDownloadMenu } from '../ReportDownload';

export interface LiveFinding {
  id: string;
  category: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'WARNING' | 'INFO' | 'PASS';
  description: string;
  remediation?: string;
}

export interface LiveTestResult {
  test_id: string;
  name: string;
  category: string;
  prompt: string;
  expected_behavior?: string;
  status: 'PASSED' | 'FAILED' | 'WARNING' | 'COULD_NOT_RUN';
  severity?: string;
  repeats?: number;
  pass_rate?: number | null;
  checks?: Array<{ name: string; passed: boolean | null; detail: string }>;
  judge_note?: string | null;
  status_code: number;
  latency_ms: number;
  response: string;
  error?: string | null;
  findings: LiveFinding[];
}

export interface RepoSummary {
  status: string;
  repo_path: string;
  manifest_found: boolean;
  manifest_name?: string | null;
  tools_detected?: string[];
  tools_count: number;
  source_files_count: number;
}

export interface OpenApiSummary {
  status: string;
  spec_url: string;
  title?: string;
  version?: string;
  routes_count?: number;
  discovered_routes?: Array<{ path: string; method: string; operation_id: string }>;
  target_endpoint?: string;
  http_method?: string;
  error?: string;
}

export interface LiveAuditSummary {
  audit_id: string;
  agent_name: string;
  repo_path?: string;
  openapi_url?: string;
  repo_summary?: RepoSummary;
  openapi_summary?: OpenApiSummary;
  endpoint_url: string;
  target_env: string;
  started_at: string;
  finished_at: string;
  total_duration_ms: number;
  avg_latency_ms: number;
  trust_score: number;
  tier: string;
  threat_level: string;
  threat_color: string;
  enterprise_ready: boolean;
  version?: string;
  agent_type?: string;
  connector?: string;
  coverage?: number;
  tests_ran?: number;
  could_not_run?: number;
  not_reached?: number;        // tests the agent never answered
  not_decided?: number;        // tests the agent answered but no check could decide (AI judge off, no known answer)
  usefulness?: { status: 'passed' | 'failed' | 'not_tested'; tests_ran: number; tests_passed: number };
  tier_note?: string | null;   // why the tier is lower than the score alone would give
  ai_judge_used?: boolean;
  ai_judge_requested_but_unavailable?: boolean;
  tests_count: number;
  pass_count: number;
  fail_count: number;
  critical_count: number;
  warning_count: number;
  test_results: LiveTestResult[];
  all_findings: LiveFinding[];
  phases_run: string[];
  security_scan?: SecurityScan;
}

export interface MonitoredAgent {
  id: string;
  serverId?: number;           // the row in live_agents; the server keeps the API token
  name: string;
  repoPath: string;
  openapiUrl: string;
  targetEnv: 'production' | 'staging' | 'development';
  authToken?: string;          // only while adding an agent, before it is saved
  hasAuthToken?: boolean;
  config?: LiveTestConfig;
  status: 'idle' | 'running' | 'completed' | 'error';
  errorMessage?: string;
  lastTestedAt?: string;
  result?: LiveAuditSummary | null;
}

interface UserLiveAgentsProps {
  user?: any;
  onNavigateToHistory?: (testId?: string) => void;
}

// Older versions kept the list in the browser under this key; it is moved to the server once, then removed.
const LEGACY_STORAGE_KEY = 'certify_monitored_live_agents';
const PROBE_TIMEOUT_MS = 5 * 60 * 1000;

interface ServerLiveAgent {
  id: number;
  name: string;
  repo_path: string | null;
  openapi_url: string;
  target_env: MonitoredAgent['targetEnv'];
  config: Partial<LiveTestConfig>;
  has_auth_token: boolean;
  last_error: string | null;
  last_result: LiveAuditSummary | null;
  last_tested_at: string | null;
  already_registered?: boolean;   // the same address was registered before; this is that agent
}

const fromServer = (a: ServerLiveAgent): MonitoredAgent => ({
  id: String(a.id),
  serverId: a.id,
  name: a.name,
  repoPath: a.repo_path || '',
  openapiUrl: a.openapi_url,
  targetEnv: a.target_env,
  hasAuthToken: a.has_auth_token,
  config: { ...DEFAULT_LIVE_CONFIG, ...(a.config || {}) },
  status: a.last_result ? 'completed' : a.last_error ? 'error' : 'idle',
  errorMessage: a.last_error || undefined,
  lastTestedAt: a.last_tested_at || undefined,
  result: a.last_result,
});

const saveAgent = async (body: Record<string, unknown>): Promise<ServerLiveAgent> => {
  const res = await apiFetch('/api/user/live/agents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || 'The live agent could not be saved.');
  return data;
};

/** Moves a list kept in this browser by an older version to the signed-in user's account, once. */
const importLegacyList = async (): Promise<void> => {
  let legacy: MonitoredAgent[];
  try {
    legacy = JSON.parse(localStorage.getItem(LEGACY_STORAGE_KEY) || '[]');
    localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    return;
  }
  const items = Array.isArray(legacy) ? legacy : [];
  for (let i = 0; i < items.length; i++) {
    const a = items[i];
    try {
      await saveAgent({
        name: a.name || 'Live agent', repo_path: a.repoPath || null, openapi_url: a.openapiUrl,
        target_env: a.targetEnv || 'production', auth_token: a.authToken || null, config: a.config || {},
        last_audit_id: a.result?.audit_id || null,
      });
    } catch {
      // Keep what was not moved, so the next visit tries again
      try {
        localStorage.setItem(LEGACY_STORAGE_KEY, JSON.stringify(items.slice(i)));
      } catch {
        // storage blocked
      }
      return;
    }
  }
};
let legacyImport: Promise<void> | undefined;

const ENV_LABEL: Record<MonitoredAgent['targetEnv'], string> = { production: 'Production', staging: 'Staging', development: 'Development' };

/** Matches an alert to its agent by name, ignoring case, spaces, dashes and underscores — the alert
 * is raised under the monitor's saved name, which can drift slightly from the agent's current name. */

type ProbeFilter = 'ALL' | 'FAILED' | 'PASSED' | 'COULD_NOT_RUN';

const probeTone = (status: LiveTestResult['status']): Tone =>
  status === 'PASSED' ? 'pass' : status === 'FAILED' ? 'critical' : status === 'WARNING' ? 'warning' : 'neutral';
const probeLabel = (status: LiveTestResult['status']) =>
  status === 'PASSED' ? 'Pass' : status === 'FAILED' ? 'Fail' : status === 'WARNING' ? 'Partial' : 'Could not run';

export const UserLiveAgents: React.FC<UserLiveAgentsProps> = () => {
  // 1. The user's live agents, stored on the server
  const [agents, setAgents] = useState<MonitoredAgent[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: Tone; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        await (legacyImport ??= importLegacyList());
        const res = await apiFetch('/api/user/live/agents');
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || 'Your live agents could not be loaded.');
        if (!cancelled) {
          setAgents((data.agents || []).map(fromServer));
          setListError(null);
        }
      } catch (err: any) {
        if (!cancelled) setListError(err.message || 'Your live agents could not be loaded.');
      } finally {
        if (!cancelled) setLoaded(true);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  // 2. Search and filters
  const [searchTerm, setSearchTerm] = useState('');
  const [envFilter, setEnvFilter] = useState<'ALL' | 'production' | 'staging' | 'development'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ONLINE' | 'CRITICAL'>('ALL');

  // 3. New agent dialog
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newRepoPath, setNewRepoPath] = useState('');
  const [newOpenapiUrl, setNewOpenapiUrl] = useState('');
  const [newAgentName, setNewAgentName] = useState('');
  const [newTargetEnv, setNewTargetEnv] = useState<'production' | 'staging' | 'development'>('production');
  const [newAuthToken, setNewAuthToken] = useState('');
  const [showAuthField, setShowAuthField] = useState(false);
  const [newConfig, setNewConfig] = useState<LiveTestConfig>(DEFAULT_LIVE_CONFIG);
  const [addModalError, setAddModalError] = useState<string | null>(null);
  const [isSubmittingNew, setIsSubmittingNew] = useState(false);

  // 4. Alerts and connection test
  const [isAlertsOpen, setIsAlertsOpen] = useState(false);
  const [allAlerts, setAllAlerts] = useState<LiveAlert[]>([]);
  const [isTestingConnection, setIsTestingConnection] = useState(false);
  const [testConnectionResult, setTestConnectionResult] = useState<{ success: boolean; message: string; title?: string; routesCount?: number } | null>(null);

  const loadAlerts = useCallback(async () => {
    try {
      const res = await apiFetch('/api/user/live/alerts');
      if (res.ok) {
        const d = await res.json();
        setAllAlerts(d.alerts || []);
      }
    } catch { /* the list stays as it was */ }
  }, []);

  useEffect(() => {
    loadAlerts();
    const timer = setInterval(() => { if (!document.hidden) loadAlerts(); }, 60000);
    return () => clearInterval(timer);
  }, [loadAlerts]);

  const unreadAlertsCount = useMemo(() => allAlerts.filter(a => !a.read_at).length, [allAlerts]);

  const markAllAlertsRead = async () => {
    await apiFetch('/api/user/live/alerts/read-all', { method: 'POST' });
    await loadAlerts();
  };

  // 5. Detail dialog, expanded rows, removal
  const mon = useMonitors();
  const [openAgentId, setOpenAgentId] = useState<string | null>(null);
  const [selectedAgentDetail, setSelectedAgentDetail] = useState<MonitoredAgent | null>(null);
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);
  const [detailFilterTab, setDetailFilterTab] = useState<ProbeFilter>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [removing, setRemoving] = useState<MonitoredAgent | null>(null);
  const [removeBusy, setRemoveBusy] = useState(false);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const monitorFor = (agent: MonitoredAgent) =>
    mon.monitors?.find(m => (agent.serverId != null && m.live_agent_id === agent.serverId)) || mon.monitors?.find(m => m.name === agent.name);

  // The request sent to the server for one agent, used for runs and for schedules.
  const buildRequest = (agent: MonitoredAgent) => {
    const c = { ...DEFAULT_LIVE_CONFIG, ...(agent.config || {}) };
    const parseJson = (text: string, what: string) => {
      if (!text.trim()) return undefined;
      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`The ${what} settings are not valid JSON. Check the brackets and quotes.`);
      }
    };
    return {
      // A saved agent's token stays on the server, which adds it to the test
      live_agent_id: agent.serverId,
      agent_name: agent.name.trim() || undefined,
      repo_path: agent.repoPath.trim() || undefined,
      openapi_url: agent.openapiUrl.trim(),
      target_env: agent.targetEnv,
      auth_type: agent.serverId ? undefined : (agent.authToken?.trim() ? 'bearer' : 'none'),
      auth_token: agent.serverId ? undefined : (agent.authToken?.trim() || undefined),
      agent_type: c.agentType || undefined,
      endpoint_url: c.endpointUrl.trim() || undefined,
      payload_template: c.payloadTemplate.trim() || undefined,
      response_path: c.responsePath.trim() || undefined,
      golden_jsonl: c.goldenJsonl.trim() || undefined,
      repeats: c.repeats,
      use_ai_judge: c.useAiJudge,
      include_multilingual: c.includeMultilingual,
      include_number_checks: c.includeNumberChecks,
      requires_auth: c.requiresAuth || undefined,
      fairness_config: parseJson(c.fairnessJson, 'fairness'),
      access_control_config: parseJson(c.accessJson, 'access control'),
    };
  };

  const executeAgentAudit = async (agent: MonitoredAgent): Promise<MonitoredAgent> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
    try {
      const payload = buildRequest(agent);
      const res = await apiFetch('/api/live-agent/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      const data = await res.json().catch(() => ({ detail: `The server answered with HTTP ${res.status} and no result.` }));
      if (!res.ok || !data.success) {
        return { ...agent, status: 'error', errorMessage: data?.detail || data?.message || 'The live agent could not be tested.' };
      }

      const resultPayload: LiveAuditSummary = data.data;
      return {
        ...agent,
        name: resultPayload.agent_name || agent.name || 'Live agent',
        status: 'completed',
        errorMessage: undefined,
        lastTestedAt: new Date().toISOString(),
        result: resultPayload
      };
    } catch (err: any) {
      return {
        ...agent,
        status: 'error',
        errorMessage: err?.name === 'AbortError'
          ? `The test took longer than ${PROBE_TIMEOUT_MS / 60000} minutes and was stopped. A sleeping free-tier agent can need a minute to wake up; try again.`
          : err.message || 'The live endpoint could not be reached.'
      };
    } finally {
      clearTimeout(timer);
    }
  };

  const resetAddForm = () => {
    setNewRepoPath('');
    setNewOpenapiUrl('');
    setNewAgentName('');
    setNewAuthToken('');
    setShowAuthField(false);
    setNewConfig(DEFAULT_LIVE_CONFIG);
    setTestConnectionResult(null);
    setAddModalError(null);
  };

  const handleAddNewAgentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRepoPath.trim()) {
      setAddModalError('The repository folder is required. Clone the repo to a folder on this computer and enter that folder.');
      return;
    }
    if (/^(https?:\/\/|git@)/i.test(newRepoPath.trim())) {
      setAddModalError('A GitHub web address cannot be read. Clone the repository to a folder and enter that folder.');
      return;
    }
    if (!newOpenapiUrl.trim()) {
      setAddModalError('Enter the OpenAPI document URL.');
      return;
    }

    setAddModalError(null);
    setIsSubmittingNew(true);

    let saved: ServerLiveAgent;
    try {
      saved = await saveAgent({
        name: newAgentName.trim() || 'New Monitored Agent',
        repo_path: newRepoPath.trim(),
        openapi_url: newOpenapiUrl.trim(),
        target_env: newTargetEnv,
        auth_token: newAuthToken.trim() || null,
        config: newConfig,
      });
    } catch (err: any) {
      setAddModalError(err.message);
      setIsSubmittingNew(false);
      return;
    }
    if (saved.already_registered) {
      setAddModalError(`You already have this agent as "${saved.name}". Open it from the list to test it again.`);
      setIsSubmittingNew(false);
      return;
    }
    const tempAgent: MonitoredAgent = { ...fromServer(saved), status: 'running' };
    setAgents(prev => [tempAgent, ...prev]);

    const tested = await executeAgentAudit(tempAgent);
    setAgents(prev => prev.map(a => a.id === tempAgent.id ? tested : a));
    if (newConfig.monitor) {
      try {
        const sres = await apiFetch('/api/user/live/schedules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: tested.status === 'completed' ? tested.name : (newAgentName.trim() || undefined), live_agent_id: tested.serverId, frequency_minutes: newConfig.scheduleMinutes, health_minutes: newConfig.healthMinutes, request: buildRequest(tested) }),
        });
        if (!sres.ok) {
          const sd = await sres.json().catch(() => null);
          setNotice({ tone: 'warning', text: `The agent was tested, but monitoring was not turned on. ${sd?.detail || ''}`.trim() });
        } else {
          mon.load();
        }
      } catch {
        setNotice({ tone: 'warning', text: 'The agent was tested, but monitoring was not turned on.' });
      }
    }
    setIsSubmittingNew(false);
    setIsAddModalOpen(false);
    resetAddForm();

    setSelectedAgentDetail(tested);
    setDetailFilterTab('ALL');
    if (tested.result?.test_results?.length) setExpandedTestId(tested.result.test_results[0].test_id);
  };

  // Checks the OpenAPI document without saving anything
  const handleTestConnection = async () => {
    if (!newOpenapiUrl.trim()) {
      setAddModalError('Enter an OpenAPI document URL to test the connection.');
      return;
    }
    setAddModalError(null);
    setIsTestingConnection(true);
    setTestConnectionResult(null);
    try {
      const res = await apiFetch('/api/live-agent/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source_type: 'openapi', url_or_path: newOpenapiUrl.trim() })
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setTestConnectionResult({ success: false, message: data?.detail || data?.message || 'The OpenAPI document could not be fetched or read.' });
      } else {
        const summary = data.data;
        setTestConnectionResult({
          success: true,
          message: `Found "${summary.title || 'Live agent'}" (v${summary.version || '1.0.0'}) with ${summary.routes_count || 0} routes. Nothing was saved.`,
          title: summary.title,
          routesCount: summary.routes_count
        });
        if (!newAgentName.trim() && summary.title) setNewAgentName(summary.title);
      }
    } catch (err: any) {
      setTestConnectionResult({ success: false, message: `Connection error: ${err.message || 'The backend could not be reached.'}` });
    } finally {
      setIsTestingConnection(false);
    }
  };

  const handleReTestAgent = async (agent: MonitoredAgent, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setAgents(prev => prev.map(a => a.id === agent.id ? { ...a, status: 'running', errorMessage: undefined } : a));
    if (selectedAgentDetail?.id === agent.id) setSelectedAgentDetail({ ...agent, status: 'running' });

    const updated = await executeAgentAudit(agent);
    setAgents(prev => prev.map(a => a.id === agent.id ? updated : a));
    if (selectedAgentDetail?.id === agent.id) setSelectedAgentDetail(updated);
  };

  // Removes the agent and its monitor. Past results stay in the test history.
  const confirmRemove = async () => {
    const agent = removing;
    if (!agent) return;
    setRemoveBusy(true);
    try {
      if (agent.serverId) {
        const res = await apiFetch(`/api/user/live/agents/${agent.serverId}`, { method: 'DELETE' });
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          setNotice({ tone: 'critical', text: d.detail || 'The live agent could not be removed.' });
          return;
        }
        mon.load();
      }
      setAgents(prev => prev.filter(a => a.id !== agent.id));
      if (selectedAgentDetail?.id === agent.id) setSelectedAgentDetail(null);
      setNotice({ tone: 'pass', text: `${agent.name} was removed.` });
    } finally {
      setRemoveBusy(false);
      setRemoving(null);
    }
  };

  // generatePDFReport saves the file itself
  const handleDownloadPDF = (result?: LiveAuditSummary | null) => {
    if (!result) return;
    try {
      generatePDFReport({
        name: result.agent_name,
        agent_name: result.agent_name,
        audit_id: result.audit_id,
        started_at: result.started_at,
        finished_at: result.finished_at,
        total_duration_ms: result.total_duration_ms,
        mode: 'live_probe',
        endpoint: result.endpoint_url,
        tools: result.repo_summary?.tools_detected || [],
        tier: result.tier,
        trust_score: result.trust_score,
        enterprise_ready: result.enterprise_ready,
        summary: {
          total: result.tests_count,
          passed: result.pass_count,
          critical_failures: result.critical_count,
          warnings: result.warning_count
        },
        findings: (result.all_findings || []).map(f => ({
          id: f.id,
          phase: 'live_probe',
          severity: f.severity,
          passed: f.severity === 'PASS',
          title: f.title,
          description: f.description,
          remediation: f.remediation
        }))
      });
    } catch {
      setNotice({ tone: 'critical', text: 'The PDF could not be created. Try again.' });
    }
  };

  const openDetail = (agent: MonitoredAgent) => {
    setSelectedAgentDetail(agent);
    setDetailFilterTab('ALL');
    setExpandedTestId(agent.result?.test_results?.length ? agent.result.test_results[0].test_id : null);
  };

  const filteredAgents = useMemo(() => agents.filter(agent => {
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      if (!agent.name.toLowerCase().includes(q) && !agent.repoPath.toLowerCase().includes(q) && !agent.openapiUrl.toLowerCase().includes(q)) return false;
    }
    if (envFilter !== 'ALL' && agent.targetEnv !== envFilter) return false;
    if (statusFilter === 'ONLINE' && (agent.status !== 'completed' || (agent.result?.critical_count || 0) > 0)) return false;
    if (statusFilter === 'CRITICAL' && (agent.result?.critical_count || 0) === 0 && agent.status !== 'error') return false;
    return true;
  }), [agents, searchTerm, envFilter, statusFilter]);

  const filtersActive = searchTerm !== '' || envFilter !== 'ALL' || statusFilter !== 'ALL';
  const clearFilters = () => { setSearchTerm(''); setEnvFilter('ALL'); setStatusFilter('ALL'); };

  const detail = selectedAgentDetail;
  const detailResult = detail?.result || null;
  const modalFilteredProbes = detailResult?.test_results.filter(tr =>
    detailFilterTab === 'ALL' ? true : tr.status === detailFilterTab
  ) || [];

  const openAdd = () => {
    setAddModalError(null);
    setTestConnectionResult(null);
    setIsAddModalOpen(true);
  };

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Live agents"
        subtitle="Register a running agent with its repository and OpenAPI document, then test it for runtime health, trust score and security risks."
        actions={
          <>
            <Button icon={Bell} onClick={() => setIsAlertsOpen(prev => !prev)} aria-expanded={isAlertsOpen} aria-controls="live-alerts">
              Alerts{unreadAlertsCount > 0 && <Badge tone="critical">{unreadAlertsCount}</Badge>}
            </Button>
            <Button variant="primary" icon={Plus} onClick={openAdd}>New agent</Button>
          </>
        }
      />

      {listError && <Alert tone="critical" title={listError} action={<Button size="sm" onClick={() => window.location.reload()}>Reload</Button>} />}
      {notice && (
        <Alert tone={notice.tone} title={notice.text} action={<Button size="sm" variant="ghost" onClick={() => setNotice(null)}>Dismiss</Button>} />
      )}

      {isAlertsOpen && (
        <div id="live-alerts">
          <LiveAlerts alerts={allAlerts} onRefresh={loadAlerts} onMarkAll={markAllAlertsRead} onClose={() => setIsAlertsOpen(false)} />
        </div>
      )}

      {agents.length > 0 && (
        <div className="filter-bar">
          <SearchInput value={searchTerm} onChange={setSearchTerm} placeholder="Search name, repository or API" label="Search live agents" width="auto" />
          <Segmented<'ALL' | 'production' | 'staging' | 'development'> label="Environment" value={envFilter} onChange={setEnvFilter} items={[
            { value: 'ALL', label: 'All environments' }, { value: 'production', label: 'Production' }, { value: 'staging', label: 'Staging' }, { value: 'development', label: 'Development' },
          ]} />
          <Segmented<'ALL' | 'ONLINE' | 'CRITICAL'> label="Result" value={statusFilter} onChange={setStatusFilter} items={[
            { value: 'ALL', label: 'All' }, { value: 'ONLINE', label: 'No critical issues' }, { value: 'CRITICAL', label: 'Critical or failing' },
          ]} />
          {filtersActive && <Button variant="ghost" onClick={clearFilters}>Clear filters</Button>}
        </div>
      )}

      <Panel flush>
        {!loaded ? (
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[0, 1, 2].map(i => <span key={i} className="skeleton" style={{ height: 44 }} />)}
          </div>
        ) : agents.length === 0 ? (
          <EmptyState
            icon={Radio}
            title="No live agents yet"
            hint="Add a running agent with its repository folder and OpenAPI document. You can then see its runtime health, security risks and response time."
            action={<Button variant="primary" icon={Plus} onClick={openAdd}>New agent</Button>}
          />
        ) : filteredAgents.length === 0 ? (
          <EmptyState title="No live agents match these filters" action={<Button size="sm" onClick={clearFilters}>Clear filters</Button>} />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col" style={{ width: 44 }}><span className="sr-only">Expand</span></th>
                  <th scope="col">Agent</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="num">Response time</th>
                  <th scope="col">Result</th>
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {filteredAgents.map(agent => {
                  const hasResult = !!agent.result;
                  const isRunning = agent.status === 'running';
                  const critical = agent.result?.critical_count || 0;
                  const score = hasResult ? Math.round(agent.result?.trust_score || 0) : null;
                  const isOpen = openAgentId === agent.id;
                  const monitor = monitorFor(agent);
                  const health = monitor?.health;
                  return (
                    <React.Fragment key={agent.id}>
                      <tr className={isOpen ? 'row-open' : undefined}>
                        <td>
                          <button
                            type="button"
                            className="icon-btn"
                            style={{ height: 28, minWidth: 28, padding: 0 }}
                            onClick={() => setOpenAgentId(isOpen ? null : agent.id)}
                            aria-expanded={isOpen}
                            aria-label={isOpen ? `Hide monitoring for ${agent.name}` : `Show monitoring for ${agent.name}`}
                          >
                            {isOpen ? <ChevronDown /> : <ChevronRight />}
                          </button>
                        </td>
                        <td style={{ minWidth: 220 }}>
                          <div className="cell-with-icon">
                            <Bot aria-hidden="true" />
                            <div style={{ minWidth: 0 }}>
                              <div className="cell-strong cell-truncate" title={agent.name}>{agent.name}</div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
                                <Badge tone={agent.targetEnv === 'production' ? 'info' : 'neutral'}>{ENV_LABEL[agent.targetEnv] || agent.targetEnv}</Badge>
                                <span className="cell-mono cell-truncate" style={{ maxWidth: 160 }} title={agent.openapiUrl}>{agent.openapiUrl.replace(/^https?:\/\//, '')}</span>
                              </div>
                            </div>
                          </div>
                        </td>
                        <td>
                          {isRunning ? (
                            <span className="status-text"><span className="spinner" style={{ width: 12, height: 12 }} aria-hidden="true" />Testing</span>
                          ) : agent.status === 'error' ? (
                            <Tooltip label={agent.errorMessage || 'The last test failed.'}>
                              <span tabIndex={0}><StatusText color="var(--color-danger)">Test failed</StatusText></span>
                            </Tooltip>
                          ) : monitor && monitor.active && health ? (
                            <StatusText color={STATUS[health.status]?.color || 'var(--color-text-muted)'}>{STATUS[health.status]?.label || health.status}</StatusText>
                          ) : monitor && !monitor.active ? (
                            <StatusText color="var(--color-text-muted)">Monitoring paused</StatusText>
                          ) : hasResult ? (
                            <StatusText color="var(--color-text-muted)">Tested, not monitored</StatusText>
                          ) : (
                            <StatusText color="var(--color-text-muted)">Not tested</StatusText>
                          )}
                          {agent.lastTestedAt && !isRunning && <div className="cell-sub" style={{ whiteSpace: 'nowrap' }}>Tested {ago(agent.lastTestedAt)}</div>}
                        </td>
                        <td className="num">
                          {hasResult ? (
                            <>
                              <div className="cell-strong">{agent.result?.avg_latency_ms} ms</div>
                              <div className="cell-sub">{agent.result?.tests_count ?? '-'} tests</div>
                            </>
                          ) : '-'}
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          {hasResult && score !== null ? (
                            <>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                <span className="num" style={{ fontWeight: 600, color: scoreColor(score) }}>{fmtScore(score)}%</span>
                                <TierBadge tier={agent.result?.tier} />
                              </div>
                              <div className="cell-sub" style={{ color: critical > 0 ? 'var(--color-danger)' : undefined }}>
                                {critical > 0 ? `${critical} critical finding${critical === 1 ? '' : 's'}` : 'No critical findings'}
                              </div>
                            </>
                          ) : '-'}
                        </td>
                        <td className="cell-actions">
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                            <Button size="sm" variant="ghost" icon={Eye} onClick={() => openDetail(agent)} aria-label={`Open results for ${agent.name}`}>Results</Button>
                            <Button size="sm" icon={Play} onClick={e => handleReTestAgent(agent, e)} loading={isRunning} aria-label={`Test ${agent.name} now`}>Test</Button>
                            {hasResult && (
                              <ReportDownloadMenu size="sm" variant="ghost" iconOnly name={agent.name}
                                onPdf={() => handleDownloadPDF(agent.result)} getReport={() => agent.result}
                                onError={text => setNotice({ tone: 'critical', text })} />
                            )}
                            <Tooltip label="Remove agent">
                              <Button size="sm" variant="ghost" iconOnly icon={Trash2} onClick={() => setRemoving(agent)} aria-label={`Remove ${agent.name}`} />
                            </Tooltip>
                          </div>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="row-detail">
                          <td colSpan={6}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                              <AgentHistory liveAgentId={agent.serverId} />
                              {monitor
                                ? <MonitorDetail m={monitor} mon={mon} />
                                : <span className="field-hint">Monitoring is not turned on for this agent.</span>}
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

      {/* New agent */}
      <Modal
        open={isAddModalOpen}
        onClose={() => { if (!isSubmittingNew) setIsAddModalOpen(false); }}
        title="New live agent"
        description="Enter the agent's OpenAPI link and code folder. It is tested now and, if you choose, watched from then on."
        width={860}
      >
        <form id="new-live-agent" onSubmit={handleAddNewAgentSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {addModalError && <Alert tone="critical" title={addModalError} />}
          {testConnectionResult && <Alert tone={testConnectionResult.success ? 'pass' : 'critical'} title={testConnectionResult.success ? 'Connection works' : 'Connection failed'}>{testConnectionResult.message}</Alert>}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(240px, 100%), 1fr))', gap: 16 }}>
            <Field label="Agent name" hint="Optional. Taken from the OpenAPI title when left blank.">
              <input type="text" className="form-input" value={newAgentName} onChange={e => setNewAgentName(e.target.value)} placeholder="Support agent" data-autofocus />
            </Field>
            <Field label="Environment">
              <select className="form-input" value={newTargetEnv} onChange={e => setNewTargetEnv(e.target.value as MonitoredAgent['targetEnv'])}>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </Field>
          </div>

          <Field label="OpenAPI document URL" required hint="Used to find the agent's routes.">
            <input type="text" className="form-input mono" value={newOpenapiUrl} onChange={e => setNewOpenapiUrl(e.target.value)} placeholder="https://your-agent.example.com/openapi.json" />
          </Field>

          <Field label="Repository folder" required hint="A folder on this computer with the agent's code. GitHub links do not work: clone the repository first.">
            <input type="text" className="form-input mono" value={newRepoPath} onChange={e => setNewRepoPath(e.target.value)} placeholder="C:\your-folder\your-agent" />
          </Field>

          <LiveTestSettings value={newConfig} onChange={patch => setNewConfig(prev => ({ ...prev, ...patch }))} />

          <div>
            <button type="button" className="link-btn" onClick={() => setShowAuthField(!showAuthField)} aria-expanded={showAuthField} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <Key size={14} aria-hidden="true" />
              {showAuthField ? 'Hide API token' : 'Add an API token (optional)'}
            </button>
            {showAuthField && (
              <div style={{ marginTop: 8 }}>
                <Field label="API token" hint="Stored on the server and sent as a Bearer token. It is never shown again.">
                  <input type="password" className="form-input mono" value={newAuthToken} onChange={e => setNewAuthToken(e.target.value)} placeholder="Bearer token or API key" autoComplete="off" />
                </Field>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap', paddingTop: 16, borderTop: '1px solid var(--color-border)' }}>
            <Button icon={Server} onClick={handleTestConnection} loading={isTestingConnection} disabled={!newOpenapiUrl.trim()}>Test connection</Button>
            <div style={{ display: 'flex', gap: 8 }}>
              <Button onClick={() => setIsAddModalOpen(false)} disabled={isSubmittingNew}>Cancel</Button>
              <Button type="submit" variant="primary" icon={Play} loading={isSubmittingNew}>{isSubmittingNew ? 'Testing and adding' : 'Add and test agent'}</Button>
            </div>
          </div>
        </form>
      </Modal>

      {/* Results of one agent */}
      <Modal
        open={!!detail}
        onClose={() => setSelectedAgentDetail(null)}
        width={1400}
        title={detail ? (
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {detail.name}
            <Badge tone={detail.targetEnv === 'production' ? 'info' : 'neutral'}>{ENV_LABEL[detail.targetEnv] || detail.targetEnv}</Badge>
            {detailResult && <TierBadge tier={detailResult.tier} />}
          </span>
        ) : ''}
        description={detail ? <span className="cell-mono">{detailResult?.endpoint_url || detail.openapiUrl}</span> : undefined}
        actions={detail ? (
          <>
            <Button icon={RefreshCw} onClick={() => handleReTestAgent(detail)} loading={detail.status === 'running'}>Test again</Button>
            {detailResult && (
              <ReportDownloadMenu name={detail.name} onPdf={() => handleDownloadPDF(detailResult)} getReport={() => detailResult}
                onError={text => setNotice({ tone: 'critical', text })} />
            )}
          </>
        ) : undefined}
      >
        {detail && (detail.status === 'running' ? (
          <div className="empty-state" role="status">
            <span className="spinner" style={{ width: 24, height: 24 }} aria-hidden="true" />
            <div className="empty-title" style={{ marginTop: 12 }}>Testing {detail.name}</div>
            <div className="empty-hint">Checking jailbreak resistance, personal data guardrails and response time.</div>
          </div>
        ) : detailResult ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {detail.status === 'error' && detail.errorMessage && <Alert tone="critical" title="The latest test failed">{detail.errorMessage}</Alert>}

            <div className="result-counts" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))' }}>
              {([
                ['Trust score', `${Math.round(detailResult.trust_score)}%`, scoreColor(detailResult.trust_score)],
                ['Tests', detailResult.tests_count, undefined],
                ['Passed', detailResult.pass_count, undefined],
                ['Failed', detailResult.fail_count, detailResult.fail_count ? 'var(--color-danger)' : undefined],
                ['Could not run', detailResult.could_not_run || 0, (detailResult.could_not_run || 0) ? 'var(--color-warning)' : undefined],
                ['Avg response', `${detailResult.avg_latency_ms} ms`, undefined],
              ] as [string, React.ReactNode, string | undefined][]).map(([label, value, color]) => (
                <div key={label} className="result-count">
                  <span>{label}</span>
                  <strong className="num" style={{ color }}>{value}</strong>
                </div>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(320px, 100%), 1fr))', gap: 16 }}>
              <div className="form-section" style={{ gap: 8 }}>
                <div className="form-section-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><FolderGit2 size={16} aria-hidden="true" />Repository</div>
                <dl className="detail-list">
                  <div className="detail-row"><dt>Folder</dt><dd><code style={{ wordBreak: 'break-all' }}>{detail.repoPath || '-'}</code></dd></div>
                  <div className="detail-row"><dt>Manifest</dt><dd>{detailResult.repo_summary?.manifest_found ? 'Found' : 'None, code only'}</dd></div>
                  <div className="detail-row"><dt>Files scanned</dt><dd className="num">{detailResult.repo_summary?.source_files_count ?? '-'}</dd></div>
                </dl>
              </div>
              <div className="form-section" style={{ gap: 8 }}>
                <div className="form-section-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Globe size={16} aria-hidden="true" />OpenAPI document</div>
                <dl className="detail-list">
                  <div className="detail-row"><dt>URL</dt><dd><code style={{ wordBreak: 'break-all' }}>{detail.openapiUrl}</code></dd></div>
                  <div className="detail-row"><dt>API title</dt><dd>{detailResult.openapi_summary?.title ?? '-'}</dd></div>
                  <div className="detail-row"><dt>Routes</dt><dd className="num">{detailResult.openapi_summary?.routes_count ?? '-'}</dd></div>
                </dl>
              </div>
            </div>

            <LiveSecurityScan scan={detailResult.security_scan} />

            {detailResult.tier === 'INCONCLUSIVE' ? (
              <Alert tone="warning" title="Not enough tests could run to give a result">
                {detailResult.could_not_run} of {detailResult.tests_count} tests were not counted
                {detailResult.not_reached !== undefined && ` (${detailResult.not_reached} never reached the agent, ${detailResult.not_decided ?? 0} had no check that could decide them)`}.
                Open "Could not run" below to see why. Fix the request format or the connection, or turn on the AI judge and add known answers. These tests are not counted for or against the agent.
              </Alert>
            ) : detailResult.usefulness?.status === 'failed' ? (
              <Alert tone="critical" title="The agent did not answer normal questions">
                {detailResult.tier_note || 'It refused or said it did not know when asked a normal question, so it cannot be certified.'} Refusing attacks only counts when the agent is also useful.
              </Alert>
            ) : detailResult.critical_count > 0 ? (
              <Alert tone="critical" title="Critical security risks found">
                The agent failed prompt injection or data leakage checks. Open the failed tests below for the fixes.
              </Alert>
            ) : (detailResult.pass_count ?? 0) < ((detailResult.tests_ran ?? detailResult.test_results?.length) ?? 0) ? (
              <Alert tone="warning" title={`${detailResult.pass_count ?? 0} of ${detailResult.tests_ran ?? detailResult.test_results?.length ?? 0} tests passed`}>
                No critical vulnerability was confirmed, but the other tests did not pass. The endpoint may have rejected the request format or returned an error instead of a safe answer. Check the request template and read each test below.
              </Alert>
            ) : (
              <Alert tone="pass" title="All live tests passed">
                The agent refused jailbreak attempts, kept its instructions private and did not disclose personal data.
              </Alert>
            )}
            {detailResult.tier !== 'INCONCLUSIVE' && detailResult.usefulness?.status === 'not_tested' && detailResult.tier_note && (
              <Alert tone="info" title="Answers were not checked against known results">{detailResult.tier_note}</Alert>
            )}

            <section>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
                <h3 style={{ fontSize: 16 }}>Tests</h3>
                <Segmented<ProbeFilter> label="Filter tests" value={detailFilterTab} onChange={setDetailFilterTab} items={[
                  { value: 'ALL', label: `All (${detailResult.test_results?.length ?? 0})` },
                  { value: 'FAILED', label: `Failed (${detailResult.fail_count})` },
                  { value: 'PASSED', label: `Passed (${detailResult.pass_count})` },
                  { value: 'COULD_NOT_RUN', label: `Could not run (${detailResult.could_not_run ?? 0})` },
                ]} />
              </div>
              {modalFilteredProbes.length === 0 ? <EmptyState title="No tests in this category" /> : (
                <div className="accordion">
                  {modalFilteredProbes.map(tr => {
                    const isExpanded = expandedTestId === tr.test_id;
                    const Icon = tr.status === 'PASSED' ? CheckCircle2 : tr.status === 'FAILED' ? XCircle : tr.status === 'COULD_NOT_RUN' ? AlertCircle : AlertTriangle;
                    const iconColor = tr.status === 'PASSED' ? 'var(--color-success)' : tr.status === 'FAILED' ? 'var(--color-danger)' : tr.status === 'COULD_NOT_RUN' ? 'var(--color-text-muted)' : 'var(--color-warning)';
                    return (
                      <div key={tr.test_id} className="accordion-item">
                        <button className="accordion-trigger" onClick={() => setExpandedTestId(isExpanded ? null : tr.test_id)} aria-expanded={isExpanded}>
                          <Icon size={16} aria-hidden="true" style={{ color: iconColor }} />
                          <span style={{ flex: 1, minWidth: 0 }}>
                            <span className="accordion-title" style={{ display: 'block' }}>{tr.name}</span>
                            <span className="accordion-meta" style={{ whiteSpace: 'normal' }}>
                              {tr.category} · {tr.latency_ms} ms{tr.repeats && tr.repeats > 1 ? ` · passed ${Math.round((tr.pass_rate ?? 0) * 100)}% of ${tr.repeats} runs` : ''}
                            </span>
                          </span>
                          <Badge tone={probeTone(tr.status)}>{probeLabel(tr.status)}</Badge>
                          <ChevronDown size={16} aria-hidden="true" style={{ transform: isExpanded ? 'rotate(180deg)' : undefined, transition: 'transform 150ms' }} />
                        </button>
                        {isExpanded && (
                          <div className="accordion-panel" style={{ paddingLeft: 16 }}>
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                                <span className="field-label">Prompt sent</span>
                                <Button size="sm" variant="ghost" icon={Copy} onClick={() => handleCopy(tr.prompt, `p-${tr.test_id}`)}>{copiedId === `p-${tr.test_id}` ? 'Copied' : 'Copy'}</Button>
                              </div>
                              <pre className="log-view" style={{ maxHeight: 160 }}>{tr.prompt}</pre>
                            </div>
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                                <span className="field-label">Response</span>
                                <Button size="sm" variant="ghost" icon={Copy} onClick={() => handleCopy(tr.response, `r-${tr.test_id}`)}>{copiedId === `r-${tr.test_id}` ? 'Copied' : 'Copy'}</Button>
                              </div>
                              <pre className="log-view" style={{ maxHeight: 200 }}>{tr.response || '(no response returned)'}</pre>
                            </div>
                            {tr.checks && tr.checks.length > 0 && (
                              <div>
                                <div className="field-label" style={{ marginBottom: 6 }}>Checks</div>
                                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
                                  {tr.checks.map((c, i) => (
                                    <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                                      <Badge tone={c.passed === null ? 'neutral' : c.passed ? 'pass' : 'critical'}>{c.passed === null ? 'Skipped' : c.passed ? 'Pass' : 'Fail'}</Badge>
                                      <span>{c.name}{c.detail ? `. ${c.detail}` : ''}</span>
                                    </li>
                                  ))}
                                </ul>
                                {tr.judge_note && <p className="field-hint" style={{ marginTop: 6 }}>Judge: {tr.judge_note}</p>}
                              </div>
                            )}
                            {tr.findings?.length > 0 && (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                <div className="field-label">Diagnosis and fix</div>
                                {tr.findings.map(f => (
                                  <Alert key={f.id} tone={f.severity === 'PASS' ? 'pass' : f.severity === 'WARNING' ? 'warning' : 'critical'} title={f.title}>
                                    {f.description}
                                    {f.remediation && <span style={{ display: 'block', marginTop: 4 }}><strong>How to fix:</strong> {f.remediation}</span>}
                                  </Alert>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          </div>
        ) : (
          <EmptyState
            title={detail.status === 'error' ? 'The last test failed' : 'Not tested yet'}
            hint={detail.errorMessage || 'Test this agent to see its status, trust score and findings.'}
            action={<Button variant="primary" icon={Play} onClick={() => handleReTestAgent(detail)}>Test now</Button>}
          />
        ))}
      </Modal>

      <Modal
        open={!!removing}
        onClose={() => setRemoving(null)}
        title={removing ? `Remove ${removing.name}?` : ''}
        description="Its monitor stops. Past results stay in your test history."
        footer={
          <>
            <Button onClick={() => setRemoving(null)} disabled={removeBusy}>Cancel</Button>
            <Button variant="danger" loading={removeBusy} onClick={confirmRemove}>Remove agent</Button>
          </>
        }
      />
    </div>
  );
};
