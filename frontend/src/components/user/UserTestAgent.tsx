import React, { useState, useEffect, useRef } from 'react';
import { useStickyState } from '../../utils/stickyState';
import {
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  Play,
  ShieldCheck,
  Terminal,
  Upload,
  X,
  Plus,
} from 'lucide-react';
import { generatePDFReport } from '../../utils/pdfExport';
import { apiFetch } from '../../utils/apiClient';
import {
  Alert, Badge, Button, Disclosure, EmptyState, Field, Modal, PageHeader, Panel, Segmented, SimulatedNotice, Tabs, TierBadge,
  modeLabel, scoreColor, type Tone, fmtScore,
} from '../ui';
import { BACKEND_URL } from '../../utils/apiConfig';
import { ReportDownloadMenu } from '../ReportDownload';
import { CertificateView } from '../CertificateView';

interface UserTestAgentProps {
  user: {
    id: number | string;
    name: string;
    email: string;
    role: string;
  };
  onTestCompleted?: (result: any) => void;
  preselectedAgentName?: string;
  onNavigate?: (tab: string) => void;
}

// Labels are matched against the engine's log lines to track progress. Change them only together with the engine.
const ALL_PHASES = [
  { id: 'architecture', label: 'Architecture & Limits' },
  { id: 'reliability', label: 'Reliability & Timeouts' },
  { id: 'security', label: 'Security & Prompt Injection' },
  { id: 'observability', label: 'Observability & Tracing' },
  { id: 'ops', label: 'Operational Readiness' },
  { id: 'adversarial', label: 'Adversarial Robustness' },
  { id: 'supply_chain', label: 'Supply Chain & Dependencies' },
  { id: 'data_governance', label: 'Data Governance & PII' },
  { id: 'groundedness', label: 'Groundedness & Accuracy' },
  { id: 'fairness', label: 'Fairness & Bias Parity' },
  { id: 'multi_turn', label: 'Multi-Turn Memory Safety' },
  { id: 'mcp', label: 'Model Context Protocol (MCP)' },
  { id: 'voice', label: 'Voice Agent Safety (v7)' },
  { id: 'data_analysis', label: 'Data Analysis SQL Safety (v7)' },
  { id: 'decision', label: 'Decision & Action Safety (v7)' },
  { id: 'security_agent', label: 'SecOps Agent Safety (v7)' },
  { id: 'browser', label: 'Browser Agent Safety (v7)' }
];

const DEFAULT_PHASES = ['architecture', 'reliability', 'security', 'observability', 'ops', 'adversarial', 'data_governance'];

export interface LivePhaseItem {
  id: string;
  label: string;
  status: 'completed' | 'active' | 'queued' | 'failed';
  duration?: string;
  findingCount?: number;
  activeTask?: string;
}

export interface ParsedManifest {
  agentName: string;
  tools: string[];
  destructive: string[];
  pii: string[];
  requiresHitl: boolean;
}

type InputType = 'agent_select' | 'yaml' | 'repo' | 'openapi';
type FindingFilter = 'ALL' | 'CRITICAL' | 'WARNING' | 'PASS';

export function parseManifestFromInput(
  type: InputType,
  yamlStr: string,
  selectedCard: string,
  agents: any[],
  repoPathStr: string,
  openapiUrlStr: string
): ParsedManifest {
  if (type === 'agent_select') {
    const selectedAg = agents.find(a => a.name === selectedCard || a.canonical_agent_name === selectedCard);
    let toolsList: string[] = [];
    let piiList: string[] = [];
    let destTools: string[] = [];

    if (selectedAg) {
      if (selectedAg.capabilities) {
        try {
          toolsList = typeof selectedAg.capabilities === 'string' ? JSON.parse(selectedAg.capabilities) : selectedAg.capabilities;
        } catch { /* keep empty */ }
      }
      if (selectedAg.pii_fields) {
        try {
          piiList = typeof selectedAg.pii_fields === 'string' ? JSON.parse(selectedAg.pii_fields) : selectedAg.pii_fields;
        } catch { /* keep empty */ }
      }
      if (selectedAg.destructive_tools) {
        try {
          destTools = typeof selectedAg.destructive_tools === 'string' ? JSON.parse(selectedAg.destructive_tools) : selectedAg.destructive_tools;
        } catch { /* keep empty */ }
      }
    }

    return { agentName: selectedCard, tools: toolsList, pii: piiList, destructive: destTools, requiresHitl: false };
  }

  if (type === 'openapi') {
    const urlName = openapiUrlStr.split('/').filter(Boolean).pop()?.replace('.json', '') || 'OpenAPI Target';
    return { agentName: urlName.replace(/_/g, ' '), tools: [], pii: [], destructive: [], requiresHitl: false };
  }

  if (type === 'repo') {
    const dirName = repoPathStr.replace(/\\/g, '/').split('/').filter(Boolean).pop() || 'Repository Codebase';
    return { agentName: dirName, tools: [], pii: [], destructive: [], requiresHitl: false };
  }

  // YAML parsing
  const getList = (key: string): string[] => {
    const regex = new RegExp(`${key}:\\s*\\n((?:\\s*-\\s*[^\\n]+\\n?)*)`, 'i');
    const match = yamlStr.match(regex);
    if (!match || !match[1]) return [];
    return match[1]
      .split('\n')
      .map(line => line.replace(/^\s*-\s*/, '').trim())
      .filter(item => item.length > 0 && !item.startsWith('#'));
  };

  const getScalar = (key: string): string => {
    const match = yamlStr.match(new RegExp(`${key}:\\s*([^\\n]+)`, 'i'));
    return match ? match[1].trim().replace(/^['"]|['"]$/g, '') : '';
  };

  const name = getScalar('agent_name') || getScalar('name') || selectedCard || 'Unnamed agent';
  return {
    agentName: name,
    tools: getList('tools'),
    destructive: getList('destructive_tools'),
    pii: getList('pii_fields'),
    requiresHitl: yamlStr.toLowerCase().includes('requires_hitl: true'),
  };
}

const sevTone = (sev: string): Tone => (sev === 'CRITICAL' ? 'critical' : sev === 'WARNING' || sev === 'HIGH' ? 'warning' : sev === 'PASS' ? 'pass' : 'neutral');

const verdict = (t: any) => {
  if (t.tier === 'FRAMEWORK_VALIDATION_ONLY') return 'Run against a mock target, so this result does not certify the agent.';
  if (t.tier === 'INCONCLUSIVE') return 'The agent never answered, so nothing could be judged. Check its address and login settings, then run it again.';
  if (t.untested_phases?.length) return `${t.untested_phases.length} phase${t.untested_phases.length === 1 ? '' : 's'} could not be tested, so this result cannot certify the agent. ${(t.critical_count || 0) > 0 ? 'Fix the critical findings too.' : ''}`.trim();
  if (t.tier === 'CERTIFIED') return 'No critical findings, a score of 90 or more and at most 3 warnings.';
  if ((t.critical_count || 0) > 0) return `${t.critical_count} critical finding${t.critical_count === 1 ? '' : 's'} to fix before deployment.`;
  return 'Review the warnings before deployment.';
};

export const UserTestAgent: React.FC<UserTestAgentProps> = ({
  user,
  onTestCompleted,
  preselectedAgentName,
}) => {
  // The page comes back as it was left (setup, a test still running, or its result) until "New test"
  const stickyKey = `testAgent:${user?.id ?? 'anon'}:`;

  // Wizard state: 'config' | 'running' | 'result'
  const [screenState, setScreenState] = useStickyState<'config' | 'running' | 'result'>(`${stickyKey}screenState`, 'config');

  // Config parameters
  const [inputType, setInputType] = useStickyState<InputType>(`${stickyKey}inputType`, preselectedAgentName ? 'agent_select' : 'yaml');
  const [availableAgents, setAvailableAgents] = useState<any[]>([]);
  const [selectedAgentCard, setSelectedAgentCard] = useStickyState<string>(`${stickyKey}selectedAgentCard`, preselectedAgentName || '');
  const [yamlContent, setYamlContent] = useStickyState<string>(`${stickyKey}yamlContent`, '');
  const [repoPath, setRepoPath] = useStickyState<string>(`${stickyKey}repoPath`, '');
  const [openapiUrl, setOpenapiUrl] = useStickyState<string>(`${stickyKey}openapiUrl`, '');
  const [testMode, setTestMode] = useStickyState<'validate' | 'certify'>(`${stickyKey}testMode`, 'certify');
  const [runsCount, setRunsCount] = useStickyState<number>(`${stickyKey}runsCount`, 20);
  const [concurrency, setConcurrency] = useStickyState<number>(`${stickyKey}concurrency`, 10);
  const [selectedPhases, setSelectedPhases] = useStickyState<string[]>(`${stickyKey}selectedPhases`, DEFAULT_PHASES);
  const fileInput = useRef<HTMLInputElement>(null);

  // Live execution state
  const [progress, setProgress] = useStickyState<number>(`${stickyKey}progress`, 0);
  const [currentPhaseLabel, setCurrentPhaseLabel] = useStickyState<string>(`${stickyKey}currentPhaseLabel`, 'Starting');
  const [terminalLogs, setTerminalLogs] = useStickyState<string[]>(`${stickyKey}terminalLogs`, []);
  const [runError, setRunError] = useStickyState<string | null>(`${stickyKey}runError`, null);
  const logRef = useRef<HTMLPreElement>(null);

  // Live state comes only from the engine's events and the manifest
  const [livePhaseStatuses, setLivePhaseStatuses] = useStickyState<LivePhaseItem[]>(`${stickyKey}livePhaseStatuses`, []);
  const [liveFindings, setLiveFindings] = useStickyState<{ severity: string; message: string }[]>(`${stickyKey}liveFindings`, []);
  const [liveManifestInfo, setLiveManifestInfo] = useStickyState<ParsedManifest | null>(`${stickyKey}liveManifestInfo`, null);
  const [livePassCount, setLivePassCount] = useStickyState(`${stickyKey}livePassCount`, 0);
  const [liveWarnCount, setLiveWarnCount] = useStickyState(`${stickyKey}liveWarnCount`, 0);
  const [liveCritCount, setLiveCritCount] = useStickyState(`${stickyKey}liveCritCount`, 0);
  const [liveHighCount, setLiveHighCount] = useStickyState(`${stickyKey}liveHighCount`, 0);

  // Result state
  const [testResult, setTestResult] = useStickyState<any | null>(`${stickyKey}testResult`, null);
  const [resultViewTab, setResultViewTab] = useStickyState<'report' | 'timeline'>(`${stickyKey}resultViewTab`, 'timeline');
  const [findingFilter, setFindingFilter] = useStickyState<FindingFilter>(`${stickyKey}findingFilter`, 'ALL');
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [isCertModalOpen, setIsCertModalOpen] = useState<boolean>(false);

  const [handledPreselect, setHandledPreselect] = useStickyState<string>(`${stickyKey}handledPreselect`, '');
  useEffect(() => {
    if (!preselectedAgentName) {
      if (handledPreselect) setHandledPreselect('');   // so picking the same agent again later opens its setup
      return;
    }
    if (preselectedAgentName === handledPreselect) return;
    setHandledPreselect(preselectedAgentName);
    if (screenState !== 'running') {
      setScreenState('config');
      setTestResult(null);
    }
    setInputType('agent_select');
    setSelectedAgentCard(preselectedAgentName);
  }, [preselectedAgentName, handledPreselect, screenState, setHandledPreselect, setScreenState, setTestResult, setInputType, setSelectedAgentCard]);

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const res = await apiFetch('/api/user/agents');
        if (res.ok) {
          const data = await res.json();
          setAvailableAgents(data.agents || []);
          // Keep the agent already chosen; pick the first saved agent only when none is
          if (!preselectedAgentName && data.agents && data.agents.length > 0) {
            setSelectedAgentCard(prev => prev || data.agents[0].name);
          }
        }
      } catch {
        /* the saved-agent source stays hidden */
      }
    };
    fetchAgents();
  }, [user?.id, preselectedAgentName]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [terminalLogs]);

  const togglePhase = (phaseId: string) => {
    setSelectedPhases(prev => (prev.includes(phaseId) ? prev.filter(p => p !== phaseId) : [...prev, phaseId]));
  };

  const handleSelectAllPhases = () => {
    if (selectedPhases.length === ALL_PHASES.length) setSelectedPhases(DEFAULT_PHASES);
    else setSelectedPhases(ALL_PHASES.map(p => p.id));
  };

  const readFile = (file?: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = event => {
      setYamlContent((event.target?.result as string) || '');
      setInputType('yaml');
    };
    reader.readAsText(file);
  };

  const sourceReady =
    inputType === 'agent_select' ? selectedAgentCard.trim() !== '' :
    inputType === 'yaml' ? yamlContent.trim() !== '' :
    inputType === 'repo' ? repoPath.trim() !== '' :
    openapiUrl.trim() !== '';
  const canStartAudit = sourceReady && selectedPhases.length > 0;
  const startHint = !sourceReady ? 'Add an agent source to start.' : selectedPhases.length === 0 ? 'Pick at least one phase.' : undefined;

  // Start the audit and read the engine's server-sent events
  const handleStartAudit = async () => {
    setScreenState('running');
    setProgress(5);
    setTerminalLogs([]);
    setRunError(null);
    setLiveFindings([]);
    setLivePassCount(0);
    setLiveWarnCount(0);
    setLiveCritCount(0);
    setLiveHighCount(0);
    setTestResult(null);
    setResultViewTab('timeline');
    setFindingFilter('ALL');
    setExpandedFinding(null);

    const initialManifest = parseManifestFromInput(inputType, yamlContent, selectedAgentCard, availableAgents, repoPath, openapiUrl);
    setLiveManifestInfo(initialManifest);

    const initialPhases: LivePhaseItem[] = selectedPhases.map((id, idx) => ({
      id,
      label: ALL_PHASES.find(p => p.id === id)?.label || id,
      status: idx === 0 ? 'active' : 'queued',
      duration: '',
      findingCount: 0,
      activeTask: idx === 0 ? 'Checking architecture and safety limits' : 'Queued'
    }));
    setLivePhaseStatuses(initialPhases);
    setCurrentPhaseLabel(`Testing ${initialPhases[0]?.label || ''}`);

    const payload: any = {
      mode: testMode,
      runs: testMode === 'validate' ? 1 : runsCount,
      concurrency: concurrency,
      selected_phases: selectedPhases,
      user_id: user.id,
      tested_by_email: user.email,
      tested_by_name: user.name,
      user_role: 'USER'
    };

    if (inputType === 'agent_select') {
      const selectedAg = availableAgents.find(a => a.name === selectedAgentCard || a.canonical_agent_name === selectedAgentCard);
      const cleanName = selectedAgentCard.toLowerCase().replace(/ /g, '_');
      let toolsList: string[] = [];
      let piiList: string[] = [];
      let destTools: string[] = [];

      if (selectedAg) {
        if (selectedAg.capabilities) {
          try {
            toolsList = typeof selectedAg.capabilities === 'string' ? JSON.parse(selectedAg.capabilities) : selectedAg.capabilities;
          } catch { /* keep empty */ }
        }
        if (selectedAg.pii_fields) {
          try {
            piiList = typeof selectedAg.pii_fields === 'string' ? JSON.parse(selectedAg.pii_fields) : selectedAg.pii_fields;
          } catch { /* keep empty */ }
        }
        if (selectedAg.destructive_tools) {
          try {
            destTools = typeof selectedAg.destructive_tools === 'string' ? JSON.parse(selectedAg.destructive_tools) : selectedAg.destructive_tools;
          } catch { /* keep empty */ }
        }
      }

      // The server adds the agent's address and login settings from its last real audit
      if (selectedAg?.id) {
        payload.agent_id = selectedAg.id;
        payload.agent_kind = selectedAg.agent_kind;
      }
      payload.yaml_content = `agent_name: ${cleanName}
version: 1.0.0
capabilities:
  max_steps: 10
  context_budget_tokens: 8000
  tools:
${toolsList.length > 0 ? toolsList.map(t => `    - ${t}`).join('\n') : '    []'}
  destructive_tools:
${destTools.length > 0 ? destTools.map(t => `    - ${t}`).join('\n') : '    []'}
security:
  pii_fields:
${piiList.length > 0 ? piiList.map(p => `    - ${p}`).join('\n') : '    []'}
`;
    } else if (inputType === 'yaml') {
      payload.yaml_content = yamlContent;
    } else if (inputType === 'repo') {
      payload.repo_path = repoPath;
    } else if (inputType === 'openapi') {
      payload.openapi_url = openapiUrl;
    }

    try {
      const response = await apiFetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok || !response.body) {
        // Show the server's reason (for example "Admins can view tests but cannot run them"), not just the status
        const err = await response.json().catch(() => null);
        const reason = typeof err?.detail === 'string' ? err.detail : response.statusText || `HTTP ${response.status}`;
        throw new Error(`The audit could not start: ${reason}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const event = JSON.parse(line.slice(6));
            if (event.type === 'log') {
              const msg: string = event.message || '';
              setTerminalLogs(prev => [...prev, msg]);

              // Phase start, e.g. "starting Phase 1 · Architecture"
              const startMatch = msg.match(/starting\s+(?:Phase\s+\d+\s+[·:]\s+)?([^\s—\n][^—\n]+)/i);
              if (startMatch) {
                const rawName = startMatch[1].trim().toLowerCase();
                setLivePhaseStatuses(prev => prev.map(p => {
                  const pLabel = p.label.toLowerCase();
                  const pId = p.id.toLowerCase();
                  if (pLabel.includes(rawName) || rawName.includes(pId) || rawName.includes(pLabel.split(' ')[0])) {
                    setCurrentPhaseLabel(`Testing ${p.label}`);
                    return { ...p, status: 'active', activeTask: 'Running probes and compliance checks' };
                  }
                  return p;
                }));
              }

              // Phase end, e.g. "completed Phase 1 · Architecture — 3 finding(s) in 12ms"
              const compMatch = msg.match(/completed\s+(?:Phase\s+\d+\s+[·:]\s+)?([^\s—\n][^—\n]+?)(?:\s*—\s*(\d+)\s+finding\(s\)\s+in\s+([\d.]+ms))?/i);
              if (compMatch) {
                const rawName = compMatch[1].trim().toLowerCase();
                const findingsInPhase = compMatch[2] ? parseInt(compMatch[2], 10) : 0;
                const phaseDur = compMatch[3] || '';
                setLivePassCount(p => p + 1);
                setLivePhaseStatuses(prev => {
                  const updated = [...prev];
                  const matchIdx = updated.findIndex(p => {
                    const pLabel = p.label.toLowerCase();
                    const pId = p.id.toLowerCase();
                    return pLabel.includes(rawName) || rawName.includes(pId) || rawName.includes(pLabel.split(' ')[0]);
                  });
                  if (matchIdx !== -1) {
                    updated[matchIdx] = { ...updated[matchIdx], status: 'completed', duration: phaseDur, findingCount: findingsInPhase, activeTask: `Completed in ${phaseDur}` };
                    const nextQueued = updated.findIndex((p, i) => i > matchIdx && p.status === 'queued');
                    if (nextQueued !== -1) {
                      updated[nextQueued] = { ...updated[nextQueued], status: 'active', activeTask: 'Running probes and compliance checks' };
                      setCurrentPhaseLabel(`Testing ${updated[nextQueued].label}`);
                    }
                  }
                  return updated;
                });
              }

              // Findings reported in the log. Messages about the server's own setup (such as a missing
              // certificate signing key) stay in the engine log and are not counted against the agent.
              const isServerNotice = /\bcertificate ::|SIGNING_KEY|^=+$/m.test(msg);
              if (isServerNotice) {
                // engine log only
              } else if (/\[CRITICAL\]|CRITICAL FAILURE|critical error/i.test(msg)) {
                setLiveCritCount(p => p + 1);
                setLiveFindings(prev => [...prev, { severity: 'CRITICAL', message: msg.replace(/\[.*?\]/g, '').trim().slice(0, 140) }]);
              } else if (/\[HIGH\]|high severity|HIGH_UNCERTAINTY/i.test(msg)) {
                setLiveHighCount(p => p + 1);
                setLiveFindings(prev => [...prev, { severity: 'HIGH', message: msg.replace(/\[.*?\]/g, '').trim().slice(0, 140) }]);
              } else if (/\[WARN\]|\[WARNING\]|warning/i.test(msg)) {
                setLiveWarnCount(p => p + 1);
                setLiveFindings(prev => [...prev, { severity: 'WARNING', message: msg.replace(/\[.*?\]/g, '').trim().slice(0, 140) }]);
              } else if (/\[PASS\]|passed|complete \(/i.test(msg)) {
                setLivePassCount(p => p + 1);
              }
            } else if (event.type === 'progress') {
              setProgress(event.val);
            } else if (event.type === 'result') {
              setProgress(100);
              const data = event.data;
              setTestResult(data);
              if (data?.manifest_summary) {
                const caps = data.manifest_summary.capabilities || {};
                const sec = data.manifest_summary.security || {};
                setLiveManifestInfo({
                  agentName: data.agent_name || selectedAgentCard,
                  tools: Array.isArray(caps.tools) ? caps.tools : [],
                  destructive: Array.isArray(caps.destructive_tools) ? caps.destructive_tools : [],
                  pii: Array.isArray(sec.pii_fields) ? sec.pii_fields : [],
                  requiresHitl: !!caps.requires_hitl
                });
              }
              setLiveCritCount(data?.critical_count ?? 0);
              setLiveWarnCount(data?.warning_count ?? 0);
              setLivePassCount(data?.pass_count ?? 0);
              setLivePhaseStatuses(prev => prev.map(p => ({ ...p, status: 'completed', duration: p.duration || '', activeTask: 'Completed' })));
              if (onTestCompleted) onTestCompleted(data);
            } else if (event.type === 'error') {
              setTerminalLogs(prev => [...prev, `[CRITICAL ERROR] ${event.detail}`]);
              setRunError(event.detail || 'The audit engine reported an error.');
              setLiveCritCount(p => p + 1);
              setLiveFindings(prev => [...prev, { severity: 'CRITICAL', message: event.detail || 'Audit engine error' }]);
            }
          } catch {
            // Ignore a line that is not valid JSON
          }
        }
      }
    } catch (err: any) {
      setTerminalLogs(prev => [...prev, `[CRITICAL FAILURE] ${err.message}`, `[info] Ensure the backend API server is running on ${BACKEND_URL}`]);
      setRunError(`${err.message || 'The audit could not run.'} Check that the API is running at ${BACKEND_URL}.`);
      setLiveCritCount(p => p + 1);
      setLiveFindings(prev => [...prev, { severity: 'CRITICAL', message: err.message || 'Audit execution error' }]);
    }
  };

  const handleNewTest = () => {
    setTestResult(null);
    setRunError(null);
    setProgress(0);
    setTerminalLogs([]);
    setLivePhaseStatuses([]);
    setLiveFindings([]);
    setLiveManifestInfo(null);
    setLivePassCount(0);
    setLiveWarnCount(0);
    setLiveCritCount(0);
    setLiveHighCount(0);
    setResultViewTab('timeline');
    setFindingFilter('ALL');
    setExpandedFinding(null);
    setScreenState('config');
  };

  // generatePDFReport saves the file itself
  const handleDownloadPDF = () => {
    if (testResult) generatePDFReport(testResult);
  };

  // ==========================================
  // RUNNING AND RESULT
  // ==========================================
  if (screenState === 'running' || screenState === 'result') {
    const totalPhases = selectedPhases.length;
    const completedPhasesCount = livePhaseStatuses.filter(p => p.status === 'completed').length;
    const isCompleted = testResult !== null;
    const failed = !isCompleted && !!runError;
    const findingsList: any[] = testResult?.findings || [];
    const countOf = (sev: string) => findingsList.filter(f => (f.severity || 'PASS').toUpperCase() === sev).length;
    const filteredFindings = findingsList.filter(f => findingFilter === 'ALL' || (f.severity || 'PASS').toUpperCase() === findingFilter);
    const activeAgentTitle = liveManifestInfo?.agentName || selectedAgentCard;
    const cert = testResult?.certificate || testResult?.cert || null;
    const destructive = liveManifestInfo?.destructive || [];

    return (
      <div className="page-stack animate-slideup">
        <div className="panel">
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="page-head" style={{ alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0 }}>
                <h1 style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', fontSize: 20 }}>
                  {activeAgentTitle || 'Agent audit'}
                  {isCompleted ? <TierBadge tier={testResult.tier} /> : failed ? <Badge tone="critical" dot>Failed</Badge> : <Badge tone="info" dot>Running</Badge>}
                </h1>
                <p aria-live="polite">
                  {isCompleted
                    ? `Completed in ${testResult.total_duration_ms ? (testResult.total_duration_ms / 1000).toFixed(1) + 's' : '-'}${user?.name ? `, tested by ${user.name}` : ''}`
                    : failed ? 'The audit stopped before it finished.' : currentPhaseLabel}
                </p>
              </div>
              <div className="page-head-actions">
                {isCompleted ? (
                  <>
                    <ReportDownloadMenu name={testResult?.agent_name} onPdf={handleDownloadPDF} getReport={() => testResult} />
                    <Button icon={ShieldCheck} onClick={() => setIsCertModalOpen(true)}>Certificate</Button>
                    <Button variant="primary" icon={Plus} onClick={handleNewTest}>New test</Button>
                  </>
                ) : failed ? (
                  <Button variant="primary" icon={Plus} onClick={handleNewTest}>New test</Button>
                ) : (
                  <div style={{ textAlign: 'right' }}>
                    <div className="num" style={{ fontSize: 24, fontWeight: 600, color: 'var(--color-text)', lineHeight: 1.1 }}>{progress}%</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{completedPhasesCount} of {totalPhases} phases</div>
                  </div>
                )}
              </div>
            </div>
            <div className={`progress${isCompleted ? ' done' : ''}`} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress} aria-label="Audit progress">
              <span style={{ width: `${progress}%`, background: failed ? 'var(--color-danger)' : undefined }} />
            </div>
          </div>
          {isCompleted && (
            <div style={{ padding: '0 20px' }}>
              <Tabs<'timeline' | 'report'> label="Result view" value={resultViewTab} onChange={setResultViewTab} items={[
                { value: 'report', label: 'Report' }, { value: 'timeline', label: 'Execution' },
              ]} />
            </div>
          )}
        </div>

        {failed && (
          <Alert tone="critical" title="The audit could not finish" action={<Button size="sm" onClick={handleStartAudit}>Try again</Button>}>
            {runError}
          </Alert>
        )}

        {(!isCompleted || resultViewTab === 'timeline') && (
          <div className="split-aside">
            <div className="sticky-col" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <Panel title="Agent under test" subtitle={isCompleted ? 'Capabilities found in the manifest' : 'Read from the manifest'}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div>
                    <div className="field-label" style={{ marginBottom: 6 }}>Tools <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({liveManifestInfo?.tools?.length || 0})</span></div>
                    {liveManifestInfo?.tools?.length ? (
                      <div className="chip-list">{liveManifestInfo.tools.map((t, i) => <span key={i} className="badge mono">{t}</span>)}</div>
                    ) : <span className="field-hint">No tools declared.</span>}
                  </div>
                  <div>
                    <div className="field-label" style={{ marginBottom: 6 }}>Personal data fields <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({liveManifestInfo?.pii?.length || 0})</span></div>
                    {liveManifestInfo?.pii?.length ? (
                      <div className="chip-list">{liveManifestInfo.pii.map((p, i) => <Badge key={i} tone="warning">{p}</Badge>)}</div>
                    ) : <span className="field-hint">No personal data fields declared.</span>}
                  </div>
                  <Alert
                    tone={destructive.length ? 'warning' : 'pass'}
                    title={destructive.length ? `${destructive.length} action${destructive.length === 1 ? '' : 's'} that change data` : 'Read-only agent'}
                    action={<Badge tone={liveManifestInfo?.requiresHitl ? 'warning' : 'neutral'}>{liveManifestInfo?.requiresHitl ? 'Human approval' : 'Automated'}</Badge>}
                  >
                    {destructive.length ? destructive.join(', ') : 'No database or file writes declared.'}
                  </Alert>
                </div>
              </Panel>

              <Panel title={isCompleted ? 'Findings' : 'Findings so far'}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  {([
                    ['Critical', liveCritCount, liveCritCount ? 'var(--color-danger)' : undefined],
                    ['High', liveHighCount, liveHighCount ? 'var(--color-warning)' : undefined],
                    ['Warnings', liveWarnCount, liveWarnCount ? 'var(--color-warning)' : undefined],
                    ['Passed', livePassCount, undefined],
                  ] as [string, number, string | undefined][]).map(([label, value, color]) => (
                    <div key={label} className="result-count" style={{ padding: 12 }}>
                      <span>{label}</span>
                      <strong className="num" style={{ color, fontSize: 20 }}>{value}</strong>
                    </div>
                  ))}
                </div>
                {liveFindings.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
                    {liveFindings.slice(-3).map((f, idx) => (
                      <Alert key={idx} tone={f.severity === 'CRITICAL' ? 'critical' : 'warning'} title={f.severity === 'CRITICAL' ? 'Critical' : f.severity === 'HIGH' ? 'High' : 'Warning'}>
                        {f.message}
                      </Alert>
                    ))}
                  </div>
                ) : (
                  <div style={{ marginTop: 16 }}><Alert tone="pass" title="Nothing found so far">No vulnerabilities or privilege escalations detected yet.</Alert></div>
                )}
                <dl className="detail-list" style={{ marginTop: 16 }}>
                  <div className="detail-row"><dt>Mode</dt><dd>{testMode === 'validate' ? 'Validate (simulated)' : `Certify, ${runsCount} runs`}</dd></div>
                  <div className="detail-row"><dt>Phases</dt><dd className="num">{completedPhasesCount} of {totalPhases}</dd></div>
                </dl>
              </Panel>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 24, minWidth: 0 }}>
              <Panel title="Audit phases" subtitle={`${totalPhases} selected, ${completedPhasesCount} completed`}>
                <ol className="timeline">
                  {livePhaseStatuses.map((phase, idx) => {
                    const isLast = idx === livePhaseStatuses.length - 1;
                    const phaseFindings: any[] = (testResult?.findings || []).filter((f: any) => f.phase === phase.id);
                    const phaseCritical = phaseFindings.filter((f: any) => !f.passed && f.severity === 'CRITICAL').length;
                    const phaseWarnings = phaseFindings.filter((f: any) => !f.passed && (f.severity === 'WARNING' || f.severity === 'HIGH_UNCERTAINTY')).length;
                    const status = phase.status === 'active' && failed ? 'failed' : phase.status;
                    const cls = status === 'completed' ? 'done' : status;
                    return (
                      <li key={phase.id} className={`timeline-item ${cls}`}>
                        <div className="timeline-rail" aria-hidden="true">
                          <span className="timeline-node">
                            {status === 'completed' && <Check size={13} strokeWidth={3} />}
                            {status === 'active' && <span className="spinner" style={{ width: 10, height: 10, borderWidth: 2 }} />}
                            {status === 'failed' && <X size={13} strokeWidth={3} />}
                          </span>
                          {!isLast && <span className="timeline-line" />}
                        </div>
                        <div className="timeline-body">
                          <div style={{ minWidth: 0 }}>
                            <div className="timeline-title">{phase.label}</div>
                            <div className="timeline-meta">
                              {status === 'active' ? (phase.activeTask || 'Running checks')
                                : status === 'queued' ? 'Queued'
                                : status === 'failed' ? 'Stopped'
                                : [phaseFindings.length > 0 ? `${phaseFindings.length} checks` : '', phase.duration && phase.duration !== '-' ? `ran in ${phase.duration}` : ''].filter(Boolean).join(', ') || 'Completed'}
                            </div>
                          </div>
                          {status === 'completed' && (
                            phaseCritical > 0 ? <Badge tone="critical">{phaseCritical} critical</Badge>
                              : phaseWarnings > 0 ? <Badge tone="warning">{phaseWarnings} warning{phaseWarnings === 1 ? '' : 's'}</Badge>
                              : <Badge tone="pass">{phaseFindings.length > 0 ? 'Passed' : 'Complete'}</Badge>
                          )}
                          {status === 'active' && <Badge tone="info">Testing</Badge>}
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </Panel>

              <Disclosure title={`Engine log (${terminalLogs.length} lines)`} icon={Terminal} defaultOpen={failed}>
                {terminalLogs.length === 0 ? <span className="field-hint">Waiting for output.</span> : (
                  <pre className="log-view" ref={logRef} aria-live="off">{terminalLogs.join('\n')}</pre>
                )}
              </Disclosure>
            </div>
          </div>
        )}

        {isCompleted && resultViewTab === 'report' && (
          <div className="page-stack">
            <SimulatedNotice mode={testResult.mode} />

            <div className="result-summary">
              <div className="result-score">
                <span className="stat-label">Trust score</span>
                <span className="result-score-value" style={{ color: scoreColor(testResult.trust_score) }}>{fmtScore(testResult.trust_score)}%</span>
                <div className="meter" style={{ width: '100%' }}>
                  <span style={{ width: `${Math.max(0, Math.min(100, testResult.trust_score || 0))}%`, background: scoreColor(testResult.trust_score) }} />
                </div>
                <span style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>{verdict(testResult)}</span>
              </div>
              <div className="result-counts">
                {([
                  ['Critical', testResult.critical_count || 0, (testResult.critical_count || 0) > 0 ? 'var(--color-danger)' : undefined],
                  ['Warnings', testResult.warning_count || 0, (testResult.warning_count || 0) > 0 ? 'var(--color-warning)' : undefined],
                  ['Passed', testResult.pass_count || 0, undefined],
                  ['Total checks', (testResult.critical_count || 0) + (testResult.warning_count || 0) + (testResult.pass_count || 0), undefined],
                ] as [string, number, string | undefined][]).map(([label, value, color]) => (
                  <div key={label} className="result-count">
                    <span>{label}</span>
                    <strong className="num" style={{ color }}>{value}</strong>
                  </div>
                ))}
              </div>
            </div>

            <Panel title="Run details">
              <dl className="detail-list">
                <div className="detail-row"><dt>Audit ID</dt><dd><code>{testResult.audit_id || '-'}</code></dd></div>
                <div className="detail-row"><dt>Mode</dt><dd>{modeLabel(testResult.mode)}</dd></div>
                <div className="detail-row"><dt>Run time</dt><dd>{testResult.total_duration_ms ? `${(testResult.total_duration_ms / 1000).toFixed(2)}s` : '-'}</dd></div>
              </dl>
            </Panel>

            {testResult.audit_summary?.phase_scores && (
              <Panel title="Score by phase">
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(240px, 100%), 1fr))', gap: 16 }}>
                  {Object.entries(testResult.audit_summary.phase_scores).map(([phaseName, score]: [string, any]) => {
                    const color = score >= 80 ? 'var(--color-success)' : score >= 60 ? 'var(--color-warning)' : 'var(--color-danger)';
                    return (
                      <div key={phaseName}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 6 }}>
                          <span style={{ color: 'var(--color-text)', fontWeight: 500, textTransform: 'capitalize' }}>{phaseName.replace(/_/g, ' ')}</span>
                          <span className="num" style={{ fontWeight: 600, color: 'var(--color-text)' }}>{fmtScore(score)}%</span>
                        </div>
                        <div className="meter"><span style={{ width: `${Math.max(0, Math.min(100, score))}%`, background: color }} /></div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            )}

            <Panel
              title={`Findings (${filteredFindings.length})`}
              subtitle="Open a finding to see the standards it maps to, what was expected, what happened and how to fix it."
              actions={
                <Segmented<FindingFilter> label="Filter findings" value={findingFilter} onChange={v => { setFindingFilter(v); setExpandedFinding(null); }} items={[
                  { value: 'ALL', label: 'All' },
                  { value: 'CRITICAL', label: `Critical (${countOf('CRITICAL')})` },
                  { value: 'WARNING', label: `Warning (${countOf('WARNING')})` },
                  { value: 'PASS', label: `Pass (${countOf('PASS')})` },
                ]} />
              }
            >
              {filteredFindings.length === 0 ? (
                <EmptyState title="No findings in this category" />
              ) : (
                <div className="accordion">
                  {filteredFindings.map((f: any, idx: number) => {
                    const sev = (f.severity || 'PASS').toUpperCase();
                    const isOpen = expandedFinding === idx;
                    return (
                      <div key={idx} className="accordion-item">
                        <button className="accordion-trigger" onClick={() => setExpandedFinding(isOpen ? null : idx)} aria-expanded={isOpen}>
                          {isOpen ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
                          <Badge tone={sevTone(sev)}>{sev.charAt(0) + sev.slice(1).toLowerCase()}</Badge>
                          <span className="accordion-title cell-truncate" style={{ maxWidth: 'none' }}>{f.title || f.description || 'Compliance check'}</span>
                          <span className="accordion-meta cell-mono">{f.rule_id || f.id || f.check_id || `RULE-${idx + 1}`}</span>
                        </button>
                        {isOpen && (
                          <div className="accordion-panel">
                            {f.description && <p>{f.description}</p>}
                            {f.standards && f.standards.length > 0 && (
                              <div className="chip-list">
                                {f.standards.map((s: any, sIdx: number) => (
                                  <span key={sIdx} className="badge" title={s.name}>{s.framework} {s.identifier}</span>
                                ))}
                              </div>
                            )}
                            {f.expected && <p><strong>Expected: </strong>{f.expected}</p>}
                            {f.actual && <p><strong>Observed: </strong>{f.actual}</p>}
                            {f.remediation && <p><strong>How to fix: </strong>{f.remediation}</p>}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </Panel>
          </div>
        )}

        <Modal
          open={isCertModalOpen && !!testResult}
          onClose={() => setIsCertModalOpen(false)}
          title="Certificate"
          description={cert ? 'Signed by the CertifyAI audit engine.' : undefined}
          size="lg"
          footer={<Button onClick={() => setIsCertModalOpen(false)}>Close</Button>}
        >
          {testResult && (cert ? (
            <CertificateView
              cert={{ ...cert, agent_name: cert.agent_name || testResult.agent_name || activeAgentTitle, trust_score: cert.trust_score ?? testResult.trust_score, tier: cert.tier || testResult.tier }}
            />
          ) : (
            <Alert tone="info" title="No signed certificate for this run">
              A certificate is issued for certify runs that pass. Open Reports to see the signed certificate for each stored test.
            </Alert>
          ))}
        </Modal>
      </div>
    );
  }

  // ==========================================
  // SETUP
  // ==========================================
  const sourceTabs: { value: InputType; label: string }[] = [
    ...(availableAgents.length > 0 || inputType === 'agent_select' ? [{ value: 'agent_select' as InputType, label: 'Saved agent' }] : []),
    { value: 'yaml', label: 'YAML manifest' },
    { value: 'repo', label: 'Repository' },
    { value: 'openapi', label: 'OpenAPI' },
  ];

  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Test an agent"
        subtitle="Choose a source, a mode and the phases to run, then start the audit."
      />

      <div className="dash-split" style={{ gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1fr)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24, minWidth: 0 }}>
          <section className="panel">
            <div className="panel-head">
              <div>
                <h3><span className="step-label" aria-hidden="true">1</span>Agent source</h3>
                <p>Where the audit reads the agent's configuration from.</p>
              </div>
            </div>
            <div style={{ padding: '0 20px' }}>
              <Tabs<InputType> label="Agent source" value={inputType} onChange={setInputType} items={sourceTabs} />
            </div>
            <div className="panel-body">
              {inputType === 'agent_select' && (
                <Field label="Agent" hint="Uses the tools and data fields saved from its last test.">
                  <select className="form-input" value={selectedAgentCard} onChange={e => setSelectedAgentCard(e.target.value)}>
                    {!availableAgents.some(a => a.name === selectedAgentCard) && selectedAgentCard && <option value={selectedAgentCard}>{selectedAgentCard}</option>}
                    {availableAgents.map(a => <option key={a.id || a.name} value={a.name}>{a.name}</option>)}
                  </select>
                </Field>
              )}

              {inputType === 'yaml' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <label className="field-label" htmlFor="yaml-manifest">Manifest (YAML)</label>
                    <Button size="sm" icon={Upload} onClick={() => fileInput.current?.click()}>Upload file</Button>
                    <input ref={fileInput} type="file" accept=".yaml,.yml,.json" hidden onChange={e => { readFile(e.target.files?.[0]); e.target.value = ''; }} />
                  </div>
                  <textarea
                    id="yaml-manifest"
                    className="form-input mono"
                    style={{ minHeight: 240, lineHeight: 1.6 }}
                    value={yamlContent}
                    onChange={e => setYamlContent(e.target.value)}
                    placeholder={"agent_name: your_agent\nversion: '1.0'\ncapabilities:\n  tools:\n    - search_orders"}
                    spellCheck={false}
                  />
                  <span className="field-hint">Paste a manifest or upload a .yaml, .yml or .json file.</span>
                </div>
              )}

              {inputType === 'repo' && (
                <Field label="Local path or Git repository URL" hint="The audit reads the code. Nothing is changed.">
                  <input type="text" className="form-input mono" value={repoPath} onChange={e => setRepoPath(e.target.value)} placeholder="/path/to/agent or https://github.com/org/agent" />
                </Field>
              )}

              {inputType === 'openapi' && (
                <Field label="OpenAPI document URL" hint="An OpenAPI 3.x JSON or YAML document for the agent's API.">
                  <input type="url" className="form-input mono" value={openapiUrl} onChange={e => setOpenapiUrl(e.target.value)} placeholder="https://your-service/openapi.json" />
                </Field>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h3><span className="step-label" aria-hidden="true">2</span>Mode</h3>
                <p>Validate is a quick simulated check. Certify tests your real agent.</p>
              </div>
            </div>
            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="choice-grid" role="radiogroup" aria-label="Test mode">
                <label className="choice-card">
                  <input type="radio" name="test-mode" checked={testMode === 'certify'} onChange={() => setTestMode('certify')} />
                  <span>
                    <span className="choice-title">Certify (real agent)</span>
                    <span className="choice-text" style={{ display: 'block' }}>Reads the configuration and code, and calls your real agent for the behaviour tests.</span>
                  </span>
                </label>
                <label className="choice-card">
                  <input type="radio" name="test-mode" checked={testMode === 'validate'} onChange={() => setTestMode('validate')} />
                  <span>
                    <span className="choice-title">Validate (simulated)</span>
                    <span className="choice-text" style={{ display: 'block' }}>Checks the configuration against a built-in simulator. Your agent is not contacted, so scores are not real results.</span>
                  </span>
                </label>
              </div>
              <div className="form-grid">
                <Field label="Runs per check" hint={testMode === 'validate' ? 'Validate always runs once.' : 'More runs catch inconsistent answers. 1 to 50.'}>
                  <input type="number" className="form-input" min={1} max={50} value={testMode === 'validate' ? 1 : runsCount} disabled={testMode === 'validate'} onChange={e => setRunsCount(parseInt(e.target.value) || 1)} />
                </Field>
                <Field label="Parallel requests" hint="How many calls run at once. 1 to 20.">
                  <input type="number" className="form-input" min={1} max={20} value={concurrency} onChange={e => setConcurrency(parseInt(e.target.value) || 1)} />
                </Field>
              </div>
            </div>
          </section>
        </div>

        <section className="panel">
          <div className="panel-head">
            <div>
              <h3><span className="step-label" aria-hidden="true">3</span>Phases <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({selectedPhases.length} of {ALL_PHASES.length})</span></h3>
              <p>Each phase is a group of safety and compliance checks.</p>
            </div>
            <Button size="sm" variant="ghost" onClick={handleSelectAllPhases}>
              {selectedPhases.length === ALL_PHASES.length ? 'Reset to default' : 'Select all'}
            </Button>
          </div>
          <div className="panel-body">
            <div className="check-grid" role="group" aria-label="Audit phases">
              {ALL_PHASES.map(phase => (
                <label key={phase.id} className="check-tile">
                  <input type="checkbox" checked={selectedPhases.includes(phase.id)} onChange={() => togglePhase(phase.id)} />
                  <span>{phase.label}</span>
                </label>
              ))}
            </div>
          </div>
        </section>
      </div>

      <div className="sticky-actions" style={{ margin: 0, borderRadius: 8, border: '1px solid var(--color-border)' }}>
        <span className="sticky-actions-note">
          <Bot size={14} aria-hidden="true" style={{ marginRight: 6 }} />
          {startHint || `${testMode === 'validate' ? 'Validate' : 'Certify'} mode, ${selectedPhases.length} phase${selectedPhases.length === 1 ? '' : 's'}`}
        </span>
        <Button variant="primary" icon={Play} onClick={handleStartAudit} disabled={!canStartAudit}>Start audit</Button>
      </div>

    </div>
  );
};
