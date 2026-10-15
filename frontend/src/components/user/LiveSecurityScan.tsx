import React from 'react';
import { AlertTriangle, CheckCircle2, Database, FileSearch, KeyRound, Route, Trash2, Wrench, XCircle } from 'lucide-react';
import { Badge, type Tone } from '../ui';

interface ScanFinding {
  id: string;
  category: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'WARNING' | 'INFO';
  description: string;
  remediation?: string;
  locations?: string[];
}

interface OpenApiScan {
  available: boolean;
  routes: { method: string; path: string; summary: string; login: boolean; risk: 'high' | 'medium' | 'low'; reasons: string[] }[];
  findings: ScanFinding[];
  summary: { routes?: number; with_login?: number; without_login?: number; high_risk?: number; medium_risk?: number };
}

interface RepoScan {
  available: boolean;
  error?: string;
  path?: string;
  files_scanned?: number;
  database?: { used: boolean; technologies: { name: string; files: string[] }[]; raw_sql_files: number };
  destructive_operations?: { kind: string; severity: string; file: string; line: number; code: string }[];
  tools?: { name: string; file: string; line: number; destructive: boolean }[];
  secrets?: { kind: string; file: string; line: number; value: string; severity: string }[];
  findings: ScanFinding[];
  summary: { database_used?: boolean; destructive?: number; tools?: number; destructive_tools?: number; secrets?: number };
}

export interface SecurityScan {
  openapi: OpenApiScan;
  repo: RepoScan;
  combined: ScanFinding[];
  blocking_findings: number;
  high_findings: number;
}

const SEV_TONE: Record<string, Tone> = { CRITICAL: 'critical', HIGH: 'critical', WARNING: 'warning', INFO: 'neutral' };
const RISK_TONE: Record<string, Tone> = { high: 'critical', medium: 'warning', low: 'neutral' };

const Chip: React.FC<{ label: string; value: React.ReactNode; tone?: Tone }> = ({ label, value, tone = 'neutral' }) => (
  <div className={`scan-chip tone-${tone}`}><span>{label}</span><strong>{value}</strong></div>
);

const Findings: React.FC<{ items: ScanFinding[] }> = ({ items }) => {
  if (items.length === 0) return <div className="monitor-ok"><CheckCircle2 size={15} />Nothing risky found.</div>;
  return (
    <div className="monitor-issues">
      {items.map(f => (
        <div key={f.id} className={`monitor-issue ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'critical' : f.severity === 'WARNING' ? 'warning' : 'info'}`}>
          {f.severity === 'CRITICAL' || f.severity === 'HIGH' ? <XCircle size={15} /> : <AlertTriangle size={15} />}
          <div style={{ minWidth: 0 }}>
            <strong>{f.title} <Badge tone={SEV_TONE[f.severity]}>{f.severity === 'CRITICAL' ? 'Critical' : f.severity === 'HIGH' ? 'High' : f.severity === 'WARNING' ? 'Warning' : 'Info'}</Badge></strong>
            <span>{f.description}</span>
            {f.locations && f.locations.length > 0 && <span className="scan-locs">{f.locations.slice(0, 6).join('  |  ')}</span>}
            {f.remediation && <span><strong style={{ display: 'inline', fontWeight: 600 }}>How to fix:</strong> {f.remediation}</span>}
          </div>
        </div>
      ))}
    </div>
  );
};

const Block: React.FC<{ icon: React.ElementType; title: string; children: React.ReactNode }> = ({ icon: Icon, title, children }) => (
  <div className="scan-block">
    <div className="scan-block-title"><Icon size={15} />{title}</div>
    {children}
  </div>
);

/** What the OpenAPI description and the repo code show about risk, with no calls to the agent. */
export const LiveSecurityScan: React.FC<{ scan?: SecurityScan | null }> = ({ scan }) => {
  if (!scan) return null;
  const { openapi, repo, combined } = scan;
  const ops = (repo.destructive_operations || []).filter(d => d.severity !== 'INFO');
  const secrets = (repo.secrets || []).filter(s => s.severity !== 'INFO');
  const riskyRoutes = openapi.routes.filter(r => r.risk !== 'low' || !r.login);

  return (
    <div className="scan-wrap">
      <div className="scan-title">
        <span>Security scan</span>
        {scan.blocking_findings > 0
          ? <Badge tone="critical">{scan.blocking_findings} blocking</Badge>
          : scan.high_findings > 0 ? <Badge tone="warning">{scan.high_findings} high</Badge> : <Badge tone="pass">No blocking issues</Badge>}
      </div>

      <div className="scan-grid">
        <div className="scan-card">
          <div className="scan-card-head"><Route size={16} />OpenAPI scan<span>Risky routes and missing login</span></div>
          {!openapi.available ? (
            <div className="monitor-sub">The API description could not be read, so its routes were not scanned.</div>
          ) : (
            <>
              <div className="scan-chips">
                <Chip label="Routes" value={openapi.summary.routes ?? 0} />
                <Chip label="Need a login" value={openapi.summary.with_login ?? 0} tone="pass" />
                <Chip label="No login" value={openapi.summary.without_login ?? 0} tone={(openapi.summary.without_login ?? 0) > 0 ? 'warning' : 'pass'} />
                <Chip label="High risk" value={openapi.summary.high_risk ?? 0} tone={(openapi.summary.high_risk ?? 0) > 0 ? 'critical' : 'pass'} />
              </div>
              <Findings items={openapi.findings} />
              <Block icon={Route} title={`Routes (${openapi.routes.length})`}>
                <div style={{ overflowX: 'auto' }}>
                  <table className="scan-table">
                    <thead><tr><th>Method</th><th>Route</th><th>Login</th><th>Risk</th><th>Why</th></tr></thead>
                    <tbody>
                      {(riskyRoutes.length ? riskyRoutes : openapi.routes).slice(0, 40).map((r, i) => (
                        <tr key={i}>
                          <td><code>{r.method}</code></td>
                          <td><code>{r.path}</code></td>
                          <td>{r.login ? <Badge tone="pass">Required</Badge> : <Badge tone="warning">None</Badge>}</td>
                          <td><Badge tone={RISK_TONE[r.risk]}>{r.risk === 'high' ? 'High' : r.risk === 'medium' ? 'Medium' : 'Low'}</Badge></td>
                          <td>{r.reasons.join('. ') || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Block>
            </>
          )}
        </div>

        <div className="scan-card">
          <div className="scan-card-head"><FileSearch size={16} />Repository scan<span>Database, deletes, tools and secrets</span></div>
          {!repo.available ? (
            <div className="monitor-issue critical"><XCircle size={15} /><div><strong>The repository was not scanned</strong><span>{repo.error || 'The folder could not be read.'}</span></div></div>
          ) : (
            <>
              <div className="scan-chips">
                <Chip label="Files scanned" value={repo.files_scanned ?? 0} />
                <Chip label="Database" value={repo.summary.database_used ? 'Used' : 'None'} tone={repo.summary.database_used ? 'warning' : 'pass'} />
                <Chip label="Delete or drop" value={repo.summary.destructive ?? 0} tone={(repo.summary.destructive ?? 0) > 0 ? 'warning' : 'pass'} />
                <Chip label="Tools" value={repo.summary.tools ?? 0} />
                <Chip label="Secrets in code" value={repo.summary.secrets ?? 0} tone={(repo.summary.secrets ?? 0) > 0 ? 'critical' : 'pass'} />
              </div>
              <Findings items={repo.findings} />

              {repo.database?.used && (
                <Block icon={Database} title="Database access">
                  {repo.database.technologies.map(t => (
                    <div key={t.name} className="scan-line"><strong>{t.name}</strong><span>{t.files.slice(0, 4).join(', ')}</span></div>
                  ))}
                </Block>
              )}
              {ops.length > 0 && (
                <Block icon={Trash2} title={`Delete and drop operations (${ops.length})`}>
                  {ops.slice(0, 12).map((d, i) => (
                    <div key={i} className="scan-line"><Badge tone={d.severity === 'HIGH' ? 'critical' : 'warning'}>{d.kind}</Badge><code>{d.file}:{d.line}</code><span>{d.code}</span></div>
                  ))}
                </Block>
              )}
              {(repo.tools || []).length > 0 && (
                <Block icon={Wrench} title={`Tools (${repo.tools!.length})`}>
                  {repo.tools!.slice(0, 12).map((t, i) => (
                    <div key={i} className="scan-line"><strong>{t.name}</strong>{t.destructive && <Badge tone="critical">Can change data</Badge>}<code>{t.file}:{t.line}</code></div>
                  ))}
                </Block>
              )}
              {secrets.length > 0 && (
                <Block icon={KeyRound} title={`Hardcoded secrets (${secrets.length})`}>
                  {secrets.slice(0, 12).map((s, i) => (
                    <div key={i} className="scan-line"><Badge tone={s.severity === 'CRITICAL' ? 'critical' : 'warning'}>{s.severity === 'CRITICAL' ? 'Critical' : 'High'}</Badge><strong>{s.kind}</strong><code>{s.file}:{s.line}</code><span>{s.value}</span></div>
                  ))}
                </Block>
              )}
            </>
          )}
        </div>
      </div>

      {combined.length > 0 && (
        <div className="scan-card" style={{ marginTop: 16 }}>
          <div className="scan-card-head"><AlertTriangle size={16} />Seen together<span>The code and the API description side by side</span></div>
          <Findings items={combined} />
        </div>
      )}
    </div>
  );
};
