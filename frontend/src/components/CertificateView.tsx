import React, { useState } from 'react';
import { AlertTriangle, BadgeCheck, Check, ChevronDown, ChevronRight, Copy, Download, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { Button, fmtScore, tierInfo } from './ui';

/** The signed certificate as stored with a test (fields from agent_audit.certificate.Certificate). */
export interface CertificateData {
  agent_name?: string;
  tier?: string;
  trust_score?: number;
  grade?: string;
  badges?: string[];
  issued_at?: string;
  expires_at?: string;
  audit_id?: string;
  audit_version?: string;
  cert_version?: string;
  content_hash?: string;
  key_fingerprint?: string;
  public_key?: string;
  public_key_b64?: string;
  signature_b64?: string;
  signature?: string;
  framework_validation_only?: boolean;
  findings_summary?: { total?: number; passes?: number; critical?: number; warnings?: number; suppressed?: number };
}

const DAY = 24 * 60 * 60 * 1000;

const longDate = (iso?: string) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
};

const STATEMENT: Record<string, string> = {
  CERTIFIED: 'passed every required check in this audit.',
  CONDITIONAL: 'passed with conditions. Fix the warnings before relying on it in production.',
  NOT_CERTIFIED: 'did not pass. The audit found problems that must be fixed first.',
  FRAMEWORK_VALIDATION_ONLY: 'was checked against a simulated agent. This confirms the setup works; it does not certify the real agent.',
  INCONCLUSIVE: 'could not be decided. Too many checks could not run.',
};

const SealIcon: Record<string, React.ElementType> = {
  pass: ShieldCheck,
  warning: ShieldAlert,
  critical: ShieldX,
};

/** Score as a ring, filled to the score and colored by the result. */
const ScoreRing: React.FC<{ score: number; tone: string }> = ({ score, tone }) => {
  const r = 34;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className={`cert-ring tone-${tone}`}>
      <svg viewBox="0 0 84 84" width="84" height="84" aria-hidden="true">
        <circle cx="42" cy="42" r={r} className="cert-ring-track" />
        <circle cx="42" cy="42" r={r} className="cert-ring-fill" strokeDasharray={`${c * pct} ${c}`} transform="rotate(-90 42 42)" />
      </svg>
      <div className="cert-ring-text">
        <strong>{fmtScore(score)}</strong>
        <span>of 100</span>
      </div>
    </div>
  );
};

const CopyField: React.FC<{ label: string; value?: string }> = ({ label, value }) => {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked: the value is still selectable */ }
  };
  return (
    <div className="cert-field">
      <div className="cert-field-head">
        <span>{label}</span>
        <button type="button" className="cert-copy" onClick={copy} aria-label={`Copy ${label}`}>
          {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}{copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <code>{value}</code>
    </div>
  );
};

export const CertificateView: React.FC<{ cert: CertificateData; agentName?: string }> = ({ cert, agentName }) => {
  const [showProof, setShowProof] = useState(false);
  const [now] = useState(() => Date.now());
  const tier = (cert.framework_validation_only ? 'FRAMEWORK_VALIDATION_ONLY' : cert.tier || 'NOT_CERTIFIED').toUpperCase();
  const info = tierInfo(tier);
  const tone = info.tone;
  const Seal = SealIcon[tone] || BadgeCheck;
  const name = cert.agent_name || agentName || 'Agent';
  const score = Number(cert.trust_score) || 0;
  const fs = cert.findings_summary || {};

  // Validity: how far through its life the certificate is, and how many days are left
  const issued = cert.issued_at ? new Date(cert.issued_at).getTime() : NaN;
  const expires = cert.expires_at ? new Date(cert.expires_at).getTime() : NaN;
  const hasDates = !Number.isNaN(issued) && !Number.isNaN(expires) && expires > issued;
  const daysLeft = hasDates ? Math.ceil((expires - now) / DAY) : null;
  const expired = daysLeft !== null && daysLeft <= 0;
  const used = hasDates ? Math.min(1, Math.max(0, (now - issued) / (expires - issued))) : 0;

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(cert, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name.replace(/[^\w.-]+/g, '_')}_certificate.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className={`cert tone-${tone}`}>
      <div className="cert-top">
        <div className="cert-brand">
          <span className="cert-brand-mark"><ShieldCheck aria-hidden="true" /></span>
          <div>
            <strong>CertifyAI</strong>
            <span>Agent trust certificate</span>
          </div>
        </div>
        <span className={`cert-status tone-${tone}`}><Seal aria-hidden="true" />{info.label}</span>
      </div>

      <div className="cert-hero">
        <div className="cert-hero-text">
          <span className="cert-eyebrow">This certifies that</span>
          <h3 className="cert-name">{name}</h3>
          <p className="cert-statement">{STATEMENT[tier] || 'was audited by the CertifyAI engine.'}</p>
          {(cert.badges?.length || cert.grade) ? (
            <div className="cert-badges">
              {cert.grade && cert.grade !== 'FAILED' && <span className="cert-grade">{cert.grade.charAt(0) + cert.grade.slice(1).toLowerCase()} grade</span>}
              {(cert.badges || []).map(b => <span key={b} className="cert-badge"><BadgeCheck aria-hidden="true" />{b}</span>)}
            </div>
          ) : null}
        </div>
        <ScoreRing score={score} tone={tone} />
      </div>

      {(fs.total || fs.passes || fs.warnings || fs.critical) ? (
        <div className="cert-counts">
          <div><strong>{fs.total ?? '-'}</strong><span>Checks</span></div>
          <div className="pass"><strong>{fs.passes ?? 0}</strong><span>Passed</span></div>
          <div className="warning"><strong>{fs.warnings ?? 0}</strong><span>Warnings</span></div>
          <div className="critical"><strong>{fs.critical ?? 0}</strong><span>Critical</span></div>
        </div>
      ) : null}

      <div className="cert-validity">
        <div className="cert-dates">
          <div><span>Issued</span><strong>{longDate(cert.issued_at)}</strong></div>
          <div><span>Valid until</span><strong>{longDate(cert.expires_at)}</strong></div>
          {daysLeft !== null && (
            <span className={`cert-days${expired ? ' expired' : daysLeft <= 3 ? ' soon' : ''}`}>
              {expired ? <><AlertTriangle aria-hidden="true" />Expired</> : `${daysLeft} day${daysLeft === 1 ? '' : 's'} left`}
            </span>
          )}
        </div>
        {hasDates && <div className="cert-life" aria-hidden="true"><span style={{ width: `${used * 100}%` }} /></div>}
      </div>

      <div className="cert-meta">
        {cert.audit_id && <div><span>Audit ID</span><code>{cert.audit_id}</code></div>}
        {cert.audit_version && <div><span>Audit engine</span><code>v{cert.audit_version}</code></div>}
        {cert.key_fingerprint && <div><span>Signing key</span><code>{cert.key_fingerprint}</code></div>}
      </div>

      <div className="cert-proof">
        <button type="button" className="cert-proof-toggle" aria-expanded={showProof} onClick={() => setShowProof(s => !s)}>
          {showProof ? <ChevronDown aria-hidden="true" /> : <ChevronRight aria-hidden="true" />}
          Signature details
          <span>Ed25519 signature over the content hash</span>
        </button>
        {showProof && (
          <div className="cert-proof-body">
            <CopyField label="Content hash (SHA-256)" value={cert.content_hash} />
            <CopyField label="Signature (base64)" value={cert.signature_b64 || cert.signature} />
            <CopyField label="Public key (base64)" value={cert.public_key_b64 || cert.public_key} />
            <p className="cert-proof-note">
              To check it has not been changed, download the certificate and run <code>agent-audit verify --cert {name.replace(/[^\w.-]+/g, '_')}_certificate.json</code>.
            </p>
          </div>
        )}
      </div>

      <div className="cert-actions">
        <Button size="sm" icon={Download} onClick={downloadJson}>Download certificate (.json)</Button>
      </div>
    </div>
  );
};
