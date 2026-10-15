import React, { useEffect, useState } from 'react';
import { AlertCircle, ArrowLeft, ArrowRight, Check, CheckCircle2, Eye, EyeOff, Moon, Shield, Sun, TriangleAlert, User } from 'lucide-react';
import { BACKEND_URL } from '../utils/apiConfig';
import { saveSession } from '../utils/session';

export interface AdminUser {
  id: number;
  user_id?: string;
  name: string;
  full_name?: string;
  email: string;
  role: 'ADMIN' | 'USER';
  department?: string;
  avatar_url?: string;
  status?: string;
  last_login?: string;
}

interface AdminLoginProps {
  onLoginSuccess: (user: AdminUser, token: string) => void;
  onCancel?: () => void;
  isDarkMode: boolean;
  setIsDarkMode: (val: boolean) => void;
  portalMode?: 'admin' | 'user';
}

/** An illustration of what a report shows. Labelled as an example on the page, so it is never read as live data. */
const EXAMPLE_CHECKS: { label: string; result: 'pass' | 'review' }[] = [
  { label: 'Prompt-injection resistance', result: 'pass' },
  { label: 'Data governance', result: 'pass' },
  { label: 'Fairness and bias', result: 'review' },
];
const EXAMPLE_SCORE = 90;

type Role = 'USER' | 'ADMIN';
type View = 'login' | 'forgot' | 'reset';

const MIN_PASSWORD_LENGTH = 8;

/** The link in the reset email opens /reset-password?token=... */
const resetTokenFromUrl = (): string | null =>
  window.location.pathname.replace(/\/$/, '').toLowerCase() === '/reset-password'
    ? new URLSearchParams(window.location.search).get('token')
    : null;

const postJson = async (path: string, body: unknown) => {
  const res = await fetch(`${BACKEND_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || 'Something went wrong. Try again.');
  return data;
};

/**
 * Development only. The buttons fill the real accounts below. Passwords are never in the code:
 * put them in frontend/.env.local (not committed) as VITE_DEV_USER_PASSWORD and VITE_DEV_ADMIN_PASSWORD.
 * import.meta.env.DEV is false in a production build, so none of this reaches it.
 */
const DEV_LOGINS: Record<Role, { label: string; email: string; password: string }> | null = import.meta.env.DEV
  ? {
      USER: { label: 'Ismeet', email: import.meta.env.VITE_DEV_USER_EMAIL || 'ismeet@certifyai.in', password: import.meta.env.VITE_DEV_USER_PASSWORD || '' },
      ADMIN: { label: 'Syed', email: import.meta.env.VITE_DEV_ADMIN_EMAIL || 'syed@certifyai.in', password: import.meta.env.VITE_DEV_ADMIN_PASSWORD || '' },
    }
  : null;

/** Circular score gauge for the example report. */
const ScoreRing: React.FC<{ value: number }> = ({ value }) => {
  const r = 54;
  const c = 2 * Math.PI * r;
  return (
    <div className="auth-ring">
      <svg viewBox="0 0 128 128" aria-hidden="true">
        <circle cx="64" cy="64" r={r} className="auth-ring-track" />
        <circle cx="64" cy="64" r={r} className="auth-ring-value" strokeDasharray={c} strokeDashoffset={c * (1 - value / 100)} />
      </svg>
      <div className="auth-ring-label">
        <strong>{value}</strong>
        <span>Trust score</span>
      </div>
    </div>
  );
};

export const AdminLogin: React.FC<AdminLoginProps> = ({ onLoginSuccess, isDarkMode, setIsDarkMode }) => {
  const [role, setRole] = useState<Role>('USER');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [capsOn, setCapsOn] = useState(false);
  const [resetToken] = useState<string | null>(resetTokenFromUrl);
  const [view, setView] = useState<View>(resetToken ? 'reset' : 'login');
  const [notice, setNotice] = useState<string | null>(null);
  const [resetEmail, setResetEmail] = useState<string | null>(null);
  const [tokenChecked, setTokenChecked] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  useEffect(() => {
    if (!resetToken) return;
    postJson('/api/auth/reset-password/verify', { token: resetToken })
      .then(d => {
        if (d.valid) setResetEmail(d.email);
        else setErrorMessage('This reset link is invalid, expired or already used. Request a new one.');
      })
      .catch(() => setErrorMessage('Unable to check the reset link. Make sure the server is running.'))
      .finally(() => setTokenChecked(true));
  }, [resetToken]);

  const goTo = (next: View) => {
    setErrorMessage(null);
    setNotice(null);
    setView(next);
    if (window.location.pathname !== '/login') window.history.replaceState(null, '', '/login');
  };

  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const d = await postJson('/api/auth/forgot-password', { email: email.trim().toLowerCase() });
      setNotice(d.message);
    } catch (err: any) {
      setErrorMessage(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setErrorMessage('The two passwords do not match.');
      return;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const d = await postJson('/api/auth/reset-password', { token: resetToken, new_password: newPassword });
      window.history.replaceState(null, '', '/login');
      if (resetEmail) setEmail(resetEmail);
      setPassword('');
      setView('login');
      setNotice(d.message);
    } catch (err: any) {
      setErrorMessage(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const devLogin = DEV_LOGINS?.[role];

  const autofill = () => {
    if (!devLogin) return;
    setEmail(devLogin.email);
    setPassword(devLogin.password);
    setErrorMessage(null);
    if (!devLogin.password) document.getElementById('login-password')?.focus();
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase(), password, remember_me: rememberMe, role }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Authentication failed' }));
        throw new Error(errorData.detail || 'Invalid email or password');
      }

      const data = await response.json();
      const userData = data.user || data;
      saveSession(userData, data.token, rememberMe);
      onLoginSuccess(userData, data.token);
    } catch (err: any) {
      setErrorMessage(err.message || 'Unable to connect to the authentication server.');
    } finally {
      setIsLoading(false);
    }
  };

  const messages = (
    <>
      {notice && (
        <div className="auth-msg ok" role="status">
          <CheckCircle2 size={16} aria-hidden="true" />
          <span>{notice}{view === 'forgot' ? ' Check your inbox and spam folder.' : ''}</span>
        </div>
      )}
      {errorMessage && (
        <div className="auth-msg error" role="alert">
          <AlertCircle size={16} aria-hidden="true" />
          <span>{errorMessage}</span>
        </div>
      )}
    </>
  );

  const passwordToggle = (
    <button type="button" className="auth-eye" onClick={() => setShowPassword(v => !v)} aria-label={showPassword ? 'Hide password' : 'Show password'}>
      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
    </button>
  );

  return (
    <div className="auth">
      <div className="auth-grid">
        {/* Left: what the product does */}
        <section className="auth-hero" aria-label="About CertifyAI">
          <header className="auth-col auth-col-head">
            <div className="auth-brand">
              <span className="auth-brand-mark"><Shield size={22} aria-hidden="true" /></span>
              CertifyAI
            </div>
          </header>

          <div className="auth-col auth-hero-body">
            <div className="auth-eyebrow"><span className="auth-eyebrow-dot" aria-hidden="true" />Trust layer for autonomous AI</div>
            <h1 className="auth-title">Every agent, verified before it <span className="auth-accent">acts.</span></h1>
            <p className="auth-lead">
              Audit autonomous agents across 22 risk areas, issue signed certificates, and monitor them in production, all in one place.
            </p>

            <figure className="auth-example">
              <ScoreRing value={EXAMPLE_SCORE} />
              <div className="auth-example-body">
                <ul className="auth-checks">
                  {EXAMPLE_CHECKS.map(c => (
                    <li key={c.label}>
                      {c.result === 'pass'
                        ? <Check size={16} className="auth-check-icon pass" aria-hidden="true" />
                        : <TriangleAlert size={16} className="auth-check-icon review" aria-hidden="true" />}
                      <span>{c.label}</span>
                      <span className={`auth-check-result ${c.result}`}>{c.result === 'pass' ? 'Pass' : 'Review'}</span>
                    </li>
                  ))}
                </ul>
                <figcaption className="auth-standards">
                  Example report. Findings map to OWASP · NIST AI RMF · MITRE ATLAS · EU AI Act
                </figcaption>
              </div>
            </figure>
          </div>
        </section>

        {/* Right: the form */}
        <main className="auth-panel">
          <div className="auth-theme" role="group" aria-label="Theme">
            <button type="button" aria-pressed={!isDarkMode} className={!isDarkMode ? 'active' : ''} onClick={() => setIsDarkMode(false)}><Sun size={14} aria-hidden="true" />Light</button>
            <button type="button" aria-pressed={isDarkMode} className={isDarkMode ? 'active' : ''} onClick={() => setIsDarkMode(true)}><Moon size={14} aria-hidden="true" />Dark</button>
          </div>

          <div className="auth-panel-body">
            {view === 'login' && (
              <form className="auth-form" onSubmit={handleLoginSubmit}>
                <div>
                  <h2 className="auth-heading">Welcome back</h2>
                  <p className="auth-sub">Sign in to your workspace to continue.</p>
                </div>

                <div className="auth-tabs" role="tablist" aria-label="Account type">
                  <button type="button" role="tab" aria-selected={role === 'USER'} onClick={() => setRole('USER')}>Team member</button>
                  <button type="button" role="tab" aria-selected={role === 'ADMIN'} onClick={() => setRole('ADMIN')}>Administrator</button>
                </div>

                {messages}

                {DEV_LOGINS && (
                  <button type="button" className="auth-btn ghost" onClick={autofill}>
                    <User size={15} aria-hidden="true" />Autofill {role === 'ADMIN' ? 'admin' : 'user'} (development)
                  </button>
                )}

                <div className="auth-field">
                  <label htmlFor="login-email">Work email</label>
                  <input
                    id="login-email"
                    className="auth-input"
                    type="text"
                    inputMode="email"
                    autoComplete="username"
                    placeholder="you@company.com"
                    required
                    autoFocus
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                  />
                </div>

                <div className="auth-field">
                  <div className="auth-field-top">
                    <label htmlFor="login-password">Password</label>
                    <button type="button" className="auth-link" onClick={() => goTo('forgot')}>Forgot password?</button>
                  </div>
                  <div className="auth-input-wrap">
                    <input
                      id="login-password"
                      className="auth-input"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      placeholder="Your password"
                      required
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      onKeyUp={e => setCapsOn(e.getModifierState('CapsLock'))}
                      aria-describedby={capsOn ? 'caps-warning' : undefined}
                    />
                    {passwordToggle}
                  </div>
                  {capsOn && <span id="caps-warning" className="auth-caps">Caps Lock is on.</span>}
                </div>

                <label className="auth-check">
                  <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} />
                  <span>Keep me signed in</span>
                </label>

                <button type="submit" className="auth-btn primary" disabled={isLoading || !email.trim() || !password}>
                  <span>{isLoading ? 'Signing in' : role === 'ADMIN' ? 'Sign in as administrator' : 'Sign in'}</span>
                  <span className="auth-btn-icon" aria-hidden="true">
                    {isLoading ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <ArrowRight size={16} />}
                  </span>
                </button>
              </form>
            )}

            {view === 'forgot' && (
              <form className="auth-form" onSubmit={handleForgotSubmit}>
                <div>
                  <h2 className="auth-heading">Reset your password</h2>
                  <p className="auth-sub">Enter the email of your account. We will send a link to choose a new password.</p>
                </div>
                {messages}
                <div className="auth-field">
                  <label htmlFor="forgot-email">Work email</label>
                  <input id="forgot-email" className="auth-input" type="email" autoComplete="username" placeholder="you@company.com" required autoFocus
                    value={email} onChange={e => setEmail(e.target.value)} />
                </div>
                <button type="submit" className="auth-btn primary" disabled={isLoading || !email.trim()}>
                  <span>{isLoading ? 'Sending' : notice ? 'Send another link' : 'Send reset link'}</span>
                  <span className="auth-btn-icon" aria-hidden="true"><ArrowRight size={16} /></span>
                </button>
                <button type="button" className="auth-link back" onClick={() => goTo('login')}>
                  <ArrowLeft size={14} aria-hidden="true" />Back to sign in
                </button>
              </form>
            )}

            {view === 'reset' && (
              <form className="auth-form" onSubmit={handleResetSubmit}>
                <div>
                  <h2 className="auth-heading">Choose a new password</h2>
                  <p className="auth-sub">
                    {resetEmail ? <>For <strong>{resetEmail}</strong>.</> : tokenChecked ? 'This link cannot be used.' : 'Checking your reset link.'}
                  </p>
                </div>
                {messages}
                {resetEmail && (
                  <>
                    <div className="auth-field">
                      <label htmlFor="new-password">New password</label>
                      <div className="auth-input-wrap">
                        <input id="new-password" className="auth-input" type={showPassword ? 'text' : 'password'} autoComplete="new-password" required autoFocus
                          minLength={MIN_PASSWORD_LENGTH} placeholder={`At least ${MIN_PASSWORD_LENGTH} characters`}
                          value={newPassword} onChange={e => setNewPassword(e.target.value)} />
                        {passwordToggle}
                      </div>
                    </div>
                    <div className="auth-field">
                      <label htmlFor="confirm-password">Confirm new password</label>
                      <input id="confirm-password" className="auth-input" type={showPassword ? 'text' : 'password'} autoComplete="new-password" required
                        value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} />
                    </div>
                    <button type="submit" className="auth-btn primary" disabled={isLoading || newPassword.length < MIN_PASSWORD_LENGTH || !confirmPassword}>
                      <span>{isLoading ? 'Saving' : 'Save new password'}</span>
                      <span className="auth-btn-icon" aria-hidden="true"><ArrowRight size={16} /></span>
                    </button>
                  </>
                )}
                {tokenChecked && !resetEmail && (
                  <button type="button" className="auth-btn primary" onClick={() => goTo('forgot')}>
                    <span>Request a new link</span>
                    <span className="auth-btn-icon" aria-hidden="true"><ArrowRight size={16} /></span>
                  </button>
                )}
                <button type="button" className="auth-link back" onClick={() => goTo('login')}>
                  <ArrowLeft size={14} aria-hidden="true" />Back to sign in
                </button>
              </form>
            )}
          </div>

          <nav className="auth-legal" aria-label="Legal">
            <a href="/privacy">Privacy Policy</a>
            <a href="/terms">Terms and Conditions</a>
          </nav>
        </main>
      </div>
    </div>
  );
};
