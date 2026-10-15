import React, { useEffect, useState } from 'react';
import { Building2, CalendarDays, Clock, Download, History, Layers, Mail, Pencil, Play, User } from 'lucide-react';
import { apiFetch } from '../../utils/apiClient';
import { replaceToken, updateStoredUser } from '../../utils/session';
import { Alert, Avatar, Badge, Button, Field, Panel } from '../ui';

interface UserProfileProps {
  user: {
    id: number | string;
    name: string;
    email: string;
    role: string;
    department?: string;
    avatar_url?: string;
    created_at?: string;
    last_login?: string;
    status?: string;
  };
}

const CAPABILITIES: { icon: React.ElementType; title: string; text: string }[] = [
  { icon: Play, title: 'Run audits', text: 'Test agents with the testing studio.' },
  { icon: History, title: 'Track results', text: 'View your own scores, findings and test history.' },
  { icon: Download, title: 'Export reports', text: 'Download audit reports as PDF or Markdown and view certificates.' },
  { icon: Layers, title: 'Compare versions', text: 'See the agents you have tested and how each has changed.' },
];

const formatDate = (iso?: string) => {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
};

export const UserProfile: React.FC<UserProfileProps> = ({ user }) => {
  const [profile, setProfile] = useState({ name: user?.name || '', department: user?.department || '' });
  const [isEditing, setIsEditing] = useState(false);
  const [name, setName] = useState(profile.name);
  const [department, setDepartment] = useState(profile.department);
  const [password, setPassword] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  // The stored login copy can be older than the account record, so read the dates fresh.
  const [dates, setDates] = useState({ created_at: user?.created_at, last_login: user?.last_login });

  useEffect(() => {
    let live = true;
    apiFetch('/api/auth/me')
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (live && d?.user) setDates({ created_at: d.user.created_at, last_login: d.user.last_login });
      })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const passwordError = password && password.length < 8 ? 'Use at least 8 characters.' : null;
  const currentMissing = !!password && !currentPassword;
  const dirty = name !== profile.name || department !== profile.department || password !== '';

  const startEdit = () => {
    setName(profile.name);
    setDepartment(profile.department);
    setPassword('');
    setCurrentPassword('');
    setMessage(null);
    setIsEditing(true);
  };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passwordError || currentMissing) return;
    setIsSaving(true);
    setMessage(null);
    try {
      const payload: Record<string, string> = { name, department };
      if (password) {
        payload.password = password;
        payload.current_password = currentPassword;
      }
      const res = await apiFetch('/api/user/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'The profile could not be updated.' }));
        throw new Error(err.detail || 'The profile could not be updated.');
      }
      const data = await res.json();
      const updated = data.user || {};
      updateStoredUser(updated);
      if (data.token) replaceToken(data.token);   // a password change signs out other devices, not this one
      setProfile({ name: updated.name || name, department: updated.department || department });
      setIsEditing(false);
      const passwordChanged = !!password;
      setPassword('');
      setCurrentPassword('');
      setMessage({ text: passwordChanged ? 'Profile updated. Your other devices have been signed out.' : 'Profile updated.', type: 'success' });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : 'The profile could not be updated.', type: 'error' });
    } finally {
      setIsSaving(false);
    }
  };

  const isAdmin = user?.role === 'ADMIN';
  const rows: [React.ElementType, string, React.ReactNode][] = [
    [User, 'Full name', profile.name || '-'],
    [Mail, 'Email', user?.email || '-'],
    [Building2, 'Department', profile.department || '-'],
    [CalendarDays, 'Member since', formatDate(dates.created_at)],
    [Clock, 'Last sign in', formatDate(dates.last_login)],
  ];

  return (
    <div className="page-stack animate-slideup">
      <section className="profile-hero">
        <Avatar name={profile.name} size="xl" />
        <div className="profile-hero-text">
          <h1>{profile.name || 'Profile'}</h1>
          <p>{user?.email}</p>
          <div className="profile-hero-badges">
            <Badge tone="info">{isAdmin ? 'Admin' : 'User'}</Badge>
            {user?.status && <Badge tone={user.status === 'Active' ? 'pass' : 'neutral'} dot>{user.status}</Badge>}
          </div>
        </div>
        {!isEditing && (
          <div className="profile-hero-actions">
            <Button variant="primary" onClick={startEdit}><Pencil size={14} aria-hidden="true" />Edit profile</Button>
          </div>
        )}
      </section>

      {message && <Alert tone={message.type === 'success' ? 'pass' : 'critical'} title={message.text} />}

      <div className="profile-grid">
        <Panel title={isEditing ? 'Edit profile' : 'Account details'} subtitle={isEditing ? 'Changes apply the next time you sign in on other devices.' : 'Administrators manage roles and access.'}>
          {isEditing ? (
            <form onSubmit={save} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <Field label="Name" required>
                <input className="form-input" value={name} onChange={e => setName(e.target.value)} autoComplete="name" data-autofocus />
              </Field>
              <Field label="Department" required>
                <input className="form-input" value={department} onChange={e => setDepartment(e.target.value)} autoComplete="organization-title" />
              </Field>
              <Field label="New password" hint="Leave blank to keep your current password. At least 8 characters." error={passwordError}>
                <input className="form-input" type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} />
              </Field>
              {password && (
                <Field label="Current password" required hint="Needed to change your password. Your other devices will be signed out.">
                  <input className="form-input" type="password" autoComplete="current-password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} />
                </Field>
              )}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, paddingTop: 16, borderTop: '1px solid var(--color-border)' }}>
                <Button onClick={() => setIsEditing(false)} disabled={isSaving}>Cancel</Button>
                <Button type="submit" variant="primary" loading={isSaving} disabled={!dirty || !!passwordError || currentMissing}>Save changes</Button>
              </div>
            </form>
          ) : (
            <dl className="detail-list">
              {rows.map(([Icon, label, value]) => (
                <div className="detail-row" key={label}>
                  <dt><Icon size={16} aria-hidden="true" />{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </Panel>

        <Panel title="What you can do" subtitle="Permissions granted to your role." footer={isAdmin ? undefined : 'User management and system settings are reserved for administrators.'}>
          <ul className="profile-caps">
            {CAPABILITIES.map(({ icon: Icon, title, text }) => (
              <li key={title}>
                <span className="profile-cap-icon"><Icon size={18} aria-hidden="true" /></span>
                <div>
                  <div className="profile-cap-title">{title}</div>
                  <div className="profile-cap-text">{text}</div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
};
