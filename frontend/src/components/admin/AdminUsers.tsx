import React, { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, Bot, ChevronRight, RefreshCw, UserPlus, Users } from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts';
import { apiFetch } from '../../utils/apiClient';
import {
  Alert, Avatar, Badge, Button, EmptyState, Field, Modal, PageHeader, Panel, SearchInput, SortHeader, Stat, TableSkeleton, TierBadge,
  modeLabel, scoreColor, scoreTone, useSort, fmtScore,
} from '../ui';
import { ChartTooltip, axisProps, lineProps } from '../charts';

type SortKey = 'name' | 'tests' | 'score';

const RoleBadge: React.FC<{ role?: string }> = ({ role }) => (
  <Badge tone={role === 'ADMIN' ? 'info' : 'neutral'}>{role === 'ADMIN' ? 'Admin' : 'User'}</Badge>
);
const StatusBadge: React.FC<{ status?: string }> = ({ status }) => (
  <Badge tone={status === 'Active' ? 'pass' : 'neutral'} dot>{status || 'Unknown'}</Badge>
);

export const AdminUsers: React.FC = () => {
  const [users, setUsers] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Selected user detail state
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [userDetail, setUserDetail] = useState<any | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [confirmToggle, setConfirmToggle] = useState<any | null>(null);
  const [toggling, setToggling] = useState(false);

  // Add user modal state
  const [isAddUserOpen, setIsAddUserOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'USER' | 'ADMIN'>('USER');
  const [newDept, setNewDept] = useState('');
  const [addError, setAddError] = useState('');
  const [creating, setCreating] = useState(false);

  const fetchUsers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/admin/users');
      if (!res.ok) throw new Error('The users could not be loaded.');
      const data = await res.json();
      setUsers(data.users || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The users could not be loaded.');
    } finally {
      setIsLoading(false);
      setLoaded(true);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleSelectUser = async (userId: number) => {
    setSelectedUserId(userId);
    setIsDetailLoading(true);
    setDetailError(null);
    try {
      const res = await apiFetch(`/api/admin/users/${userId}`);
      if (!res.ok) throw new Error();
      setUserDetail(await res.json());
    } catch {
      setDetailError('This user could not be loaded.');
    } finally {
      setIsDetailLoading(false);
    }
  };

  const resetAddForm = () => {
    setNewName(''); setNewEmail(''); setNewPassword(''); setNewRole('USER'); setNewDept(''); setAddError('');
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddError('');
    setCreating(true);
    try {
      const res = await apiFetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName, email: newEmail, password: newPassword, role: newRole, department: newDept }),
      });
      if (res.ok) {
        setIsAddUserOpen(false);
        resetAddForm();
        fetchUsers();
      } else {
        const err = await res.json().catch(() => ({}));
        setAddError(typeof err.detail === 'string' ? err.detail : 'The account could not be created.');
      }
    } catch (err: any) {
      setAddError(err?.message || 'Network error. Check your connection and try again.');
    } finally {
      setCreating(false);
    }
  };

  const handleToggleStatus = async (userObj: any) => {
    const newStatus = userObj.status === 'Active' ? 'Inactive' : 'Active';
    setToggling(true);
    try {
      const res = await apiFetch(`/api/admin/users/${userObj.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error();
      fetchUsers();
      if (selectedUserId === userObj.id) handleSelectUser(userObj.id);
    } catch {
      setDetailError('The account status could not be changed.');
    } finally {
      setToggling(false);
      setConfirmToggle(null);
    }
  };

  const filteredUsers = useMemo(() => users.filter(u =>
    (u.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (u.email || '').toLowerCase().includes(searchTerm.toLowerCase())
  ), [users, searchTerm]);

  const { sorted, sort, toggle } = useSort<any, SortKey>(filteredUsers, {
    name: u => u.name,
    tests: u => u.total_tests || 0,
    score: u => u.avg_score || null,
  }, { key: 'name', dir: 'asc' });

  const confirmModal = (
    <Modal
      open={!!confirmToggle}
      onClose={() => setConfirmToggle(null)}
      title={confirmToggle?.status === 'Active' ? `Deactivate ${confirmToggle?.name}?` : `Activate ${confirmToggle?.name}?`}
      description={confirmToggle?.status === 'Active'
        ? 'They will not be able to sign in until the account is activated again. Their tests and reports are kept.'
        : 'They will be able to sign in again with their existing password.'}
      footer={
        <>
          <Button onClick={() => setConfirmToggle(null)}>Cancel</Button>
          <Button variant={confirmToggle?.status === 'Active' ? 'danger' : 'primary'} loading={toggling} onClick={() => handleToggleStatus(confirmToggle)}>
            {confirmToggle?.status === 'Active' ? 'Deactivate account' : 'Activate account'}
          </Button>
        </>
      }
    />
  );

  // ==========================================
  // VIEW: USER DETAILS
  // ==========================================
  if (selectedUserId) {
    const back = () => { setSelectedUserId(null); setUserDetail(null); setDetailError(null); };
    if (!userDetail) {
      return (
        <div className="page-stack animate-slideup">
          <div><Button variant="ghost" icon={ArrowLeft} onClick={back}>All users</Button></div>
          {detailError ? (
            <Alert tone="critical" title={detailError} action={<Button size="sm" onClick={() => handleSelectUser(selectedUserId)}>Try again</Button>} />
          ) : (
            <div className="page-loading" role="status" aria-label="Loading user">
              <span className="skeleton" style={{ height: 96 }} />
              <div className="stat-grid kpi-6">{[0, 1, 2, 3, 4, 5].map(i => <span key={i} className="skeleton" style={{ height: 104 }} />)}</div>
              <span className="skeleton" style={{ height: 240 }} />
            </div>
          )}
        </div>
      );
    }
    const u = userDetail.user;
    const stats = userDetail.stats;
    const history = userDetail.test_history || [];
    const trend = userDetail.score_trend || [];
    const hasTrend = trend.some((d: any) => d.score != null);

    return (
      <div className="page-stack animate-slideup">
        <div><Button variant="ghost" icon={ArrowLeft} onClick={back}>All users</Button></div>

        {detailError && <Alert tone="critical" title={detailError} />}

        <div className="page-head" style={{ alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, minWidth: 0 }}>
            <Avatar name={u.name} size="lg" />
            <div style={{ minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <h1>{u.name}</h1>
                <RoleBadge role={u.role} />
                <StatusBadge status={u.status} />
              </div>
              <p>{[u.email, u.department].filter(Boolean).join(' · ')}</p>
            </div>
          </div>
          <div className="page-head-actions">
            <Button icon={RefreshCw} variant="ghost" loading={isDetailLoading} onClick={() => handleSelectUser(u.id)}>Refresh</Button>
            <Button variant={u.status === 'Active' ? 'secondary' : 'primary'} onClick={() => setConfirmToggle(u)}>
              {u.status === 'Active' ? 'Deactivate account' : 'Activate account'}
            </Button>
          </div>
        </div>

        <div className="stat-grid kpi-6">
          <Stat label="Total tests" value={stats.total_tests} />
          <Stat label="Agents tested" value={stats.agents_tested} />
          <Stat label="Average score" value={stats.total_tests ? `${fmtScore(stats.average_score)}%` : '-'} tone={scoreTone(stats.average_score, !!stats.total_tests)} />
          <Stat label="Certified" value={stats.certified_count} />
          <Stat label="Conditional" value={stats.conditional_count} />
          <Stat label="Not certified" value={stats.not_certified_count} tone={stats.not_certified_count ? 'critical' : 'neutral'} />
        </div>

        <Panel title="Score trend" subtitle="Daily average score over the last 14 days.">
          <div style={{ height: 200 }}>
            {hasTrend ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trend} margin={{ top: 8, right: 12, left: -8, bottom: 0 }}>
                  <CartesianGrid vertical={false} />
                  <ReferenceLine y={90} stroke="var(--color-text-muted)" strokeDasharray="4 4" />
                  <XAxis dataKey="date" {...axisProps} />
                  <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 90, 100]} {...axisProps} tickFormatter={v => `${v}%`} width={48} />
                  <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--color-border-strong)', strokeWidth: 1 }} />
                  <Line dataKey="score" name="Average score" {...lineProps('var(--chart-1)')} />
                </LineChart>
              </ResponsiveContainer>
            ) : <EmptyState title="No tests in the last 14 days" />}
          </div>
        </Panel>

        <Panel title="Testing history" subtitle={`${history.length} test${history.length === 1 ? '' : 's'} run by ${u.name}.`} flush>
          {history.length === 0 ? <EmptyState icon={Bot} title="No tests yet" /> : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Agent</th>
                    <th scope="col">Date</th>
                    <th scope="col">Mode</th>
                    <th scope="col" className="num">Score</th>
                    <th scope="col">Result</th>
                    <th scope="col" className="num">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h: any) => (
                    <tr key={h.id}>
                      <td><span className="cell-with-icon cell-strong"><Bot aria-hidden="true" /><span className="cell-truncate" title={h.agent_name}>{h.agent_name}</span></span></td>
                      <td style={{ whiteSpace: 'nowrap' }}>{new Date(h.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</td>
                      <td>{modeLabel(h.mode)}</td>
                      <td className="num" style={{ fontWeight: 600, color: scoreColor(h.trust_score) }}>{fmtScore(h.trust_score)}%</td>
                      <td><TierBadge tier={h.tier} /></td>
                      <td className="num">{h.duration_ms ? `${(h.duration_ms / 1000).toFixed(1)}s` : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {confirmModal}
      </div>
    );
  }

  // ==========================================
  // VIEW: MAIN USERS TABLE
  // ==========================================
  return (
    <div className="page-stack animate-slideup">
      <PageHeader
        title="Users"
        subtitle="Manage accounts and roles, and review each person's testing history."
        actions={
          <>
            <SearchInput value={searchTerm} onChange={setSearchTerm} placeholder="Search by name or email" label="Search users" />
            <Button variant="primary" icon={UserPlus} onClick={() => setIsAddUserOpen(true)}>Add user</Button>
          </>
        }
      />

      {error && <Alert tone="critical" title={error} action={<Button size="sm" onClick={fetchUsers}>Try again</Button>} />}

      <Panel flush>
        {loaded && filteredUsers.length === 0 ? (
          <EmptyState
            icon={Users}
            title={users.length === 0 ? 'No users yet' : 'No users match your search'}
            action={users.length === 0
              ? <Button variant="primary" icon={UserPlus} onClick={() => setIsAddUserOpen(true)}>Add user</Button>
              : <Button size="sm" onClick={() => setSearchTerm('')}>Clear search</Button>}
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <SortHeader label="Name" column="name" sort={sort} onSort={toggle} />
                  <th scope="col">Role</th>
                  <th scope="col">Department</th>
                  <SortHeader label="Tests" column="tests" sort={sort} onSort={toggle} numeric />
                  <SortHeader label="Avg score" column="score" sort={sort} onSort={toggle} numeric />
                  <th scope="col">Status</th>
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {!loaded || (isLoading && users.length === 0) ? <TableSkeleton columns={7} /> : sorted.map(u => (
                  <tr
                    key={u.id}
                    className="clickable"
                    tabIndex={0}
                    onClick={() => handleSelectUser(u.id)}
                    onKeyDown={e => { if (e.key === 'Enter') handleSelectUser(u.id); }}
                  >
                    <td style={{ minWidth: 220 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <Avatar name={u.name} />
                        <div style={{ minWidth: 0 }}>
                          <div className="cell-strong">{u.name}</div>
                          <div className="cell-sub">{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td><RoleBadge role={u.role} /></td>
                    <td>{u.department || '-'}</td>
                    <td className="num">{u.total_tests > 0 ? u.total_tests : '-'}</td>
                    <td className="num" style={{ fontWeight: 600, color: u.avg_score ? scoreColor(u.avg_score) : 'var(--color-text-muted)' }}>{u.avg_score ? `${fmtScore(u.avg_score)}%` : '-'}</td>
                    <td><StatusBadge status={u.status} /></td>
                    <td className="cell-actions">
                      <Button size="sm" variant="ghost" onClick={e => { e.stopPropagation(); handleSelectUser(u.id); }} aria-label={`View ${u.name}`}>
                        View <ChevronRight size={14} aria-hidden="true" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Modal
        open={isAddUserOpen}
        onClose={() => { setIsAddUserOpen(false); setAddError(''); }}
        title="Add user"
        description="They can sign in right away with this email and password."
      >
        <form id="add-user-form" onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {addError && <Alert tone="critical" title={addError} />}
          <Field label="Full name" required>
            <input type="text" className="form-input" data-autofocus value={newName} onChange={e => setNewName(e.target.value)} autoComplete="off" />
          </Field>
          <Field label="Email" required>
            <input type="email" className="form-input" value={newEmail} onChange={e => setNewEmail(e.target.value)} autoComplete="off" placeholder="name@company.com" />
          </Field>
          <Field label="Temporary password" required hint="Share it securely. They can change it from the sign-in page.">
            <input type="password" className="form-input" value={newPassword} onChange={e => setNewPassword(e.target.value)} autoComplete="new-password" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
            <Field label="Role" hint={newRole === 'ADMIN' ? 'Sees and manages the whole organization.' : 'Tests agents and sees their own reports.'}>
              <select className="form-input" value={newRole} onChange={e => setNewRole(e.target.value as 'USER' | 'ADMIN')}>
                <option value="USER">User</option>
                <option value="ADMIN">Admin</option>
              </select>
            </Field>
            <Field label="Department">
              <input type="text" className="form-input" value={newDept} onChange={e => setNewDept(e.target.value)} placeholder="Optional" />
            </Field>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 8 }}>
            <Button onClick={() => { setIsAddUserOpen(false); setAddError(''); }}>Cancel</Button>
            <Button type="submit" variant="primary" loading={creating}>Create account</Button>
          </div>
        </form>
      </Modal>

      {confirmModal}
    </div>
  );
};
