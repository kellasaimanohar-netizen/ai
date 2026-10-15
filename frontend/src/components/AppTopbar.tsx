import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  AlertCircle, AlertTriangle, Bell, BookOpen, CheckCheck, CornerDownLeft, Info, LogOut, Menu, Moon, Search, Sun, Trash2, X,
  type LucideIcon,
} from 'lucide-react';
import type { AdminUser } from './AdminLogin';
import { findNav, navFor, type NavTabType } from '../navigation';
import { apiFetch } from '../utils/apiClient';
import { BACKEND_URL } from '../utils/apiConfig';
import { Breadcrumbs, Button, Kbd, Tooltip, useDismiss, useFocusTrap } from './ui';

interface TopbarProps {
  currentUser: AdminUser;
  activeTab: NavTabType;
  setActiveTab: (tab: NavTabType) => void;
  isDarkMode: boolean;
  setIsDarkMode: (v: boolean) => void;
  onOpenNav: () => void;
  onLogout: () => void;
}

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

export const AppTopbar: React.FC<TopbarProps> = ({ currentUser, activeTab, setActiveTab, isDarkMode, setIsDarkMode, onOpenNav, onLogout }) => {
  const isAdmin = currentUser.role === 'ADMIN';
  const [paletteOpen, setPaletteOpen] = useState(false);
  const current = findNav(isAdmin, activeTab);

  // Ctrl+K / Cmd+K opens search from anywhere
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(o => !o);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  // The portal badge already names the workspace, so the trail starts at the section.
  const crumbs: { label: string; onClick?: () => void }[] = [];
  if (current && current.group.label !== 'Overview') crumbs.push({ label: current.group.label });
  crumbs.push({ label: current?.item.label || 'Dashboard' });

  return (
    <header className="top-navigation-header">
      <div className="topbar-left">
        <button type="button" className="icon-btn nav-toggle" onClick={onOpenNav} aria-label="Open navigation" aria-controls="app-sidebar">
          <Menu />
        </button>
        <div className={`portal-indicator-badge ${isAdmin ? 'admin' : 'user'}`}>
          <span className="portal-pulse-dot" />
          <span>{isAdmin ? 'Admin Console' : 'Workspace'}</span>
          <span className="portal-sub-badge">{isAdmin ? 'PRIVILEGED' : 'AUDITOR'}</span>
        </div>
        <Breadcrumbs items={crumbs} />
      </div>

      <div className="topbar-center">
        <button type="button" className="topbar-search" onClick={() => setPaletteOpen(true)} aria-haspopup="dialog" aria-label="Search pages and actions">
          <Search aria-hidden="true" />
          <span>Search pages and actions</span>
          <Kbd>{isMac ? '⌘' : 'Ctrl'} K</Kbd>
        </button>
      </div>

      <div className="topbar-actions">
        <NotificationsMenu onOpenLive={() => setActiveTab(isAdmin ? 'admin-live-agents' : 'user-live-agents')} />
        <Tooltip label="Guide" placement="bottom">
          <button
            type="button"
            className="icon-btn"
            onClick={() => setActiveTab(isAdmin ? 'admin-guide' : 'user-guide')}
            aria-label="Open the guide"
            aria-current={activeTab === 'admin-guide' || activeTab === 'user-guide' ? 'page' : undefined}
          >
            <BookOpen />
          </button>
        </Tooltip>
        {/* The signed-in user, profile and sign out live at the bottom of the sidebar. */}
        <Tooltip label={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'} placement="bottom">
          <button type="button" className="icon-btn" onClick={() => setIsDarkMode(!isDarkMode)}
            aria-label={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}>
            {isDarkMode ? <Sun /> : <Moon />}
          </button>
        </Tooltip>
      </div>

      {paletteOpen && createPortal(
        <CommandPalette
          isAdmin={isAdmin}
          onClose={() => setPaletteOpen(false)}
          onNavigate={tab => { setActiveTab(tab); setPaletteOpen(false); }}
          isDarkMode={isDarkMode}
          setIsDarkMode={setIsDarkMode}
          onLogout={() => { setPaletteOpen(false); onLogout(); }}
        />,
        document.body,
      )}
    </header>
  );
};

/* ------------------------------------------------------------------ */
/* Notifications                                                       */
/* ------------------------------------------------------------------ */

interface LiveAlert {
  id: number;
  agent_name: string;
  severity: string;
  message: string;
  created_at: string;
  read_at: string | null;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();

/** The date heading a notification sits under. */
const dayGroup = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'Earlier';
  const days = Math.round((startOfDay(new Date()) - startOfDay(d)) / DAY_MS);
  if (days <= 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days < 7) return d.toLocaleDateString('en-GB', { weekday: 'long' });
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: d.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' });
};

/** The time on each notification: relative within the hour, then the clock time (the date is in the heading). */
const alertTime = (iso: string) => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const mins = Math.round((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins} min ago`;
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
};

const isProblem = (a: LiveAlert) => a.severity === 'CRITICAL' || a.severity === 'WARNING';

type NotifFilter = 'all' | 'unread' | 'problems';

const NotificationsMenu: React.FC<{ onOpenLive: () => void }> = ({ onOpenLive }) => {
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [unread, setUnread] = useState(0);
  const [state, setState] = useState<'idle' | 'loading' | 'error'>('loading');
  const [filter, setFilter] = useState<NotifFilter>('all');
  const [confirmClear, setConfirmClear] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const close = useCallback(() => { setOpen(false); setConfirmClear(false); }, []);
  useDismiss(ref, open, close);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch('/api/user/live/alerts');
      if (!res.ok) throw new Error();
      const d = await res.json();
      setAlerts(d.alerts || []);
      setUnread(d.unread || 0);
      setState('idle');
    } catch {
      setState('error');
    }
  }, []);

  // Poll once a minute while the tab is visible
  useEffect(() => {
    load();
    const t = window.setInterval(() => { if (!document.hidden) load(); }, 60000);
    return () => window.clearInterval(t);
  }, [load]);

  // Changes show at once; the list reloads from the server afterwards either way.
  const markAll = async () => {
    const now = new Date().toISOString();
    setAlerts(prev => prev.map(a => (a.read_at ? a : { ...a, read_at: now })));
    setUnread(0);
    await apiFetch('/api/user/live/alerts/read-all', { method: 'POST' }).catch(() => undefined);
    load();
  };

  const clearOne = async (a: LiveAlert) => {
    setAlerts(prev => prev.filter(x => x.id !== a.id));
    if (!a.read_at) setUnread(u => Math.max(0, u - 1));
    await apiFetch(`/api/user/live/alerts/${a.id}`, { method: 'DELETE' }).catch(() => undefined);
    load();
  };

  const clearAll = async () => {
    setConfirmClear(false);
    setAlerts([]);
    setUnread(0);
    await apiFetch('/api/user/live/alerts', { method: 'DELETE' }).catch(() => undefined);
    load();
  };

  const iconFor = (sev: string): [LucideIcon, string] =>
    sev === 'CRITICAL' ? [AlertCircle, 'critical'] : sev === 'WARNING' ? [AlertTriangle, 'warning'] : [Info, 'info'];

  const shown = alerts.filter(a => (filter === 'unread' ? !a.read_at : filter === 'problems' ? isProblem(a) : true));
  const groups: { label: string; items: LiveAlert[] }[] = [];
  for (const a of shown) {
    const label = dayGroup(a.created_at);
    const last = groups[groups.length - 1];
    if (last && last.label === label) last.items.push(a);
    else groups.push({ label, items: [a] });
  }
  const tabs: [NotifFilter, string, number][] = [
    ['all', 'All', alerts.length],
    ['unread', 'Unread', unread],
    ['problems', 'Problems', alerts.filter(isProblem).length],
  ];
  const hasCritical = alerts.some(a => !a.read_at && a.severity === 'CRITICAL');

  return (
    <div className="menu-anchor" ref={ref}>
      <button
        type="button"
        className="icon-btn"
        aria-label={unread ? `Notifications, ${unread} unread` : 'Notifications'}
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => { if (open) close(); else { setOpen(true); load(); } }}
      >
        <Bell />
        {unread > 0 && <span className={`notif-dot${hasCritical ? '' : ' warning'}`} aria-hidden="true">{unread > 9 ? '9+' : unread}</span>}
      </button>
      {open && (
        <div className="popover notifications" role="dialog" aria-label="Notifications">
          <div className="notif-head">
            <div className="notif-title">
              <h2>Notifications</h2>
              {unread > 0 && <span className="notif-count">{unread} new</span>}
            </div>
            <div className="notif-actions">
              {unread > 0 && (
                <Button size="sm" variant="ghost" icon={CheckCheck} onClick={markAll}>Mark all read</Button>
              )}
            </div>
          </div>

          {alerts.length > 0 && (
            <div className="notif-tabs" role="tablist" aria-label="Show">
              {tabs.map(([id, label, n]) => (
                <button key={id} type="button" role="tab" aria-selected={filter === id}
                  className={`notif-tab${filter === id ? ' active' : ''}`} onClick={() => setFilter(id)}>
                  {label}<span className="notif-tab-n">{n}</span>
                </button>
              ))}
            </div>
          )}

          <div className="popover-body notif-body">
            {state === 'error' && alerts.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px 16px' }}>
                <div className="empty-title">Notifications could not be loaded</div>
                <div className="empty-action"><Button size="sm" onClick={load}>Try again</Button></div>
              </div>
            ) : state === 'loading' && alerts.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px 16px' }}><span className="spinner" aria-label="Loading" /></div>
            ) : shown.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px 16px' }}>
                <div className="empty-icon"><Bell aria-hidden="true" /></div>
                <div className="empty-title">{alerts.length === 0 ? 'No notifications' : filter === 'unread' ? 'Nothing unread' : 'No problems'}</div>
                {alerts.length === 0 && <div className="empty-hint">Failed tests, score drops, new critical findings and agents that go down show up here.</div>}
              </div>
            ) : (
              groups.map(g => (
                <section key={g.label} className="notif-group" aria-label={g.label}>
                  <h3 className="notif-group-label">{g.label}</h3>
                  {g.items.map(a => {
                    const [Icon, tone] = iconFor(a.severity);
                    return (
                      <div key={a.id} className={`notif-item ${tone}${a.read_at ? ' read' : ''}`}>
                        <span className="notif-icon"><Icon aria-hidden="true" /></span>
                        <div className="notif-text">
                          <div className="notif-msg">{a.message}</div>
                          <div className="notif-meta">
                            {a.agent_name && <span className="notif-agent">{a.agent_name}</span>}
                            <time dateTime={a.created_at} title={new Date(a.created_at).toLocaleString('en-GB')}>{alertTime(a.created_at)}</time>
                            {!a.read_at && <span className="sr-only">, unread</span>}
                          </div>
                        </div>
                        {!a.read_at && <span className="notif-unread" aria-hidden="true" />}
                        <button type="button" className="notif-clear" onClick={() => clearOne(a)} aria-label={`Clear notification: ${a.message}`}>
                          <X aria-hidden="true" />
                        </button>
                      </div>
                    );
                  })}
                </section>
              ))
            )}
          </div>
          {confirmClear ? (
            <div className="popover-foot notif-confirm" role="alert">
              <span>Clear all {alerts.length} notifications? This cannot be undone.</span>
              <div className="notif-confirm-actions">
                <Button size="sm" variant="ghost" onClick={() => setConfirmClear(false)}>Cancel</Button>
                <Button size="sm" variant="danger" onClick={clearAll}>Clear all</Button>
              </div>
            </div>
          ) : (
            <div className="popover-foot notif-foot">
              <button type="button" className="menu-item" onClick={() => { close(); onOpenLive(); }}>
                Open live agents
              </button>
              {alerts.length > 0 && (
                <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setConfirmClear(true)}>Clear all</Button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* Command palette                                                     */
/* ------------------------------------------------------------------ */

interface PaletteOption {
  id: string;
  label: string;
  group: string;
  icon: LucideIcon;
  hint?: string;
  run: () => void;
}

const CommandPalette: React.FC<{
  isAdmin: boolean;
  onClose: () => void;
  onNavigate: (tab: NavTabType) => void;
  isDarkMode: boolean;
  setIsDarkMode: (v: boolean) => void;
  onLogout: () => void;
}> = ({ isAdmin, onClose, onNavigate, isDarkMode, setIsDarkMode, onLogout }) => {
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  useFocusTrap(ref, true);

  const options = useMemo<PaletteOption[]>(() => {
    const pages = navFor(isAdmin).flatMap(g => g.items.map(i => ({
      id: i.tab, label: i.label, group: 'Pages', icon: i.icon, hint: g.label, run: () => onNavigate(i.tab),
    })));
    const actions: PaletteOption[] = [
      { id: 'theme', label: isDarkMode ? 'Switch to light mode' : 'Switch to dark mode', group: 'Actions', icon: isDarkMode ? Sun : Moon, run: () => { setIsDarkMode(!isDarkMode); onClose(); } },
      { id: 'docs', label: 'Open API documentation', group: 'Actions', icon: BookOpen, run: () => { window.open(`${BACKEND_URL}/docs`, '_blank', 'noopener'); onClose(); } },
      { id: 'logout', label: 'Sign out', group: 'Actions', icon: LogOut, run: onLogout },
    ];
    return [...pages, ...actions];
  }, [isAdmin, isDarkMode, onNavigate, setIsDarkMode, onClose, onLogout]);

  const q = query.trim().toLowerCase();
  const results = q ? options.filter(o => `${o.label} ${o.hint || ''}`.toLowerCase().includes(q)) : options;
  const active = Math.min(index, Math.max(0, results.length - 1));

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); onClose(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setIndex(Math.min(active + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIndex(Math.max(active - 1, 0)); }
    else if (e.key === 'Enter' && results[active]) { e.preventDefault(); results[active].run(); }
  };

  let lastGroup = '';
  return (
    <div className="modal-layer" onPointerDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} className="palette" role="dialog" aria-modal="true" aria-label="Search pages and actions" onKeyDown={onKey}>
        <div className="palette-input">
          <Search aria-hidden="true" />
          <input
            data-autofocus
            value={query}
            onChange={e => { setQuery(e.target.value); setIndex(0); }}
            placeholder="Search pages and actions"
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={results[active] ? `palette-${results[active].id}` : undefined}
            aria-autocomplete="list"
          />
          <Kbd>Esc</Kbd>
        </div>
        {results.length === 0 ? (
          <div className="palette-empty">No pages or actions match "{query}".</div>
        ) : (
          <ul className="palette-list" id="palette-list" role="listbox" ref={listRef} aria-label="Results">
            {results.map((o, i) => {
              const heading = o.group !== lastGroup ? o.group : null;
              lastGroup = o.group;
              const Icon = o.icon;
              return (
                <React.Fragment key={o.id}>
                  {heading && <li className="palette-group" role="presentation">{heading}</li>}
                  <li
                    id={`palette-${o.id}`}
                    data-index={i}
                    role="option"
                    aria-selected={i === active}
                    className="palette-option"
                    onPointerMove={() => setIndex(i)}
                    onClick={() => o.run()}
                  >
                    <Icon aria-hidden="true" />
                    {o.label}
                    {o.hint && <span className="palette-hint">{o.hint}</span>}
                  </li>
                </React.Fragment>
              );
            })}
          </ul>
        )}
        <div className="palette-foot" aria-hidden="true">
          <span><Kbd>↑</Kbd><Kbd>↓</Kbd> to move</span>
          <span><Kbd><CornerDownLeft size={11} /></Kbd> to open</span>
        </div>
      </div>
    </div>
  );
};
