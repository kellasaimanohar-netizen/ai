import React, { useEffect, useRef } from 'react';
import { LogOut, Shield, ShieldAlert, X } from 'lucide-react';
import type { AdminUser } from './AdminLogin';
import { isActiveItem, navFor, type NavTabType } from '../navigation';
import { Avatar, useFocusTrap } from './ui';

export type { NavTabType } from '../navigation';

interface SidebarProps {
  /** Mobile drawer state. On desktop the sidebar is always shown. */
  isOpen: boolean;
  onClose: () => void;
  activeTab: NavTabType;
  setActiveTab: (val: NavTabType) => void;
  currentUser?: AdminUser | null;
  onLogout: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose, activeTab, setActiveTab, currentUser, onLogout }) => {
  // The sidebar is always docked open on desktop. Clear the auto-hide settings older builds saved.
  useEffect(() => {
    try { localStorage.removeItem('nav-pinned'); localStorage.removeItem('nav-autohide'); } catch { /* storage unavailable */ }
    delete document.documentElement.dataset.nav;
  }, []);

  const ref = useRef<HTMLElement>(null);
  useFocusTrap(ref, isOpen);
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  const isAdmin = currentUser?.role === 'ADMIN';
  const groups = navFor(isAdmin);

  const userName = currentUser?.name || currentUser?.full_name || 'User';
  const onProfile = activeTab === 'user-profile' || activeTab === 'profile';
  const userBody = (
    <>
      <Avatar name={userName} />
      <span className="nav-user-text">
        <span className="nav-user-name">{userName}</span>
        <span className="nav-user-email">{currentUser?.email}</span>
      </span>
    </>
  );

  const go = (tab: NavTabType) => {
    setActiveTab(tab);
    onClose();
  };

  return (
    <>
      {isOpen && <div className="nav-scrim" onClick={onClose} aria-hidden="true" />}
      <aside
        ref={ref}
        id="app-sidebar"
        className={`nav-sidebar${isOpen ? ' open' : ''}`}
        aria-label="Main navigation"
      >
        <div className="nav-brand">
          <button type="button" className="nav-brand-link" onClick={() => go(isAdmin ? 'admin-dashboard' : 'user-dashboard')} aria-label="CertifyAI, go to dashboard">
            <span className="nav-brand-mark">
              {isAdmin ? <ShieldAlert aria-hidden="true" /> : <Shield aria-hidden="true" />}
            </span>
            <span className="nav-brand-text">
              <span className="nav-brand-name">CertifyAI</span>
              <span className="nav-brand-scope">{isAdmin ? 'SOC Command' : 'Security Studio'}</span>
            </span>
          </button>
          <button type="button" className="icon-btn nav-close" onClick={onClose} aria-label="Close navigation">
            <X />
          </button>
        </div>

        <nav className="nav-scroll">
          {groups.map(group => (
            <div key={group.label} className="nav-group" role="group" aria-labelledby={`nav-group-${group.label}`}>
              <div className="nav-group-label" id={`nav-group-${group.label}`}>{group.label}</div>
              {group.items.map(item => {
                const Icon = item.icon;
                const active = isActiveItem(item, activeTab);
                return (
                  <button
                    key={item.tab}
                    type="button"
                    className={`nav-item${active ? ' active' : ''}`}
                    onClick={() => go(item.tab)}
                    aria-current={active ? 'page' : undefined}
                    aria-label={item.label}
                  >
                    <Icon aria-hidden="true" />
                    <span className="nav-item-label">{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {currentUser && (
          <div className="nav-footer nav-user">
            {/* Admins have no profile page, so their card is not a link. */}
            {isAdmin ? (
              <div className="nav-user-card">{userBody}</div>
            ) : (
              <button type="button" className={`nav-user-card${onProfile ? ' active' : ''}`} onClick={() => go('user-profile')}
                aria-label={`${userName}, open profile`} aria-current={onProfile ? 'page' : undefined}>
                {userBody}
              </button>
            )}
            <button type="button" className="icon-btn nav-user-logout" onClick={onLogout} aria-label="Sign out" title="Sign out">
              <LogOut size={16} aria-hidden="true" />
            </button>
          </div>
        )}
      </aside>
    </>
  );
};
