import { Suspense, lazy, useState, useEffect, useCallback } from 'react';

import { Sidebar } from './components/Sidebar';
import { AppTopbar } from './components/AppTopbar';
import { Skeleton, Toaster, type ToastItem } from './components/ui';
import type { NavTabType } from './navigation';
import { LegalPage } from './components/LegalPage';
import { ErrorBoundary } from './components/ErrorBoundary';
import { AdminLogin, type AdminUser } from './components/AdminLogin';
import { BACKEND_URL } from './utils/apiConfig';
import { clearSession, getStoredToken, getStoredUser } from './utils/session';
import { clearSticky } from './utils/stickyState';

// Each page is loaded when it is first opened, so signing in does not download the whole console.
const UserDashboard = lazy(() => import('./components/user/UserDashboard').then(m => ({ default: m.UserDashboard })));
const UserLiveAgents = lazy(() => import('./components/user/UserLiveAgents').then(m => ({ default: m.UserLiveAgents })));
const UserTestAgent = lazy(() => import('./components/user/UserTestAgent').then(m => ({ default: m.UserTestAgent })));
const UserTestHistory = lazy(() => import('./components/user/UserTestHistory').then(m => ({ default: m.UserTestHistory })));
const UserAgents = lazy(() => import('./components/user/UserAgents').then(m => ({ default: m.UserAgents })));
const UserReports = lazy(() => import('./components/user/UserReports').then(m => ({ default: m.UserReports })));
const UserProfile = lazy(() => import('./components/user/UserProfile').then(m => ({ default: m.UserProfile })));
const AdminDashboard = lazy(() => import('./components/admin/AdminDashboard').then(m => ({ default: m.AdminDashboard })));
const AdminTestingActivity = lazy(() => import('./components/admin/AdminTestingActivity').then(m => ({ default: m.AdminTestingActivity })));
const AdminUsers = lazy(() => import('./components/admin/AdminUsers').then(m => ({ default: m.AdminUsers })));
const AdminAgents = lazy(() => import('./components/admin/AdminAgents').then(m => ({ default: m.AdminAgents })));
const AdminLiveAgents = lazy(() => import('./components/admin/AdminLiveAgents').then(m => ({ default: m.AdminLiveAgents })));
const AdminActivityLog = lazy(() => import('./components/admin/AdminActivityLog').then(m => ({ default: m.AdminActivityLog })));
const AdminReports = lazy(() => import('./components/admin/AdminReports').then(m => ({ default: m.AdminReports })));
const AdminAnalytics = lazy(() => import('./components/admin/AdminAnalytics').then(m => ({ default: m.AdminAnalytics })));
const GuidePage = lazy(() => import('./components/GuidePage').then(m => ({ default: m.GuidePage })));
const AdminSettings = lazy(() => import('./components/admin/AdminSettings').then(m => ({ default: m.AdminSettings })));

type Toast = ToastItem;

/** Shown while a page's code loads: the page header and KPI row in outline, so the layout does not jump. */
const PageFallback = () => (
  <div className="page-loading" role="status" aria-label="Loading page">
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <Skeleton width={180} height={24} />
      <Skeleton width={320} height={14} />
    </div>
    <div className="stat-grid">
      {[0, 1, 2, 3].map(i => <Skeleton key={i} height={112} style={{ borderRadius: 8 }} />)}
    </div>
    <Skeleton height={320} style={{ borderRadius: 8 }} />
  </div>
);

const ADMIN_ROUTES: Record<string, NavTabType> = {
  '': 'admin-dashboard',
  dashboard: 'admin-dashboard',
  'live-agents': 'admin-live-agents',
  live: 'admin-live-agents',
  activity: 'admin-activity',
  'testing-activity': 'admin-activity',
  'activity-log': 'admin-activity-log',
  users: 'admin-users',
  agents: 'admin-agents',
  reports: 'admin-reports',
  analytics: 'admin-analytics',
  settings: 'admin-settings',
  guide: 'admin-guide',
  policy: 'admin-guide',
};

const USER_ROUTES: Record<string, NavTabType> = {
  '': 'user-dashboard',
  dashboard: 'user-dashboard',
  'live-agents': 'user-live-agents',
  live: 'user-live-agents',
  'test-agent': 'user-test-agent',
  runner: 'user-test-agent',
  tests: 'user-tests',
  history: 'user-tests',
  agents: 'user-agents',
  reports: 'user-reports',
  profile: 'user-profile',
  guide: 'user-guide',
};

function parsePathToTab(path: string): { tab: NavTabType; roleHint?: 'ADMIN' | 'USER' } {
  const cleanPath = path.toLowerCase().replace(/\/$/, '');

  const parts = cleanPath.split('/').filter(Boolean);
  if (parts[0] === 'admin' && parts.length <= 2) {
    const tab = ADMIN_ROUTES[parts[1] || ''];
    if (tab) return { tab, roleHint: 'ADMIN' };
  }
  if (parts[0] === 'user' && parts.length <= 2) {
    const tab = USER_ROUTES[parts[1] || ''];
    if (tab) return { tab, roleHint: 'USER' };
  }

  // Default fallback to login
  return { tab: 'login' };
}

/** A user who opens an admin page, or an admin a user page, lands on their own dashboard instead of a blank page. */
function allowedTab(tab: NavTabType, isAdmin: boolean): NavTabType {
  if (tab === 'login') return tab;
  if (isAdmin && tab.startsWith('user-')) return 'admin-dashboard';
  if (!isAdmin && tab.startsWith('admin')) return 'user-dashboard';
  return tab;
}

function App() {
  // 1. Initial Route Resolution
  const initialRoute = parsePathToTab(window.location.pathname);
  // A password reset link always opens the sign-in screen, even for someone already signed in
  const isResetLink = /^\/reset-password\/?$/i.test(window.location.pathname);

  // 2. Current Authenticated User (null by default on initial entry or /login)
  const [currentUser, setCurrentUser] = useState<AdminUser | null>(() => {
    if (initialRoute.tab === 'login' || isResetLink) {
      return null;
    }
    const saved = getStoredUser<AdminUser>();
    return saved && saved.role ? saved : null;
  });

  // 3. Navigation State - defaults to 'login' when at root or /login
  const [activeTab, setActiveTabState] = useState<NavTabType>(() => {
    if (initialRoute.tab === 'login') {
      return 'login';
    }
    const saved = getStoredUser<AdminUser>();
    if (!saved) {
      return 'login';
    }
    return allowedTab(initialRoute.tab, saved.role === 'ADMIN');
  });
  const [isNavOpen, setIsNavOpen] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    // An explicit choice wins; otherwise follow the operating system setting.
    const saved = localStorage.getItem('theme-mode');
    if (saved) return saved === 'dark';
    return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-color-scheme: dark)').matches;
  });

  const [toasts, setToasts] = useState<Toast[]>([]);

  // Navigation props/parameters
  const [preselectedAgentForTest, setPreselectedAgentForTest] = useState<string>('');
  const [selectedTestIdForView, setSelectedTestIdForView] = useState<number | null>(null);

  // Sync tab with URL
  const setActiveTab = useCallback((tab: NavTabType) => {
    setActiveTabState(tab);
    if (tab === 'login') {
      window.history.pushState(null, '', '/login');
    } else if (tab.startsWith('admin-') || tab === 'admin') {
      const sub = tab.replace('admin-', '');
      window.history.pushState(null, '', `/admin/${sub === 'admin' ? 'dashboard' : sub}`);
    } else {
      const sub = tab.replace('user-', '');
      window.history.pushState(null, '', `/user/${sub === 'user' ? 'dashboard' : sub}`);
    }
  }, []);

  // Sidebar, top bar and search go to a page fresh: a test opened earlier from another page does not reopen.
  const navigate = useCallback((tab: NavTabType) => {
    setSelectedTestIdForView(null);
    setPreselectedAgentForTest('');
    setActiveTab(tab);
  }, [setActiveTab]);

  // Every page starts at the top, not where the previous page was scrolled to.
  useEffect(() => {
    window.scrollTo(0, 0);
    document.querySelector('.page-container')?.scrollTo?.(0, 0);
  }, [activeTab, selectedTestIdForView]);

  // Ensure URL is /login when on login tab or not authenticated
  useEffect(() => {
    if (!currentUser || activeTab === 'login') {
      if (window.location.pathname !== '/login' && !/^\/(privacy|terms|reset-password)\/?$/i.test(window.location.pathname)) {
        window.history.replaceState(null, '', '/login');
      }
    }
  }, [currentUser, activeTab]);

  // Listen to browser forward/back buttons
  useEffect(() => {
    const handlePopState = () => {
      const route = parsePathToTab(window.location.pathname);
      const parsed = getStoredUser<AdminUser>();
      if (!parsed) {
        setCurrentUser(null);
        setActiveTabState('login');
        return;
      }
      setCurrentUser(parsed);
      setSelectedTestIdForView(null);
      if (route.tab === 'login') {
        setActiveTabState(parsed.role === 'ADMIN' ? 'admin-dashboard' : 'user-dashboard');
      } else {
        setActiveTabState(allowedTab(route.tab, parsed.role === 'ADMIN'));
      }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const triggerToast = (message: string, type: Toast['type'] = 'info') => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setToasts(prev => [...prev.slice(-3), { id, message, type }]);
    // Errors stay a little longer so they can be read
    setTimeout(() => dismissToast(id), type === 'error' ? 8000 : 5000);
  };

  const handleLogout = () => {
    // Ends the session on the server too, so the token cannot be reused after signing out
    const token = getStoredToken();
    if (token) {
      fetch(`${BACKEND_URL}/api/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } }).catch(() => {});
    }
    clearSession();
    clearSticky('testAgent:');   // the last test and its result belong to this session only
    setSelectedTestIdForView(null);
    setPreselectedAgentForTest('');
    setCurrentUser(null);
    setActiveTab('login');
    triggerToast('Logged out successfully', 'info');
  };

  const isAdmin = currentUser?.role === 'ADMIN';

  // A page that belongs to the other role (typed or bookmarked URL) is replaced with this user's dashboard
  useEffect(() => {
    if (!currentUser || activeTab === 'login') return;
    const allowed = allowedTab(activeTab, currentUser.role === 'ADMIN');
    if (allowed !== activeTab) setActiveTab(allowed);
  }, [currentUser, activeTab, setActiveTab]);

  // Theme tokens are keyed on <html data-theme>; index.html sets it before first paint.
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', isDarkMode ? 'dark' : 'light');
    localStorage.setItem('theme-mode', isDarkMode ? 'dark' : 'light');
  }, [isDarkMode]);

  const legalPath = window.location.pathname.replace(/\/$/, '').toLowerCase();
  if (legalPath === '/privacy' || legalPath === '/terms') {
    return <LegalPage kind={legalPath === '/privacy' ? 'privacy' : 'terms'} />;
  }

  // If activeTab === 'login' or not logged in, render login screen
  if (!currentUser || activeTab === 'login') {
    return (
      <AdminLogin
        onLoginSuccess={(user) => {
          setCurrentUser(user);
          if (user.role === 'ADMIN') {
            setActiveTab('admin-dashboard');
          } else {
            setActiveTab('user-dashboard');
          }
          triggerToast(`Welcome back, ${user.name || user.full_name || 'User'}!`, 'success');
        }}
        isDarkMode={isDarkMode}
        setIsDarkMode={setIsDarkMode}
        portalMode={currentUser ? (isAdmin ? 'admin' : 'user') : undefined}
      />
    );
  }

  return (
    <div className={`app-layout ${isAdmin ? 'admin-layout' : 'user-layout'}`}>
      <a className="skip-link" href="#main-content">Skip to content</a>

      {/* 1. Sidebar Navigation */}
      <Sidebar
        isOpen={isNavOpen}
        onClose={() => setIsNavOpen(false)}
        activeTab={activeTab}
        setActiveTab={navigate}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      {/* 2. Main Workspace Content Area */}
      <div className="main-content-layout">

        <AppTopbar
          currentUser={currentUser}
          activeTab={activeTab}
          setActiveTab={navigate}
          isDarkMode={isDarkMode}
          setIsDarkMode={setIsDarkMode}
          onOpenNav={() => setIsNavOpen(true)}
          onLogout={handleLogout}
        />

        {/* Dynamic Workspace Body */}
        <main className="page-container" id="main-content" tabIndex={-1}>
          <ErrorBoundary key={activeTab}>
          <Suspense fallback={<PageFallback />}>
          
          {/* ========================================================= */}
          {/* USER WORKSPACE ROUTES                                     */}
          {/* ========================================================= */}
          {(!isAdmin || activeTab.startsWith('user-') || activeTab === 'dashboard') && (
            <>
              {/* Tab 1: User Dashboard */}
              {(activeTab === 'user-dashboard' || activeTab === 'dashboard') && (
                <UserDashboard
                  user={currentUser}
                  onStartNewTest={() => navigate('user-test-agent')}
                  onViewTestResult={(testId) => {
                    setSelectedTestIdForView(testId);
                    setActiveTab('user-tests');
                  }}
                  onNavigate={(tab) => {
                    if (tab === 'tests') navigate('user-tests');
                    else if (tab === 'agents') navigate('user-agents');
                    else if (tab === 'reports') navigate('user-reports');
                    else navigate(tab as NavTabType);
                  }}
                />
              )}

              {/* Tab: Live Agents Studio */}
              {(activeTab === 'user-live-agents' || activeTab === 'live-agents' || activeTab === 'live') && (
                <UserLiveAgents
                  user={currentUser}
                  onNavigateToHistory={(testId) => {
                    if (testId) {
                      const num = Number(testId);
                      if (!isNaN(num)) {
                        setSelectedTestIdForView(num);
                      }
                    }
                    setActiveTab(isAdmin ? 'admin-activity' : 'user-tests');
                  }}
                />
              )}

              {/* Tab 2: Test Agent */}
              {(activeTab === 'user-test-agent' || activeTab === 'runner') && (
                <UserTestAgent
                  user={currentUser}
                  preselectedAgentName={preselectedAgentForTest}
                  onTestCompleted={() => {
                    triggerToast('AI agent audit completed and recorded in database!', 'success');
                  }}
                  onNavigate={(tab) => navigate(tab as NavTabType)}
                />
              )}

              {/* Tab 3: My Tests */}
              {(activeTab === 'user-tests' || activeTab === 'tests') && (
                <UserTestHistory
                  user={currentUser}
                  initialSelectedTestId={selectedTestIdForView}
                  onStartNewTest={() => navigate('user-test-agent')}
                  onViewTestResult={(testId) => {
                    setSelectedTestIdForView(testId);
                  }}
                />
              )}

              {/* Tab: Monitored Agents */}
              {(activeTab === 'user-agents' || activeTab === 'agents') && (
                <UserAgents
                  user={currentUser}
                  onSelectAgentForTest={(agentName) => {
                    setPreselectedAgentForTest(agentName);
                    setActiveTab('user-test-agent');
                  }}
                  onViewReport={(testId) => {
                    setSelectedTestIdForView(testId);
                    setActiveTab('user-tests');
                  }}
                />
              )}

              {/* Tab 4: My Reports */}
              {(activeTab === 'user-reports' || activeTab === 'reports') && (
                <UserReports
                  user={currentUser}
                  onViewReportDetail={(testId) => {
                    setSelectedTestIdForView(testId);
                    setActiveTab('user-tests');
                  }}
                />
              )}

              {/* Tab 5: User Profile */}
              {(activeTab === 'user-profile' || activeTab === 'profile') && (
                <UserProfile user={currentUser} />
              )}

              {activeTab === 'user-guide' && <GuidePage isAdmin={false} />}
            </>
          )}

          {/* ========================================================= */}
          {/* ADMIN WORKSPACE ROUTES                                    */}
          {/* ========================================================= */}
          {isAdmin && (
            <>
              {/* Tab 1: Admin Dashboard */}
              {(activeTab === 'admin-dashboard' || activeTab === 'admin') && (
                <AdminDashboard
                  user={currentUser}
                  onNavigate={(tab) => {
                    if (tab === 'activity') navigate('admin-activity');
                    else if (tab === 'users') navigate('admin-users');
                    else if (tab === 'agents') navigate('admin-activity');
                    else if (tab === 'reports') navigate('admin-reports');
                    else if (tab === 'analytics') navigate('admin-analytics');
                    else navigate(tab as NavTabType);
                  }}
                  onViewTestDetails={(testId: number) => {
                    setSelectedTestIdForView(testId);
                    setActiveTab('admin-activity');
                  }}
                />
              )}

              {/* Live agents: read-only, admins watch but do not test */}
              {activeTab === 'admin-live-agents' && (
                <AdminLiveAgents />
              )}

              {/* Activity log: everything users did */}
              {activeTab === 'admin-activity-log' && (
                <AdminActivityLog />
              )}

              {/* Tab 2: Testing Activity (Who Tested What) */}
              {activeTab === 'admin-activity' && (
                <AdminTestingActivity
                  initialSelectedTestId={selectedTestIdForView}
                />
              )}

              {/* Tab 3: User Management */}
              {activeTab === 'admin-users' && (
                <AdminUsers />
              )}

              {/* Tab 4: Monitored Agent Fleet */}
              {activeTab === 'admin-agents' && (
                <AdminAgents />
              )}

              {/* Tab 5: Organization Reports Vault */}
              {activeTab === 'admin-reports' && (
                <AdminReports
                  onViewTestDetails={(testId: number) => {
                    setSelectedTestIdForView(testId);
                    setActiveTab('admin-activity');
                  }}
                />
              )}

              {/* Tab 6: Deep Analytics & Heatmaps */}
              {activeTab === 'admin-analytics' && (
                <AdminAnalytics />
              )}

              {/* Tab 7: Engine Settings */}
              {activeTab === 'admin-settings' && (
                <AdminSettings />
              )}

              {activeTab === 'admin-guide' && <GuidePage isAdmin />}
            </>
          )}

          </Suspense>
                  </ErrorBoundary>
        </main>

      </div>

      <Toaster toasts={toasts} onDismiss={dismissToast} />

    </div>
  );
}

export default App;
