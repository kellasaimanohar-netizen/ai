import {
  Activity,
  BookOpen,
  Bot,
  Clock,
  FileText,
  LayoutDashboard,
  Layers,
  Play,
  Radio,
  ScrollText,
  Settings,
  TrendingUp,
  User,
  Users,
  type LucideIcon,
} from 'lucide-react';

export type NavTabType =
  // User routes
  | 'user-dashboard'
  | 'user-live-agents'
  | 'user-test-agent'
  | 'user-tests'
  | 'user-agents'
  | 'user-reports'
  | 'user-profile'
  | 'user-guide'
  // Admin routes
  | 'admin-dashboard'
  | 'admin-live-agents'
  | 'admin-activity'
  | 'admin-activity-log'
  | 'admin-users'
  | 'admin-agents'
  | 'admin-reports'
  | 'admin-analytics'
  | 'admin-settings'
  | 'admin-guide'
  // General / legacy aliases
  | 'runner'
  | 'tests'
  | 'reports'
  | 'agents'
  | 'dashboard'
  | 'profile'
  | 'admin'
  | 'login'
  | 'live-agents'
  | 'live'
  | 'results'
  | 'rules'
  | 'datasources'
  | 'copilot';

export interface NavItem {
  tab: NavTabType;
  label: string;
  icon: LucideIcon;
  aliases?: NavTabType[];
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const USER_NAV: NavGroup[] = [
  { label: 'Overview', items: [{ tab: 'user-dashboard', label: 'Dashboard', icon: LayoutDashboard, aliases: ['dashboard'] }] },
  {
    label: 'Testing',
    items: [
      { tab: 'user-test-agent', label: 'Test an agent', icon: Play, aliases: ['runner'] },
      { tab: 'user-live-agents', label: 'Live agents', icon: Radio, aliases: ['live-agents', 'live'] },
      { tab: 'user-tests', label: 'Test history', icon: Clock, aliases: ['tests'] },
    ],
  },
  {
    label: 'Fleet',
    items: [
      { tab: 'user-agents', label: 'Agents', icon: Layers, aliases: ['agents'] },
      { tab: 'user-reports', label: 'Reports', icon: FileText, aliases: ['reports'] },
    ],
  },
  {
    label: 'Account',
    items: [
      { tab: 'user-profile', label: 'Profile', icon: User, aliases: ['profile'] },
      { tab: 'user-guide', label: 'Guides', icon: BookOpen },
    ],
  },
];

export const ADMIN_NAV: NavGroup[] = [
  { label: 'Overview', items: [{ tab: 'admin-dashboard', label: 'Dashboard', icon: LayoutDashboard, aliases: ['admin'] }] },
  {
    label: 'Operations',
    items: [
      { tab: 'admin-live-agents', label: 'Live agents', icon: Radio },
      { tab: 'admin-activity', label: 'Testing activity', icon: Activity },
      { tab: 'admin-activity-log', label: 'Activity log', icon: ScrollText },
      { tab: 'admin-agents', label: 'Agent fleet', icon: Bot },
      { tab: 'admin-reports', label: 'Reports', icon: FileText },
    ],
  },
  { label: 'Insights', items: [{ tab: 'admin-analytics', label: 'Analytics', icon: TrendingUp }] },
  {
    label: 'Administration',
    items: [
      { tab: 'admin-users', label: 'Users', icon: Users },
      { tab: 'admin-settings', label: 'System', icon: Settings },
      { tab: 'admin-guide', label: 'Policy and guidance', icon: BookOpen },
    ],
  },
];

export const navFor = (isAdmin: boolean) => (isAdmin ? ADMIN_NAV : USER_NAV);

export const isActiveItem = (item: NavItem, tab: NavTabType) => item.tab === tab || (item.aliases || []).includes(tab);

/** The nav group and item for the current tab, for breadcrumbs. */
export function findNav(isAdmin: boolean, tab: NavTabType): { group: NavGroup; item: NavItem } | null {
  for (const group of navFor(isAdmin)) {
    const item = group.items.find(i => isActiveItem(i, tab));
    if (item) return { group, item };
  }
  return null;
}
