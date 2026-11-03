import React, { useEffect, useMemo, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';
import {
  faTableColumns,
  faShieldHalved,
  faTowerBroadcast,
  faBolt,
  faTerminal,
  faShieldVirus,
  faFire,
  faServer,
  faDesktop,
  faNetworkWired,
  faBug,
  faDiagramProject,
  faGlobe,
  faMagnifyingGlass,
  faWandMagicSparkles,
  faChartSimple,
  faFileLines,
  faClipboardCheck,
  faScroll,
  faUsers,
  faLayerGroup,
  faCreditCard,
  faSliders,
  faChevronRight,
  faChevronDown,
  faChevronLeft,
  faLifeRing,
  faHeadset,
  faSun,
  faMoon,
  faHouse,
  faCrosshairs,
  faGear,
  faXmark
} from '@fortawesome/free-solid-svg-icons';
import { useAuth } from '../../context/AuthContext';
import { useLiveConnectionState } from '../../hooks/useRealtimeStatus';
import type { LiveConnectionState } from '../../hooks/useRealtimeStatus';
import { securityApi, globalRealtimeClient } from '../../services/api';

export type DashboardView =
  | 'dashboard'
  | 'security-overview'
  | 'waf'
  | 'firewall'
  | 'applications'
  | 'networks'
  | 'agents'
  | 'threats'
  | 'security-events'
  | 'live-traffic'
  | 'logs'
  | 'analytics'
  | 'threat-intel'
  | 'incidents'
  | 'reports'
  | 'users-roles'
  | 'integrations'
  | 'billing'
  | 'settings'
  | 'malware'
  | 'ai-agent'
  | 'compliance'
  | 'audit-log'
  | 'contact'
  | 'superadmin';

export type SidebarIconComponent = React.ComponentType<{ className?: string }>;

export const createFaIcon = (icon: IconDefinition): SidebarIconComponent => {
  const IconComponent: SidebarIconComponent = ({ className = '' }) => (
    <FontAwesomeIcon icon={icon} className={className} />
  );
  return IconComponent;
};

export interface NavItem {
  id: DashboardView;
  label: string;
  icon: SidebarIconComponent;
  live?: boolean;
}

export interface NavGroup {
  group: string;
  icon: SidebarIconComponent;
  items: NavItem[];
}

// Single source of truth for sidebar navigation with Font Awesome 6 icons
export const NAV_GROUPS: NavGroup[] = [
  {
    group: 'Main',
    icon: createFaIcon(faHouse),
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: createFaIcon(faTableColumns) },
      { id: 'security-overview', label: 'Security Overview', icon: createFaIcon(faShieldHalved) },
      { id: 'live-traffic', label: 'Live Traffic', icon: createFaIcon(faTowerBroadcast), live: true },
      { id: 'security-events', label: 'Security Events', icon: createFaIcon(faBolt) },
      { id: 'logs', label: 'Centralized Logs', icon: createFaIcon(faTerminal) }
    ]
  },
  {
    group: 'Protection',
    icon: createFaIcon(faShieldHalved),
    items: [
      { id: 'waf', label: 'WAF Engine', icon: createFaIcon(faShieldVirus) },
      { id: 'firewall', label: 'Firewall', icon: createFaIcon(faFire) },
      { id: 'applications', label: 'Applications', icon: createFaIcon(faServer) },
      { id: 'networks', label: 'Networks', icon: createFaIcon(faNetworkWired) },
      { id: 'agents', label: 'Endpoint Agents', icon: createFaIcon(faDesktop) }
    ]
  },
  {
    group: 'Detection & Response',
    icon: createFaIcon(faCrosshairs),
    items: [
      { id: 'threats', label: 'Threats', icon: createFaIcon(faBug) },
      { id: 'incidents', label: 'Incidents', icon: createFaIcon(faDiagramProject) },
      { id: 'threat-intel', label: 'Threat Intel', icon: createFaIcon(faGlobe) },
      { id: 'malware', label: 'Malware Analysis', icon: createFaIcon(faMagnifyingGlass) },
      { id: 'ai-agent', label: 'AI Security Agent', icon: createFaIcon(faWandMagicSparkles) }
    ]
  },
  {
    group: 'Reporting',
    icon: createFaIcon(faChartSimple),
    items: [
      { id: 'analytics', label: 'Analytics', icon: createFaIcon(faChartSimple) },
      { id: 'reports', label: 'Reports', icon: createFaIcon(faFileLines) },
      { id: 'compliance', label: 'Compliance', icon: createFaIcon(faClipboardCheck) },
      { id: 'audit-log', label: 'Audit Logs', icon: createFaIcon(faScroll) }
    ]
  },
  {
    group: 'Administration',
    icon: createFaIcon(faGear),
    items: [
      { id: 'users-roles', label: 'Audience & Roles', icon: createFaIcon(faUsers) },
      { id: 'integrations', label: 'Integrations', icon: createFaIcon(faLayerGroup) },
      { id: 'billing', label: 'Billing & Plan', icon: createFaIcon(faCreditCard) },
      { id: 'settings', label: 'Settings', icon: createFaIcon(faSliders) },
      { id: 'contact', label: 'Contact & Support', icon: createFaIcon(faHeadset) }
    ]
  }
];

/**
 * Adds the Super Admin hub for platform operators. Kept outside the component
 * so the "active group" effect and the rendered navigation always agree.
 */
export function navGroupsForRole(_isSuperAdmin: boolean): NavGroup[] {
  return NAV_GROUPS;
}

// --- Width management ---
export const SIDEBAR_WIDTH_DEFAULT = 252;
export const SIDEBAR_WIDTH_MIN = 220;
export const SIDEBAR_WIDTH_MAX = 320;
const WIDTH_STORAGE_KEY = 'oat-sidebar-width';

// Icon-only rail width (collapsed state, like the reference)
const RAIL_WIDTH = 72;
const RAIL_STORAGE_KEY = 'oat-sidebar-rail';

function clampWidth(value: number) {
  return Math.min(SIDEBAR_WIDTH_MAX, Math.max(SIDEBAR_WIDTH_MIN, Math.round(value)));
}

export function useSidebarWidth(): [number, (next: number) => void] {
  const [width, setWidth] = useState(() => {
    try {
      const stored = Number(localStorage.getItem(WIDTH_STORAGE_KEY));
      if (Number.isFinite(stored) && stored > 0) return clampWidth(stored);
    } catch {
      // storage unavailable
    }
    return SIDEBAR_WIDTH_DEFAULT;
  });

  const update = (next: number) => {
    const clamped = clampWidth(next);
    setWidth(clamped);
    try {
      localStorage.setItem(WIDTH_STORAGE_KEY, String(clamped));
    } catch {
      // storage unavailable
    }
  };

  return [width, update];
}

// --- Group open/closed state ---
const GROUPS_STORAGE_KEY = 'oat-sidebar-collapsed-groups';

function loadCollapsedGroups(): string[] {
  try {
    const raw = localStorage.getItem(GROUPS_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    if (Array.isArray(parsed)) return parsed.filter((entry): entry is string => typeof entry === 'string');
  } catch {
    // fall through
  }
  return [];
}

// --- Engine health ---
interface EngineHealth {
  total: number;
  operational: number;
  degraded: number;
  offline: number;
}

function describeEngineHealth(health: EngineHealth | null, failed: boolean) {
  if (failed) {
    return {
      dot: 'bg-slate-400',
      title: 'Engine status unavailable',
      detail: 'Health endpoint unreachable'
    };
  }
  if (!health || health.total === 0) {
    return {
      dot: 'bg-slate-400',
      title: 'No engines reporting',
      detail: 'Awaiting telemetry'
    };
  }
  if (health.operational === health.total) {
    return {
      dot: 'bg-emerald-500',
      title: 'All engines operational',
      detail: `${health.operational}/${health.total} reporting`
    };
  }
  if (health.operational === 0) {
    return {
      dot: 'bg-rose-500',
      title: 'No engines online',
      detail: `0 of ${health.total} reporting`
    };
  }
  return {
    dot: 'bg-amber-500',
    title: `${health.operational}/${health.total} online`,
    detail: `${health.offline} offline · ${health.degraded} degraded`
  };
}

function LiveTrafficStatusBadge({ state }: { state: LiveConnectionState }) {
  const isLive = state === 'live';
  const isOffline = state === 'offline';

  return (
    <span
      role="status"
      aria-live="polite"
      title={
        isLive
          ? 'Live feed connected — receiving real-time traffic.'
          : isOffline
            ? 'Live feed offline — the server is unreachable. Reconnecting automatically.'
            : 'Live feed connecting — waiting for the real-time stream.'
      }
      className={`shrink-0 inline-flex items-center gap-1 text-[9px] font-bold tracking-wide px-1.5 py-0.5 rounded-md transition-colors ${
        isLive
          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400'
          : isOffline
            ? 'bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-400'
            : 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400'
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          isLive ? 'bg-emerald-500 animate-pulse' : isOffline ? 'bg-rose-500' : 'bg-amber-500 animate-pulse'
        }`}
      />
      {isLive ? 'LIVE' : isOffline ? 'OFFLINE' : 'SYNC'}
    </span>
  );
}

interface DashboardSidebarProps {
  currentView: DashboardView;
  onSelectView: (view: DashboardView) => void;
  width: number;
  onWidthChange: (next: number) => void;
  onOpenSearch?: () => void;
  /** Off-canvas drawer state (below `lg`, the sidebar floats over the content). */
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

type ThemeMode = 'light' | 'dark' | 'system';

export const DashboardSidebar: React.FC<DashboardSidebarProps> = ({
  currentView,
  onSelectView,
  width,
  onWidthChange,
  onOpenSearch,
  mobileOpen = false,
  onMobileClose
}) => {
  const { user } = useAuth();
  const liveConnection = useLiveConnectionState();

  const asideRef = useRef<HTMLElement>(null);
  const railNavRef = useRef<HTMLElement>(null);
  const railFlyoutRef = useRef<HTMLDivElement>(null);

  const [closedGroups, setClosedGroups] = useState<string[]>(loadCollapsedGroups);
  const [health, setHealth] = useState<EngineHealth | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);
  const [showStatusPopover, setShowStatusPopover] = useState(false);

  // Icon-only rail (collapsed sidebar) state
  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(RAIL_STORAGE_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [railTip, setRailTip] = useState<{ label: string; top: number; left: number } | null>(null);
  const [railFlyout, setRailFlyout] = useState<{ group: NavGroup; top: number; left: number } | null>(null);

  // Theme switcher state
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    try {
      const stored = localStorage.getItem('oat-theme-mode') as ThemeMode | null;
      if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
    } catch {
      // ignore
    }
    return 'light';
  });
  const [resolvedDark, setResolvedDark] = useState(false);

  // Apply theme to document root
  useEffect(() => {
    const applyTheme = (mode: ThemeMode) => {
      let isDark = false;
      if (mode === 'dark') {
        isDark = true;
      } else if (mode === 'light') {
        isDark = false;
      } else {
        isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      }

      if (isDark) {
        document.documentElement.classList.add('dark');
        document.documentElement.classList.remove('light');
      } else {
        document.documentElement.classList.remove('dark');
        document.documentElement.classList.add('light');
      }
      setResolvedDark(isDark);

      try {
        localStorage.setItem('oat-theme-mode', mode);
      } catch {
        // ignore
      }
    };

    applyTheme(themeMode);

    if (themeMode === 'system') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const handleChange = () => applyTheme('system');
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
  }, [themeMode]);

  // Persisted group state
  useEffect(() => {
    try {
      localStorage.setItem(GROUPS_STORAGE_KEY, JSON.stringify(closedGroups));
    } catch {
      // storage unavailable
    }
  }, [closedGroups]);

  // Persisted rail state
  useEffect(() => {
    try {
      localStorage.setItem(RAIL_STORAGE_KEY, railCollapsed ? '1' : '0');
    } catch {
      // storage unavailable
    }
  }, [railCollapsed]);

  // Keep group containing active item expanded
  useEffect(() => {
    const owner = navGroupsForRole(user?.role === 'Super Admin')
      .find(group => group.items.some(item => item.id === currentView));
    if (!owner) return;
    setClosedGroups(prev => (prev.includes(owner.group) ? prev.filter(name => name !== owner.group) : prev));
  }, [currentView]);

  // Telemetry health — realtime via the /ws stream (server pushes the whole
  // snapshot every second), REST poll kept only as a low-frequency fallback.
  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const result = await securityApi.getSystemHealthDetailed();
        if (cancelled) return;
        setHealth(result.summary);
        setHealthFailed(false);
      } catch {
        if (cancelled) return;
        setHealthFailed(true);
      }
    };

    load();

    const unsub = globalRealtimeClient.subscribe((msg: any) => {
      if (cancelled) return;
      if (msg?.type === 'system.health' || msg?.type === 'system.health_changed') {
        const summary = msg?.data?.summary ?? msg?.summary;
        if (summary) {
          setHealth(summary);
          setHealthFailed(false);
        }
      }
    });

    const timer = window.setInterval(load, 60000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
      unsub();
    };
  }, []);

  const statusPopoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (statusPopoverRef.current && !statusPopoverRef.current.contains(e.target as Node)) {
        setShowStatusPopover(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  // Close the rail flyout when clicking anywhere outside the rail / flyout
  useEffect(() => {
    if (!railCollapsed || !railFlyout) return;
    const handleOutsideClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (railFlyoutRef.current?.contains(target)) return;
      if (railNavRef.current?.contains(target)) return;
      setRailFlyout(null);
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, [railCollapsed, railFlyout]);

  // Rail resize handlers (pure drag to resize width, no close/toggle)
  const dragRef = useRef<{ startX: number; startWidth: number; moved: boolean } | null>(null);

  const handleRailPointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    event.preventDefault();
    dragRef.current = { startX: event.clientX, startWidth: width, moved: false };
    document.body.dataset.sidebarResizing = 'true';

    const handleMove = (moveEvent: PointerEvent) => {
      const drag = dragRef.current;
      if (!drag) return;
      const delta = moveEvent.clientX - drag.startX;
      if (Math.abs(delta) > 3) drag.moved = true;
      if (drag.moved) onWidthChange(drag.startWidth + delta);
    };

    const handleUp = () => {
      dragRef.current = null;
      delete document.body.dataset.sidebarResizing;
      window.removeEventListener('pointermove', handleMove);
      window.removeEventListener('pointerup', handleUp);
    };

    window.addEventListener('pointermove', handleMove);
    window.addEventListener('pointerup', handleUp);
  };

  const engineStatus = describeEngineHealth(health, healthFailed);

  const toggleGroup = (groupName: string) => {
    setClosedGroups(prev =>
      prev.includes(groupName) ? prev.filter(g => g !== groupName) : [...prev, groupName]
    );
  };

  const isDarkActive = themeMode === 'dark' || (themeMode === 'system' && resolvedDark);

  // Rail interactions are desktop-only: while the mobile drawer is open the
  // panel always renders expanded, even if the rail mode is enabled.
  const isSuperAdminRole = user?.role === 'Super Admin';
  const effectiveNavGroups = useMemo(() => navGroupsForRole(isSuperAdminRole), [isSuperAdminRole]);

  const railActive = railCollapsed && !mobileOpen;

  const toggleRail = () => {
    setRailCollapsed(prev => !prev);
    setRailTip(null);
    setRailFlyout(null);
  };

  const panelRightEdge = () => asideRef.current?.getBoundingClientRect().right ?? 0;

  const showRailTip = (label: string, event: React.MouseEvent<HTMLButtonElement>) => {
    if (!railActive || railFlyout) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const top = Math.min(Math.max(rect.top + rect.height / 2, 28), window.innerHeight - 28);
    setRailTip({ label, top, left: panelRightEdge() + 10 });
  };

  const toggleRailFlyout = (group: NavGroup, event: React.MouseEvent<HTMLButtonElement>) => {
    if (!railActive) return;
    setRailTip(null);
    if (railFlyout?.group.group === group.group) {
      setRailFlyout(null);
      return;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    const maxTop = Math.max(12, window.innerHeight - 320);
    const top = Math.min(Math.max(rect.top - 6, 12), maxTop);
    setRailFlyout({ group, top, left: panelRightEdge() + 10 });
  };

  const selectFromRail = (view: DashboardView) => {
    onSelectView(view);
    setRailFlyout(null);
  };

  return (
    <>
      {/* Mobile backdrop — below `lg` the sidebar floats over the content. */}
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 z-40 bg-black/50 backdrop-blur-xs" onClick={onMobileClose} />
      )}

      <aside
        ref={asideRef}
        data-slot="sidebar-container"
        style={{ width: `${railActive ? RAIL_WIDTH : width}px` }}

        className={`relative m-3 shrink-0 flex flex-col rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100 select-none shadow-xs transition-all duration-200 h-[calc(100%-1.5rem)] max-lg:fixed max-lg:top-0 max-lg:bottom-0 max-lg:left-0 max-lg:m-0 max-lg:h-full max-lg:w-72 max-lg:max-w-[85vw] max-lg:rounded-r-2xl max-lg:rounded-l-none max-lg:z-50 max-lg:shadow-2xl ${mobileOpen ? 'max-lg:translate-x-0' : 'max-lg:-translate-x-full'}`}
      >
        {/* Collapse / expand toggle */}
        <button
          type="button"
          onClick={toggleRail}
          title={railCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="max-lg:hidden absolute -right-3 top-5 z-40 w-6 h-6 rounded-full border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 shadow-md flex items-center justify-center transition-colors cursor-pointer"
        >
          <FontAwesomeIcon icon={railCollapsed ? faChevronRight : faChevronLeft} className="text-[9px]" />
        </button>

        {/* Brand header */}
        <header className={`shrink-0 flex items-center gap-2.5 pt-4 pb-1 ${railActive ? 'justify-center px-2' : 'px-3.5'}`}>
          <span className="w-10 h-10 shrink-0 rounded-xl bg-zinc-900 dark:bg-zinc-100 flex items-center justify-center shadow-xs">
            <FontAwesomeIcon icon={faShieldHalved} className="text-[17px] text-white dark:text-zinc-900" />
          </span>
          {!railActive && (
            <div className="min-w-0 flex-1 leading-tight">
              <div className="text-[15px] font-extrabold tracking-tight text-zinc-900 dark:text-white truncate">
                OAT <span className="font-light text-zinc-500 dark:text-zinc-400">SECURITY</span>
              </div>
              <div className="text-[11px] font-medium text-zinc-400 dark:text-zinc-500 truncate mt-0.5">
                UrbanNusaCyber
              </div>
            </div>
          )}
          {!railActive && onOpenSearch && (
            <button
              type="button"
              onClick={onOpenSearch}
              title="Search modules (Cmd+K)"
              className="shrink-0 w-7 h-7 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 transition-colors cursor-pointer"
            >
              <FontAwesomeIcon icon={faMagnifyingGlass} className="text-[12px]" />
            </button>
          )}
          {!railActive && onMobileClose && (
            <button
              type="button"
              onClick={onMobileClose}
              title="Tutup Menu"
              className="lg:hidden shrink-0 w-7 h-7 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 transition-colors cursor-pointer"
            >
              <FontAwesomeIcon icon={faXmark} className="text-[13px]" />
            </button>
          )}
        </header>

        {/* Navigation */}
        <nav
          ref={railNavRef}
          className={`flex-1 min-h-0 ${railActive
            ? 'overflow-visible px-3 pt-3 pb-2 flex flex-col items-center gap-1.5'
            : 'overflow-y-auto px-3 pt-2 pb-2 custom-scrollbar'
            }`}
        >
          {railActive ? (
            /* Icon-only rail */
            effectiveNavGroups.map(group => {
              const Icon = group.icon;
              const groupActive = group.items.some(item => item.id === currentView);
              const flyoutOpen = railFlyout?.group.group === group.group;
              return (
                <button
                  key={group.group}
                  type="button"
                  onClick={e => toggleRailFlyout(group, e)}
                  onMouseEnter={e => showRailTip(group.group, e)}
                  onMouseLeave={() => setRailTip(null)}
                  className={`w-11 h-11 rounded-xl flex items-center justify-center transition-colors cursor-pointer ${
                    flyoutOpen || groupActive
                      ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                      : 'text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100/80 dark:hover:bg-zinc-800/60 hover:text-zinc-900 dark:hover:text-zinc-100'
                  }`}
                >
                  <Icon className="text-[16px]" />
                </button>
              );
            })
          ) : (
            /* Full tree navigation */
            <div className="flex flex-col gap-0.5">
              {effectiveNavGroups.map(group => {
                const isClosed = closedGroups.includes(group.group);
                const Icon = group.icon;

                return (
                  <div key={group.group} className="flex flex-col">
                    {/* Group row */}
                    <button
                      type="button"
                      onClick={() => toggleGroup(group.group)}
                      className="group/group flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13.5px] font-medium text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors text-left cursor-pointer"
                    >
                      <span className="w-5 flex items-center justify-center shrink-0">
                        <Icon className="text-[15px] text-zinc-400 dark:text-zinc-500 group-hover/group:text-zinc-600 dark:group-hover/group:text-zinc-300 transition-colors" />
                      </span>
                      <span className="flex-1 truncate">{group.group}</span>
                      <FontAwesomeIcon
                        icon={faChevronDown}
                        className={`text-[9px] text-zinc-400 dark:text-zinc-500 transition-transform duration-200 ${
                          isClosed ? '' : 'rotate-180'
                        }`}
                      />
                    </button>

                    {/* Submenu items (tree) */}
                    {!isClosed && (
                      <div className="relative ml-[26px] pl-4 border-l border-zinc-200/90 dark:border-zinc-800/80 mt-0.5 mb-0.5 flex flex-col gap-0.5">
                        {group.items.map(item => {
                          const isActive = currentView === item.id;

                          return (
                            <button
                              key={item.id}
                              type="button"

                              onClick={() => {
                                onSelectView(item.id);
                                if (onMobileClose) onMobileClose();
                              }}
                              className={`flex items-center gap-2 px-3 py-2 rounded-xl text-[13px] transition-all duration-150 text-left cursor-pointer ${
                                isActive
                                  ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-zinc-100 font-semibold'
                                  : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50 hover:text-zinc-900 dark:hover:text-zinc-100 font-medium'
                              }`}
                            >
                              <span className="flex-1 truncate">{item.label}</span>
                              {item.live && <LiveTrafficStatusBadge state={liveConnection} />}
                              {isActive && (
                                <FontAwesomeIcon
                                  icon={faChevronRight}
                                  className="shrink-0 text-[9px] text-zinc-400 dark:text-zinc-500"
                                />
                              )}
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </nav>

        {/* Bottom section */}
        {railActive ? (
          <footer className="shrink-0 flex flex-col items-center gap-2 px-2 pb-3 pt-1.5">
            <div className="relative" ref={statusPopoverRef}>
              <button
                type="button"
                onClick={() => setShowStatusPopover(prev => !prev)}
                title={engineStatus.title}
                className="w-8 h-8 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors cursor-pointer"
              >
                <FontAwesomeIcon icon={faLifeRing} className="text-[13px]" />
              </button>

              {showStatusPopover && (
                <div className="absolute bottom-full left-0 mb-2 w-56 bg-white dark:bg-zinc-900 rounded-2xl shadow-lg border border-zinc-200/80 dark:border-zinc-800 p-3 z-50 text-xs">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${engineStatus.dot}`} />
                    <span className="font-semibold text-zinc-800 dark:text-zinc-200 truncate">
                      {engineStatus.title}
                    </span>
                  </div>
                  <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mb-2">
                    {engineStatus.detail}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      onSelectView('settings');
                      setShowStatusPopover(false);
                    }}
                    className="w-full text-center py-1 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 font-medium transition-colors cursor-pointer"
                  >
                    System Settings
                  </button>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => setThemeMode(isDarkActive ? 'light' : 'dark')}
              title={isDarkActive ? 'Switch to light mode' : 'Switch to dark mode'}
              className="w-9 h-9 rounded-xl flex items-center justify-center text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
            >
              <FontAwesomeIcon icon={isDarkActive ? faSun : faMoon} className="text-[13px]" />
            </button>
          </footer>
        ) : (
          <footer className="shrink-0 px-3 pb-3 pt-1.5 space-y-2">
            {/* Plan + health row */}
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => onSelectView('billing')}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800/80 text-zinc-700 dark:text-zinc-300 transition-all text-[11px] font-semibold shadow-2xs group/plan cursor-pointer"
              >
                <span className="w-3.5 h-3.5 rounded-full bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center text-zinc-500 group-hover/plan:text-zinc-800 dark:group-hover/plan:text-zinc-200 transition-colors">
                  <FontAwesomeIcon icon={faBolt} className="w-2 h-2" />
                </span>
                <span>Free</span>
              </button>

              <div className="relative" ref={statusPopoverRef}>
                <button
                  type="button"
                  onClick={() => setShowStatusPopover(prev => !prev)}
                  title={engineStatus.title}
                  className="w-7 h-7 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors cursor-pointer"
                >
                  <FontAwesomeIcon icon={faLifeRing} className="text-[12px]" />
                </button>

                {showStatusPopover && (
                  <div className="absolute bottom-full right-0 mb-2 w-56 bg-white dark:bg-zinc-900 rounded-2xl shadow-lg border border-zinc-200/80 dark:border-zinc-800 p-3 z-50 text-xs">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${engineStatus.dot}`} />
                      <span className="font-semibold text-zinc-800 dark:text-zinc-200 truncate">
                        {engineStatus.title}
                      </span>
                    </div>
                    <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mb-2">
                      {engineStatus.detail}
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        onSelectView('settings');
                        setShowStatusPopover(false);
                      }}
                      className="w-full text-center py-1 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 font-medium transition-colors cursor-pointer"
                    >
                      System Settings
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Light / Dark segmented control */}
            <div className="flex items-center gap-1 p-1 rounded-full bg-zinc-100 dark:bg-zinc-800/60">
              <button
                type="button"
                onClick={() => setThemeMode('light')}
                title="Light Mode"
                className={`flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-full text-[11px] transition-all cursor-pointer ${
                  !isDarkActive
                    ? 'bg-white dark:bg-zinc-700 text-zinc-900 dark:text-zinc-100 font-semibold border border-zinc-200/80 dark:border-zinc-600 shadow-2xs'
                    : 'text-zinc-500 dark:text-zinc-400 font-medium hover:text-zinc-700 dark:hover:text-zinc-200'
                }`}
              >
                <FontAwesomeIcon icon={faSun} className="text-[10px]" />
                <span>Light</span>
              </button>
              <button
                type="button"
                onClick={() => setThemeMode('dark')}
                title="Dark Mode"
                className={`flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-full text-[11px] transition-all cursor-pointer ${
                  isDarkActive
                    ? 'bg-white dark:bg-zinc-700 text-zinc-900 dark:text-zinc-100 font-semibold border border-zinc-200/80 dark:border-zinc-600 shadow-2xs'
                    : 'text-zinc-500 dark:text-zinc-400 font-medium hover:text-zinc-700 dark:hover:text-zinc-200'
                }`}
              >
                <FontAwesomeIcon icon={faMoon} className="text-[10px]" />
                <span>Dark</span>
              </button>
            </div>
          </footer>
        )}

        {/* Resize rail on right edge */}
        {!railActive && (
          <div
            onPointerDown={handleRailPointerDown}
            onDoubleClick={() => onWidthChange(SIDEBAR_WIDTH_DEFAULT)}
            className="max-lg:hidden absolute inset-y-3 -right-1 w-2 cursor-col-resize rounded-full transition-colors hover:bg-blue-500/30 z-30"
            title="Drag to resize width"
          />
        )}
      </aside>

      {/* Rail hover tooltip */}
      {railActive && railTip && (
        <div
          className="fixed z-[70] pointer-events-none -translate-y-1/2 px-2.5 py-1.5 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 text-[11px] font-semibold whitespace-nowrap shadow-lg"
          style={{ top: railTip.top, left: railTip.left }}
        >
          {railTip.label}
        </div>
      )}

      {/* Rail flyout submenu */}
      {railActive && railFlyout && (
        <div
          ref={railFlyoutRef}
          className="fixed z-[60] w-56 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xl p-1.5"
          style={{ top: railFlyout.top, left: railFlyout.left }}
        >
          <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
            {railFlyout.group.group}
          </div>
          <div className="flex flex-col gap-0.5">
            {railFlyout.group.items.map(item => {
              const isActive = currentView === item.id;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => selectFromRail(item.id)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-xl text-[13px] transition-all duration-150 text-left cursor-pointer ${
                    isActive
                      ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-zinc-100 font-semibold'
                      : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50 hover:text-zinc-900 dark:hover:text-zinc-100 font-medium'
                  }`}
                >
                  <span className="flex-1 truncate">{item.label}</span>
                  {item.live && <LiveTrafficStatusBadge state={liveConnection} />}
                  {isActive && (
                    <FontAwesomeIcon
                      icon={faChevronRight}
                      className="shrink-0 text-[9px] text-zinc-400 dark:text-zinc-500"
                    />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </>
  );
};
