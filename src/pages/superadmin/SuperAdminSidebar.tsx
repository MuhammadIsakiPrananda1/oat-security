import React, { useEffect, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';
import {
  faTableColumns,
  faTowerBroadcast,
  faBolt,
  faServer,
  faMicrochip,
  faShieldVirus,
  faBuilding,
  faUsers,
  faScroll,
  faSliders,
  faWaveSquare,
  faCloudArrowUp,
  faChevronRight,
  faChevronLeft,
  faChevronDown,
  faArrowLeft,
  faRightFromBracket,
  faShieldHalved,
  faSun,
  faMoon,
  faHouseLaptop,
  faUserGear,
  faDiagramProject,
  faFileShield
} from '@fortawesome/free-solid-svg-icons';
import { useAuth } from '../../context/AuthContext';
import { DASHBOARD_PATH } from '../../App';
import { navigate } from '../../router';

export type SuperAdminTab =
  | 'overview'
  | 'traffic'
  | 'events'
  | 'fleet'
  | 'engines'
  | 'waf-cluster'
  | 'tenants'
  | 'users'
  | 'audit-log'
  | 'engine-config'
  | 'telemetry'
  | 'maintenance';

export type SidebarIconComponent = React.ComponentType<{ className?: string }>;

export const createFaIcon = (icon: IconDefinition): SidebarIconComponent => {
  const IconComponent: SidebarIconComponent = ({ className = '' }) => (
    <FontAwesomeIcon icon={icon} className={className} />
  );
  return IconComponent;
};

export interface SuperAdminNavItem {
  id: SuperAdminTab;
  label: string;
  icon: SidebarIconComponent;
  live?: boolean;
}

export interface SuperAdminNavGroup {
  group: string;
  icon: SidebarIconComponent;
  items: SuperAdminNavItem[];
}

export const SUPERADMIN_NAV_GROUPS: SuperAdminNavGroup[] = [
  {
    group: 'Tenant & User Control',
    icon: createFaIcon(faUserGear),
    items: [
      { id: 'users', label: 'Users & RBAC Control', icon: createFaIcon(faUsers) },
      { id: 'tenants', label: 'Tenant Directory', icon: createFaIcon(faBuilding) },
      { id: 'audit-log', label: 'Global Audit Logs', icon: createFaIcon(faScroll) }
    ]
  },
  {
    group: 'Global Operations',
    icon: createFaIcon(faTableColumns),
    items: [
      { id: 'overview', label: 'Cross-Tenant Overview', icon: createFaIcon(faTableColumns) },
      { id: 'traffic', label: 'Global Live Traffic', icon: createFaIcon(faTowerBroadcast), live: true },
      { id: 'events', label: 'Security Events', icon: createFaIcon(faBolt) }
    ]
  },
  {
    group: 'Fleet & Infrastructure',
    icon: createFaIcon(faServer),
    items: [
      { id: 'fleet', label: 'Agents & Servers', icon: createFaIcon(faServer) },
      { id: 'engines', label: 'Engine Health & Services', icon: createFaIcon(faMicrochip) },
      { id: 'waf-cluster', label: 'WAF Cluster Monitoring', icon: createFaIcon(faShieldVirus) }
    ]
  },
  {
    group: 'Platform & Engine',
    icon: createFaIcon(faSliders),
    items: [
      { id: 'engine-config', label: 'Engine Configuration', icon: createFaIcon(faSliders) },
      { id: 'telemetry', label: 'Platform Telemetry', icon: createFaIcon(faWaveSquare) },
      { id: 'maintenance', label: 'Maintenance & Backup', icon: createFaIcon(faCloudArrowUp) }
    ]
  }
];

export const SIDEBAR_WIDTH_DEFAULT = 252;
export const SIDEBAR_WIDTH_MIN = 220;
export const SIDEBAR_WIDTH_MAX = 320;
const WIDTH_STORAGE_KEY = 'oat-superadmin-sidebar-width';
const RAIL_WIDTH = 72;
const RAIL_STORAGE_KEY = 'oat-superadmin-sidebar-rail';
const GROUPS_STORAGE_KEY = 'oat-superadmin-sidebar-groups';

function clampWidth(value: number) {
  return Math.min(SIDEBAR_WIDTH_MAX, Math.max(SIDEBAR_WIDTH_MIN, Math.round(value)));
}

export function useSuperAdminSidebarWidth(): [number, (next: number) => void] {
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

interface SuperAdminSidebarProps {
  currentTab: SuperAdminTab;
  onSelectTab: (tab: SuperAdminTab) => void;
  width: number;
  onWidthChange: (next: number) => void;
  counts?: {
    agents?: number;
    events?: number;
    tenants?: number;
    users?: number;
    operationalEngines?: number;
    totalEngines?: number;
  };
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

type ThemeMode = 'light' | 'dark' | 'system';

export const SuperAdminSidebar: React.FC<SuperAdminSidebarProps> = ({
  currentTab,
  onSelectTab,
  width,
  onWidthChange,
  counts,
  mobileOpen = false,
  onMobileClose
}) => {
  const { user, logout } = useAuth();
  const asideRef = useRef<HTMLElement>(null);
  const railNavRef = useRef<HTMLElement>(null);
  const railFlyoutRef = useRef<HTMLDivElement>(null);

  const [closedGroups, setClosedGroups] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem(GROUPS_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      if (Array.isArray(parsed)) return parsed.filter((entry): entry is string => typeof entry === 'string');
    } catch {
      // fall through
    }
    return [];
  });

  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(RAIL_STORAGE_KEY) === '1';
    } catch {
      return false;
    }
  });

  const [railTip, setRailTip] = useState<{ label: string; top: number; left: number } | null>(null);
  const [railFlyout, setRailFlyout] = useState<{ group: SuperAdminNavGroup; top: number; left: number } | null>(null);

  // Theme switcher state matching tenant sidebar
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

  useEffect(() => {
    const applyTheme = (mode: ThemeMode) => {
      let isDark = false;
      if (mode === 'dark') isDark = true;
      else if (mode === 'light') isDark = false;
      else isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

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
  }, [themeMode]);

  useEffect(() => {
    try {
      localStorage.setItem(GROUPS_STORAGE_KEY, JSON.stringify(closedGroups));
    } catch {
      // ignore
    }
  }, [closedGroups]);

  useEffect(() => {
    try {
      localStorage.setItem(RAIL_STORAGE_KEY, railCollapsed ? '1' : '0');
    } catch {
      // ignore
    }
  }, [railCollapsed]);

  // Keep group containing active item expanded
  useEffect(() => {
    const owner = SUPERADMIN_NAV_GROUPS.find(g => g.items.some(item => item.id === currentTab));
    if (!owner) return;
    setClosedGroups(prev => (prev.includes(owner.group) ? prev.filter(name => name !== owner.group) : prev));
  }, [currentTab]);

  // Close flyout on outside click
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

  // Drag rail resize
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

  const toggleGroup = (groupName: string) => {
    setClosedGroups(prev =>
      prev.includes(groupName) ? prev.filter(g => g !== groupName) : [...prev, groupName]
    );
  };

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

  const toggleRailFlyout = (group: SuperAdminNavGroup, event: React.MouseEvent<HTMLButtonElement>) => {
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

  const selectItem = (tab: SuperAdminTab) => {
    onSelectTab(tab);
    setRailFlyout(null);
    if (mobileOpen && onMobileClose) onMobileClose();
  };

  const getItemBadge = (id: SuperAdminTab) => {
    if (!counts) return undefined;
    switch (id) {
      case 'fleet': return counts.agents;
      case 'events': return counts.events;
      case 'tenants': return counts.tenants;
      case 'users': return counts.users;
      case 'engines':
        return counts.totalEngines !== undefined
          ? `${counts.operationalEngines ?? 0}/${counts.totalEngines}`
          : undefined;
      default: return undefined;
    }
  };

  const isDarkActive = themeMode === 'dark' || (themeMode === 'system' && resolvedDark);

  return (
    <>
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 z-40 bg-black/50 backdrop-blur-xs" onClick={onMobileClose} />
      )}

      <aside
        ref={asideRef}
        data-slot="superadmin-sidebar-container"
        style={{ width: `${railActive ? RAIL_WIDTH : width}px` }}
        className={`relative m-3 shrink-0 flex flex-col rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100 select-none shadow-xs transition-all duration-200 h-[calc(100%-1.5rem)] max-lg:fixed max-lg:top-0 max-lg:bottom-0 max-lg:left-0 max-lg:z-50 max-lg:shadow-2xl ${
          mobileOpen ? 'max-lg:translate-x-0' : 'max-lg:-translate-x-[130%]'
        }`}
      >
        {/* Rail collapse/expand button */}
        <button
          type="button"
          onClick={toggleRail}
          title={railCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="max-lg:hidden absolute -right-3 top-5 z-40 w-6 h-6 rounded-full border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 shadow-md flex items-center justify-center transition-colors cursor-pointer"
        >
          <FontAwesomeIcon icon={railCollapsed ? faChevronRight : faChevronLeft} className="text-[9px]" />
        </button>

        {/* Brand header - Exact matching height, margins, logo and font sizes */}
        <header className={`shrink-0 flex items-center gap-2.5 pt-4 pb-2 ${railActive ? 'justify-center px-2' : 'px-3.5'}`}>
          <span className="w-10 h-10 shrink-0 rounded-xl bg-zinc-900 dark:bg-zinc-100 flex items-center justify-center shadow-xs">
            <FontAwesomeIcon icon={faShieldHalved} className="text-[17px] text-white dark:text-zinc-900" />
          </span>
          {!railActive && (
            <div className="min-w-0 flex-1 leading-tight">
              <span className="text-sm font-bold tracking-tight text-zinc-900 dark:text-white block">
                OAT Security
              </span>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 font-medium truncate mt-0.5">
                Dashboard Admin
              </p>
            </div>
          )}
        </header>

        {/* Navigation body - Tree layout matching DashboardSidebar */}
        <nav
          ref={railNavRef}
          aria-label="Super admin navigation"
          className={`flex-1 overflow-y-auto custom-scrollbar min-h-0 ${
            railActive ? 'px-2 py-3 flex flex-col items-center gap-1' : 'px-3 py-2'
          }`}
        >
          {railActive ? (
            /* Collapsed icon-only rail with flyouts */
            SUPERADMIN_NAV_GROUPS.map(group => {
              const GroupIcon = group.icon;
              const hasActiveChild = group.items.some(i => i.id === currentTab);
              const isFlyoutOpen = railFlyout?.group.group === group.group;

              return (
                <button
                  key={group.group}
                  type="button"
                  onClick={e => toggleRailFlyout(group, e)}
                  onMouseEnter={e => showRailTip(group.group, e)}
                  onMouseLeave={() => setRailTip(null)}
                  className={`w-11 h-11 rounded-xl flex items-center justify-center transition-colors cursor-pointer relative ${
                    isFlyoutOpen || hasActiveChild
                      ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                      : 'text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100/80 dark:hover:bg-zinc-800/60 hover:text-zinc-900 dark:hover:text-zinc-100'
                  }`}
                  aria-label={group.group}
                >
                  <GroupIcon className="text-[16px]" />
                  {hasActiveChild && (
                    <span className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-indigo-500" />
                  )}
                </button>
              );
            })
          ) : (
            /* Full tree navigation identical to DashboardSidebar */
            <div className="flex flex-col gap-0.5">
              {SUPERADMIN_NAV_GROUPS.map(group => {
                const isClosed = closedGroups.includes(group.group);
                const GroupIcon = group.icon;

                return (
                  <div key={group.group} className="flex flex-col">
                    {/* Group header row */}
                    <button
                      type="button"
                      onClick={() => toggleGroup(group.group)}
                      className="group/group flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13.5px] font-medium text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors text-left cursor-pointer"
                    >
                      <span className="w-5 flex items-center justify-center shrink-0">
                        <GroupIcon className="text-[15px] text-zinc-400 dark:text-zinc-500 group-hover/group:text-zinc-600 dark:group-hover/group:text-zinc-300 transition-colors" />
                      </span>
                      <span className="flex-1 truncate">{group.group}</span>
                      <FontAwesomeIcon
                        icon={faChevronDown}
                        className={`text-[9px] text-zinc-400 dark:text-zinc-500 transition-transform duration-200 ${
                          isClosed ? '' : 'rotate-180'
                        }`}
                      />
                    </button>

                    {/* Submenu items tree */}
                    {!isClosed && (
                      <div className="relative ml-[26px] pl-4 border-l border-zinc-200/90 dark:border-zinc-800/80 mt-0.5 mb-0.5 flex flex-col gap-0.5">
                        {group.items.map(item => {
                          const isActive = currentTab === item.id;
                          const badge = getItemBadge(item.id);

                          return (
                            <button
                              key={item.id}
                              type="button"
                              onClick={() => selectItem(item.id)}
                              className={`flex items-center gap-2 px-3 py-2 rounded-xl text-[13px] transition-all duration-150 text-left cursor-pointer ${
                                isActive
                                  ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-zinc-100 font-semibold'
                                  : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50 hover:text-zinc-900 dark:hover:text-zinc-100 font-medium'
                              }`}
                            >
                              <span className="flex-1 truncate">{item.label}</span>

                              {item.live && (
                                <span className="shrink-0 inline-flex items-center gap-1 text-[9px] font-bold tracking-wide px-1.5 py-0.5 rounded-md bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400">
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                                  LIVE
                                </span>
                              )}

                              {badge !== undefined && (
                                <span className={`px-1.5 py-0.5 rounded-md text-[10px] font-mono ${
                                  isActive
                                    ? 'bg-zinc-200/70 dark:bg-zinc-700/60 text-zinc-900 dark:text-zinc-100'
                                    : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400'
                                }`}>
                                  {badge}
                                </span>
                              )}

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

        {/* Footer info & Profile bar matching tenant layout */}
        <footer className={`shrink-0 border-t border-zinc-200/80 dark:border-zinc-800 p-3 space-y-2.5 ${railActive ? 'flex flex-col items-center !p-2' : ''}`}>
          {/* Quick Action: Control Regular Dashboard */}
          <button
            type="button"
            onClick={() => navigate(DASHBOARD_PATH)}
            title="Switch to Tenant Workspace (Buka Dashboard Biasa)"
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200/80 dark:text-indigo-300 dark:bg-indigo-950/40 dark:hover:bg-indigo-900/60 dark:border-indigo-800/60 transition cursor-pointer shadow-2xs ${
              railActive ? 'justify-center !px-0 !w-10 !h-10' : ''
            }`}
          >
            <FontAwesomeIcon icon={faHouseLaptop} className="text-xs shrink-0" />
            {!railActive && <span className="truncate">Buka Dashboard Biasa</span>}
          </button>

          {/* Theme switcher segmented control */}
          {!railActive ? (
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
          ) : (
            <button
              type="button"
              onClick={() => setThemeMode(isDarkActive ? 'light' : 'dark')}
              title={isDarkActive ? 'Switch to light mode' : 'Switch to dark mode'}
              className="w-10 h-10 rounded-xl flex items-center justify-center text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
            >
              <FontAwesomeIcon icon={isDarkActive ? faSun : faMoon} className="text-[13px]" />
            </button>
          )}

          {/* User profile card */}
          <div className={`p-2 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/70 dark:border-zinc-800/60 flex items-center justify-between gap-2 ${
            railActive ? 'w-10 h-10 !p-0 justify-center' : 'w-full'
          }`}>
            <div className={`flex items-center gap-2.5 min-w-0 ${railActive ? 'hidden' : ''}`}>
              <div className="w-8 h-8 rounded-lg bg-indigo-500/10 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-300 font-bold text-xs flex items-center justify-center shrink-0 border border-indigo-500/20">
                {user?.name ? user.name.slice(0, 2).toUpperCase() : 'SA'}
              </div>
              <div className="min-w-0 leading-tight">
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                  {user?.name || 'Super Admin'}
                </p>
                <p className="text-[10px] text-zinc-500 dark:text-zinc-400 truncate">
                  {user?.email || 'admin@oat.security'}
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={logout}
              title="Sign out"
              className="w-7 h-7 rounded-lg text-zinc-500 dark:text-zinc-400 hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40 dark:hover:text-rose-400 flex items-center justify-center transition cursor-pointer shrink-0"
            >
              <FontAwesomeIcon icon={faRightFromBracket} className="text-xs" />
            </button>
          </div>
        </footer>

        {/* Drag handle for resizing (desktop only) */}
        {!railActive && (
          <div
            onPointerDown={handleRailPointerDown}
            onDoubleClick={() => onWidthChange(SIDEBAR_WIDTH_DEFAULT)}
            className="max-lg:hidden absolute inset-y-3 -right-1 w-2 cursor-col-resize rounded-full transition-colors hover:bg-indigo-500/30 z-30"
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
          className="fixed z-[60] w-56 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xl p-1.5 animate-in fade-in zoom-in-95 duration-150"
          style={{ top: railFlyout.top, left: railFlyout.left }}
        >
          <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 border-b border-zinc-100 dark:border-zinc-800/80 mb-1">
            {railFlyout.group.group}
          </div>
          <div className="flex flex-col gap-0.5">
            {railFlyout.group.items.map(item => {
              const isActive = currentTab === item.id;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => selectItem(item.id)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-xl text-[13px] transition-all duration-150 text-left cursor-pointer ${
                    isActive
                      ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-zinc-100 font-semibold'
                      : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100/70 dark:hover:bg-zinc-800/50 hover:text-zinc-900 dark:hover:text-zinc-100 font-medium'
                  }`}
                >
                  <span className="flex-1 truncate">{item.label}</span>
                  {item.live && (
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shrink-0" />
                  )}
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
