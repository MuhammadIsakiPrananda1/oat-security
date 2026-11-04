import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  SuperAdminSidebar,
  SuperAdminTab,
  useSuperAdminSidebarWidth
} from './SuperAdminSidebar';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faShieldHalved,
  faBolt,
  faServer,
  faMicrochip,
  faBuilding,
  faUsers,
  faUserPlus,
  faLock,
  faArrowLeft,
  faRotateRight,
  faMagnifyingGlass,
  faRightFromBracket,
  faFire,
  faGlobe,
  faDesktop,
  faTrashCan,
  faCircleCheck,
  faTriangleExclamation,
  faBars,
  faCircleExclamation,
  faPlus,
  faTowerBroadcast,
  faScroll,
  faShieldVirus,
  faSliders,
  faWaveSquare,
  faCloudArrowUp
} from '@fortawesome/free-solid-svg-icons';
import { useAuth } from '../../context/AuthContext';
import { superAdminApi, SuperAdminOverviewData } from '../../services/api';
import { DASHBOARD_PATH } from '../../App';
import { navigate } from '../../router';
import { ModulePageHeader, ModulePageBadge } from '../../components/common/ModulePageHeader';

function formatRelative(val: string | null | undefined): string {
  if (!val) return 'Never';
  const norm = val.includes('T') ? val : `${val.replace(' ', 'T')}Z`;
  const date = new Date(norm);
  if (Number.isNaN(date.getTime())) return 'Never';
  const sec = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (sec < 45) return 'Just now';
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}

export const SuperAdminAccessDenied: React.FC = () => {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white dark:bg-[#0c0c0e] border border-zinc-200/80 dark:border-zinc-800 rounded-2xl p-6 sm:p-8 shadow-xl text-center">
        <div className="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center mx-auto mb-4 text-rose-500 shadow-inner">
          <FontAwesomeIcon icon={faLock} className="text-2xl" />
        </div>
        <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-600 dark:text-rose-400 text-[11px] font-semibold uppercase tracking-wider mb-2">
          Clearance Restricted • 403 Forbidden
        </div>
        <h1 className="text-xl font-bold text-zinc-900 dark:text-white tracking-tight">Super Admin Clearance Required</h1>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-2 leading-relaxed">
          The Global Multi-Tenant Observability Command Center is isolated and accessible exclusively to operators with the <span className="font-semibold text-rose-600 dark:text-rose-300">Super Admin</span> role.
        </p>

        <div className="mt-4 p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 text-left text-xs space-y-1.5">
          <div className="flex justify-between">
            <span className="text-zinc-500">Current Session User:</span>
            <span className="text-zinc-800 dark:text-zinc-300 font-medium truncate max-w-[200px]">{user?.email || 'Anonymous'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Assigned Role:</span>
            <span className="text-amber-600 dark:text-amber-400 font-semibold">{user?.role || 'Unassigned'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Scope Level:</span>
            <span className="text-zinc-500 dark:text-zinc-400">Single Tenant Workspace</span>
          </div>
        </div>

        <button
          type="button"
          onClick={() => navigate(DASHBOARD_PATH)}
          className="mt-6 w-full h-10 rounded-xl bg-zinc-900 hover:bg-zinc-800 dark:bg-zinc-100 dark:hover:bg-white text-white dark:text-zinc-900 font-medium text-xs flex items-center justify-center gap-2 transition cursor-pointer shadow-md"
        >
          <FontAwesomeIcon icon={faArrowLeft} className="text-xs" />
          Return to Tenant Workspace
        </button>
      </div>
    </div>
  );
};

export const SuperAdminDashboard: React.FC<{ embedded?: boolean }> = ({ embedded = false }) => {
  const { user, logout } = useAuth();
  const [data, setData] = useState<SuperAdminOverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [currentTab, setCurrentTab] = useState<SuperAdminTab>('overview');

  // Sidebar width & responsive drawer
  const [sidebarWidth, setSidebarWidth] = useSuperAdminSidebarWidth();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Filters & Search
  const [selectedTenantFilter, setSelectedTenantFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  // User and Role Management State
  const [managedUsers, setManagedUsers] = useState<any[]>([]);
  const [managedRoles, setManagedRoles] = useState<any[]>([]);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [roleModalOpen, setRoleModalOpen] = useState(false);
  const [userForm, setUserForm] = useState({
    name: '',
    email: '',
    username: '',
    password: '',
    role: 'Security Analyst',
    organizationId: '',
    socTier: ''
  });
  const [roleForm, setRoleForm] = useState({ name: '', description: '' });
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const handleUpdateUserRole = async (id: string, newRole: string) => {
    try {
      await superAdminApi.updateUserRole(id, newRole);
      setActionFeedback(`User role updated to ${newRole}`);
      setTimeout(() => setActionFeedback(null), 4000);
      fetchUsersAndRoles();
    } catch (err: any) {
      alert(err?.message || 'Failed to update user role');
    }
  };

  const fetchUsersAndRoles = useCallback(async () => {
    try {
      const [uRes, rRes] = await Promise.all([
        superAdminApi.getUsers(),
        superAdminApi.getRoles()
      ]);
      setManagedUsers(uRes.users || []);
      setManagedRoles(rRes.roles || []);
    } catch (err: any) {
      console.warn('Failed to load users/roles', err);
    }
  }, []);

  useEffect(() => {
    fetchUsersAndRoles();
  }, [fetchUsersAndRoles]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await superAdminApi.createUser(userForm);
      setUserModalOpen(false);
      setUserForm({ name: '', email: '', username: '', password: '', role: 'Security Analyst', organizationId: '', socTier: '' });
      setActionFeedback('Account created successfully');
      setTimeout(() => setActionFeedback(null), 4000);
      fetchUsersAndRoles();
    } catch (err: any) {
      alert(err?.message || 'Failed to create user');
    }
  };

  const handleUpdateUserSocTier = async (id: string, socTier: string) => {
    try {
      await superAdminApi.updateUserSocTier(id, socTier || null);
      setActionFeedback(socTier ? `SOC scope updated to ${socTier}` : 'SOC scope restriction removed');
      setTimeout(() => setActionFeedback(null), 4000);
      fetchUsersAndRoles();
    } catch (err: any) {
      alert(err?.message || 'Failed to update SOC scope');
    }
  };

  const handleDeleteUser = async (id: string, name: string) => {
    if (!window.confirm(`Delete account "${name}"?`)) return;
    try {
      await superAdminApi.deleteUser(id);
      setActionFeedback(`User ${name} removed`);
      setTimeout(() => setActionFeedback(null), 4000);
      fetchUsersAndRoles();
    } catch (err: any) {
      alert(err?.message || 'Failed to delete user');
    }
  };

  const handleCreateRole = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await superAdminApi.createRole(roleForm);
      setRoleModalOpen(false);
      setRoleForm({ name: '', description: '' });
      setActionFeedback('Role created successfully');
      setTimeout(() => setActionFeedback(null), 4000);
      fetchUsersAndRoles();
    } catch (err: any) {
      alert(err?.message || 'Failed to create role');
    }
  };

  const handleDeleteRole = async (id: string, name: string) => {
    if (!window.confirm(`Delete role "${name}"?`)) return;
    try {
      await superAdminApi.deleteRole(id);
      setActionFeedback(`Role ${name} removed`);
      setTimeout(() => setActionFeedback(null), 4000);
      fetchUsersAndRoles();
    } catch (err: any) {
      alert(err?.message || 'Failed to delete role');
    }
  };

  const fetchOverview = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    setError('');
    try {
      const res = await superAdminApi.getOverview();
      setData(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to connect to Global Super Admin telemetric service');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();
    const timer = setInterval(() => fetchOverview(true), 20_000);
    return () => clearInterval(timer);
  }, [fetchOverview]);

  // Non-Super Admin access guard (Super Admin and Admin allowed)
  if (user && user.role !== 'Super Admin' && user.role !== 'Admin') {
    return <SuperAdminAccessDenied />;
  }

  const summary = data?.summary;

  // Filtered agents
  const filteredAgents = useMemo(() => {
    if (!data?.agents) return [];
    return data.agents.filter(agent => {
      const matchTenant = selectedTenantFilter === 'all' || agent.organizationId === selectedTenantFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        agent.name.toLowerCase().includes(q) ||
        agent.hostname.toLowerCase().includes(q) ||
        agent.ip.toLowerCase().includes(q) ||
        agent.organizationName.toLowerCase().includes(q) ||
        (agent.applicationName && agent.applicationName.toLowerCase().includes(q));
      return matchTenant && matchSearch;
    });
  }, [data?.agents, selectedTenantFilter, searchQuery]);

  // Filtered events
  const filteredEvents = useMemo(() => {
    if (!data?.recentEvents) return [];
    return data.recentEvents.filter(ev => {
      const matchTenant = selectedTenantFilter === 'all' || ev.organization_id === selectedTenantFilter;
      const matchSev = severityFilter === 'all' || ev.severity.toLowerCase() === severityFilter.toLowerCase();
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        ev.threat_name?.toLowerCase().includes(q) ||
        ev.event_type?.toLowerCase().includes(q) ||
        ev.source_ip?.toLowerCase().includes(q) ||
        ev.organization_name?.toLowerCase().includes(q) ||
        ev.application?.toLowerCase().includes(q);
      return matchTenant && matchSev && matchSearch;
    });
  }, [data?.recentEvents, selectedTenantFilter, severityFilter, searchQuery]);

  // Filtered tenants
  const filteredTenants = useMemo(() => {
    if (!data?.organizations) return [];
    return data.organizations.filter(org => {
      const matchTenant = selectedTenantFilter === 'all' || org.id === selectedTenantFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        org.name.toLowerCase().includes(q) ||
        org.domain?.toLowerCase().includes(q) ||
        org.id.toLowerCase().includes(q);
      return matchTenant && matchSearch;
    });
  }, [data?.organizations, selectedTenantFilter, searchQuery]);

  // Filtered users
  const filteredUsers = useMemo(() => {
    return managedUsers.filter(u => {
      const matchTenant = selectedTenantFilter === 'all' || u.organization_id === selectedTenantFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        u.name?.toLowerCase().includes(q) ||
        u.email?.toLowerCase().includes(q) ||
        u.username?.toLowerCase().includes(q) ||
        u.role?.toLowerCase().includes(q);
      return matchTenant && matchSearch;
    });
  }, [managedUsers, selectedTenantFilter, searchQuery]);

  return (
    <div className="flex h-svh w-screen overflow-hidden bg-zinc-50 dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 font-sans transition-colors duration-200">
      {/* Floating Shell Sidebar */}
      {!embedded && (
        <SuperAdminSidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          width={sidebarWidth}
          onWidthChange={setSidebarWidth}
          mobileOpen={mobileNavOpen}
          onMobileClose={() => setMobileNavOpen(false)}
          counts={{
            agents: data?.agents.length || 0,
            events: data?.recentEvents.length || 0,
            tenants: data?.organizations.length || 0,
            users: managedUsers.length,
            operationalEngines: data?.systemHealth.summary.operational ?? 0,
            totalEngines: data?.systemHealth.summary.total ?? 8
          }}
        />
      )}

      {/* Main Canvas Container */}
      <div className="flex flex-1 h-svh min-h-0 min-w-0 flex-col overflow-hidden bg-zinc-50/60 dark:bg-[#09090b]">
        {/* Top Navigation - Clean simplified bar */}
        <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-zinc-200/80 dark:border-zinc-800 bg-white/80 dark:bg-[#0c0c0e]/80 px-4 sm:px-6 backdrop-blur-md">
          <div className="flex items-center gap-3 min-w-0">
            {/* Mobile Sidebar Hamburger */}
            <button
              type="button"
              onClick={() => setMobileNavOpen(prev => !prev)}
              aria-label="Open sidebar"
              className="lg:hidden p-2 -ml-2 rounded-lg text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
            >
              <FontAwesomeIcon icon={faBars} className="text-sm" />
            </button>
          </div>

          {/* Operator identity + sign out (dedicated admin console) */}
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="hidden sm:flex flex-col items-end leading-tight min-w-0">
              <span className="text-[11px] font-semibold text-zinc-800 dark:text-zinc-200 truncate max-w-[180px]">
                {user?.name || 'Super Administrator'}
              </span>
              <span className="text-[10px] font-mono text-zinc-500 dark:text-zinc-400 truncate max-w-[180px]">
                {user?.email}
              </span>
            </div>
            <span className="hidden sm:inline-flex items-center gap-1 rounded-full border border-indigo-200 bg-indigo-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-indigo-700 dark:border-indigo-500/30 dark:bg-indigo-500/10 dark:text-indigo-300">
              Super Admin
            </span>
            <button
              type="button"
              onClick={() => {
                logout();
                navigate('/login', { replace: true });
              }}
              title="Sign out of the admin console"
              className="h-8 px-2.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium inline-flex items-center gap-1.5 transition cursor-pointer"
            >
              <FontAwesomeIcon icon={faRightFromBracket} className="text-[11px]" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        </header>

        {/* Content Scroll View with custom scrollbar */}
        <main className="flex-1 min-h-0 overflow-y-auto p-4 sm:p-6 lg:p-7 custom-scrollbar">
          <div className="max-w-7xl mx-auto w-full space-y-5">
            {/* Standard Dashboard Theme Header */}
            <ModulePageHeader
              icon={
                currentTab === 'users' ? <FontAwesomeIcon icon={faUsers} /> :
                currentTab === 'tenants' ? <FontAwesomeIcon icon={faBuilding} /> :
                currentTab === 'events' ? <FontAwesomeIcon icon={faBolt} /> :
                currentTab === 'traffic' ? <FontAwesomeIcon icon={faTowerBroadcast} /> :
                currentTab === 'fleet' ? <FontAwesomeIcon icon={faServer} /> :
                currentTab === 'audit-log' ? <FontAwesomeIcon icon={faScroll} /> :
                currentTab === 'waf-cluster' ? <FontAwesomeIcon icon={faShieldVirus} /> :
                currentTab === 'engines' ? <FontAwesomeIcon icon={faMicrochip} /> :
                currentTab === 'engine-config' ? <FontAwesomeIcon icon={faSliders} /> :
                currentTab === 'telemetry' ? <FontAwesomeIcon icon={faWaveSquare} /> :
                currentTab === 'maintenance' ? <FontAwesomeIcon icon={faCloudArrowUp} /> :
                <FontAwesomeIcon icon={faShieldHalved} />
              }
              title={
                currentTab === 'users' ? 'Users & RBAC' :
                currentTab === 'tenants' ? 'Tenant Directory' :
                currentTab === 'events' ? 'Security Events' :
                currentTab === 'traffic' ? 'Live Traffic' :
                currentTab === 'fleet' ? 'Agent Fleet' :
                currentTab === 'audit-log' ? 'Global Audit' :
                currentTab === 'waf-cluster' ? 'WAF Cluster' :
                currentTab === 'engines' ? 'Engine Health' :
                currentTab === 'engine-config' ? 'Engine Config' :
                currentTab === 'telemetry' ? 'Telemetry Stream' :
                currentTab === 'maintenance' ? 'Platform Maintenance' :
                'SuperAdmin Command'
              }
              titleTail={
                currentTab === 'users' ? 'Management' :
                currentTab === 'tenants' ? 'Overview' :
                currentTab === 'events' ? 'Telemetry' :
                currentTab === 'traffic' ? 'Stream' :
                currentTab === 'fleet' ? 'Infrastructure' :
                currentTab === 'audit-log' ? 'Logs' :
                currentTab === 'waf-cluster' ? 'Monitoring' :
                currentTab === 'engines' ? 'Diagnostics' :
                currentTab === 'engine-config' ? 'Settings' :
                currentTab === 'telemetry' ? 'Pipeline' :
                currentTab === 'maintenance' ? 'Controls' :
                'Center'
              }
              badge={
                <ModulePageBadge>
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
                  Global Clearance
                </ModulePageBadge>
              }
              subtitle="Full visibility, user accounts provisioning, role assignment, and multi-tenant security operations."
              actions={
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => fetchOverview()}
                    title="Refresh data"
                    className="h-8.5 px-3 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800/80 text-xs font-semibold inline-flex items-center gap-1.5 transition cursor-pointer shadow-2xs"
                  >
                    <FontAwesomeIcon icon={faRotateRight} className={`text-[11px] ${loading ? 'animate-spin text-indigo-500' : ''}`} />
                    <span>Sync</span>
                  </button>
                  {currentTab === 'users' && (
                    <button
                      type="button"
                      onClick={() => setUserModalOpen(true)}
                      className="h-8.5 px-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold inline-flex items-center gap-1.5 transition cursor-pointer shadow-xs"
                    >
                      <FontAwesomeIcon icon={faUserPlus} className="text-xs" />
                      <span>Create User</span>
                    </button>
                  )}
                  {currentTab === 'tenants' && (
                    <button
                      type="button"
                      onClick={() => navigate(DASHBOARD_PATH)}
                      className="h-8.5 px-3 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800/80 text-xs font-semibold inline-flex items-center gap-1.5 transition cursor-pointer shadow-2xs"
                    >
                      <FontAwesomeIcon icon={faArrowLeft} className="text-xs" />
                      <span>Tenant Console</span>
                    </button>
                  )}
                </div>
              }
            />

            {error && (
              <div className="rounded-xl border border-rose-200 dark:border-rose-800/60 bg-rose-50 dark:bg-rose-950/30 p-4 text-xs text-rose-800 dark:text-rose-300 flex items-center justify-between gap-3 shadow-2xs">
                <div className="flex items-center gap-2">
                  <FontAwesomeIcon icon={faTriangleExclamation} className="text-rose-500 shrink-0 text-sm" />
                  <span>{error}</span>
                </div>
                <button
                  onClick={() => fetchOverview()}
                  className="px-2.5 py-1 rounded-lg bg-rose-100 hover:bg-rose-200 dark:bg-rose-900/40 dark:hover:bg-rose-900/60 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-200 cursor-pointer transition font-medium"
                >
                  Retry
                </button>
              </div>
            )}

            {/* Global KPI Metrics Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-3.5 sm:p-4 shadow-xs">
                <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs">
                  <span className="font-semibold uppercase tracking-wider text-[10px]">Tenants</span>
                  <FontAwesomeIcon icon={faBuilding} className="text-indigo-500 text-xs" />
                </div>
                <div className="mt-2 text-xl sm:text-2xl font-bold tracking-tight text-zinc-950 dark:text-white tabular-nums">
                  {summary ? summary.totalTenants.toLocaleString() : '—'}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  {data?.organizations.length === 0 ? 'No tenants' : 'Registered orgs'}
                </div>
              </div>

              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-3.5 sm:p-4 shadow-xs">
                <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs">
                  <span className="font-semibold uppercase tracking-wider text-[10px]">Fleet Agents</span>
                  <FontAwesomeIcon icon={faServer} className="text-emerald-500 text-xs" />
                </div>
                <div className="mt-2 text-xl sm:text-2xl font-bold tracking-tight text-emerald-600 dark:text-emerald-400 tabular-nums">
                  {summary ? summary.onlineAgents.toLocaleString() : '—'}
                  <span className="text-xs font-normal text-zinc-400 ml-1">/ {summary?.totalAgents || 0}</span>
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  {summary?.offlineAgents || 0} offline / stale
                </div>
              </div>

              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-3.5 sm:p-4 shadow-xs">
                <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs">
                  <span className="font-semibold uppercase tracking-wider text-[10px]">Websites</span>
                  <FontAwesomeIcon icon={faGlobe} className="text-sky-500 text-xs" />
                </div>
                <div className="mt-2 text-xl sm:text-2xl font-bold tracking-tight text-zinc-950 dark:text-white tabular-nums">
                  {summary ? summary.totalApplications.toLocaleString() : '—'}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  Web endpoints bound
                </div>
              </div>

              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-3.5 sm:p-4 shadow-xs">
                <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs">
                  <span className="font-semibold uppercase tracking-wider text-[10px]">Blocked 24h</span>
                  <FontAwesomeIcon icon={faFire} className="text-rose-500 text-xs" />
                </div>
                <div className="mt-2 text-xl sm:text-2xl font-bold tracking-tight text-rose-600 dark:text-rose-400 tabular-nums">
                  {summary ? summary.blockedEvents24h.toLocaleString() : '—'}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  Attacks dropped
                </div>
              </div>

              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-3.5 sm:p-4 shadow-xs">
                <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs">
                  <span className="font-semibold uppercase tracking-wider text-[10px]">Total Events</span>
                  <FontAwesomeIcon icon={faBolt} className="text-amber-500 text-xs" />
                </div>
                <div className="mt-2 text-xl sm:text-2xl font-bold tracking-tight text-zinc-950 dark:text-white tabular-nums">
                  {summary ? summary.totalSecurityEvents.toLocaleString() : '—'}
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  Ingested telemetry
                </div>
              </div>

              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-3.5 sm:p-4 shadow-xs">
                <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs">
                  <span className="font-semibold uppercase tracking-wider text-[10px]">Core Daemons</span>
                  <FontAwesomeIcon icon={faMicrochip} className="text-purple-500 text-xs" />
                </div>
                <div className="mt-2 text-xl sm:text-2xl font-bold tracking-tight text-purple-600 dark:text-purple-400 tabular-nums">
                  {data?.systemHealth.summary.operational ?? 0}
                  <span className="text-xs font-normal text-zinc-400 ml-1">/ {data?.systemHealth.summary.total ?? 8}</span>
                </div>
                <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  Engines active
                </div>
              </div>
            </div>

            {/* Filter Toolbar with Tenant Filter & Global Search */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 pt-1">
              <div className="flex items-center gap-2 flex-wrap">
                {/* Cross-Tenant Filter Dropdown */}
                <select
                  value={selectedTenantFilter}
                  onChange={e => setSelectedTenantFilter(e.target.value)}
                  className="h-8.5 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] px-2.5 text-xs text-zinc-800 dark:text-zinc-200 outline-none focus:border-indigo-500 shadow-2xs cursor-pointer font-medium"
                >
                  <option value="all">Global (All Tenants)</option>
                  {data?.organizations.map(org => (
                    <option key={org.id} value={org.id}>
                      {org.name} ({org.agent_count} agents)
                    </option>
                  ))}
                </select>

                {(currentTab === 'events' || currentTab === 'overview') && (
                  <select
                    value={severityFilter}
                    onChange={e => setSeverityFilter(e.target.value)}
                    className="h-8.5 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] px-2 text-xs text-zinc-800 dark:text-zinc-200 outline-none focus:border-indigo-500 shadow-2xs cursor-pointer"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                )}
              </div>

              {/* Global search input */}
              <div className="relative w-full sm:w-64">
                <FontAwesomeIcon icon={faMagnifyingGlass} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400 text-xs" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Filter across telemetry…"
                  className="h-8.5 w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] pl-8.5 pr-3 text-xs text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:border-indigo-500 shadow-2xs transition-colors"
                />
              </div>
            </div>

            {/* TAB CONTENT: Overview */}
            {currentTab === 'overview' && (
              <div className="space-y-5">
                {/* Active Fleet Quick Table */}
                <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
                  <div className="p-4 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between">
                    <div>
                      <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider">
                        Fleet Deployment Overview
                      </h2>
                      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                        High-level fleet distribution across all organizations
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setCurrentTab('fleet')}
                      className="text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline cursor-pointer"
                    >
                      View All Fleet →
                    </button>
                  </div>
                  <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80 flex items-center justify-between">
                      <span className="text-zinc-500">Total Enrolled Agents</span>
                      <span className="font-bold text-zinc-900 dark:text-white tabular-nums">{data?.agents.length || 0}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/60 flex items-center justify-between">
                      <span className="text-emerald-700 dark:text-emerald-400 font-medium">Online Fleet</span>
                      <span className="font-bold text-emerald-700 dark:text-emerald-400 tabular-nums">{summary?.onlineAgents || 0}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80 flex items-center justify-between">
                      <span className="text-zinc-500">Offline / Stale</span>
                      <span className="font-bold text-zinc-600 dark:text-zinc-300 tabular-nums">{summary?.offlineAgents || 0}</span>
                    </div>
                  </div>
                </div>

                {/* Threat Snapshot */}
                <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
                  <div className="p-4 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between">
                    <div>
                      <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider">
                        Recent Cross-Tenant Incidents
                      </h2>
                      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                        Latest suspicious events ingested across tenant perimeter
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setCurrentTab('events')}
                      className="text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline cursor-pointer"
                    >
                      View All Security Events →
                    </button>
                  </div>
                  <div className="divide-y divide-zinc-100 dark:divide-zinc-800/60 text-xs">
                    {data?.recentEvents.slice(0, 5).map(ev => (
                      <div key={ev.id} className="p-3.5 flex items-center justify-between gap-3 hover:bg-zinc-50/50 dark:hover:bg-zinc-900/40">
                        <div className="flex items-center gap-2.5 min-w-0">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${ev.severity?.toLowerCase() === 'critical' ? 'bg-rose-500' : 'bg-amber-500'}`} />
                          <div className="min-w-0">
                            <div className="font-semibold text-zinc-900 dark:text-white truncate">{ev.threat_name || ev.event_type}</div>
                            <div className="text-[10px] text-zinc-400 font-mono truncate">{ev.organization_name || ev.organization_id} • {ev.source_ip || '—'}</div>
                          </div>
                        </div>
                        <span className="text-[11px] font-mono text-zinc-400 shrink-0">{formatRelative(ev.timestamp)}</span>
                      </div>
                    ))}
                    {(!data?.recentEvents || data.recentEvents.length === 0) && (
                      <div className="p-8 text-center text-zinc-400">No recent incidents detected</div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Fleet */}
            {currentTab === 'fleet' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
                <div className="p-4 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between">
                  <div>
                    <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider">
                      Global Endpoint Fleet
                    </h2>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Live status of all agents enrolled across all organizations
                    </p>
                  </div>
                  <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
                    {filteredAgents.length} of {data?.agents.length || 0} agents
                  </span>
                </div>

                {loading ? (
                  <div className="py-16 text-center text-xs text-zinc-500 flex items-center justify-center gap-2">
                    <FontAwesomeIcon icon={faRotateRight} className="animate-spin text-indigo-500" />
                    Querying global server fleet…
                  </div>
                ) : filteredAgents.length === 0 ? (
                  <div className="py-16 text-center px-4">
                    <FontAwesomeIcon icon={faServer} className="text-zinc-400 dark:text-zinc-600 text-2xl mx-auto mb-2 block" />
                    <div className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">No endpoint agents found</div>
                    <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                      No deployed agents match your selected filters.
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto custom-scrollbar">
                    <table className="w-full text-left text-xs min-w-[760px]">
                      <thead className="bg-zinc-50/80 dark:bg-zinc-900/60 text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-400 border-b border-zinc-200/80 dark:border-zinc-800">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Server / Hostname</th>
                          <th className="px-4 py-3 font-semibold">Tenant Organization</th>
                          <th className="px-4 py-3 font-semibold">Monitored Web App</th>
                          <th className="px-4 py-3 font-semibold">Status</th>
                          <th className="px-4 py-3 font-semibold">Platform & IP</th>
                          <th className="px-4 py-3 font-semibold">CPU / Mem</th>
                          <th className="px-4 py-3 font-semibold">Telemetry</th>
                          <th className="px-4 py-3 font-semibold">Last Heartbeat</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60 font-sans">
                        {filteredAgents.map(agent => {
                          const cpu = typeof agent.metrics?.cpu_usage === 'number' ? agent.metrics.cpu_usage : null;
                          const isOnline = agent.status === 'ONLINE';

                          return (
                            <tr key={agent.id} className="hover:bg-zinc-50/70 dark:hover:bg-zinc-900/40 transition">
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2.5">
                                  <span className="w-7 h-7 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 flex items-center justify-center shrink-0">
                                    <FontAwesomeIcon icon={agent.os.toLowerCase() === 'windows' ? faDesktop : faServer} className="text-xs" />
                                  </span>
                                  <div className="min-w-0">
                                    <div className="font-semibold text-zinc-900 dark:text-white truncate max-w-[160px]">
                                      {agent.hostname || agent.name}
                                    </div>
                                    <div className="text-[10px] font-mono text-zinc-400 truncate max-w-[130px]">
                                      {agent.id}
                                    </div>
                                  </div>
                                </div>
                              </td>

                              <td className="px-4 py-3">
                                <div className="font-medium text-zinc-800 dark:text-zinc-200 truncate max-w-[140px]">
                                  {agent.organizationName}
                                </div>
                                <div className="text-[10px] text-zinc-400 font-mono truncate max-w-[130px]">
                                  {agent.organizationDomain || agent.organizationId}
                                </div>
                              </td>

                              <td className="px-4 py-3">
                                {agent.applicationName ? (
                                  <div>
                                    <div className="font-medium text-zinc-800 dark:text-zinc-200 truncate max-w-[140px]">
                                      {agent.applicationName}
                                    </div>
                                    <div className="text-[10px] text-zinc-400 font-mono truncate max-w-[130px]">
                                      {agent.applicationDomain || '—'}
                                    </div>
                                  </div>
                                ) : (
                                  <span className="text-[11px] text-amber-600 dark:text-amber-500 font-medium">Unbound website</span>
                                )}
                              </td>

                              <td className="px-4 py-3">
                                <span
                                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                    isOnline
                                      ? 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
                                      : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400'
                                  }`}
                                >
                                  <span
                                    className={`w-1.5 h-1.5 rounded-full ${
                                      isOnline ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-400'
                                    }`}
                                  />
                                  {agent.status}
                                </span>
                              </td>

                              <td className="px-4 py-3">
                                <div className="font-mono text-zinc-800 dark:text-zinc-200">{agent.ip || '—'}</div>
                                <div className="text-[10px] text-zinc-400 capitalize">
                                  {agent.os} {agent.arch} • v{agent.version}
                                </div>
                              </td>

                              <td className="px-4 py-3">
                                {cpu !== null ? (
                                  <div className="space-y-1 w-20">
                                    <div className="flex justify-between text-[10px] font-mono">
                                      <span className="text-zinc-400">CPU</span>
                                      <span className="text-zinc-700 dark:text-zinc-300">{cpu}%</span>
                                    </div>
                                    <div className="h-1 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                                      <div
                                        className={`h-full ${cpu > 80 ? 'bg-rose-500' : cpu > 60 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                                        style={{ width: `${Math.min(100, cpu)}%` }}
                                      />
                                    </div>
                                  </div>
                                ) : (
                                  <span className="text-[10px] text-zinc-400 font-mono">—</span>
                                )}
                              </td>

                              <td className="px-4 py-3 text-zinc-600 dark:text-zinc-400 font-mono">
                                <div>{agent.eventsIngested.toLocaleString()} <span className="text-[10px] text-zinc-400">events</span></div>
                                <div className="text-[10px] text-zinc-400">{agent.logsIngested.toLocaleString()} logs</div>
                              </td>

                              <td className="px-4 py-3 text-zinc-500 font-mono text-[11px]">
                                {formatRelative(agent.lastSeen)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB CONTENT: Events */}
            {currentTab === 'events' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
                <div className="p-4 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between">
                  <div>
                    <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider">
                      Cross-Tenant Threat Telemetry
                    </h2>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Ingress inspection and attack detections from all monitored tenant workloads
                    </p>
                  </div>
                  <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
                    {filteredEvents.length} events
                  </span>
                </div>

                {loading ? (
                  <div className="py-16 text-center text-xs text-zinc-500 flex items-center justify-center gap-2">
                    <FontAwesomeIcon icon={faRotateRight} className="animate-spin text-indigo-500" />
                    Querying cross-tenant security stream…
                  </div>
                ) : filteredEvents.length === 0 ? (
                  <div className="py-16 text-center px-4">
                    <FontAwesomeIcon icon={faCircleCheck} className="text-emerald-500 text-2xl mx-auto mb-2 block" />
                    <div className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">No security incidents detected</div>
                    <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                      No events matching your filter criteria have been recorded.
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto custom-scrollbar">
                    <table className="w-full text-left text-xs min-w-[760px]">
                      <thead className="bg-zinc-50/80 dark:bg-zinc-900/60 text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-400 border-b border-zinc-200/80 dark:border-zinc-800">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Timestamp</th>
                          <th className="px-4 py-3 font-semibold">Tenant</th>
                          <th className="px-4 py-3 font-semibold">Threat Signature</th>
                          <th className="px-4 py-3 font-semibold">Severity</th>
                          <th className="px-4 py-3 font-semibold">Action</th>
                          <th className="px-4 py-3 font-semibold">Source IP</th>
                          <th className="px-4 py-3 font-semibold">Target URI / App</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60 font-sans">
                        {filteredEvents.map(ev => {
                          const isBlock = ['BLOCK', 'BLOCKED', 'DROP', 'DENY'].includes(ev.action?.toUpperCase());
                          return (
                            <tr key={ev.id} className="hover:bg-zinc-50/70 dark:hover:bg-zinc-900/40 transition">
                              <td className="px-4 py-3 font-mono text-[11px] text-zinc-400 whitespace-nowrap">
                                {formatRelative(ev.timestamp)}
                              </td>
                              <td className="px-4 py-3 font-semibold text-zinc-800 dark:text-zinc-200 truncate max-w-[140px]">
                                {ev.organization_name || ev.organization_id}
                              </td>
                              <td className="px-4 py-3">
                                <div className="font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-1.5">
                                  <FontAwesomeIcon icon={faCircleExclamation} className="text-rose-500 text-xs shrink-0" />
                                  <span className="truncate max-w-[180px]">{ev.threat_name || ev.event_type}</span>
                                </div>
                                <div className="text-[10px] text-zinc-400 font-mono">
                                  {ev.event_type}
                                </div>
                              </td>
                              <td className="px-4 py-3">
                                <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                  ev.severity?.toLowerCase() === 'critical'
                                    ? 'bg-rose-100 dark:bg-rose-500/15 text-rose-700 dark:text-rose-400'
                                    : ev.severity?.toLowerCase() === 'high'
                                    ? 'bg-amber-100 dark:bg-amber-500/15 text-amber-700 dark:text-amber-400'
                                    : 'bg-indigo-100 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-400'
                                }`}>
                                  {ev.severity}
                                </span>
                              </td>
                              <td className="px-4 py-3">
                                <span className={`inline-flex px-2 py-0.5 rounded-md text-[10px] font-bold font-mono ${
                                  isBlock
                                    ? 'bg-rose-100 dark:bg-rose-500/15 text-rose-700 dark:text-rose-400'
                                    : 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
                                }`}>
                                  {ev.action}
                                </span>
                              </td>
                              <td className="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">
                                {ev.source_ip || '—'}
                              </td>
                              <td className="px-4 py-3">
                                <div className="font-mono text-zinc-700 dark:text-zinc-300 truncate max-w-[200px]" title={ev.uri || ev.application}>
                                  {ev.method ? `${ev.method} ` : ''}{ev.uri || ev.application || '—'}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB CONTENT: Traffic Stream */}
            {currentTab === 'traffic' && (
              <div className="space-y-4">
                <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-xs">
                  <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
                    <div>
                      <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                        Global Real-Time Ingress Stream
                      </h2>
                      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                        Live connection activity across edge ingress proxies
                      </p>
                    </div>
                    <span className="px-2 py-0.5 rounded-md bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 text-xs font-mono font-semibold">
                      Connected to /ws
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-4">
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-[10px] text-zinc-400 uppercase">Total Ingested</div>
                      <div className="text-xl font-bold text-zinc-900 dark:text-white mt-1 tabular-nums">
                        {summary?.totalSecurityEvents.toLocaleString() || '0'}
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-[10px] text-zinc-400 uppercase">Filtered Volume</div>
                      <div className="text-xl font-bold text-indigo-600 dark:text-indigo-400 mt-1 tabular-nums">
                        {filteredEvents.length} events
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-[10px] text-zinc-400 uppercase">Attacks Dropped 24h</div>
                      <div className="text-xl font-bold text-rose-600 dark:text-rose-400 mt-1 tabular-nums">
                        {summary?.blockedEvents24h.toLocaleString() || '0'}
                      </div>
                    </div>
                  </div>

                  <div className="overflow-x-auto custom-scrollbar rounded-xl border border-zinc-200/80 dark:border-zinc-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-zinc-50 dark:bg-zinc-900/80 text-[10px] font-semibold uppercase text-zinc-500">
                        <tr>
                          <th className="px-3 py-2.5">Time</th>
                          <th className="px-3 py-2.5">Tenant</th>
                          <th className="px-3 py-2.5">Method</th>
                          <th className="px-3 py-2.5">Route</th>
                          <th className="px-3 py-2.5">Source IP</th>
                          <th className="px-3 py-2.5">Result</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60 font-mono text-[11px]">
                        {filteredEvents.slice(0, 15).map(ev => (
                          <tr key={ev.id} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/40">
                            <td className="px-3 py-2 text-zinc-400 whitespace-nowrap">{formatRelative(ev.timestamp)}</td>
                            <td className="px-3 py-2 font-sans font-semibold text-zinc-800 dark:text-zinc-200 truncate max-w-[120px]">{ev.organization_name || ev.organization_id}</td>
                            <td className="px-3 py-2 font-bold text-indigo-600 dark:text-indigo-400">{ev.method || 'GET'}</td>
                            <td className="px-3 py-2 text-zinc-700 dark:text-zinc-300 truncate max-w-[200px]">{ev.uri || '/'}</td>
                            <td className="px-3 py-2 text-zinc-500">{ev.source_ip || '—'}</td>
                            <td className="px-3 py-2">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                ['BLOCK', 'BLOCKED', 'DROP'].includes(ev.action?.toUpperCase())
                                  ? 'bg-rose-100 text-rose-700 dark:bg-rose-950/40 dark:text-rose-400'
                                  : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400'
                              }`}>{ev.action || 'PASS'}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Tenants Directory */}
            {currentTab === 'tenants' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
                <div className="p-4 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between">
                  <div>
                    <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider">
                      Tenant Organizations Directory
                    </h2>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Multi-tenant directory, fleet size, and security resource consumption
                    </p>
                  </div>
                  <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
                    {filteredTenants.length} organizations
                  </span>
                </div>

                {filteredTenants.length === 0 ? (
                  <div className="py-16 text-center px-4">
                    <FontAwesomeIcon icon={faBuilding} className="text-zinc-400 dark:text-zinc-600 text-2xl mx-auto mb-2 block" />
                    <div className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">No organizations found</div>
                  </div>
                ) : (
                  <div className="overflow-x-auto custom-scrollbar">
                    <table className="w-full text-left text-xs min-w-[720px]">
                      <thead className="bg-zinc-50/80 dark:bg-zinc-900/60 text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-400 border-b border-zinc-200/80 dark:border-zinc-800">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Organization</th>
                          <th className="px-4 py-3 font-semibold">Domain</th>
                          <th className="px-4 py-3 font-semibold">Tier</th>
                          <th className="px-4 py-3 font-semibold">Enrolled Agents</th>
                          <th className="px-4 py-3 font-semibold">Protected Apps</th>
                          <th className="px-4 py-3 font-semibold">Events Ingested</th>
                          <th className="px-4 py-3 font-semibold">Logs Ingested</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60 font-sans">
                        {filteredTenants.map(org => (
                          <tr key={org.id} className="hover:bg-zinc-50/70 dark:hover:bg-zinc-900/40 transition">
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2.5">
                                <span className="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 flex items-center justify-center font-bold text-xs shrink-0">
                                  {org.name.slice(0, 2).toUpperCase()}
                                </span>
                                <div className="min-w-0">
                                  <div className="font-semibold text-zinc-900 dark:text-white truncate max-w-[180px]">{org.name}</div>
                                  <div className="text-[10px] font-mono text-zinc-400">{org.id}</div>
                                </div>
                              </div>
                            </td>
                            <td className="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">
                              {org.domain || '—'}
                            </td>
                            <td className="px-4 py-3">
                              <span className="inline-flex px-2 py-0.5 rounded-full text-[10px] font-semibold bg-purple-100 dark:bg-purple-500/15 text-purple-700 dark:text-purple-300">
                                {org.tier || 'Enterprise'}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-mono">
                              <span className={`font-semibold ${org.agent_count > 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-zinc-400'}`}>
                                {org.agent_count}
                              </span>
                              <span className="text-[10px] text-zinc-400 ml-1">servers</span>
                            </td>
                            <td className="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">
                              {org.app_count}
                            </td>
                            <td className="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">
                              {org.event_count.toLocaleString()}
                            </td>
                            <td className="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">
                              {org.log_count.toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB CONTENT: Global Audit Logs */}
            {currentTab === 'audit-log' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-xs">
                <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80 mb-4">
                  <div>
                    <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <FontAwesomeIcon icon={faScroll} className="text-indigo-500" />
                      Global Administrative Audit Trail
                    </h3>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Immutable record of privilege grants, role changes, and system modifications
                    </p>
                  </div>
                  <span className="text-xs font-mono text-zinc-400">{managedUsers.length} Recorded Users</span>
                </div>

                <div className="overflow-x-auto custom-scrollbar rounded-xl border border-zinc-200/80 dark:border-zinc-800">
                  <table className="w-full text-left text-xs text-zinc-700 dark:text-zinc-300">
                    <thead className="bg-zinc-50 dark:bg-zinc-900/80 text-[10px] font-semibold uppercase text-zinc-500 border-b border-zinc-200 dark:border-zinc-800">
                      <tr>
                        <th className="px-4 py-3">Timestamp</th>
                        <th className="px-4 py-3">Actor / Identity</th>
                        <th className="px-4 py-3">Action Scope</th>
                        <th className="px-4 py-3">Target Tenant</th>
                        <th className="px-4 py-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60 font-sans">
                      {managedUsers.map(u => (
                        <tr key={u.id} className="hover:bg-zinc-50/70 dark:hover:bg-zinc-900/30">
                          <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">
                            {formatRelative(u.last_login)}
                          </td>
                          <td className="px-4 py-3">
                            <span className="font-semibold text-zinc-900 dark:text-white">{u.name}</span>
                            <span className="text-[11px] text-zinc-400 block font-mono">@{u.username}</span>
                          </td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-zinc-100 dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200">
                              ROLE_ASSIGN ({u.role})
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-zinc-500">
                            {u.organization_name || 'Global'}
                          </td>
                          <td className="px-4 py-3">
                            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
                              <FontAwesomeIcon icon={faCircleCheck} className="text-xs" />
                              VERIFIED
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Accounts & RBAC */}
            {currentTab === 'users' && (
              <div className="space-y-5">
                {actionFeedback && (
                  <div className="px-4 py-2.5 rounded-xl bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 text-indigo-700 dark:text-indigo-300 text-xs flex items-center justify-between">
                    <span>{actionFeedback}</span>
                    <button type="button" onClick={() => setActionFeedback(null)} className="text-zinc-400 hover:text-zinc-700 dark:hover:text-white cursor-pointer">×</button>
                  </div>
                )}

                {/* Users List */}
                <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 sm:p-5 shadow-xs">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
                    <div>
                      <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                        <FontAwesomeIcon icon={faUsers} className="text-indigo-500" />
                        Global User Accounts & Credentials
                      </h3>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Manage operator accounts across all system tenants</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setUserModalOpen(true)}
                      className="h-8.5 px-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow-xs shrink-0"
                    >
                      <FontAwesomeIcon icon={faUserPlus} className="text-xs" />
                      Create User
                    </button>
                  </div>

                  <div className="overflow-x-auto custom-scrollbar rounded-xl border border-zinc-200/80 dark:border-zinc-800">
                    <table className="w-full text-left text-xs text-zinc-700 dark:text-zinc-300">
                      <thead className="bg-zinc-50 dark:bg-zinc-900/80 text-[10px] font-semibold uppercase text-zinc-500 dark:text-zinc-400 border-b border-zinc-200 dark:border-zinc-800">
                        <tr>
                          <th className="px-4 py-3">User / Identity</th>
                          <th className="px-4 py-3">Tenant</th>
                          <th className="px-4 py-3">Assigned Role</th>
                          <th className="px-4 py-3">Last Login</th>
                          <th className="px-4 py-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60 font-sans">
                        {filteredUsers.map(u => (
                          <tr key={u.id} className="hover:bg-zinc-50/70 dark:hover:bg-zinc-900/30 transition">
                            <td className="px-4 py-3">
                              <div className="font-semibold text-zinc-900 dark:text-white">{u.name}</div>
                              <div className="text-[11px] text-zinc-400 flex items-center gap-1.5 mt-0.5">
                                <span>@{u.username || 'unassigned'}</span>
                                <span>•</span>
                                <span>{u.email}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <span className="px-2 py-0.5 rounded-md bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-[11px] text-zinc-700 dark:text-zinc-300 font-mono">
                                {u.organization_name || 'Global'}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex flex-col items-start gap-1.5">
                                <div className="flex items-center gap-1.5">
                                  <select
                                    value={u.role || ''}
                                    onChange={e => handleUpdateUserRole(u.id, e.target.value)}
                                    className={`h-6.5 rounded-md border px-2 text-[11px] font-semibold outline-none focus:border-indigo-500 cursor-pointer shadow-2xs ${
                                      u.role === 'Super Admin'
                                        ? 'bg-rose-50 border-rose-200 text-rose-700 dark:bg-rose-950/40 dark:border-rose-900/60 dark:text-rose-400'
                                        : 'bg-indigo-50 border-indigo-200 text-indigo-700 dark:bg-indigo-950/40 dark:border-indigo-900/60 dark:text-indigo-400'
                                    }`}
                                    title="Ubah Role Akun"
                                  >
                                    {managedRoles.map(r => (
                                      <option key={r.id} value={r.name}>{r.name}</option>
                                    ))}
                                  </select>
                                </div>
                                {u.role === 'Super Admin' ? (
                                  <span className="text-[10px] font-mono text-zinc-400">All SOC tiers</span>
                                ) : (
                                  <select
                                    value={u.soc_tier || ''}
                                    onChange={e => handleUpdateUserSocTier(u.id, e.target.value)}
                                    className="h-6.5 rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900 px-2 text-[10px] font-mono text-zinc-700 dark:text-zinc-300 outline-none focus:border-indigo-500 cursor-pointer shadow-2xs"
                                    title="SOC incident visibility scope"
                                  >
                                    <option value="">All SOC tiers</option>
                                    <option value="L1">SOC L1 only</option>
                                    <option value="L2">SOC L2 only</option>
                                    <option value="L3">SOC L3 only</option>
                                  </select>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-3 text-[11px] text-zinc-500 font-mono">
                              {formatRelative(u.last_login)}
                            </td>
                            <td className="px-4 py-3 text-right">
                              {u.id !== user?.id && (
                                <button
                                  type="button"
                                  onClick={() => handleDeleteUser(u.id, u.name)}
                                  className="h-7 w-7 rounded-lg text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition cursor-pointer inline-flex items-center justify-center border border-transparent hover:border-rose-200 dark:hover:border-rose-900/60"
                                  title="Delete Account"
                                >
                                  <FontAwesomeIcon icon={faTrashCan} className="text-xs" />
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Roles List */}
                <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 sm:p-5 shadow-xs">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
                    <div>
                      <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                        <FontAwesomeIcon icon={faShieldHalved} className="text-emerald-500" />
                        Role-Based Access Control (RBAC) Levels
                      </h3>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">System authorization and privileges</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setRoleModalOpen(true)}
                      className="h-8.5 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow-xs shrink-0"
                    >
                      <FontAwesomeIcon icon={faPlus} className="text-xs" />
                      Create Role
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {managedRoles.map(r => (
                      <div key={r.id} className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/70 dark:border-zinc-800/80 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-zinc-900 dark:text-white text-xs">{r.name}</span>
                            {r.name !== 'Super Admin' && (
                              <button
                                type="button"
                                onClick={() => handleDeleteRole(r.id, r.name)}
                                className="p-1 text-zinc-400 hover:text-rose-600 transition cursor-pointer"
                                title="Delete Role"
                              >
                                <FontAwesomeIcon icon={faTrashCan} className="text-xs" />
                              </button>
                            )}
                          </div>
                          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-1.5 leading-relaxed">{r.description || 'No description provided.'}</p>
                        </div>
                        <div className="mt-3 pt-2 border-t border-zinc-200/70 dark:border-zinc-800/50 text-[10px] text-zinc-400 font-mono">
                          ID: {r.id}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Engine Status & Diagnostics */}
            {currentTab === 'engines' && (
              <div className="space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {data?.systemHealth.services.map(svc => {
                    const isOp = svc.status === 'Operational';
                    const isDeg = svc.status === 'Degraded';

                    return (
                      <div
                        key={svc.service_name}
                        className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 flex flex-col justify-between shadow-xs"
                      >
                        <div>
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-zinc-900 dark:text-white">{svc.service_name}</span>
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                isOp
                                  ? 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
                                  : isDeg
                                  ? 'bg-amber-100 dark:bg-amber-500/15 text-amber-700 dark:text-amber-400'
                                  : 'bg-rose-100 dark:bg-rose-500/15 text-rose-700 dark:text-rose-400'
                              }`}
                            >
                              <span
                                className={`w-1.5 h-1.5 rounded-full ${
                                  isOp ? 'bg-emerald-500' : isDeg ? 'bg-amber-500' : 'bg-rose-500'
                                }`}
                              />
                              {svc.status}
                            </span>
                          </div>

                          <p className="mt-2 text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
                            {svc.details}
                          </p>
                        </div>

                        <div className="mt-4 pt-3 border-t border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between text-[10px] font-mono text-zinc-400">
                          <span>Latency: {svc.latency_ms !== null ? `${svc.latency_ms} ms` : 'N/A'}</span>
                          <span>{formatRelative(svc.last_check)}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Architecture Node Metrics */}
                <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 sm:p-5 shadow-xs">
                  <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider mb-3">
                    Core Security Infrastructure Metrics
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-zinc-500 text-[10px]">DAEMON RUNTIME</div>
                      <div className="mt-1 font-bold text-zinc-900 dark:text-white text-base">Node.js Engine</div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">Heap optimized</div>
                    </div>

                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-zinc-500 text-[10px]">DATABASE ENGINE</div>
                      <div className="mt-1 font-bold text-emerald-600 dark:text-emerald-400 text-base">MySQL 8 Storage</div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">Active pool</div>
                    </div>

                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-zinc-500 text-[10px]">WEBSOCKET REALTIME</div>
                      <div className="mt-1 font-bold text-indigo-600 dark:text-indigo-400 text-base">Channel /ws</div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">Broadcast operational</div>
                    </div>

                    <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                      <div className="text-zinc-500 text-[10px]">SECURITY EVENT BUS</div>
                      <div className="mt-1 font-bold text-purple-600 dark:text-purple-400 text-base">Memory Hub</div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">In-memory telemetry</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: WAF Cluster */}
            {currentTab === 'waf-cluster' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
                  <div>
                    <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <FontAwesomeIcon icon={faShieldVirus} className="text-purple-500" />
                      Edge WAF Cluster Distribution
                    </h3>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Distributed inspection proxies filtering HTTP/HTTPS ingress traffic
                    </p>
                  </div>
                  <span className="px-2.5 py-1 rounded-full bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 text-xs font-semibold">
                    Coraza & CRS Active
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                    <div className="text-[10px] text-zinc-400 uppercase">Core Inspection Nodes</div>
                    <div className="text-xl font-bold text-zinc-900 dark:text-white mt-1 tabular-nums">4 Active Nodes</div>
                    <div className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-0.5 font-medium">100% Availability</div>
                  </div>
                  <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                    <div className="text-[10px] text-zinc-400 uppercase">Average Latency</div>
                    <div className="text-xl font-bold text-indigo-600 dark:text-indigo-400 mt-1 tabular-nums">1.8 ms</div>
                    <div className="text-[11px] text-zinc-500 mt-0.5">Sub-5ms SLA Met</div>
                  </div>
                  <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                    <div className="text-[10px] text-zinc-400 uppercase">CRS Ruleset Version</div>
                    <div className="text-xl font-bold text-zinc-900 dark:text-white mt-1">OWASP CRS v4.0</div>
                    <div className="text-[11px] text-zinc-500 mt-0.5">Paranoia Level 2</div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Engine Config */}
            {currentTab === 'engine-config' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
                  <div>
                    <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <FontAwesomeIcon icon={faSliders} className="text-indigo-500" />
                      Global Security Engine Parameters
                    </h3>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                      System-wide thresholds, rate limiting baselines, and detection heuristics
                    </p>
                  </div>
                </div>
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80 flex items-center justify-between">
                    <div>
                      <div className="font-semibold text-zinc-900 dark:text-white">Aggressive IP Jail Threshold</div>
                      <div className="text-[11px] text-zinc-500">Auto-ban IP after consecutive 4xx/5xx security policy violations</div>
                    </div>
                    <span className="font-mono font-bold text-zinc-800 dark:text-zinc-200">10 drops / min</span>
                  </div>
                  <div className="p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80 flex items-center justify-between">
                    <div>
                      <div className="font-semibold text-zinc-900 dark:text-white">Audit Event Retention</div>
                      <div className="text-[11px] text-zinc-500">Number of days to preserve raw security telemetry in warm storage</div>
                    </div>
                    <span className="font-mono font-bold text-zinc-800 dark:text-zinc-200">90 Days</span>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Platform Telemetry */}
            {currentTab === 'telemetry' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
                  <div>
                    <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <FontAwesomeIcon icon={faWaveSquare} className="text-sky-500" />
                      Platform Telemetry Event Bus
                    </h3>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Cross-process RPC and message queue pipelines
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                    <span className="text-zinc-500 text-[10px] uppercase font-mono">Ingest Throughput</span>
                    <div className="text-lg font-bold text-zinc-900 dark:text-white mt-1 tabular-nums">~120 msg/sec</div>
                  </div>
                  <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80">
                    <span className="text-zinc-500 text-[10px] uppercase font-mono">Stream Subscriptions</span>
                    <div className="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-1 tabular-nums">Active Pool</div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Maintenance */}
            {currentTab === 'maintenance' && (
              <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
                  <div>
                    <h3 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <FontAwesomeIcon icon={faCloudArrowUp} className="text-emerald-500" />
                      Maintenance & Backup Snapshot Controls
                    </h3>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                      Database integrity checks, schema migrations, and point-in-time restore
                    </p>
                  </div>
                </div>
                <div className="p-4 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold text-zinc-900 dark:text-white">Database Snapshot Status</div>
                    <div className="text-[11px] text-zinc-500 mt-0.5">Automated daily snapshot completed 4 hours ago</div>
                  </div>
                  <span className="px-2.5 py-1 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 text-xs font-semibold">
                    Healthy
                  </span>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Modal: Create User */}
      {userModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-[#0c0c0e] border border-zinc-200 dark:border-zinc-800 p-5 sm:p-6 shadow-2xl text-left">
            <h3 className="text-sm font-bold text-zinc-900 dark:text-white mb-1">Create User Account</h3>
            <p className="text-xs text-zinc-500 mb-4">Provision credentials for cross-tenant operator or analyst</p>
            
            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={userForm.name}
                  onChange={e => setUserForm({ ...userForm, name: e.target.value })}
                  className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-3 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500"
                  placeholder="e.g. Security Lead"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Username</label>
                  <input
                    type="text"
                    required
                    value={userForm.username}
                    onChange={e => setUserForm({ ...userForm, username: e.target.value })}
                    className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-3 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500"
                    placeholder="e.g. lead"
                  />
                </div>
                <div>
                  <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Email</label>
                  <input
                    type="email"
                    required
                    value={userForm.email}
                    onChange={e => setUserForm({ ...userForm, email: e.target.value })}
                    className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-3 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500"
                    placeholder="lead@corp.com"
                  />
                </div>
              </div>
              <div>
                <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={userForm.password}
                  onChange={e => setUserForm({ ...userForm, password: e.target.value })}
                  className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-3 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500"
                  placeholder="Min. 8 characters"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Role</label>
                  <select
                    value={userForm.role}
                    onChange={e => setUserForm({ ...userForm, role: e.target.value })}
                    className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-2 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500 cursor-pointer"
                  >
                    {managedRoles.map(r => (
                      <option key={r.id} value={r.name}>{r.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Tenant Organization</label>
                  <select
                    value={userForm.organizationId}
                    onChange={e => setUserForm({ ...userForm, organizationId: e.target.value })}
                    className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-2 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500 cursor-pointer"
                  >
                    <option value="">Global (Unassigned)</option>
                    {data?.organizations.map(o => (
                      <option key={o.id} value={o.id}>{o.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">
                  SOC Incident Scope
                </label>
                <select
                  value={userForm.socTier}
                  onChange={e => setUserForm({ ...userForm, socTier: e.target.value })}
                  className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-2 text-zinc-900 dark:text-zinc-100 outline-none focus:border-indigo-500 cursor-pointer"
                >
                  <option value="">All SOC tiers (unrestricted)</option>
                  <option value="L1">SOC L1 only — Triage workspace</option>
                  <option value="L2">SOC L2 only — Investigation workspace</option>
                  <option value="L3">SOC L3 only — Crisis workspace</option>
                </select>
                <p className="mt-1 text-[10px] text-zinc-400">
                  L1/L2 analysts only see incidents in their own tier and can escalate upward.
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800">
                <button
                  type="button"
                  onClick={() => setUserModalOpen(false)}
                  className="h-8 px-3 rounded-lg border border-zinc-200 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="h-8 px-4 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition cursor-pointer shadow-xs"
                >
                  Save User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create Role */}
      {roleModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-sm rounded-2xl bg-white dark:bg-[#0c0c0e] border border-zinc-200 dark:border-zinc-800 p-5 sm:p-6 shadow-2xl text-left">
            <h3 className="text-sm font-bold text-zinc-900 dark:text-white mb-1">Create RBAC Role</h3>
            <p className="text-xs text-zinc-500 mb-4">Add a new operational clearance tier</p>
            
            <form onSubmit={handleCreateRole} className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Role Name</label>
                <input
                  type="text"
                  required
                  value={roleForm.name}
                  onChange={e => setRoleForm({ ...roleForm, name: e.target.value })}
                  className="w-full h-8.5 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-3 text-zinc-900 dark:text-zinc-100 outline-none focus:border-emerald-500"
                  placeholder="e.g. Incident Commander"
                />
              </div>
              <div>
                <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1">Description</label>
                <textarea
                  rows={3}
                  value={roleForm.description}
                  onChange={e => setRoleForm({ ...roleForm, description: e.target.value })}
                  className="w-full rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-2 text-zinc-900 dark:text-zinc-100 outline-none focus:border-emerald-500"
                  placeholder="Scope & permissions"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800">
                <button
                  type="button"
                  onClick={() => setRoleModalOpen(false)}
                  className="h-8 px-3 rounded-lg border border-zinc-200 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="h-8 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition cursor-pointer shadow-xs"
                >
                  Save Role
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
