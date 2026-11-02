import React, { useState, useEffect, useCallback } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LandingPage } from './pages/public/LandingPage';
import { AuthView } from './pages/auth/AuthView';
import { DashboardSidebar, DashboardView, NAV_GROUPS, useSidebarWidth } from './components/layout/DashboardSidebar';
import { DashboardTopNav } from './components/layout/DashboardTopNav';
import { SearchModal } from './components/common/SearchModal';
import { GlobalTranslator } from './i18n/GlobalTranslator';
import { usePathname, navigate } from './router';
import { ToastContainer, ToastItem } from './components/common/ToastNotification';
import { globalRealtimeClient } from './services/api';

// Dashboard Modules
import { DashboardOverview } from './pages/dashboard/DashboardOverview';
import { SecurityOverviewModule } from './pages/dashboard/SecurityOverviewModule';
import { WafModule } from './pages/dashboard/WafModule';
import { FirewallModule } from './pages/dashboard/FirewallModule';
import { ApplicationsModule } from './pages/dashboard/ApplicationsModule';
import { NetworksModule } from './pages/dashboard/NetworksModule';
import { AgentsModule } from './pages/dashboard/AgentsModule';
import { ThreatsModule } from './pages/dashboard/ThreatsModule';
import { SecurityEventsModule } from './pages/dashboard/SecurityEventsModule';
import { LiveTrafficModule } from './pages/dashboard/LiveTrafficModule';
import { CentralizedLogsModule } from './pages/dashboard/CentralizedLogsModule';
import { AnalyticsModule } from './pages/dashboard/AnalyticsModule';
import { ThreatIntelModule } from './pages/dashboard/ThreatIntelModule';
import { IncidentsModule } from './pages/dashboard/IncidentsModule';
import { ReportsModule } from './pages/dashboard/ReportsModule';
import { UsersRolesModule } from './pages/dashboard/UsersRolesModule';
import { IntegrationsModule } from './pages/dashboard/IntegrationsModule';
import { BillingModule } from './pages/dashboard/BillingModule';
import { SettingsModule } from './pages/dashboard/SettingsModule';
import { MalwareAnalysisModule } from './pages/dashboard/MalwareAnalysisModule';
import { AiSecurityAgentModule } from './pages/dashboard/AiSecurityAgentModule';
import { ComplianceModule } from './pages/dashboard/ComplianceModule';
import { AuditLogModule } from './pages/dashboard/AuditLogModule';
import { ContactModule } from './pages/dashboard/ContactModule';
import { SuperAdminDashboard } from './pages/superadmin/SuperAdminDashboard';

// ---------------------------------------------------------------------------
// Route table — real URL paths so the console can be refreshed and deep-linked.
//   /public              → marketing / public portal
//   /login               → sign-in screen
//   /contact             → public contact / support page
//   /dashboard           → operations overview
//   /dashboard/<view>    → dashboard module
// ---------------------------------------------------------------------------
export const PUBLIC_PATH = '/public';
export const LOGIN_PATH = '/login';
export const CONTACT_PATH = '/contact';
export const DASHBOARD_PATH = '/dashboard';

const ALL_VIEWS: DashboardView[] = [...NAV_GROUPS.flatMap(group => group.items.map(item => item.id)), 'superadmin'];

export function pathForView(view: DashboardView): string {
  return view === 'dashboard' ? DASHBOARD_PATH : `${DASHBOARD_PATH}/${view}`;
}

export function viewFromPath(pathname: string): DashboardView | null {
  if (pathname === DASHBOARD_PATH || pathname === `${DASHBOARD_PATH}/`) return 'dashboard';
  if (!pathname.startsWith(`${DASHBOARD_PATH}/`)) return null;
  const candidate = pathname.slice(DASHBOARD_PATH.length + 1).split('/')[0];
  return (ALL_VIEWS as string[]).includes(candidate) ? (candidate as DashboardView) : null;
}

// ---------------------------------------------------------------------------
// Toast helpers — map realtime WebSocket events → toast items
// ---------------------------------------------------------------------------
const THREAT_EVENTS = new Set([
  'security_event', 'security_event.created', 'security.alert', 'threat.created',
  'threat.updated', 'waf.event', 'waf.blocked', 'malware.detected', 'firewall.event',
]);

function toastFromPayload(payload: any): Omit<ToastItem, 'id' | 'timestamp'> | null {
  const type: string = payload?.type ?? '';
  if (!THREAT_EVENTS.has(type)) return null;

  const d = payload?.data ?? payload;
  const severity: string =
    (d?.severity ?? d?.threat?.severity ?? d?.event?.severity ?? 'HIGH').toUpperCase();

  // Filter: only show toast for High or Critical severity or blocked attacks
  const isHighOrCritical = severity === 'HIGH' || severity === 'CRITICAL';
  const isBlocked = ['BLOCK', 'DENY', 'DROP', 'CHALLENGE'].includes((d?.action || '').toUpperCase());
  if (!isHighOrCritical && !isBlocked && type !== 'threat.created') {
    return null;
  }

  let title = 'Security Alert';
  let desc = 'Ancaman terdeteksi di jaringan Anda.';

  if (type === 'threat.created') {
    title = `Threat Detected: ${d?.attackType ?? d?.attack_type ?? d?.name ?? 'SQL Injection / Web Attack'}`;
    desc = d?.description ?? d?.reason ?? d?.sourceIp ?? desc;
  } else if (type === 'security_event' || type === 'security_event.created' || type === 'security.alert') {
    title = `Threat: ${d?.threat ?? d?.eventType ?? d?.event_type ?? d?.category ?? 'Attack Detected'}`;
    desc = d?.message ?? d?.description ?? (d?.sourceIp ? `Source IP: ${d.sourceIp}` : desc);
  } else if (type === 'waf.blocked' || type === 'waf.event') {
    title = `WAF Blocked: ${d?.threat ?? d?.category ?? 'Web Attack'}`;
    desc = `IP ${d?.clientIp ?? d?.sourceIp ?? d?.ip ?? 'unknown'} — ${d?.rule ?? d?.ruleName ?? d?.reason ?? 'policy violation'}`;
  } else if (type === 'malware.detected') {
    title = `Malware Detected: ${d?.malwareName ?? d?.name ?? 'Unknown'}`;
    desc = d?.filePath ?? d?.host ?? d?.description ?? desc;
  } else if (type === 'firewall.event') {
    title = `Firewall Event: ${d?.action ?? 'BLOCK'}`;
    desc = `${d?.srcIp ?? d?.sourceIp ?? 'unknown'} → port ${d?.dstPort ?? d?.destinationPort ?? '?'}`;
  }

  return { title, desc, severity };
}

// ---------------------------------------------------------------------------
// Main app shell
// ---------------------------------------------------------------------------
const MainContent: React.FC = () => {
  const { isAuthenticated, user } = useAuth();
  const pathname = usePathname();
  const [showSearchModal, setShowSearchModal] = useState(false);
  // Mobile navigation drawer (the sidebar becomes an off-canvas panel below lg).
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  // Operator-adjustable sidebar width (240-300px), remembered per browser.
  const [sidebarWidth, setSidebarWidth] = useSidebarWidth();

  // ── Toast state ────────────────────────────────────────────────────────────
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // Subscribe to realtime threat events and fire in-app toast
  useEffect(() => {
    if (!isAuthenticated) return;

    const unsub = globalRealtimeClient.subscribe((payload: any) => {
      const partial = toastFromPayload(payload);
      if (!partial) return;
      const toast: ToastItem = {
        ...partial,
        id: `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp: Date.now(),
      };
      setToasts(prev => [toast, ...prev].slice(0, 5)); // max 5 stacked
    });

    return unsub;
  }, [isAuthenticated]);

  // Keyboard shortcut Cmd+K or Ctrl+K for search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setShowSearchModal(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const isPublic = pathname === PUBLIC_PATH || pathname === `${PUBLIC_PATH}/`;
  const isContact = pathname === CONTACT_PATH || pathname === `${CONTACT_PATH}/`;
  const view = viewFromPath(pathname);

  // Keep the address bar in sync with auth state and the known route table.
  useEffect(() => {
    if (isPublic || isContact) return;

    if (!isAuthenticated) {
      if (pathname !== LOGIN_PATH) navigate(LOGIN_PATH, { replace: true });
      return;
    }

    if (pathname === LOGIN_PATH || !view) {
      const target = user?.role === 'Super Admin' ? pathForView('superadmin') : DASHBOARD_PATH;
      navigate(target, { replace: true });
    }
  }, [pathname, isAuthenticated, isPublic, isContact, view]);

  if (isPublic) {
    return (
      <LandingPage
        onEnterDashboard={() => navigate(DASHBOARD_PATH)}
        onOpenAuth={() => navigate(LOGIN_PATH)}
        onOpenContact={() => navigate(CONTACT_PATH)}
      />
    );
  }

  // Public contact / support page — reachable from the marketing navbar and
  // the mobile navigation panel without signing in.
  if (isContact) {
    return (
      <ContactModule
        variant="public"
        onBack={() => navigate(PUBLIC_PATH)}
        onEnterDashboard={() => navigate(DASHBOARD_PATH)}
      />
    );
  }

  // Authentication gate — the dashboard is unreachable without a session.
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-zinc-50 text-zinc-900 dark:bg-black dark:text-slate-100 font-sans">
        <AuthView variant="page" onSuccess={() => navigate(DASHBOARD_PATH)} />
      </div>
    );
  }

  // Super Admin uses dedicated standalone dashboard
  if (user?.role === 'Super Admin') {
    return <SuperAdminDashboard />;
  }

  const currentView: DashboardView = view || 'dashboard';
  const handleNavigateView = (next: DashboardView) => {
    setMobileNavOpen(false);
    navigate(pathForView(next));
  };

  return (
    <div className="flex h-svh w-screen overflow-hidden bg-zinc-50 dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 font-sans transition-colors duration-200">
      {/* Sidebar */}
      <DashboardSidebar
        currentView={currentView}
        onSelectView={handleNavigateView}
        width={sidebarWidth}
        onWidthChange={setSidebarWidth}
        onOpenSearch={() => setShowSearchModal(true)}
        mobileOpen={mobileNavOpen}
        onMobileClose={() => setMobileNavOpen(false)}
      />

      {/* Right Main Container */}
      <div className="flex flex-1 h-svh min-h-0 min-w-0 flex-col overflow-hidden bg-zinc-50/60 dark:bg-[#09090b]">
        {/* Top Navigation */}
        <DashboardTopNav
          onOpenSearch={() => setShowSearchModal(true)}
          onNavigatePublic={() => navigate(PUBLIC_PATH)}
          onNavigateView={handleNavigateView}
          onOpenSidebar={() => setMobileNavOpen(prev => !prev)}
        />

        {/* Content Scroll View */}
        <div className="flex-1 min-h-0 overflow-y-auto p-3 sm:p-6 lg:p-8 custom-scrollbar">
          <div className="max-w-7xl mx-auto w-full">
            {currentView === 'dashboard' && <DashboardOverview onNavigate={handleNavigateView} />}
            {currentView === 'security-overview' && <SecurityOverviewModule onNavigate={handleNavigateView} />}
            {currentView === 'waf' && <WafModule onNavigate={handleNavigateView} />}
            {currentView === 'firewall' && <FirewallModule />}
            {currentView === 'applications' && <ApplicationsModule />}
            {currentView === 'networks' && <NetworksModule />}
            {currentView === 'agents' && <AgentsModule />}
            {currentView === 'threats' && <ThreatsModule onNavigate={handleNavigateView} />}
            {currentView === 'security-events' && <SecurityEventsModule />}
            {currentView === 'live-traffic' && <LiveTrafficModule />}
            {currentView === 'logs' && <CentralizedLogsModule />}
            {currentView === 'analytics' && <AnalyticsModule />}
            {currentView === 'threat-intel' && <ThreatIntelModule />}
            {currentView === 'incidents' && <IncidentsModule />}
            {currentView === 'reports' && <ReportsModule />}
            {currentView === 'users-roles' && <UsersRolesModule />}
            {currentView === 'integrations' && <IntegrationsModule />}
            {currentView === 'billing' && <BillingModule />}
            {currentView === 'settings' && <SettingsModule />}
            {currentView === 'malware' && <MalwareAnalysisModule />}
            {currentView === 'ai-agent' && <AiSecurityAgentModule />}
            {currentView === 'compliance' && <ComplianceModule />}
            {currentView === 'audit-log' && <AuditLogModule />}
            {currentView === 'contact' && <ContactModule variant="dashboard" />}
            {currentView === 'superadmin' && <SuperAdminDashboard embedded />}
          </div>
        </div>
      </div>

      {/* Global Search Modal */}
      <SearchModal
        isOpen={showSearchModal}
        onClose={() => setShowSearchModal(false)}
        onNavigate={handleNavigateView}
      />

      {/* Global Threat Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <GlobalTranslator />
      <MainContent />
    </AuthProvider>
  );
}
