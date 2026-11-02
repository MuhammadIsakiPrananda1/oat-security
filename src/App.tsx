import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LandingPage } from './pages/public/LandingPage';
import { AuthView } from './pages/auth/AuthView';
import { DashboardSidebar, DashboardView, NAV_GROUPS, useSidebarWidth } from './components/layout/DashboardSidebar';
import { DashboardTopNav } from './components/layout/DashboardTopNav';
import { SearchModal } from './components/common/SearchModal';
import { GlobalTranslator } from './i18n/GlobalTranslator';
import { usePathname, navigate } from './router';

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
// Main app shell
// Toast notifications are handled exclusively in DashboardTopNav to avoid
// duplicate toasts from multiple subscribers on the same event bus.
// ---------------------------------------------------------------------------
const MainContent: React.FC = () => {
  const { isAuthenticated, user } = useAuth();
  const pathname = usePathname();
  const [showSearchModal, setShowSearchModal] = useState(false);
  // Mobile navigation drawer (the sidebar becomes an off-canvas panel below lg).
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  // Operator-adjustable sidebar width (240-300px), remembered per browser.
  const [sidebarWidth, setSidebarWidth] = useSidebarWidth();

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
        {/* Top Navigation — also owns the single ToastContainer for the entire app */}
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
