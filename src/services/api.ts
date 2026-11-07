import { 
  SystemHealth, 
  SecurityEvent, 
  ThreatItem, 
  WafRule, 
  ProtectedApplication, 
  FirewallRule, 
  FirewallDeployment,
  NetworkInventory, 
  NatRule, 
  Incident, 
  AuditLogItem, 
  ApiKeyItem, 
  User,
  EndpointAgent,
  AgentSummary,
  AgentEnrollmentToken,
  AgentDetail,
  ApplicationAgent,
  WafDeploymentView,
  MalwareScanListResponse,
  MalwareScan,
  MalwareHashLookup,
  MalwareContainmentResult,
  ReportItem
} from '../types';
import { classifyLocalIp, getCountryName } from '../utils/ip';

export type BackendConnectionStatus = 'ONLINE' | 'BACKEND OFFLINE';
export type RealtimeStreamStatus = 'CONNECTED' | 'RECONNECTING' | 'REAL-TIME CONNECTION LOST';

const API_BASE = (import.meta as any).env?.VITE_API_URL || '';

const ACTIVE_ORG_STORAGE_KEY = 'oat-active-org';

let forceBackendOffline = false;
// Restored from the stored session so the very first request after a reload is
// already authenticated — child effects fire before the AuthContext effect
// that would otherwise attach the bearer token.
let activeAuthToken: string | null = (() => {
  try {
    const raw = localStorage.getItem('oat-session');
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return typeof parsed?.token === 'string' ? parsed.token : null;
  } catch {
    return null;
  }
})();
// Restored from storage so the very first request after a reload is already
// scoped to the tenant the operator was last working in.
let activeOrganizationId: string = (() => {
  try {
    return localStorage.getItem(ACTIVE_ORG_STORAGE_KEY) || '';
  } catch {
    return '';
  }
})();

export function setSimulatedOffline(offline: boolean) {
  forceBackendOffline = offline;
  notifyConnectivityChange();
  if (offline) {
    globalRealtimeClient.disconnect();
  } else {
    globalRealtimeClient.connect();
  }
}

export function isSimulatedOffline() {
  return forceBackendOffline;
}

export function setAuthToken(token: string | null) {
  activeAuthToken = token;
}

export function setActiveOrganization(orgId: string) {
  activeOrganizationId = orgId;
  try {
    if (orgId) localStorage.setItem(ACTIVE_ORG_STORAGE_KEY, orgId);
    else localStorage.removeItem(ACTIVE_ORG_STORAGE_KEY);
  } catch {
    // Storage unavailable — the in-memory tenant still applies.
  }
  globalRealtimeClient.setOrganization(orgId);
}

/**
 * Build an authenticated EventSource URL. EventSource cannot send custom
 * headers, so the stream uses the same bearer token and tenant scope in its
 * query string. Keep this in one place so every SSE consumer uses identical
 * auth semantics.
 */
export function getRealtimeStreamUrl(path = '/api/stream/telemetry'): string {
  const separator = path.includes('?') ? '&' : '?';
  const params = new URLSearchParams();
  if (activeAuthToken) params.set('token', activeAuthToken);
  if (activeOrganizationId) params.set('org', activeOrganizationId);
  const query = params.toString();
  return `${API_BASE}${path}${query ? `${separator}${query}` : ''}`;
}

type ConnectivityListener = (status: BackendConnectionStatus) => void;
const connectivityListeners: Set<ConnectivityListener> = new Set();

export function onConnectivityChange(fn: ConnectivityListener) {
  connectivityListeners.add(fn);
  return () => connectivityListeners.delete(fn);
}

function notifyConnectivityChange() {
  const status: BackendConnectionStatus = forceBackendOffline ? 'BACKEND OFFLINE' : 'ONLINE';
  connectivityListeners.forEach(fn => fn(status));
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  if (forceBackendOffline) {
    throw new Error('BACKEND OFFLINE');
  }

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'x-organization-id': activeOrganizationId,
      ...(options?.headers as any || {})
    };

    if (activeAuthToken) {
      headers['Authorization'] = `Bearer ${activeAuthToken}`;
    }

    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers
    });

    if (!res.ok) {
      if (res.status >= 500) {
        notifyConnectivityChange();
      }
      const errPayload = await res.json().catch(() => null);
      const detail = errPayload?.error || errPayload?.message;
      throw new Error(detail ? `${detail}` : `API HTTP Error: ${res.status} ${res.statusText}`);
    }

    return await res.json();
  } catch (err: any) {
    if (err.message !== 'BACKEND OFFLINE') {
      notifyConnectivityChange();
    }
    throw err;
  }
}

function eventCategory(source?: string): string {
  switch (String(source || '').toLowerCase()) {
    case 'waf':
      return 'WAF';
    case 'firewall':
      return 'Firewall';
    case 'agent':
      return 'Endpoint';
    case 'auth':
      return 'Authentication';
    case 'system':
      return 'System';
    default:
      return 'Security';
  }
}

// API Service Functions
export const securityApi = {
  async getHealth() {
    return request<{ status: string; service: string }>('/api/health');
  },

  async getSystemStatus(): Promise<SystemHealth> {
    return request<SystemHealth>('/api/system/status');
  },

  async getSystemHealthDetailed() {
    return request<{
      services: Array<{
        service_name: string;
        status: string;
        latency_ms: number | null;
        last_check: string;
        details: string;
      }>;
      timestamp: string;
      summary: { total: number; operational: number; degraded: number; offline: number };
    }>('/api/system/health');
  },

  async getOrganizations() {
    return request<{ organizations: any[] }>('/api/organizations');
  },

  async deleteOrganization(id: string) {
    return request<{ success: boolean; removed: boolean; id: string }>(`/api/organizations/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
  },

  async getDashboardSummary() {
    return request<{
      requests: number;
      blocked: number;
      allowed: number;
      threats: number;
      critical: number;
      applications: number;
      networks: number;
      securityScore: number | null;
      securityScoreStatus: string;
      securityScoreGrade: string;
    }>('/api/dashboard/summary');
  },

  async getDashboard() {
    return request<{
      metrics: {
        protectedAppsCount: number;
        protectedNetworksCount: number;
        requestsToday: number;
        blockedRequests: number;
        activeThreats: number;
        criticalAlerts: number;
        securityEventsCount: number;
        securityScore: number | null;
        slaCompliancePct?: number;
        breachedIncidentsCount?: number;
        totalIncidentsCount?: number;
      };
      trafficHistory: { hour: string; allowed: number; blocked: number; suspicious: number }[];
      threatOverview: { critical: number; high: number; medium: number; low: number };
      recentEvents: SecurityEvent[];
      systemHealth?: SystemHealth;
      isLiveTraffic?: boolean;
      latestTelemetryTimestamp?: string | null;
      hasConnectedEndpoints?: boolean;
      connectedEndpointsCount?: number;
      activeEndpoints?: any[];
    }>('/api/dashboard');
  },

  async getEndpointStatus(orgId?: string) {
    const query = orgId ? `?org=${encodeURIComponent(orgId)}` : '';
    return request<{
      hasConnectedEndpoints: boolean;
      connectedCount: number;
      totalAgents: number;
      endpoints: Array<{
        id: string;
        name: string;
        hostname: string;
        ip: string;
        os: string;
        arch: string;
        version: string;
        status: 'ONLINE' | 'OFFLINE';
        lastSeen: string | null;
        organizationId: string;
      }>;
      timestamp: string;
    }>(`/api/endpoints/status${query}`);
  },

  async createEnrollmentToken(label = 'Web Console Quick Enroll') {
    return request<{
      token: string;
      expiresAt: string;
      label: string;
    }>('/api/agents/enrollment-token', {
      method: 'POST',
      body: JSON.stringify({ label })
    });
  },

  async getSecurityScore() {
    return request<{
      score: number | null;
      grade: string;
      status: 'OPTIMAL' | 'GOOD' | 'NEEDS_ATTENTION' | 'CRITICAL' | 'INSUFFICIENT DATA';
      breakdown: {
        wafCoverage: number;
        firewallCoverage: number;
        threatPosture: number;
        incidentResolution: number;
        engineHealth: number;
        mfaEnforcement: number;
      };
      factors: Array<{
        name: string;
        weight: number;
        score: number;
        status: 'Pass' | 'Warning' | 'Fail';
        details: string;
      }>;
      calculatedAt: string;
    }>('/api/security-score');
  },

  async getWafData() {
    return request<{
      status: string;
      protectedDomainsCount: number;
      totalRequests24h: number;
      blockedRequests24h: number;
      rateLimited24h: number;
      challenged24h: number;
      rules: WafRule[];
      protectedApplications: ProtectedApplication[];
      topCategories: Array<{ category: string; count: number }>;
      deployment: WafDeploymentView;
      agents: WafDeploymentView['agents'];
      wafRevision: number;
      wafStatus: string;
      wafEngineEnabled: boolean;
    }>('/api/waf');
  },

  async getWafRules() {
    return request<{ rules: WafRule[]; deployment: WafDeploymentView }>('/api/waf/rules');
  },

  async toggleWafRule(ruleId: string, status?: 'Active' | 'Disabled', enabled?: boolean) {
    return request<{ success: boolean; rule: WafRule; deployment: WafDeploymentView }>('/api/waf/rules/toggle', {
      method: 'POST',
      body: JSON.stringify({ ruleId, status, enabled }),
    });
  },

  async createWafRule(rule: Partial<WafRule>) {
    return request<{ success: boolean; rule: WafRule; deployment: WafDeploymentView }>('/api/waf/rules/create', {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  },

  async deleteWafRule(ruleId: string) {
    return request<{ success: boolean; message: string; deployment: WafDeploymentView }>(`/api/waf/rules/${ruleId}`, {
      method: 'DELETE',
    });
  },

  async getWafPolicy() {
    return request<{
      policy: {
        id: string;
        engine_enabled: number;
        mode: string;
        rate_limit_requests: number;
        rate_limit_window_s: number;
        ip_allowlist: string;
        ip_blocklist: string;
        geo_block_countries: string;
        bot_protection_enabled: number;
        sync_to_server: number;
        revision: number;
        last_applied_at: string | null;
        server_status: string;
        server_log: string | null;
        updated_at: string;
      };
      deployment: WafDeploymentView;
    }>('/api/waf/policy');
  },

  async saveWafPolicy(policy: any) {
    return request<{
      success: boolean;
      policy: any;
      deployment: WafDeploymentView;
    }>('/api/waf/policy', {
      method: 'POST',
      body: JSON.stringify(policy),
    });
  },

  async syncWafToServer() {
    return request<{
      success: boolean;
      deployment: WafDeploymentView;
      policy: any;
    }>('/api/waf/sync', {
      method: 'POST',
    });
  },

  async getFirewallData() {
    const res = await request<{
      status: string;
      activeConnections: number;
      blockedConnections: number;
      allowedConnections: number;
      rules: FirewallRule[];
      networkZones: NetworkInventory[];
      zones?: NetworkInventory[];
      natRules?: NatRule[];
      deployment?: FirewallDeployment;
    }>('/api/firewall');

    // Normalize raw server columns into the UI contract: `enabled` → status,
    // `created_at` → created (the ACL table renders these directly).
    if (res?.rules) {
      res.rules = res.rules.map((r: any) => ({
        ...r,
        enabled: r.enabled === undefined ? undefined : Number(r.enabled),
        status: (r.enabled === undefined ? r.status : Number(r.enabled) ? 'Active' : 'Disabled') as FirewallRule['status'],
        created: r.created || r.created_at || ''
      }));
    }
    // The Firewall security-zones tab reads `zones`; the API names the same
    // collection `networkZones`. Keep both keys pointing at one array.
    if (res?.networkZones) {
      res.zones = res.networkZones;
    }
    return res;
  },

  async createFirewallRule(rule: Partial<FirewallRule>) {
    return request<{ success: boolean; rule: FirewallRule }>('/api/firewall/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  },

  async toggleFirewallRule(ruleId: string, enabled: boolean) {
    return request<{ success: boolean; rule: FirewallRule }>('/api/firewall/rules/toggle', {
      method: 'POST',
      body: JSON.stringify({ ruleId, enabled }),
    });
  },

  async deleteFirewallRule(ruleId: string) {
    return request<{ success: boolean; message: string }>(`/api/firewall/rules/${encodeURIComponent(ruleId)}`, {
      method: 'DELETE'
    });
  },

  async detectServerFirewall() {
    return request<{
      success: boolean;
      importedCount: number;
      rules: FirewallRule[];
      deployment?: FirewallDeployment;
    }>('/api/firewall/detect-server', {
      method: 'POST'
    });
  },

  async getNatRules() {
    return request<{ rules: NatRule[] }>('/api/firewall/nat');
  },

  async createNatRule(rule: Partial<NatRule>) {
    return request<{ success: boolean; rule: NatRule }>('/api/firewall/nat', {
      method: 'POST',
      body: JSON.stringify(rule)
    });
  },

  async toggleNatRule(id: string) {
    return request<{ success: boolean; enabled: boolean }>(`/api/firewall/nat/${encodeURIComponent(id)}/toggle`, {
      method: 'POST'
    });
  },

  async deleteNatRule(id: string) {
    return request<{ success: boolean; message: string }>(`/api/firewall/nat/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
  },

  async getFail2banData() {
    return request<{
      config: {
        id: string;
        organization_id: string;
        enabled: boolean;
        bantime: number;
        findtime: number;
        maxretry: number;
        ignore_ips: string;
      };
      bans: Array<{
        id: string;
        ip: string;
        jail: string;
        reason: string;
        banned_at: string;
        status: string;
        unbanned_at?: string;
      }>;
    }>('/api/firewall/fail2ban');
  },

  async updateFail2banConfig(data: {
    enabled: boolean;
    bantime: number;
    findtime: number;
    maxretry: number;
    ignore_ips: string;
  }) {
    return request<{ success: boolean; message: string }>('/api/firewall/fail2ban/config', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async fail2banBan(data: { ip: string; jail?: string; reason?: string }) {
    return request<{ success: boolean; message: string }>('/api/firewall/fail2ban/ban', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async fail2banUnban(data: { id?: string; ip?: string }) {
    return request<{ success: boolean; message: string }>('/api/firewall/fail2ban/unban', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async getThreats(params?: { severity?: string; attackType?: string; category?: string; search?: string; status?: string; application?: string; page?: number; limit?: number }) {
    const q = new URLSearchParams();
    if (params?.severity) q.append('severity', params.severity);
    if (params?.attackType) q.append('attackType', params.attackType);
    if (params?.category) q.append('category', params.category);
    if (params?.search) q.append('search', params.search);
    if (params?.status) q.append('status', params.status);
    if (params?.application) q.append('application', params.application);
    if (params?.page) q.append('page', String(params.page));
    if (params?.limit) q.append('limit', String(params.limit));
    return request<{ threats: ThreatItem[]; total: number; page?: number; limit?: number; metrics?: { total: number; critical: number; high: number; medium: number; low: number; unresolved: number } }>(`/api/threats?${q.toString()}`);
  },

  async getThreatDetail(id: string) {
    return request<ThreatItem & { relatedEventsDetails?: SecurityEvent[]; mitre?: any }>(`/api/threats/${id}`);
  },

  async updateThreatStatus(threatId: string, status: string) {
    return request<{ success: boolean; threat: ThreatItem }>(`/api/threats/${threatId}/status`, {
      method: 'POST',
      body: JSON.stringify({ status })
    });
  },

  async mitigateThreat(threatId: string, action: string = 'BLOCK') {
    return request<{ success: boolean; threatId: string; status: string }>('/api/threats/mitigate', {
      method: 'POST',
      body: JSON.stringify({ threatId, action }),
    });
  },

  async simulateThreat(attackType?: string) {
    return request<{ success: boolean; message: string; event?: any }>('/api/threats/simulate', {
      method: 'POST',
      body: JSON.stringify({ attackType: attackType || 'random' })
    });
  },

  async getSecurityEvents(params?: { category?: string; source?: string; severity?: string; action?: string; status?: string; search?: string; application?: string; eventType?: string; startDate?: string; endDate?: string; page?: number; limit?: number }) {
    const q = new URLSearchParams();
    if (params?.category) q.append('category', params.category);
    if (params?.source) q.append('source', params.source);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.action) q.append('action', params.action);
    if (params?.status) q.append('status', params.status);
    if (params?.search) q.append('search', params.search);
    if (params?.application) q.append('application', params.application);
    if (params?.eventType) q.append('eventType', params.eventType);
    if (params?.startDate) q.append('startDate', params.startDate);
    if (params?.endDate) q.append('endDate', params.endDate);
    if (params?.page) q.append('page', String(params.page));
    if (params?.limit) q.append('limit', String(params.limit));
    return request<{ events: SecurityEvent[]; total: number; page?: number; limit?: number; metrics?: { total: number; critical: number; high: number; medium: number; low: number; allowed: number; blocked: number } }>(`/api/events?${q.toString()}`);
  },

  async getSecurityEventsAggregates(params?: { limit?: number }) {
    const q = new URLSearchParams();
    if (params?.limit) q.append('limit', String(params.limit));
    return request<{
      total: number;
      actions: { blocked: number; allowed: number; challenged: number; logged: number; other: number };
      severities: { critical: number; high: number; medium: number; low: number };
      topSourceIps: Array<{ ip: string; count: number }>;
      topApplications: Array<{ application: string; count: number }>;
      topCountries?: Array<{ country: string; code: string; count: number }>;
    }>(`/api/events/aggregates?${q.toString()}`);
  },

  async getSecurityEventDetail(id: string) {
    return request<SecurityEvent & { ruleId?: string; ruleName?: string; description?: string; rawEvent?: string; relatedEvents?: any[] }>(`/api/events/${id}`);
  },

  async getApplications(params?: { environment?: string; status?: string; search?: string }) {
    const q = new URLSearchParams();
    if (params?.environment) q.append('environment', params.environment);
    if (params?.status) q.append('status', params.status);
    if (params?.search) q.append('search', params.search);
    return request<{ applications: ProtectedApplication[]; total: number; metrics?: { total: number; protected: number; monitoring: number; offline: number; unknown: number } }>(`/api/applications?${q.toString()}`);
  },

  async getApplicationDetail(id: string) {
    return request<{ application: ProtectedApplication; recentEvents: SecurityEvent[]; activeThreats: ThreatItem[]; agents: ApplicationAgent[] }>(`/api/applications/${id}`);
  },

  async checkApplicationHealth(id: string) {
    return request<{ id: string; name: string; domain: string; status: string; responseTime: number; lastCheckedAt: string }>(`/api/applications/${id}/health`, {
      method: 'POST'
    });
  },

  async createApplication(app: Partial<ProtectedApplication>) {
    return request<{ success: boolean; application: ProtectedApplication }>('/api/applications', {
      method: 'POST',
      body: JSON.stringify(app),
    });
  },

  // Drop a website from the inventory (it also disappears for every operator
  // in real time).
  async removeApplication(id: string) {
    return request<{ success: boolean; removed: boolean; id: string }>(`/api/applications/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
  },

  async clearApplicationEvents(id: string) {
    return request<{ success: boolean; deleted: number }>(`/api/applications/${encodeURIComponent(id)}/events`, {
      method: 'DELETE'
    });
  },

  async getLogs(params?: { level?: string; source?: string; eventType?: string; host?: string; search?: string; page?: number; limit?: number }) {
    const q = new URLSearchParams();
    if (params?.level) q.append('level', params.level);
    if (params?.source) q.append('source', params.source);
    if (params?.eventType) q.append('eventType', params.eventType);
    if (params?.host) q.append('host', params.host);
    if (params?.search) q.append('search', params.search);
    if (params?.page) q.append('page', String(params.page));
    if (params?.limit) q.append('limit', String(params.limit));
    return request<{
      logs: any[];
      total: number;
      page: number;
      limit: number;
      metrics: any;
      topSourceIps?: Array<{ ip: string; count: number; sourceCountry?: string; sourceCountryCode?: string; sourceCountryFlag?: string }>;
      topSources?: Array<{ source: string; count: number }>;
    }>(`/api/logs?${q.toString()}`);
  },

  async getLogDetail(id: string) {
    return request<any>(`/api/logs/${id}`);
  },

  // -------------------------------------------------------------------------
  // Endpoint Agents
  // -------------------------------------------------------------------------
  async getAgents() {
    return request<{ agents: EndpointAgent[]; summary: AgentSummary; serverVersion: string }>('/api/agents');
  },

  async getActiveEnrollmentTokens() {
    return request<{ tokens: Array<{ id: string; label: string; expires_at: string; application_id?: string; created_at: string }> }>('/api/agents/enrollment-tokens/active');
  },

  async createAgentEnrollmentToken(payload: { label?: string; expiresInMinutes?: number; applicationId?: string }) {
    return request<AgentEnrollmentToken>('/api/agents/enrollment-token', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  async getAgent(id: string) {
    return request<AgentDetail>(`/api/agents/${encodeURIComponent(id)}`);
  },

  async revokeAgent(id: string, purge = false) {
    return request<{
      success: boolean;
      removed: boolean;
      purged: boolean;
      deletedEvents: number;
      deletedLogs: number;
      unlinkedEvents: number;
      unlinkedLogs: number;
    }>(`/api/agents/${encodeURIComponent(id)}${purge ? '?purge=1' : ''}`, {
      method: 'DELETE'
    });
  },

  // Point an agent at the website it should protect (a host can host many).
  async setAgentApplication(id: string, payload: { applicationId?: string; domain?: string; protocol?: string; port?: number }) {
    return request<{ ok: boolean; agentId: string; application: { id: string; name: string; domain: string } }>(
      `/api/agents/${encodeURIComponent(id)}/application`,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },

  // Re-activate a revoked agent entry so the running endpoint can report again.
  async restoreAgent(id: string) {
    return request<{ ok: boolean; agentId: string; status: string }>(`/api/agents/${encodeURIComponent(id)}/restore`, {
      method: 'POST'
    });
  },

  async getNetworks() {
    return request<{ networks: NetworkInventory[]; count: number }>('/api/networks');
  },

  async createNetwork(network: Partial<NetworkInventory>) {
    return request<{ success: boolean; network: NetworkInventory }>('/api/networks', {
      method: 'POST',
      body: JSON.stringify(network),
    });
  },

  async updateNetwork(networkId: string, network: Partial<NetworkInventory>) {
    return request<{ success: boolean; network: NetworkInventory }>(`/api/networks/${encodeURIComponent(networkId)}`, {
      method: 'PUT',
      body: JSON.stringify(network),
    });
  },

  async deleteNetwork(networkId: string) {
    return request<{ success: boolean; message: string }>(`/api/networks/${encodeURIComponent(networkId)}`, {
      method: 'DELETE',
    });
  },

  async getIncidents() {
    return request<{ incidents: Incident[] }>('/api/incidents');
  },

  async createIncident(incident: { title: string; severity: string; tier?: 'L1' | 'L2' | 'L3'; assignedTo?: string; affectedAsset?: string; notes?: string }) {
    return request<{ success: boolean; incident: Incident }>('/api/incidents', {
      method: 'POST',
      body: JSON.stringify(incident),
    });
  },

  async updateIncidentStatus(id: string, status: string, note?: string, analyst?: string, tier?: 'L1' | 'L2' | 'L3') {
    return request<{ success: boolean; incident: Incident }>(`/api/incidents/${id}/status`, {
      method: 'POST',
      body: JSON.stringify({ status, note, analyst, tier }),
    });
  },

  async updateIncidentTier(id: string, payload: { tier: 'L1' | 'L2' | 'L3'; note?: string; assignedTo?: string; analyst?: string }) {
    return request<{ success: boolean; incident: Incident }>(`/api/incidents/${id}/tier`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async deleteIncident(id: string) {
    return request<{ success: boolean; message: string }>(`/api/incidents/${id}`, {
      method: 'DELETE',
    });
  },

  async assignIncident(id: string, analyst: string, note?: string) {
    return request<{ success: boolean; incident: Incident }>(`/api/incidents/${id}/assign`, {
      method: 'POST',
      body: JSON.stringify({ analyst, note }),
    });
  },

  async executeIncidentContainment(id: string, payload: { action: string; target?: string; note?: string; blockIp?: string }) {
    return request<{ success: boolean; incident: Incident; firewallRuleCreated?: boolean; agentIsolated?: boolean }>(`/api/incidents/${id}/contain`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },


  async getThreatIntel() {
    return request<{
      configured: boolean;
      status: string;
      feeds: any[];
      cves: any[];
      stats: {
        totalIocs: number;
        blockedIocs: number;
        monitoredIocs: number;
        activeFeeds: number;
        criticalCves: number;
      };
    }>('/api/threat-intel');
  },

  async getThreatIntelIocs(params?: { type?: string; status?: string; search?: string }) {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return request<{ indicators: any[] }>(`/api/threat-intel/iocs${q ? `?${q}` : ''}`);
  },

  async getThreatIntelCves() {
    return request<{ cves: any[] }>('/api/threat-intel/cves');
  },

  async syncThreatIntel() {
    return request<{
      success: boolean;
      message: string;
      syncedAt: string;
      addedIndicatorsCount: number;
      feeds: any[];
    }>('/api/threat-intel/sync', {
      method: 'POST'
    });
  },

  async addThreatIntelIoc(payload: {
    indicator: string;
    type?: string;
    threatScore?: number;
    confidence?: number;
    severity?: string;
    targetSector?: string;
    tags?: string[];
    status?: string;
    country?: string;
  }) {
    return request<{ success: boolean; ioc: any }>('/api/threat-intel/iocs', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  async updateThreatIntelIocStatus(id: string, status: 'Active' | 'Blocked' | 'Monitored') {
    return request<{ success: boolean; id: string; status: string }>(`/api/threat-intel/iocs/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
  },

  async blockThreatIntelIndicator(indicator: string, reason?: string) {
    return request<{ success: boolean; message: string; ruleId: string }>('/api/threat-intel/block', {
      method: 'POST',
      body: JSON.stringify({ indicator, reason })
    });
  },

  async lookupThreatIntel(query: string, type: 'ip' | 'domain' | 'url' = 'ip') {
    return request<{ configured: boolean; indicator: string; type: string; message?: string; data?: any }>(
      `/api/threat-intel/lookup?query=${encodeURIComponent(query)}&type=${type}`
    );
  },


  async getIntegrations() {
    return request<{ integrations: any[] }>('/api/integrations');
  },

  async saveIntegration(provider: string, config: any) {
    return request<{ success: boolean; integration: any }>('/api/integrations', {
      method: 'POST',
      body: JSON.stringify({ provider, ...config })
    });
  },

  async getUsers() {
    return request<{ users: User[] }>('/api/users');
  },

  async updateProfile(payload: {
    name?: string;
    avatarUrl?: string | null;
    username?: string | null;
    phone?: string | null;
    telegramBotToken?: string | null;
    bio?: string | null;
    linkedinUrl?: string | null;
    githubUrl?: string | null;
    twitterUrl?: string | null;
    instagramUrl?: string | null;
  }) {
    return request<{ user: User }>('/api/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(payload)
    });
  },

  async getAuditLogs() {
    return request<{ logs: AuditLogItem[] }>('/api/audit-logs');
  },

  async getApiKeys() {
    return request<{ keys: ApiKeyItem[] }>('/api/api-keys');
  },

  async createApiKey(name: string, permissions: string[]) {
    return request<{ success: boolean; key: ApiKeyItem; fullSecretOnce: string }>('/api/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name, permissions }),
    });
  },

  async getReports() {
    return request<{ success: boolean; reports: ReportItem[] }>('/api/reports');
  },

  async generateReport(type: string, dateRange: string, format: 'PDF' | 'CSV', lang?: string) {
    return request<{
      success: boolean;
      reportId: string;
      report?: ReportItem;
      generatedAt: string;
      type: string;
      dateRange: string;
      format: string;
      dataSummary: any;
    }>('/api/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ type, period: dateRange, format, lang }),
    });
  },

  async deleteReport(id: string) {
    return request<{ success: boolean; message: string; id: string }>(`/api/reports/${id}`, {
      method: 'DELETE',
    });
  },

  async sendDevTestEvent(testType: 'sqli' | 'xss' | 'ssh_brute' | 'normal' = 'sqli') {
    return request<{ success: boolean; message: string; event: any }>('/api/dev/test-event', {
      method: 'POST',
      body: JSON.stringify({ testType }),
    });
  },

  async getAiCopilotContext() {
    return request<{ success: boolean; telemetry: any }>('/api/ai/context');
  },

  async querySocCopilot(params: { query: string; incidentId?: string; event?: any; promptContext?: string }) {
    return request<{
      success: boolean;
      mode: string;
      analysis: {
        summary: string;
        severityExplanation: string;
        threatActorProfile: string;
        mitreTechnique: string;
        threatScore: number;
        confidence: number;
        owaspCategory: string;
        playbookSteps?: Array<{ stage: string; title: string; detail: string }>;
        recommendations: Array<{
          title: string;
          action: string;
          deployable: boolean;
          rule?: {
            type: 'WAF' | 'FIREWALL';
            name: string;
            category: string;
            action: 'BLOCK' | 'LOG' | 'CHALLENGE';
            pattern?: string;
            ip?: string;
            syntax: string;
            description: string;
          };
        }>;
        requiresAnalystApproval: boolean;
      };
    }>('/api/ai/analyze-event', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  },

  async deployCopilotMitigation(params: {
    type: 'WAF' | 'FIREWALL';
    name: string;
    category?: string;
    action?: string;
    pattern?: string;
    ip?: string;
    description?: string;
  }) {
    return request<{ success: boolean; type: string; ruleId: string; message: string }>('/api/ai/deploy-rule', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  },

  async analyzeWithAI(event: any, promptContext?: string) {
    return this.querySocCopilot({ query: promptContext || '', event, promptContext });
  },

  async analyzeEventWithAi(params: any, promptContext?: string) {
    if (typeof params === 'string') {
      return this.querySocCopilot({ query: params, promptContext });
    }
    const query = params?.query || params?.payloadContext || params?.threatType || promptContext || '';
    return this.querySocCopilot({ query, incidentId: params?.incidentId, event: params, promptContext });
  },

  async getMalwareScans(params: {
    verdict?: string;
    status?: string;
    search?: string;
    applicationId?: string;
    limit?: number;
    offset?: number;
  } = {}) {
    const qs = new URLSearchParams();
    if (params.verdict && params.verdict !== 'ALL') qs.set('verdict', params.verdict);
    if (params.status && params.status !== 'ALL') qs.set('status', params.status);
    if (params.search) qs.set('search', params.search);
    if (params.applicationId) qs.set('applicationId', params.applicationId);
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.offset) qs.set('offset', String(params.offset));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return request<MalwareScanListResponse>(`/api/malware/scans${suffix}`);
  },

  async getMalwareScan(id: string) {
    return request<{ scan: MalwareScan }>(`/api/malware/scans/${encodeURIComponent(id)}`);
  },

  async lookupMalwareHash(hash: string) {
    return request<MalwareHashLookup>('/api/malware/lookup', {
      method: 'POST',
      body: JSON.stringify({ hash })
    });
  },

  async analyzeMalwareFile(payload: {
    fileName: string;
    contentBase64: string;
    size?: number;
    filePath?: string;
  }) {
    return request<{ scan: MalwareScan }>('/api/malware/analyze', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  async requestMalwareAction(scanId: string, action: 'QUARANTINE' | 'DELETE' | 'IGNORE' | 'BLOCK_IP') {
    return request<MalwareContainmentResult>(`/api/malware/scans/${encodeURIComponent(scanId)}/action`, {
      method: 'POST',
      body: JSON.stringify({ action })
    });
  },

  async deleteMalwareScan(scanId: string) {
    return request<{ success: boolean; message: string }>(`/api/malware/scans/${encodeURIComponent(scanId)}`, {
      method: 'DELETE'
    });
  },

  async getMalwareSignatures() {
    return request<{ signatures: Array<Record<string, any>> }>('/api/malware/signatures');
  },

  async addMalwareSignature(payload: {
    sha256: string;
    label?: string;
    verdict?: 'malicious' | 'clean';
    severity?: string;
    description?: string;
  }) {
    return request<{ signature: Record<string, any> }>('/api/malware/signatures', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  async getAnalytics() {
    return request<{
      generatedAt: string;
      windowHours: number;
      metrics: {
        totalRequests: number;
        blocked: number;
        allowed: number;
        challenged: number;
        rateLimited: number;
        logged: number;
        uniqueSources: number;
        blockRate: string;
      };
      topAttackingIps: Array<{ ip: string; country: string; countryCode?: string; asn: string; count: number; threat: string }>;
      topTargetedApps: Array<{ name: string; requests: number; blocked: number; pctBlocked: string }>;
      responseCodes: Array<{ code: string; count: number; pct: string; color: string }>;
      actions: Array<{ action: string; count: number; pct: string; color: string }>;
      timeline: Array<{ hour: string; total: number; blocked: number }>;
      webSecurity?: {
        httpsRate: number;
        wafPrecision: number;
        botPassRate: number;
        originShieldRate: number;
        ddosResistance: number;
        http2Rate: number;
        history: {
          https: number[];
          waf: number[];
          bot: number[];
          origin: number[];
          ddos: number[];
          http2: number[];
        };
      };
    }>('/api/analytics');
  },

  async getContactChannels() {
    return request<{
      channels: {
        email: string;
        phone: string;
        address: string;
        hours: string;
        responseSla: string;
      };
    }>('/api/contact/channels');
  },

  async getContactMessages(params: { status?: string; limit?: number; offset?: number } = {}) {
    const query = new URLSearchParams();
    if (params.status) query.set('status', params.status);
    if (params.limit) query.set('limit', String(params.limit));
    if (params.offset) query.set('offset', String(params.offset));
    const suffix = query.toString() ? `?${query.toString()}` : '';
    return request<{
      messages: ContactMessage[];
      total: number;
      open: number;
    }>(`/api/contact/messages${suffix}`);
  },

  async submitContactMessage(payload: {
    name?: string;
    email?: string;
    company?: string;
    topic?: string;
    severity?: string;
    message: string;
    source?: 'public' | 'console';
  }) {
    return request<{ message: ContactMessage }>('/api/contact/messages', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  async updateContactMessage(id: string, status: ContactMessage['status']) {
    return request<{ message: ContactMessage }>(`/api/contact/messages/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
  }
};

export type ContactMessageStatus = 'OPEN' | 'IN_REVIEW' | 'RESOLVED';

export interface ContactMessage {
  id: string;
  organizationId: string | null;
  userId: string | null;
  name: string;
  email: string;
  company: string | null;
  topic: string;
  severity: string;
  message: string;
  status: ContactMessageStatus;
  source: string;
  createdAt: string;
  updatedAt: string;
}

// ======================================================================
// Real-Time message normalization
// ----------------------------------------------------------------------
// The WebSocket / SSE channel broadcasts every backend bus event wrapped in
// an envelope: { type, data, organizationId?, timestamp }. It also delivers
// control frames (CONNECTION_STATUS, SUBSCRIBED, HANDSHAKE, PONG). Consumers
// that render live traffic must ignore control frames and non-security bus
// types, otherwise those frames get mistaken for security telemetry and
// produce fake, endlessly repeating alerts.
// ======================================================================
export function normalizeRealtimeSecurityEvent(msg: any): SecurityEvent | null {
  if (!msg || typeof msg !== 'object') return null;

  const type: string = msg.type || '';
  const raw = msg.data && typeof msg.data === 'object' ? msg.data : null;

  // Canonical normalized security event or ingested log from agent / detector
  if ((type === 'security_event' || type === 'security_event.created' || type === 'log.created' || type === 'waf.event' || type === 'firewall.event') && raw) {
    const sourceIp = raw.sourceIp || raw.source_ip || raw.ip || '0.0.0.0';
    const destinationIp = raw.destinationIp || raw.destination_ip || '';
    const threat = raw.threat || raw.threatName || raw.threat_name || raw.message || 'Security Event';

    let sourceCountryCode = raw.sourceCountryCode || raw.source_country_code;
    let sourceCountry = raw.sourceCountry || raw.source_country;
    if (!sourceCountryCode) {
      const localClass = classifyLocalIp(sourceIp);
      if (localClass === 'SYS') {
        sourceCountryCode = 'SYS';
        sourceCountry = 'Local Host';
      } else if (localClass === 'LAN') {
        sourceCountryCode = 'LAN';
        sourceCountry = 'Local Network';
      } else {
        sourceCountryCode = 'UN';
        sourceCountry = 'Unknown';
      }
    } else if (!sourceCountry || sourceCountry === 'Unknown' || sourceCountry === sourceCountryCode) {
      sourceCountry = getCountryName(sourceCountryCode, sourceCountry);
    }

    const meta = raw.metadata && typeof raw.metadata === 'object' ? raw.metadata : undefined;
    const fullLog = raw.rawLog || raw.raw_log || meta?.rawLog || meta?.logMessage || raw.payloadSnippet || raw.payload_snippet || threat;

    return {
      ...raw,
      id: raw.id || `EVT-${Date.now()}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      sourceIp,
      sourceCountry,
      sourceCountryCode,
      destinationIp,
      destination: raw.destination || destinationIp,
      application: raw.application || raw.host || 'Edge Gateway',
      threat,
      threatName: raw.threatName || threat,
      category: raw.category || eventCategory(raw.source),
      severity: raw.severity || null,
      action: raw.action || 'LOG',
      status: raw.status || 'Detected',
      rawLog: fullLog
    } as SecurityEvent;
  }

  // Original fallback branch
  if (false && type === 'security_event' && raw) {
    const sourceIp = raw.sourceIp || raw.source_ip || '0.0.0.0';
    const destinationIp = raw.destinationIp || raw.destination_ip || '';
    const threat = raw.threat || raw.threatName || raw.threat_name || 'Security Event';

    let sourceCountryCode = raw.sourceCountryCode || raw.source_country_code;
    let sourceCountry = raw.sourceCountry || raw.source_country;
    if (!sourceCountryCode) {
      const localClass = classifyLocalIp(sourceIp);
      if (localClass === 'SYS') {
        sourceCountryCode = 'SYS';
        sourceCountry = 'Local Host';
      } else if (localClass === 'LAN') {
        sourceCountryCode = 'LAN';
        sourceCountry = 'Local Network';
      } else {
        sourceCountryCode = 'UN';
        sourceCountry = 'Unknown';
      }
    } else if (!sourceCountry || sourceCountry === 'Unknown' || sourceCountry === sourceCountryCode) {
      sourceCountry = getCountryName(sourceCountryCode, sourceCountry);
    }

    return {
      ...raw,
      id: raw.id || `EVT-${Date.now()}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      sourceIp,
      sourceCountry,
      sourceCountryCode,
      destinationIp,
      destination: raw.destination || destinationIp,
      application: raw.application || 'Edge Gateway',
      threat,
      threatName: raw.threatName || threat,
      category: raw.category || eventCategory(raw.source),
      severity: raw.severity || null,
      action: raw.action || 'LOG',
      status: raw.status || 'Detected'
    } as SecurityEvent;
  }

  // Correlated alert raised when the detector promotes an event to a threat.
  if ((type === 'security.alert' || type === 'threat.created' || type === 'threat.updated') && raw) {
    const threat = raw.attackType || raw.attack_type || raw.threatName || raw.threat || 'Correlated Threat';
    return {
      id: raw.id || `THR-${Date.now()}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      source: 'threat',
      sourceIp: raw.sourceIp || raw.source_ip || '0.0.0.0',
      destination: raw.destination || raw.target || '',
      destinationIp: raw.destinationIp || raw.destination_ip || raw.target || '',
      application: raw.affectedApplication || raw.affected_application || 'Edge Gateway',
      threat,
      threatName: threat,
      category: 'Security',
      eventType: 'threat',
      severity: raw.severity || 'High',
      action: raw.action || 'BLOCK',
      status: raw.status || 'Active',
      metadata: { confidence: raw.confidence, summary: raw.summary }
    } as SecurityEvent;
  }

  // System alerts: agent offline, firewall failure
  if (type === 'agent.offline' && raw) {
    return {
      id: `AOF-${Date.now()}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      source: raw.source || 'monitor',
      sourceIp: raw.sourceIp || raw.ip || '0.0.0.0',
      destination: '',
      destinationIp: '',
      application: raw.threat || 'Endpoint Monitor',
      threat: raw.threat || 'Endpoint Offline',
      threatName: raw.threat || 'Endpoint Offline',
      category: 'System',
      eventType: 'agent_offline',
      severity: 'High',
      action: 'ALERT',
      status: 'Active',
      metadata: { message: raw.message, offlineCount: raw.offlineCount }
    } as SecurityEvent;
  }

  if ((type === 'firewall.failed' || type === 'firewall.error') && raw) {
    return {
      id: `FWF-${Date.now()}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      source: 'firewall',
      sourceIp: raw.sourceIp || raw.ip || '0.0.0.0',
      destination: '',
      destinationIp: '',
      application: raw.threat || 'Firewall Engine',
      threat: raw.threat || 'Firewall Installation Failed',
      threatName: raw.threat || 'Firewall Installation Failed',
      category: 'Firewall',
      eventType: 'firewall_failure',
      severity: 'Critical',
      action: 'ALERT',
      status: 'Active',
      metadata: { message: raw.message, agentId: raw.agentId }
    } as SecurityEvent;
  }

  // Malware event normalization
  if (type === 'malware.detected' && raw) {
    return {
      id: raw.id || `MAL-${Date.now()}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      source: 'agent',
      sourceIp: raw.sourceIp || raw.ip || '0.0.0.0',
      destination: '',
      destinationIp: '',
      application: raw.host || raw.hostname || 'Endpoint',
      threat: `Malware: ${raw.malwareName || raw.name || 'Unknown'}`,
      threatName: `Malware: ${raw.malwareName || raw.name || 'Unknown'}`,
      category: 'Malware',
      eventType: 'malware',
      severity: raw.severity || 'Critical',
      action: raw.action || 'QUARANTINE',
      status: 'Active',
      metadata: { filePath: raw.filePath, family: raw.family }
    } as SecurityEvent;
  }

  // Backwards compatible: a bare event object with no envelope.
  if (!type && (msg.sourceIp || msg.source_ip) && msg.action) {
    return msg as SecurityEvent;
  }

  return null;
}

// ======================================================================
// Real-Time WebSocket & SSE Client with Automatic Fallback & Reconnect
// ======================================================================
export class RealtimeClientManager {
  private ws: WebSocket | null = null;
  private sse: EventSource | null = null;
  private retryAttempt = 0;
  private maxBackoffMs = 10000;
  private baseBackoffMs = 300;
  private reconnectTimer: any = null;
  private listeners: Set<(data: any) => void> = new Set();
  private statusListeners: Set<(status: RealtimeStreamStatus) => void> = new Set();
  private currentStatus: RealtimeStreamStatus = 'RECONNECTING';
  private orgId: string = typeof window !== 'undefined' ? (localStorage.getItem(ACTIVE_ORG_STORAGE_KEY) || '') : '';

  constructor() {
    this.connect();
  }

  public getStatus(): RealtimeStreamStatus {
    return this.currentStatus;
  }

  public setOrganization(orgId: string) {
    this.orgId = orgId;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'SUBSCRIBE_ORG', organizationId: orgId }));
    }
  }

  public onData(fn: (data: any) => void) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  public onStatusChange(fn: (status: RealtimeStreamStatus) => void) {
    this.statusListeners.add(fn);
    fn(this.currentStatus);
    return () => this.statusListeners.delete(fn);
  }

  public subscribe(onMessage: (data: any) => void, onError?: (err: any) => void) {
    const unsubData = this.onData(onMessage);
    const unsubStatus = this.onStatusChange(status => {
      if (status === 'REAL-TIME CONNECTION LOST' && onError) {
        onError(new Error('Connection lost'));
      }
    });
    return () => {
      unsubData();
      unsubStatus();
    };
  }

  private setStatus(s: RealtimeStreamStatus) {
    this.currentStatus = s;
    this.statusListeners.forEach(fn => fn(s));
  }

  public connect() {
    if (forceBackendOffline) {
      this.setStatus('REAL-TIME CONNECTION LOST');
      return;
    }

    this.setStatus('RECONNECTING');

    // Attempt WebSocket connection first
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const token = activeAuthToken || (typeof window !== 'undefined' ? (localStorage.getItem('oat_token') || '') : '');
      const org = this.orgId || activeOrganizationId || (typeof window !== 'undefined' ? (localStorage.getItem(ACTIVE_ORG_STORAGE_KEY) || '') : '');
      this.orgId = org;
      const wsUrl = `${protocol}//${host}/ws?org=${encodeURIComponent(org)}&token=${encodeURIComponent(token)}`;

      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.retryAttempt = 0;
        this.setStatus('CONNECTED');
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          if (token) {
            this.ws.send(JSON.stringify({ type: 'AUTH', token }));
          }
          if (this.orgId) {
            this.ws.send(JSON.stringify({ type: 'SUBSCRIBE_ORG', organizationId: this.orgId }));
          }
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          this.listeners.forEach(fn => fn(payload));
        } catch (err) {
          console.warn('[Realtime WS] Parse error:', err);
        }
      };

      this.ws.onerror = () => {
        // Switch to SSE fallback if WS fails
        this.fallbackToSSE();
      };

      this.ws.onclose = () => {
        this.handleDisconnect();
      };
    } catch {
      this.fallbackToSSE();
    }
  }

  private fallbackToSSE() {
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }

    try {
      if (this.sse) {
        this.sse.close();
      }

       this.sse = new EventSource(getRealtimeStreamUrl('/api/stream/telemetry'));

      this.sse.onopen = () => {
        this.retryAttempt = 0;
        this.setStatus('CONNECTED');
      };

      this.sse.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          this.listeners.forEach(fn => fn(payload));
        } catch (err) {
          console.warn('[Realtime SSE] Parse error:', err);
        }
      };

      this.sse.onerror = () => {
        this.handleDisconnect();
      };
    } catch {
      this.handleDisconnect();
    }
  }

  private handleDisconnect() {
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }
    if (this.sse) {
      try { this.sse.close(); } catch {}
      this.sse = null;
    }

    this.setStatus('REAL-TIME CONNECTION LOST');

    const delay = Math.min(
      this.baseBackoffMs * Math.pow(1.6, this.retryAttempt),
      this.maxBackoffMs
    );
    this.retryAttempt++;

    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  public disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }
    if (this.sse) {
      try { this.sse.close(); } catch {}
      this.sse = null;
    }
    this.setStatus('REAL-TIME CONNECTION LOST');
  }
}

export const globalRealtimeClient = new RealtimeClientManager();
export const globalTelemetryStream = globalRealtimeClient;

export interface SuperAdminOverviewData {
  summary: {
    totalTenants: number;
    totalAgents: number;
    onlineAgents: number;
    offlineAgents: number;
    totalApplications: number;
    totalSecurityEvents: number;
    totalLogs: number;
    blockedEvents24h: number;
    criticalThreats24h: number;
    systemUptimeSeconds: number;
    timestamp: string;
  };
  organizations: Array<{
    id: string;
    name: string;
    domain: string;
    industry: string;
    tier: string;
    created_at: string;
    agent_count: number;
    app_count: number;
    event_count: number;
    log_count: number;
  }>;
  agents: Array<{
    id: string;
    organizationId: string;
    organizationName: string;
    organizationDomain: string;
    name: string;
    hostname: string;
    os: string;
    arch: string;
    version: string;
    ip: string;
    status: 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED';
    lastSeen: string;
    createdAt: string;
    eventsIngested: number;
    logsIngested: number;
    applicationId: string | null;
    applicationName: string | null;
    applicationDomain: string | null;
    metrics: Record<string, any>;
    hostInfo: Record<string, any>;
    labels: Record<string, any>;
  }>;
  recentEvents: Array<{
    id: string;
    organization_id: string;
    organization_name: string;
    timestamp: string;
    source: string;
    event_type: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    source_ip: string;
    destination_ip: string;
    application: string;
    action: string;
    threat_name: string;
    agent_id: string;
    uri?: string;
    method?: string;
    status_code?: number;
    payload_snippet?: string;
  }>;
  systemHealth: {
    services: Array<{
      service_name: string;
      status: 'Operational' | 'Degraded' | 'Offline';
      latency_ms: number | null;
      last_check: string;
      details: string;
    }>;
    timestamp: string;
    summary: {
      total: number;
      operational: number;
      degraded: number;
      offline: number;
    };
  };
}

export const superAdminApi = {
  getOverview: () => request<SuperAdminOverviewData>('/api/super-admin/overview'),
  getEvents: (params?: { limit?: number; severity?: string; action?: string; organizationId?: string }) => {
    const q = new URLSearchParams();
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.severity) q.set('severity', params.severity);
    if (params?.action) q.set('action', params.action);
    if (params?.organizationId) q.set('organizationId', params.organizationId);
    return request<{ events: any[] }>(`/api/super-admin/events?${q.toString()}`);
  },
  getUsers: () => request<{ users: any[] }>('/api/super-admin/users'),
  createUser: (data: { name: string; email: string; username?: string; password: string; role: string; organizationId?: string; socTier?: string | null }) =>
    request<{ ok: boolean; user: any }>('/api/super-admin/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUserSocTier: (id: string, socTier: string | null) =>
    request<{ ok: boolean; socTier: string | null }>(`/api/super-admin/users/${id}/soc-tier`, {
      method: 'PUT',
      body: JSON.stringify({ socTier })
    }),
  updateUserRole: (id: string, role: string) =>
    request<{ ok: boolean; role: string }>(`/api/super-admin/users/${id}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role })
    }),
  deleteUser: (id: string) => request<{ ok: boolean }>(`/api/super-admin/users/${id}`, { method: 'DELETE' }),
  getRoles: () => request<{ roles: Array<{ id: string; name: string; description?: string }> }>('/api/super-admin/roles'),
  createRole: (data: { name: string; description?: string }) =>
    request<{ ok: boolean; role: any }>('/api/super-admin/roles', { method: 'POST', body: JSON.stringify(data) }),
  deleteRole: (id: string) => request<{ ok: boolean }>(`/api/super-admin/roles/${id}`, { method: 'DELETE' })
};

export const telemetryStreamManager = globalRealtimeClient;
