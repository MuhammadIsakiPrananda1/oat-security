export type UserRole = 
  | 'Super Admin' 
  | 'Security Admin' 
  | 'Security Analyst' 
  | 'Organization Admin' 
  | 'Viewer';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  /** Optional SOC response tier. When set, incident visibility is scoped to it. */
  socTier?: SocTier | null;
  organizationId: string;
  organizationName: string;
  avatarUrl?: string;
  username?: string | null;
  phone?: string | null;
  /** Telegram bot API key for personal alert delivery. */
  telegramBotToken?: string | null;
  bio?: string | null;
  linkedinUrl?: string | null;
  githubUrl?: string | null;
  twitterUrl?: string | null;
  instagramUrl?: string | null;
  mfaEnabled: boolean;
  lastLogin: string;
}

export interface Organization {
  id: string;
  name: string;
  domain: string;
  industry: 'Banking' | 'FinTech' | 'E-Commerce' | 'Government' | 'Technology' | 'Enterprise';
  tier: 'Starter' | 'Business' | 'Enterprise';
  riskScore: number; // 0 - 100
  wafStatus: 'Operational' | 'Degraded' | 'Offline';
  firewallStatus: 'Operational' | 'Degraded' | 'Offline';
}

export type ThreatSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type ThreatAction = 'Allowed' | 'Blocked' | 'Challenged' | 'Logged';
export type IncidentStatus = 'New' | 'Investigating' | 'Contained' | 'Resolved' | 'Closed';

export interface SystemHealth {
  wafEngine: 'Operational' | 'Degraded' | 'Offline';
  firewall: 'Operational' | 'Degraded' | 'Offline';
  endpointDetection: 'Operational' | 'Degraded' | 'Offline';
  database: 'Operational' | 'Degraded' | 'Offline';
  api: 'Operational' | 'Degraded' | 'Offline';
  monitoring: 'Operational' | 'Degraded' | 'Offline';
  webSocket: 'Operational' | 'Degraded' | 'Offline';
  threatIntelligence: 'Operational' | 'Degraded' | 'Offline';
  lastHeartbeat: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  source?: string;
  sourceIp: string;
  sourceCountry?: string;
  sourceCountryCode?: string;
  sourceCountryFlag?: string;
  destination: string;
  destinationIp?: string;
  application: string;
  threat: string;
  threatName?: string;
  category: 'WAF' | 'Firewall' | 'Authentication' | 'Network' | 'Endpoint' | 'API' | 'System' | 'Security' | string;
  eventType?: string;
  severity: ThreatSeverity | string;
  action: ThreatAction | string;
  status: 'Detected' | 'Mitigated' | 'Under Review' | string;
  uri?: string;
  method?: string;
  protocol?: string;
  port?: number;
  statusCode?: number;
  payloadSnippet?: string;
  rawLog?: string;
  metadata?: Record<string, any>;
}

export interface LiveTrafficEntry {
  id: string;
  timestamp: string;
  sourceIp: string;
  destination: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'CONNECT' | string;
  uri: string;
  protocol: 'HTTP/2' | 'HTTP/3' | 'HTTPS' | 'TCP' | 'UDP' | string;
  port: number;
  country: string;
  countryCode: string;
  threatScore: number; // 0-100
  action: ThreatAction | string;
}

export interface ThreatItem {
  id: string;
  /** `incident` rows are SOC cases surfaced in the correlated feed. */
  kind?: 'threat' | 'incident';
  incidentId?: string;
  tier?: SocTier | string;
  assignedAnalyst?: string;
  timestamp: string;
  sourceIp: string;
  target: string;
  attackType: string;
  category?: string;
  severity: ThreatSeverity | string;
  confidence: number; // e.g. 98%
  action: ThreatAction | string;
  status: 'Active' | 'Blocked' | 'Investigating' | 'Resolved' | 'MITIGATED' | 'NEW' | 'CONTAINED' | string;
  summary: string;
  detectionReason?: string;
  detectionSource?: string;
  affectedApplication: string;
  destination?: string;
  timeline?: { time: string; event: string }[];
  relatedEvents?: string[];
  recommendedAction?: string;
  mitre?: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    description: string;
  };
}

export interface WafRule {
  id: string;
  ruleId?: string;
  name: string;
  category: string;
  severity: ThreatSeverity | string;
  action: 'Block' | 'Allow' | 'Log' | 'Challenge' | string;
  status: 'Active' | 'Disabled';
  enabled?: number;
  pattern?: string;
  lastTriggered?: string;
  description?: string;
  hitCount?: number;
}

export type AgentWafState = 'PENDING' | 'APPLIED' | 'FAILED' | 'UNSUPPORTED';

export interface AgentDetectedSite {
  domain: string;
  port?: number;
  protocol?: string;
  serverType?: string;
}

export interface AgentWafTarget {
  id: string;
  name: string;
  hostname: string;
  os: string;
  ip: string;
  applicationId: string | null;
  applicationName: string | null;
  applicationDomain: string | null;
  detectedSites: AgentDetectedSite[];
  agentStatus: 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED';
  status: AgentWafState;
  wafCapable: boolean | null;
  message: string;
  target: string;
  rulesApplied: number;
  appliedRevision: number;
  desiredRevision: number;
  appliedAt: string | null;
  lastSeen: string | null;
}

export interface WafDeploymentView {
  revision: number;
  engineEnabled: boolean;
  mode: string;
  totalAgents: number;
  onlineAgents: number;
  appliedAgents: number;
  pendingAgents: number;
  failedAgents: number;
  unsupportedAgents: number;
  status: 'NO_AGENT' | 'PENDING' | 'APPLIED' | 'FAILED' | 'PARTIAL' | 'UNSUPPORTED';
  lastAppliedAt: string | null;
  agents: AgentWafTarget[];
}

export interface ProtectedApplication {
  id: string;
  name: string;
  domain: string;
  originIp?: string;
  ipAddress?: string;
  environment?: 'Production' | 'Staging' | 'Development' | string;
  owner?: string;
  protocol?: string;
  port?: number;
  wafStatus?: 'Protected' | 'Monitoring' | 'Offline' | 'ACTIVE' | string;
  tlsStatus?: string;
  health?: 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN' | string;
  threatLevel?: ThreatSeverity | string;
  requestCount?: number;
  requests24h?: number;
  blocked24h?: number;
  responseTime?: number;
  sslExpiry?: string;
  createdAt?: string;
  lastSeen?: string;
  agentCount?: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'CRITICAL' | 'ERROR' | 'WARN' | 'INFO' | 'DEBUG' | string;
  source: 'waf' | 'firewall' | 'system' | 'auth' | 'agent' | string;
  eventType?: string;
  message: string;
  host?: string;
  ip?: string;
  correlationId?: string;
  metadata?: Record<string, any>;
  rawLog?: string;
}

export interface FirewallRule {
  id: string;
  priority: number;
  source: string;
  destination: string;
  port: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  action: 'ALLOW' | 'DENY' | 'LOG';
  status: 'Active' | 'Disabled';
  /** Raw server column (`0|1`); `status` below is derived from it. */
  enabled?: number;
  created: string;
  description: string;
}

/** Progress feedback from the enforcement point (endpoint agents). */
export interface FirewallAgentTarget {
  id: string;
  name: string;
  hostname: string;
  os: string;
  ip: string;
  agentStatus: 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED';
  status: 'PENDING' | 'APPLIED' | 'FAILED' | 'UNSUPPORTED';
  message: string;
  target: string;
  rulesApplied: number;
  appliedRevision: number;
  desiredRevision: number;
  appliedAt: string | null;
  lastSeen: string | null;
}

export interface FirewallDeployment {
  revision: number;
  totalAgents: number;
  onlineAgents: number;
  appliedAgents: number;
  pendingAgents: number;
  failedAgents: number;
  unsupportedAgents: number;
  status: 'NO_AGENT' | 'PENDING' | 'APPLIED' | 'FAILED' | 'PARTIAL' | 'UNSUPPORTED';
  lastAppliedAt: string | null;
  agents: FirewallAgentTarget[];
}

export type NetworkZone =
  | 'DMZ'
  | 'Internal Core'
  | 'Cloud VPC'
  | 'Corporate Office'
  | 'Database Cluster'
  | 'Payment Gateway'
  | 'Edge Proxy';

export interface NatRule {
  id: string;
  organization_id?: string;
  name: string;
  external_vip: string;
  external_port: string;
  internal_ip: string;
  internal_port: string;
  protocol: 'TCP' | 'UDP' | 'TCP/UDP';
  nat_mode: 'DNAT' | 'Full Cone NAT' | 'SNAT';
  enabled: boolean;
  description?: string;
  created_at?: string;
}

export interface NetworkInventory {
  id: string;
  name: string;
  cidr: string;
  gateway: string;
  /** Live count of distinct hosts observed inside the CIDR (agents + telemetry). */
  devicesCount: number;
  /** Firewall engine enforcing the zone (configured by the operator). */
  firewall: string;
  status: 'Online' | 'Warning' | 'Offline';
  /** Derived from the highest severity seen targeting this subnet in the last 24h. */
  riskLevel: ThreatSeverity;
  zone: NetworkZone | string;
  /** Requests seen targeting this subnet in the last 24h. */
  trafficVolume?: number;
  interface?: string;
  description?: string;
  createdAt?: string;
}

export type SocTier = 'L1' | 'L2' | 'L3';

export interface IncidentTimelineEntry {
  time: string;
  note: string;
  author: string;
  tier?: SocTier;
}

export interface Incident {
  id: string;
  title: string;
  severity: ThreatSeverity;
  status: string;
  tier?: SocTier;
  created: string;
  updated?: string;
  assignedAnalyst: string;
  affectedAsset: string;
  relatedThreatsCount: number;
  timeline: IncidentTimelineEntry[];
  notes: string;
  recommendedMitigation?: string;
  escalationReason?: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  message: string;
  severity: ThreatSeverity;
  timestamp: string;
  read: boolean;
  link?: string;
}

export interface AuditLogItem {
  id: string;
  user: string;
  role: string;
  action: 'Login' | 'Logout' | 'Create Policy' | 'Update Rule' | 'Delete Rule' | 'Change Permission' | 'Add Application' | 'Remove Application' | 'Export Report' | 'Apply AI Recommendation';
  resource: string;
  timestamp: string;
  ip: string;
  result: 'Success' | 'Denied' | 'Failed';
}

export interface ApiKeyItem {
  id: string;
  name: string;
  prefix: string;
  created: string;
  lastUsed: string;
  permissions: string[];
  status: 'Active' | 'Revoked';
}

export interface ThreatIntelligenceFeed {
  id: string;
  indicator: string; // IP, Domain, Hash
  type: 'Malicious IP' | 'C2 Server' | 'Phishing Domain' | 'Botnet Node' | 'Cryptominer' | 'Exploit Payload' | string;
  threatScore: number;
  confidence: number;
  severity?: 'Critical' | 'High' | 'Medium' | 'Low';
  firstSeen: string;
  lastSeen: string;
  reportedBy: string;
  status: 'Active' | 'Blocked' | 'Monitored';
  tags?: string[];
  targetSector?: string;
  country?: string;
}

export interface ThreatFeedSource {
  id: string;
  name: string;
  provider: string;
  category: 'Financial Sector ISAC' | 'National CERT' | 'Community Threat Feed' | 'Commercial Intel' | 'Internal Honeypot';
  entries: string;
  lastSync: string;
  status: 'Operational' | 'Syncing' | 'Degraded';
  confidenceAvg: number;
}

export interface CveMitigationItem {
  cve: string;
  score: string;
  severity: 'Critical' | 'High' | 'Medium';
  desc: string;
  status: 'WAF Rule Active' | 'Virtual Patch Applied' | 'Deep Inspection' | string;
  affectedSoftware?: string;
  publishedDate?: string;
  exploitAvailable?: boolean;
}


export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  version: string;
  controlsCount: number;
  alignedCount: number;
  coveragePercentage: number;
  status: 'Aligned' | 'In Review';
  keyControls: { id: string; name: string; status: 'Aligned' | 'Needs Review'; description: string }[];
}

// ---------------------------------------------------------------------------
// Endpoint Agents (OAT agent deployed on servers/workstations)
// ---------------------------------------------------------------------------
export type AgentStatus = 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED';

export interface AgentMetrics {
  hostname?: string;
  os?: string;
  arch?: string;
  ip?: string;
  cpuPercent?: number;
  cpuCores?: number;
  memoryPercent?: number;
  memoryUsedMb?: number;
  memoryTotalMb?: number;
  diskPercent?: number;
  diskUsedGb?: number;
  diskTotalGb?: number;
  load1?: number;
  load5?: number;
  load15?: number;
  uptimeSeconds?: number;
  processCount?: number;
  kernel?: string;
  [key: string]: unknown;
}

export interface EndpointAgent {
  id: string;
  applicationId: string | null;
  applicationName: string | null;
  applicationDomain: string | null;
  application: { id: string; name: string; domain: string } | null;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  ip: string;
  status: AgentStatus;
  lastSeen: string | null;
  createdAt: string | null;
  revokedAt: string | null;
  eventsIngested: number;
  logsIngested: number;
  labels: Record<string, string>;
  hostInfo: Record<string, unknown>;
  metrics: AgentMetrics;
}

export interface AgentSummary {
  total: number;
  online: number;
  offline: number;
  pending: number;
  revoked: number;
  eventsIngested: number;
  logsIngested: number;
}

export interface AgentEnrollmentToken {
  id: string;
  token: string;
  label: string;
  expiresAt: string;
  expiresInMinutes: number;
  applicationId: string;
  applicationName: string;
  applicationDomain: string;
}

export interface AgentDetail {
  agent: EndpointAgent;
  recentEvents: Array<Record<string, unknown>>;
  recentLogs: Array<Record<string, unknown>>;
}

export interface ApplicationAgent {
  id: string;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  ip: string;
  status: AgentStatus;
  lastSeen: string | null;
  eventsIngested: number;
  logsIngested: number;
}

export type MalwareVerdict = 'clean' | 'suspicious' | 'malicious';

export interface MalwareEngineMatch {
  id: string;
  name: string;
  category: string;
  weight: number;
  evidence: string;
}

export interface MalwareScan {
  id: string;
  organizationId: string;
  applicationId: string | null;
  agentId: string | null;
  timestamp: string;
  fileName: string;
  filePath: string | null;
  fileSize: number;
  sha256: string;
  md5: string | null;
  mimeType: string | null;
  verdict: MalwareVerdict;
  score: number;
  cvssScore?: number;
  cvssVector?: string;
  family: string | null;
  severity: string;
  status: string;
  action: string;
  actionStatus: string;
  source: string;
  sourceIp: string | null;
  requestUri: string | null;
  engines: MalwareEngineMatch[];
  c2: string[];
  samplePreview: string | null;
  metadata: Record<string, any>;
  quarantinedPath: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface MalwareMetrics {
  watched24h: number;
  malicious: number;
  suspicious: number;
  clean: number;
  quarantined: number;
  deleted: number;
  pendingActions: number;
  signatures: number;
}

export interface MalwareScanListResponse {
  scans: MalwareScan[];
  total: number;
  metrics: MalwareMetrics;
}

export interface MalwareHashLookup {
  found: boolean;
  hash: string;
  verdict: MalwareVerdict | 'unknown' | 'invalid';
  label: string;
  severity: string;
  source?: string;
  scan: MalwareScan | null;
}

export interface MalwareContainmentResult {
  scan: MalwareScan;
  firewallRuleCreated?: boolean;
  message: string;
}

export interface ReportItem {
  id: string;
  organizationId?: string;
  title: string;
  category: string;
  period: string;
  format: string;
  status: string;
  summary: string;
  fileSize: string;
  sha256?: string;
  content?: string;
  generatedBy?: string;
  createdAt: string;
}

