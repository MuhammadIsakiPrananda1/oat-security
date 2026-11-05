import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronDown,
  Clock,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  Globe,
  HardDrive,
  KeyRound,
  MemoryStick,
  Monitor,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Terminal,
  Trash2,
  Wifi,
  X
} from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { CountUpNumber } from '../../components/common/CountUpNumber';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faDesktop } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import {
  AgentDetail,
  AgentEnrollmentToken,
  AgentStatus,
  AgentSummary,
  EndpointAgent,
  ProtectedApplication
} from '../../types';

type PlatformTab = 'linux' | 'windows';

/** A website the agent discovered on the monitored host. */
interface DetectedSiteView {
  domain: string;
  port: number;
  protocol: string;
  serverType: string;
}

/** How many websites an agent reported from its host scan. */
function detectedSiteCount(agent: EndpointAgent): number {
  const raw = agent.hostInfo?.detectedSites;
  if (!Array.isArray(raw)) return 0;
  const domains = new Set<string>();
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const domain = String((entry as Record<string, unknown>).domain || '').trim().toLowerCase();
    if (domain) domains.add(domain);
  }
  return domains.size;
}

const STATUS_STYLES: Record<AgentStatus, { dot: string; text: string; bg: string }> = {
  ONLINE: { dot: 'bg-emerald-500', text: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-50 dark:bg-emerald-950/40' },
  OFFLINE: { dot: 'bg-amber-500', text: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-950/40' },
  STALE: { dot: 'bg-zinc-400', text: 'text-zinc-500 dark:text-zinc-400', bg: 'bg-zinc-100 dark:bg-zinc-800/60' },
  PENDING: { dot: 'bg-sky-500', text: 'text-sky-600 dark:text-sky-400', bg: 'bg-sky-50 dark:bg-sky-950/40' },
  REVOKED: { dot: 'bg-rose-500', text: 'text-rose-600 dark:text-rose-400', bg: 'bg-rose-50 dark:bg-rose-950/40' }
};

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const normalized = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatRelative(value: string | null | undefined): string {
  const date = parseDate(value);
  if (!date) return 'Never';
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 45) return 'Just now';
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  if (seconds < 86400 * 30) return `${Math.round(seconds / 86400)} d ago`;
  return formatDate(value);
}

function formatDate(value: string | null | undefined): string {
  const date = parseDate(value);
  if (!date) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function formatUptime(seconds: unknown): string {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function metricPercent(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return `${Math.max(0, Math.min(100, value)).toFixed(1)}%`;
}

function osLabel(os: string): string {
  const value = String(os || '').toLowerCase();
  if (value === 'linux') return 'Linux';
  if (value === 'windows') return 'Windows';
  if (value === 'darwin') return 'macOS';
  return os || 'Unknown';
}

function StatusBadge({ status }: { status: AgentStatus }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.STALE;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${style.bg} ${style.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      {status}
    </span>
  );
}

function StatCard({
  label,
  value,
  icon,
  hint,
  accent
}: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">{label}</span>
        <span className={accent || 'text-zinc-400 dark:text-zinc-500'}>{icon}</span>
      </div>
      <div className="mt-1.5 text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {hint && <div className="mt-0.5 text-[11px] text-zinc-400 dark:text-zinc-500">{hint}</div>}
    </div>
  );
}

function MetricBar({
  label,
  value,
  subLabel,
  icon
}: {
  label: string;
  value: unknown;
  subLabel?: string;
  icon: React.ReactNode;
}) {
  const percent = typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : null;
  return (
    <div className="rounded-xl border border-zinc-100 bg-zinc-50/60 p-3 dark:border-zinc-800/60 dark:bg-zinc-900/40">
      <div className="flex items-center justify-between gap-2 text-[11px] text-zinc-500 dark:text-zinc-400">
        <span className="inline-flex items-center gap-1.5">{icon}{label}</span>
        <span className="font-semibold text-zinc-800 dark:text-zinc-100">{metricPercent(value)}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
        <div
          className={`h-full rounded-full ${percent !== null && percent >= 90 ? 'bg-rose-500' : percent !== null && percent >= 70 ? 'bg-amber-500' : 'bg-emerald-500'}`}
          style={{ width: `${percent ?? 0}%` }}
        />
      </div>
      {subLabel && (
        <div className="mt-1.5 text-right font-mono text-[10px] text-zinc-400 dark:text-zinc-500">
          {subLabel}
        </div>
      )}
    </div>
  );
}

export const AgentsModule: React.FC = () => {
  const { isBackendOffline, currentOrg, loadOrganizations } = useAuth();
  const [agents, setAgents] = useState<EndpointAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const [applications, setApplications] = useState<ProtectedApplication[]>([]);

  const [search, setSearch] = useState('');
  const [selectedAgent, setSelectedAgent] = useState<AgentDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [savingWebsite, setSavingWebsite] = useState(false);
  const [websiteError, setWebsiteError] = useState('');
  const [newlyEnrolledAgent, setNewlyEnrolledAgent] = useState<EndpointAgent | null>(null);

  const [showEnroll, setShowEnroll] = useState(false);
  const [enrollLabel, setEnrollLabel] = useState('');
  const [enrollMinutes, setEnrollMinutes] = useState(60);
  const [enrollment, setEnrollment] = useState<AgentEnrollmentToken | null>(() => {
    try {
      const saved = localStorage.getItem('oat_active_enrollment_token');
      if (!saved) return null;
      const parsed: AgentEnrollmentToken = JSON.parse(saved);
      if (parsed?.expiresAt && Date.parse(parsed.expiresAt) > Date.now()) {
        return parsed;
      }
      localStorage.removeItem('oat_active_enrollment_token');
    } catch {}
    return null;
  });

  // Whenever agents list updates and there is at least one connected agent, ensure pending enrollment token & modal are dismissed
  useEffect(() => {
    if (agents.some(a => a.status === 'ONLINE' || a.status === 'ACTIVE')) {
      setEnrollment(null);
      localStorage.removeItem('oat_active_enrollment_token');
      setShowEnroll(false);
    }
  }, [agents]);
  const [enrollLoading, setEnrollLoading] = useState(false);
  const [enrollError, setEnrollError] = useState('');
  const [tokenTimeRemaining, setTokenTimeRemaining] = useState<string>('');

  useEffect(() => {
    if (!enrollment?.expiresAt) {
      setTokenTimeRemaining('');
      return;
    }
    const updateCountdown = () => {
      const diff = Date.parse(enrollment.expiresAt) - Date.now();
      if (diff <= 0) {
        setTokenTimeRemaining('Expired');
        setEnrollment(null);
        localStorage.removeItem('oat_active_enrollment_token');
        return;
      }
      const mins = Math.floor(diff / 60000);
      const secs = Math.floor((diff % 60000) / 1000);
      setTokenTimeRemaining(`${mins}m ${secs.toString().padStart(2, '0')}s`);
    };
    updateCountdown();
    const interval = window.setInterval(updateCountdown, 1000);
    return () => window.clearInterval(interval);
  }, [enrollment]);
  const [platform, setPlatform] = useState<PlatformTab>('linux');
  const [serverBaseUrl, setServerBaseUrl] = useState(() => (
    typeof window !== 'undefined' ? window.location.origin : 'https://your-oat-server'
  ));
  const [allowInsecure, setAllowInsecure] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const [revokeTarget, setRevokeTarget] = useState<EndpointAgent | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [revokeError, setRevokeError] = useState('');
  const [purgeAgentData, setPurgeAgentData] = useState(false);

  const fetchAgents = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    try {
      const data = await securityApi.getAgents();
      setAgents(data.agents || []);
      setError('');

      // If any active agent is already connected (e.g. status ONLINE), clear any pending enrollment state and dismiss modal
      if ((data.agents || []).some(a => a.status === 'ONLINE')) {
        setEnrollment(null);
        localStorage.removeItem('oat_active_enrollment_token');
        setShowEnroll(false);
      } else {
        // Otherwise check if current pending enrollment token has already been consumed / used on server
        try {
          const tokenRes = await securityApi.getActiveEnrollmentTokens();
          const activeIds = new Set((tokenRes.tokens || []).map(t => t.id));
          setEnrollment(current => {
            if (current?.id && !activeIds.has(current.id)) {
              localStorage.removeItem('oat_active_enrollment_token');
              return null;
            }
            return current;
          });
        } catch {}
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load endpoint agents.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const fetchApplications = useCallback(async () => {
    try {
      const data = await securityApi.getApplications();
      setApplications(data.applications || []);
    } catch {
      setApplications([]);
    }
  }, []);

  // Keep the row that is open in the drawer easy to find from the realtime
  // listener without re-subscribing every time the selection changes.
  const selectedAgentIdRef = useRef<string | null>(null);
  useEffect(() => {
    selectedAgentIdRef.current = selectedAgent?.agent.id || null;
  }, [selectedAgent?.agent.id]);

  // Server summaries are a snapshot; deriving from the live list keeps the
  // stat cards accurate the instant a heartbeat or ingest event arrives.
  const summary = useMemo<AgentSummary>(() => ({
    total: agents.length,
    online: agents.filter(agent => agent.status === 'ONLINE').length,
    offline: agents.filter(agent => agent.status === 'OFFLINE' || agent.status === 'STALE').length,
    pending: agents.filter(agent => agent.status === 'PENDING').length,
    revoked: agents.filter(agent => agent.status === 'REVOKED').length,
    eventsIngested: agents.reduce((total, agent) => total + agent.eventsIngested, 0),
    logsIngested: agents.reduce((total, agent) => total + agent.logsIngested, 0)
  }), [agents]);

  const applyAgentSnapshot = useCallback((snapshot: EndpointAgent) => {
    setAgents(prev => {
      const index = prev.findIndex(agent => agent.id === snapshot.id);
      if (index === -1) return [snapshot, ...prev];
      const next = prev.slice();
      next[index] = { ...next[index], ...snapshot };
      return next;
    });
    setSelectedAgent(prev => (
      prev && prev.agent.id === snapshot.id
        ? {
            ...prev,
            agent: {
              ...prev.agent,
              ...snapshot,
              metrics: snapshot.metrics ? { ...prev.agent.metrics, ...snapshot.metrics } : prev.agent.metrics
            }
          }
        : prev
    ));
  }, []);

  useEffect(() => {
    let detailTimer: number | null = null;

    const unsubEvents = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;
      const type = String(msg.type || '');
      const data = msg.data || msg;

      if (
        type === 'agent.enrolled' ||
        type === 'agent.heartbeat' ||
        type === 'agent.ingested' ||
        type === 'agent.updated' ||
        type === 'agent.restored'
      ) {
        // When any agent successfully enrolls or checks in, immediately clear the
        // pending enrollment token and close the deploy modal so the connected
        // live agent row is displayed instantly.
        setEnrollment(null);
        localStorage.removeItem('oat_active_enrollment_token');
        setShowEnroll(false);
        const snapshot = data?.agent as EndpointAgent | undefined;
        if (snapshot?.id) {
          applyAgentSnapshot(snapshot);
        } else if (data?.agentId || data?.id) {
          // Older payloads only carried an id — fall back to a quiet refetch.
          fetchAgents(true);
        }

        if (type === 'agent.enrolled' && snapshot) {
          setNewlyEnrolledAgent(data?.agent || snapshot);
        }

        // The open drawer also shows recent telemetry: refresh it after a short
        // debounce so a 2-second log flush does not cause a request storm.
        if (type === 'agent.ingested' && selectedAgentIdRef.current === snapshot.id) {
          if (detailTimer) window.clearTimeout(detailTimer);
          detailTimer = window.setTimeout(() => {
            const id = snapshot.id;
            securityApi.getAgent(id)
              .then(detail => setSelectedAgent(prev => (prev?.agent.id === id ? detail : prev)))
              .catch(() => {});
          }, 1200);
        }
        return;
      }

      if (type === 'endpoint.status') {
        // Sync live status online/offline directly without waiting for page refresh
        const endpoints = (data?.endpoints as any[]) || [];
        if (Array.isArray(endpoints)) {
          setAgents(prev => prev.map(agent => {
            const match = endpoints.find(e => e.id === agent.id);
            if (match && match.status !== agent.status) {
              return { ...agent, status: match.status, lastSeen: match.lastSeen || agent.lastSeen };
            }
            return agent;
          }));
          setSelectedAgent(prev => {
            if (!prev) return null;
            const match = endpoints.find(e => e.id === prev.agent.id);
            if (match && match.status !== prev.agent.status) {
              return { ...prev, agent: { ...prev.agent, status: match.status, lastSeen: match.lastSeen || prev.agent.lastSeen } };
            }
            return prev;
          });
        }
        return;
      }

      if (type === 'agent.removed') {
        const agentId = data?.agentId || data?.id;
        if (agentId) {
          setAgents(prev => prev.filter(agent => agent.id !== agentId));
          setSelectedAgent(prev => (prev?.agent.id === agentId ? null : prev));
        } else {
          fetchAgents(true);
        }
        return;
      }

      // Agent-discovered websites and binding changes land in the picker live.
      if (type === 'application.created' || type === 'application.updated' || type === 'application.removed') {
        fetchApplications();
      }
    });

    return () => {
      unsubEvents();
      if (detailTimer) window.clearTimeout(detailTimer);
    };
  }, [applyAgentSnapshot, fetchAgents, fetchApplications]);

  useEffect(() => {
    fetchAgents();
    // Safety net: check if an enrolled agent has appeared every 3s if we have an active enrollment token
    const interval = window.setInterval(() => {
      fetchAgents(true);
    }, enrollment ? 1000 : 3000);
    return () => window.clearInterval(interval);
  }, [fetchAgents, currentOrg?.id, enrollment]);

  useEffect(() => {
    fetchApplications();
  }, [fetchApplications, currentOrg?.id]);

  // Live real-time sync for Live Host Metrics drawer: poll every 1.5s when drawer is open
  useEffect(() => {
    const agentId = selectedAgent?.agent?.id;
    if (!agentId) return;
    const liveTimer = window.setInterval(async () => {
      try {
        const detail = await securityApi.getAgent(agentId);
        if (detail?.agent) {
          setSelectedAgent(prev => (prev && prev.agent.id === agentId ? detail : prev));
        }
      } catch {}
    }, 1500);
    return () => window.clearInterval(liveTimer);
  }, [selectedAgent?.agent?.id]);

  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      if (revokeTarget) setRevokeTarget(null);
      else if (showEnroll) closeEnroll();
      else if (selectedAgent) setSelectedAgent(null);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  });

  const filteredAgents = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return agents;
    return agents.filter(agent =>
      [
        agent.name,
        agent.hostname,
        agent.ip,
        agent.os,
        agent.id,
        agent.applicationName || '',
        agent.applicationDomain || '',
        ...Object.values(agent.labels || {})
      ]
        .join(' ')
        .toLowerCase()
        .includes(query)
    );
  }, [agents, search]);

  const copyText = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied(current => (current === key ? null : current)), 2000);
    } catch {
      // Clipboard permissions can be denied; the user can select the text.
    }
  };

  const openEnroll = () => {
    setShowEnroll(true);
    setEnrollError('');
    setEnrollLabel('');
    setEnrollMinutes(60);
    setPlatform('linux');
    fetchApplications();
  };

  const closeEnroll = () => {
    setShowEnroll(false);
    setEnrollError('');
    setEnrollLoading(false);
  };

  const discardToken = () => {
    setEnrollment(null);
    localStorage.removeItem('oat_active_enrollment_token');
  };

  const createEnrollment = async () => {
    setEnrollLoading(true);
    setEnrollError('');
    try {
      // The token is intentionally "open": the agent reports every website it
      // finds on the host, and the operator picks the monitored website in the
      // console afterwards.
      const token = await securityApi.createAgentEnrollmentToken({
        label: enrollLabel.trim() || 'Endpoint agent',
        expiresInMinutes: enrollMinutes
      });
      setEnrollment(token);
      try {
        localStorage.setItem('oat_active_enrollment_token', JSON.stringify(token));
      } catch {}
      fetchAgents(true);
    } catch (err) {
      setEnrollError(err instanceof Error ? err.message : 'Failed to create an enrollment token.');
    } finally {
      setEnrollLoading(false);
    }
  };

  const openAgentDetail = async (agent: EndpointAgent) => {
    setSelectedAgent({ agent, recentEvents: [], recentLogs: [] });
    setDetailLoading(true);
    setDetailError('');
    setWebsiteError('');
    try {
      const detail = await securityApi.getAgent(agent.id);
      setSelectedAgent(detail);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Unable to load agent details.');
    } finally {
      setDetailLoading(false);
    }
  };

  // Websites the agent discovered on its host.
  const detectedSites = useMemo<DetectedSiteView[]>(() => {
    if (!selectedAgent) return [];
    const raw = selectedAgent.agent.hostInfo?.detectedSites;
    if (!Array.isArray(raw)) return [];
    const seen = new Set<string>();
    const sites: DetectedSiteView[] = [];
    for (const entry of raw) {
      if (!entry || typeof entry !== 'object') continue;
      const item = entry as Record<string, unknown>;
      const domain = String(item.domain || '').trim().toLowerCase();
      if (!domain) continue;
      const port = Number(item.port) || 0;
      const key = `${domain}:${port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      sites.push({
        domain,
        port,
        protocol: String(item.protocol || (port === 443 ? 'HTTPS' : 'HTTP')).toUpperCase(),
        serverType: String(item.serverType || '')
      });
    }
    return sites;
  }, [selectedAgent]);

  // Bind the agent to the website the operator picked.
  const assignWebsite = async (agentId: string, applicationId: string | undefined, site: DetectedSiteView) => {
    setSavingWebsite(true);
    setWebsiteError('');
    try {
      if (applicationId) {
        await securityApi.setAgentApplication(agentId, { applicationId });
      } else {
        await securityApi.setAgentApplication(agentId, {
          domain: site.domain,
          protocol: site.protocol,
          port: site.port || undefined
        });
      }
      if (selectedAgent && selectedAgent.agent.id === agentId) {
        const detail = await securityApi.getAgent(agentId);
        setSelectedAgent(detail);
      }
      if (newlyEnrolledAgent && newlyEnrolledAgent.id === agentId) {
        setNewlyEnrolledAgent(prev => prev ? ({
          ...prev,
          applicationDomain: site.domain,
          applicationName: site.domain
        }) : null);
      }
      await fetchApplications();
      await fetchAgents(true);
      await loadOrganizations({ announce: true });
    } catch (err) {
      setWebsiteError(err instanceof Error ? err.message : 'Unable to bind the agent to this website.');
    } finally {
      setSavingWebsite(false);
    }
  };

  const confirmRevoke = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    setRevokeError('');
    try {
      await securityApi.revokeAgent(revokeTarget.id, purgeAgentData);
      setRevokeTarget(null);
      setPurgeAgentData(false);
      if (selectedAgent?.agent.id === revokeTarget.id) setSelectedAgent(null);
      await fetchAgents(true);
    } catch (err) {
      setRevokeError(err instanceof Error ? err.message : 'Failed to remove the agent.');
    } finally {
      setRevoking(false);
    }
  };

  // Re-activate a revoked agent: the endpoint is still running, so the server
  // only has to accept its signed requests again.
  const restoreAgentEntry = async () => {
    if (!selectedAgent) return;
    setRestoring(true);
    setDetailError('');
    try {
      await securityApi.restoreAgent(selectedAgent.agent.id);
      await fetchAgents(true);
      const detail = await securityApi.getAgent(selectedAgent.agent.id);
      setSelectedAgent(detail);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Failed to restore the agent.');
    } finally {
      setRestoring(false);
    }
  };

  const defaultOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://your-oat-server';
  const serverBase = (serverBaseUrl.trim() || defaultOrigin).replace(/\/+$/, '');
  const insecureFlag = allowInsecure ? ' --insecure' : '';
  const windowsInsecureFlag = allowInsecure ? ' -Insecure' : '';
  const exampleName = (enrollment?.label || enrollLabel || 'endpoint-agent').replace(/[^a-zA-Z0-9._-]/g, '-');
  const linuxCommand = enrollment
    ? `curl -fsSL ${serverBase}/api/agents/install.sh | sudo bash -s -- --server ${serverBase} --token ${enrollment.token} --name ${exampleName}${insecureFlag}`
    : '';
  const windowsCommand = enrollment
    ? `$s="${serverBase}"; $t="${enrollment.token}"; $n="${exampleName}"; irm "$s/api/agents/install.ps1" -OutFile "$env:TEMP\\oat-install.ps1"; & "$env:TEMP\\oat-install.ps1" -Server $s -Token $t -Name $n${windowsInsecureFlag}`
    : '';

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => fetchAgents()} />;
  }

  // A revoked or never-connected agent has no telemetry at all; the panel
  // shows why instead of empty cards.
  const hasLiveMetrics = Boolean(
    selectedAgent && (
      typeof selectedAgent.agent.metrics.cpuPercent === 'number' ||
      typeof selectedAgent.agent.metrics.memoryPercent === 'number' ||
      typeof selectedAgent.agent.metrics.diskPercent === 'number' ||
      typeof selectedAgent.agent.metrics.uptimeSeconds === 'number'
    )
  );

  return (
    <div className="space-y-5">
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faDesktop} />}
        title="Endpoint Agents"
        subtitle="Manage and deploy OAT endpoint agents — heartbeats, metrics, events, and discovered websites stream into the console in real time."
        actions={
          <button
            type="button"
            onClick={openEnroll}
            className="inline-flex h-9 items-center gap-1.5 rounded-xl bg-zinc-900 px-3.5 text-xs font-semibold text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white shadow-2xs"
          >
              <Plus className="h-3.5 w-3.5" />
              {enrollment ? 'Resume deployment' : 'Deploy agent'}
              {enrollment && tokenTimeRemaining && (
                <span className="ml-1 inline-flex items-center gap-1 rounded bg-emerald-500/20 px-1.5 py-0.5 font-mono text-[10px] text-emerald-400">
                  <Clock className="h-2.5 w-2.5" /> {tokenTimeRemaining}
                </span>
              )}
            </button>
        }
      />

      <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <StatCard label="Enrolled endpoints" value={<CountUpNumber value={summary.total} />} icon={<Server className="h-4 w-4" />} hint={`${summary.pending} awaiting first heartbeat`} />
        <StatCard
          label="Online now"
          value={<CountUpNumber value={summary.online} />}
          icon={<Wifi className="h-4 w-4" />}
          hint={`${summary.offline} offline`}
          accent="text-emerald-500"
        />
        <StatCard label="Events ingested" value={<CountUpNumber value={summary.eventsIngested} />} icon={<Activity className="h-4 w-4" />} hint="Security events from agents" />
        <StatCard label="Logs ingested" value={<CountUpNumber value={summary.logsIngested} />} icon={<Terminal className="h-4 w-4" />} hint="Centralized log records" />
      </div>

      <section className="overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
        <div className="flex flex-col gap-3 border-b border-zinc-100 px-4 py-3.5 dark:border-zinc-800/80 sm:flex-row sm:items-center sm:justify-between sm:px-5">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-900 dark:text-zinc-100">
              Enrolled endpoints
            </h2>
            <p className="mt-0.5 text-[11px] text-zinc-400 dark:text-zinc-500">
              {filteredAgents.length.toLocaleString()} of {agents.length.toLocaleString()} agents
            </p>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search website, host, IP, OS, label…"
              className="h-8 w-full rounded-lg border border-zinc-200 bg-white pl-8 pr-2.5 text-xs text-zinc-700 outline-none transition placeholder:text-zinc-400 focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:focus:border-zinc-500"
            />
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-14 text-xs text-zinc-500 dark:text-zinc-400">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Loading endpoint agents…
          </div>
        ) : error ? (
          <div className="px-5 py-12 text-center">
            <AlertTriangle className="mx-auto mb-2 h-5 w-5 text-amber-500" />
            <p className="text-sm font-medium text-zinc-800 dark:text-zinc-200">Could not load agents</p>
            <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">{error}</p>
            <button
              type="button"
              onClick={() => fetchAgents()}
              className="mt-3 inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200 px-3 text-xs font-medium text-zinc-600 hover:border-zinc-300 cursor-pointer dark:border-zinc-700 dark:text-zinc-300"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Retry
            </button>
          </div>
        ) : (agents.length === 0 && !enrollment) ? (
          <div className="px-6 py-14 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-zinc-100 text-zinc-400 dark:bg-zinc-900 dark:text-zinc-500">
              <Monitor className="h-6 w-6" />
            </div>
            <h3 className="mt-3 text-sm font-semibold text-zinc-900 dark:text-zinc-100">No agents enrolled yet</h3>
            <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">
              Generate a one-time enrollment token and run the installer on the server that hosts the website.
              The agent reports every website it finds there, and you pick the one it should monitor.
              It signs every request with a key that never leaves the endpoint.
            </p>
            <button
              type="button"
              onClick={openEnroll}
              className="mt-4 inline-flex h-9 items-center gap-1.5 rounded-xl bg-zinc-900 px-4 text-xs font-semibold text-white hover:bg-zinc-800 cursor-pointer dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white"
            >
              <Download className="h-3.5 w-3.5" /> Deploy your first agent
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1040px] text-left text-sm">
              <thead className="bg-zinc-50/70 text-[10px] uppercase tracking-wider text-zinc-400 dark:bg-zinc-900/40 dark:text-zinc-500">
                <tr>
                  <th className="px-4 py-2.5 font-medium sm:px-5">Agent</th>
                  <th className="px-4 py-2.5 font-medium">Monitored website</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                  <th className="px-4 py-2.5 font-medium">Platform</th>
                  <th className="px-4 py-2.5 font-medium">Address</th>
                  <th className="px-4 py-2.5 font-medium">Last seen / Expiry</th>
                  <th className="px-4 py-2.5 text-right font-medium">Ingested / Action</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {/* Active pending enrollment token row */}
                {enrollment && (
                  <tr className="border-t border-emerald-100/80 bg-emerald-50/30 dark:border-emerald-950/60 dark:bg-emerald-950/10">
                    <td className="px-4 py-3 sm:px-5">
                      <div className="flex items-center gap-2.5">
                        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-100/80 text-emerald-600 dark:bg-emerald-900/40 dark:text-emerald-400">
                          <Clock className="h-4 w-4 animate-pulse" />
                        </span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate text-xs font-semibold text-zinc-900 dark:text-zinc-100">{enrollment.label}</span>
                            <span className="rounded bg-emerald-100 px-1.5 py-0.2 font-mono text-[9px] font-semibold text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300">
                              NEW TOKEN
                            </span>
                          </div>
                          <div className="truncate font-mono text-[10px] text-zinc-400 dark:text-zinc-500">{enrollment.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="max-w-[220px]">
                        <div className="truncate text-xs font-medium text-zinc-700 dark:text-zinc-300">
                          {enrollment.applicationName || 'Open Enrollment'}
                        </div>
                        <div className="truncate text-[10px] text-zinc-400">
                          {enrollment.applicationDomain || 'Auto-detect websites on host'}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-200 bg-amber-50 px-2.5 py-0.5 text-[11px] font-medium text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-400">
                        <span className="h-1.5 w-1.5 rounded-full bg-amber-500 animate-pulse" />
                        <span>Awaiting install</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500 dark:text-zinc-400">
                      Linux / Windows
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-400 dark:text-zinc-500">
                      Pending connection
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <div className="font-semibold text-emerald-600 dark:text-emerald-400 font-mono">
                        {tokenTimeRemaining || 'Active'} remaining
                      </div>
                      <div className="text-[10px] text-zinc-400" title={formatDate(enrollment.expiresAt)}>
                        Expires {formatDate(enrollment.expiresAt)}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => setShowEnroll(true)}
                          className="inline-flex h-7 items-center gap-1 rounded-lg bg-emerald-600 px-2.5 text-[11px] font-medium text-white shadow-2xs hover:bg-emerald-700 cursor-pointer dark:bg-emerald-500 dark:hover:bg-emerald-600"
                        >
                          <Terminal className="h-3 w-3" /> Command
                        </button>
                        <button
                          type="button"
                          onClick={discardToken}
                          className="inline-flex h-7 items-center rounded-lg border border-zinc-200 bg-white px-2 text-[11px] font-medium text-zinc-600 hover:text-rose-600 hover:border-rose-200 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400"
                          title="Discard token"
                        >
                          Discard
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3" />
                  </tr>
                )}
                {filteredAgents.map(agent => (
                  <tr
                    key={agent.id}
                    onClick={() => openAgentDetail(agent)}
                    className={`cursor-pointer border-t border-zinc-100 transition hover:bg-zinc-50/80 dark:border-zinc-800/60 dark:hover:bg-zinc-900/40 ${agent.status === 'REVOKED' ? 'opacity-55' : ''}`}
                  >
                    <td className="px-4 py-3 sm:px-5">
                      <div className="flex items-center gap-2.5">
                        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-100 text-zinc-500 dark:bg-zinc-900 dark:text-zinc-400">
                          {agent.os.toLowerCase() === 'windows' ? <Monitor className="h-4 w-4" /> : <Server className="h-4 w-4" />}
                        </span>
                        <div className="min-w-0">
                          <div className="truncate text-xs font-semibold text-zinc-900 dark:text-zinc-100">{agent.name}</div>
                          <div className="truncate font-mono text-[10px] text-zinc-400 dark:text-zinc-500">{agent.hostname}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="max-w-[220px]">
                        {agent.applicationName ? (
                          <>
                            <div className="truncate text-xs font-medium text-zinc-700 dark:text-zinc-200">
                              {agent.applicationName}
                            </div>
                            <div className="truncate font-mono text-[10px] text-zinc-400 dark:text-zinc-500">
                              {agent.applicationDomain || '—'}
                            </div>
                          </>
                        ) : (
                          <>
                            <div className="truncate text-xs font-medium text-amber-600 dark:text-amber-400">
                              Select a website
                            </div>
                            <div className="truncate text-[10px] text-zinc-400 dark:text-zinc-500">
                              {detectedSiteCount(agent) > 0
                                ? `${detectedSiteCount(agent)} website${detectedSiteCount(agent) === 1 ? '' : 's'} detected on the host`
                                : 'Waiting for the first scan'}
                            </div>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={agent.status} /></td>
                    <td className="px-4 py-3 text-xs text-zinc-600 dark:text-zinc-300">
                      {osLabel(agent.os)}
                      <span className="ml-1 text-[10px] text-zinc-400 dark:text-zinc-500">{agent.arch}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-500 dark:text-zinc-400">
                      {agent.ip ? (
                        <div className="flex flex-col gap-0.5">
                          {agent.ip.split(',').map((part, idx) => (
                            <span key={idx} className="whitespace-nowrap">
                              {part.trim()}
                            </span>
                          ))}
                        </div>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500 dark:text-zinc-400" title={formatDate(agent.lastSeen)}>
                      {formatRelative(agent.lastSeen)}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-zinc-500 dark:text-zinc-400">
                      <div>{agent.eventsIngested.toLocaleString()} <span className="text-[10px] text-zinc-400">events</span></div>
                      <div className="text-[10px] text-zinc-400">{agent.logsIngested.toLocaleString()} logs</div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      {agent.status !== 'REVOKED' && (
                        <button
                          type="button"
                          title="Remove agent"
                          onClick={event => {
                            event.stopPropagation();
                            setRevokeError('');
                            setPurgeAgentData(false);
                            setRevokeTarget(agent);
                          }}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-rose-50 hover:text-rose-600 cursor-pointer dark:hover:bg-rose-950/40 dark:hover:text-rose-400"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredAgents.length === 0 && search && (
              <div className="px-5 py-10 text-center text-xs text-zinc-500 dark:text-zinc-400">
                No agents match “{search}”.
              </div>
            )}
          </div>
        )}
      </section>

      {/* Agent detail drawer */}
      {selectedAgent && (
        <div className="fixed inset-0 z-50">
          <div
            className="absolute inset-0 bg-zinc-950/45 backdrop-blur-[2px] dark:bg-black/70"
            onClick={() => setSelectedAgent(null)}
          />
          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Agent details"
            className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-zinc-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-[#0b0b0d]"
          >
            <header className="flex items-start justify-between gap-3 border-b border-zinc-100 px-5 py-4 dark:border-zinc-800/80">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="truncate text-sm font-semibold text-zinc-900 dark:text-zinc-100">{selectedAgent.agent.name}</h2>
                  <StatusBadge status={selectedAgent.agent.status} />
                </div>
                <p className="mt-1 truncate font-mono text-[11px] text-zinc-400 dark:text-zinc-500">{selectedAgent.agent.id}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedAgent(null)}
                className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-900 dark:hover:bg-zinc-900 dark:hover:text-zinc-100"
                aria-label="Close details"
              >
                <X className="h-4 w-4" />
              </button>
            </header>

            <div className="flex-1 overflow-y-auto px-5 py-4 custom-scrollbar">
              {detailLoading ? (
                <div className="flex items-center justify-center gap-2 py-16 text-xs text-zinc-500">
                  <RefreshCw className="h-4 w-4 animate-spin" /> Loading agent telemetry…
                </div>
              ) : (
                <div className="space-y-5">
                  {detailError && (
                    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
                      {detailError}
                    </div>
                  )}

                  {/* Explain an empty panel instead of leaving blank metrics */}
                  {selectedAgent.agent.status === 'REVOKED' && (
                    <div className="rounded-xl border border-rose-200 bg-rose-50 px-3 py-3 text-xs text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <div className="min-w-0">
                          <div className="font-semibold">This agent entry was revoked.</div>
                          <p className="mt-1 leading-relaxed">
                            The server rejects every request from a revoked agent, so no metrics, events, or logs can arrive.
                            The endpoint keeps running, so restoring the entry is enough — or re-enroll it with a new
                            one-time token.
                          </p>
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              onClick={restoreAgentEntry}
                              disabled={restoring}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 px-2.5 py-1 text-[11px] font-semibold text-white transition hover:bg-rose-700 cursor-pointer disabled:opacity-50"
                            >
                              {restoring ? <RefreshCw className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                              {restoring ? 'Restoring…' : 'Restore this agent'}
                            </button>
                            <button
                              type="button"
                              onClick={() => { setSelectedAgent(null); openEnroll(); }}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-300 bg-white px-2.5 py-1 text-[11px] font-semibold text-rose-700 transition hover:bg-rose-100 cursor-pointer dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200 dark:hover:bg-rose-900/50"
                            >
                              <Plus className="h-3 w-3" />
                              Generate a new enrollment token
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {selectedAgent.agent.status === 'OFFLINE' && (
                    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-3 text-xs text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <div>
                          <div className="font-semibold">This agent is not reporting.</div>
                          <p className="mt-1 leading-relaxed">
                            The last check-in was {formatRelative(selectedAgent.agent.lastSeen)}. Metrics and telemetry
                            resume automatically as soon as the agent connects again.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {selectedAgent.agent.status === 'PENDING' && !hasLiveMetrics && (
                    <div className="rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-3 text-xs text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-400">
                      <div className="flex items-start gap-2">
                        <RefreshCw className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin" />
                        <div>
                          <div className="font-semibold text-zinc-700 dark:text-zinc-200">Waiting for the first heartbeat.</div>
                          <p className="mt-1 leading-relaxed">
                            The agent is enrolled but has not reported yet. Start the service on the host — metrics,
                            events, and logs appear here within one heartbeat.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  <section className="rounded-xl border border-zinc-200 bg-zinc-50/70 p-3.5 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                          Monitored website
                        </div>
                        <div className="mt-1 truncate text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                          {selectedAgent.agent.applicationName || 'Not selected yet'}
                        </div>
                        <div className="mt-0.5 truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                          {selectedAgent.agent.applicationDomain || 'Pick the website this agent should watch'}
                        </div>
                      </div>
                      <span className="shrink-0 rounded-full border border-zinc-200 bg-white px-2 py-0.5 text-[10px] font-medium text-zinc-500 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-400">
                        One agent · one website
                      </span>
                    </div>

                    {/* Websites the agent discovered on the host. The operator
                        decides which one this agent is responsible for. */}
                    <div className="mt-3 border-t border-zinc-200 pt-3 dark:border-zinc-800/70">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                          Websites found on this host
                        </span>
                        {detectedSites.length > 0 && (
                          <span className="font-mono text-[10px] text-zinc-400 dark:text-zinc-500">
                            {detectedSites.length} detected
                          </span>
                        )}
                      </div>

                      {detectedSites.length === 0 ? (
                        <p className="mt-2 text-[11px] leading-relaxed text-zinc-400 dark:text-zinc-500">
                          The agent has not reported any website yet. It scans the host on every heartbeat and
                          lists them here.
                        </p>
                      ) : (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {detectedSites.map(site => {
                            const isCurrent = site.domain === selectedAgent.agent.applicationDomain;
                            const known = applications.find(app => app.domain === site.domain);
                            return (
                              <button
                                key={`${site.domain}:${site.port}`}
                                type="button"
                                disabled={savingWebsite || isCurrent}
                                onClick={() => assignWebsite(selectedAgent.agent.id, known?.id, site)}
                                className={`inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[11px] font-medium transition cursor-pointer disabled:cursor-default ${
                                  isCurrent
                                    ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300'
                                    : 'border-zinc-200 bg-white text-zinc-600 hover:border-zinc-300 hover:text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100'
                                }`}
                                title={isCurrent ? 'Currently monitored' : `Monitor ${site.domain} with this agent`}
                              >
                                <Globe className="h-3 w-3" />
                                <span className="font-mono">{site.domain}</span>
                                <span className="text-[10px] text-zinc-400 dark:text-zinc-500">
                                  {site.protocol}:{site.port}
                                </span>
                                {isCurrent && <Check className="h-3 w-3" />}
                              </button>
                            );
                          })}
                        </div>
                      )}

                      {websiteError && (
                        <p className="mt-2 text-[11px] text-rose-600 dark:text-rose-400">{websiteError}</p>
                      )}
                    </div>
                  </section>

                  <section>
                    <h3 className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Identity</h3>
                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-3 text-xs">
                      <DetailItem label="Hostname" value={selectedAgent.agent.hostname} mono />
                      <DetailItem label="Address" value={selectedAgent.agent.ip || '—'} mono />
                      <DetailItem label="Platform" value={`${osLabel(selectedAgent.agent.os)} ${selectedAgent.agent.arch}`} />
                      <DetailItem label="Agent version" value={selectedAgent.agent.version || '—'} />
                      <DetailItem label="Enrolled" value={formatDate(selectedAgent.agent.createdAt)} />
                      <DetailItem label="Last heartbeat" value={formatDate(selectedAgent.agent.lastSeen)} />
                    </div>
                  </section>

                  <section>
                    <h3 className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Live host metrics</h3>
                    <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3">
                      <MetricBar
                        label="CPU"
                        value={selectedAgent.agent.metrics.cpuPercent}
                        subLabel={selectedAgent.agent.metrics.cpuCores ? `${selectedAgent.agent.metrics.cpuCores} Core${selectedAgent.agent.metrics.cpuCores > 1 ? 's' : ''}` : undefined}
                        icon={<Cpu className="h-3 w-3" />}
                      />
                      <MetricBar
                        label="Memory"
                        value={selectedAgent.agent.metrics.memoryPercent}
                        subLabel={
                          selectedAgent.agent.metrics.memoryTotalMb
                            ? `${((selectedAgent.agent.metrics.memoryUsedMb || 0) / 1024).toFixed(1)} GB / ${(selectedAgent.agent.metrics.memoryTotalMb / 1024).toFixed(1)} GB`
                            : undefined
                        }
                        icon={<MemoryStick className="h-3 w-3" />}
                      />
                      <MetricBar
                        label="Disk"
                        value={selectedAgent.agent.metrics.diskPercent}
                        subLabel={
                          selectedAgent.agent.metrics.diskTotalGb
                            ? `${(selectedAgent.agent.metrics.diskUsedGb || 0).toFixed(1)} GB / ${(selectedAgent.agent.metrics.diskTotalGb).toFixed(1)} GB`
                            : undefined
                        }
                        icon={<HardDrive className="h-3 w-3" />}
                      />
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 text-xs sm:grid-cols-4">
                      <DetailItem label="Load (1m)" value={typeof selectedAgent.agent.metrics.load1 === 'number' ? selectedAgent.agent.metrics.load1.toFixed(2) : '—'} />
                      <DetailItem label="Uptime" value={formatUptime(selectedAgent.agent.metrics.uptimeSeconds)} />
                      <DetailItem label="Processes" value={typeof selectedAgent.agent.metrics.processCount === 'number' ? selectedAgent.agent.metrics.processCount.toLocaleString() : '—'} />
                      <DetailItem label="Kernel" value={selectedAgent.agent.metrics.kernel || '—'} mono />
                    </div>
                  </section>

                  {selectedAgent.agent.status !== 'REVOKED' && (
                    <button
                      type="button"
                      onClick={() => {
                        setRevokeError('');
                        setPurgeAgentData(false);
                        setRevokeTarget(selectedAgent.agent);
                      }}
                      className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-rose-200 px-2.5 text-xs font-medium text-rose-600 transition hover:bg-rose-50 dark:border-rose-900/60 dark:text-rose-400 dark:hover:bg-rose-950/30"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Remove this agent
                    </button>
                  )}
                </div>
              )}
            </div>
          </aside>
        </div>
      )}

      {/* Congratulations & Choose Website Modal when agent connects */}
      {newlyEnrolledAgent && (() => {
        const rawSites = newlyEnrolledAgent.hostInfo?.detectedSites;
        const sites: DetectedSiteView[] = [];
        const seen = new Set<string>();
        if (Array.isArray(rawSites)) {
          for (const entry of rawSites) {
            if (!entry || typeof entry !== 'object') continue;
            const item = entry as Record<string, unknown>;
            const domain = String(item.domain || '').trim().toLowerCase();
            if (!domain) continue;
            const port = Number(item.port) || 0;
            const key = `${domain}:${port}`;
            if (seen.has(key)) continue;
            seen.add(key);
            sites.push({
              domain,
              port,
              protocol: String(item.protocol || (port === 443 ? 'HTTPS' : 'HTTP')).toUpperCase(),
              serverType: String(item.serverType || '')
            });
          }
        }
        const hasAssigned = !!newlyEnrolledAgent.applicationDomain;

        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
            <div className="fixed inset-0 bg-zinc-950/60 backdrop-blur-xs transition-opacity dark:bg-black/80" onClick={() => setNewlyEnrolledAgent(null)} />
            <div
              role="dialog"
              aria-modal="true"
              className="relative w-full max-w-lg my-auto overflow-hidden rounded-2xl border border-zinc-200/80 bg-white p-5 sm:p-6 shadow-xl dark:border-zinc-800 dark:bg-[#0c0c0e]"
            >
              {/* Header / Icon */}
              <div className="flex flex-col sm:flex-row items-center sm:items-start gap-4 text-center sm:text-left">
                <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-500 ring-1 ring-emerald-500/20">
                  <ShieldCheck className="h-6 w-6 text-emerald-500" />
                  <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                  </span>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-center sm:justify-start gap-2">
                    <h3 className="text-base font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
                      Endpoint Connected Successfully!
                    </h3>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed break-all">
                    Host <strong className="font-semibold text-zinc-800 dark:text-zinc-200">{newlyEnrolledAgent.hostname || newlyEnrolledAgent.name}</strong> ({newlyEnrolledAgent.ip || 'Local host'}) is now active.
                  </p>
                </div>
              </div>

              {/* Website Selection Card */}
              <div className="mt-5 rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3.5 text-left dark:border-zinc-800/80 dark:bg-zinc-900/40">
                <div className="flex items-center justify-between mb-2.5 gap-2">
                  <span className="text-xs font-semibold text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
                    <Globe className="h-3.5 w-3.5 text-emerald-500" />
                    Select Target Website to Monitor
                  </span>
                  {hasAssigned && (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-md bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                      <Check className="h-3 w-3" /> Selected
                    </span>
                  )}
                </div>

                {sites.length === 0 ? (
                  <p className="text-[11px] text-zinc-500 dark:text-zinc-400 italic">
                    Scanning web servers on host... You can also bind a website later in endpoint details.
                  </p>
                ) : (
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-0.5 custom-scrollbar">
                    {sites.map(site => {
                      const isSelected = newlyEnrolledAgent.applicationDomain === site.domain;
                      const known = applications.find(app => app.domain === site.domain);
                      return (
                        <button
                          key={`${site.domain}:${site.port}`}
                          type="button"
                          disabled={savingWebsite || isSelected}
                          onClick={() => assignWebsite(newlyEnrolledAgent.id, known?.id, site)}
                          className={`w-full flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-xs font-medium transition cursor-pointer disabled:cursor-default ${
                            isSelected
                              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                              : 'border-zinc-200/80 bg-white hover:border-zinc-300 text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-700'
                          }`}
                        >
                          <div className="flex items-center gap-2 truncate min-w-0">
                            <Globe className="h-3.5 w-3.5 shrink-0 text-zinc-400" />
                            <span className="font-mono font-semibold truncate text-zinc-800 dark:text-zinc-200">{site.domain}</span>
                            <span className="text-[10px] text-zinc-400 shrink-0 font-mono">
                              {site.serverType ? `${site.serverType} • ${site.port}` : `${site.protocol}:${site.port}`}
                            </span>
                          </div>
                          {isSelected ? (
                            <span className="shrink-0 flex items-center gap-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
                              <Check className="h-3.5 w-3.5" /> Active
                            </span>
                          ) : (
                            <span className="shrink-0 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 hover:underline">
                              Select Website
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                )}
                {!hasAssigned && (
                  <p className="mt-2.5 text-[11px] text-amber-600 dark:text-amber-400/90 leading-tight">
                    * An endpoint requires a target website so WAF, firewall, and traffic logs operate accurately.
                  </p>
                )}
              </div>

              {/* Action buttons */}
              <div className="mt-5 flex flex-col-reverse sm:flex-row gap-2">
                <button
                  type="button"
                  onClick={() => setNewlyEnrolledAgent(null)}
                  className="w-full sm:w-auto px-4 h-9 rounded-xl border border-zinc-200/80 dark:border-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/80 transition cursor-pointer"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const target = newlyEnrolledAgent;
                    setNewlyEnrolledAgent(null);
                    openAgentDetail(target);
                  }}
                  className="flex-1 h-9 rounded-xl bg-zinc-900 hover:bg-zinc-800 text-white text-xs font-semibold dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 transition cursor-pointer shadow-xs"
                >
                  {hasAssigned ? 'Open Details & Metrics' : 'Configure in Details'}
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Enrollment modal */}
      {showEnroll && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-zinc-950/50 backdrop-blur-[2px] dark:bg-black/75" onClick={closeEnroll} />
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Deploy endpoint agent"
            className="relative w-full max-w-2xl overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-[#0b0b0d]"
          >
            <header className="flex items-start justify-between gap-3 border-b border-zinc-100 px-5 py-4 dark:border-zinc-800/80">
              <div>
                <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  {enrollment ? 'Install the agent' : 'Deploy a new endpoint agent'}
                </h2>
                <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                  {enrollment
                    ? 'Run the command on the target host. The token is single-use and expires automatically.'
                    : 'Create a short-lived, single-use enrollment token for the host that runs the website.'}
                </p>
              </div>
              <button
                type="button"
                onClick={closeEnroll}
                className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-zinc-400 hover:bg-zinc-100 hover:text-zinc-900 dark:hover:bg-zinc-900 dark:hover:text-zinc-100"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </header>

            <div className="max-h-[70vh] overflow-y-auto px-5 py-4 custom-scrollbar">
              {enrollError && (
                <div className="mb-4 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300">
                  {enrollError}
                </div>
              )}

              {!enrollment ? (
                <div className="space-y-4">
                  <div className="rounded-xl border border-zinc-200 bg-white p-3 dark:border-zinc-800 dark:bg-zinc-950/40">
                    <div className="flex items-start gap-2.5">
                      <Globe className="mt-0.5 h-4 w-4 shrink-0 text-zinc-400 dark:text-zinc-500" />
                      <div>
                        <div className="text-xs font-semibold text-zinc-800 dark:text-zinc-100">
                          The agent finds the websites itself
                        </div>
                        <p className="mt-1 text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                          On the host, the agent scans every nginx and Apache virtual host plus the open web
                          ports, then registers each website in the console. Pick the one this agent should
                          monitor afterwards — one agent, one website.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="block">
                      <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Agent label</span>
                      <input
                        value={enrollLabel}
                        onChange={event => setEnrollLabel(event.target.value)}
                        placeholder="web-prod-01"
                        className="mt-1.5 h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 text-xs text-zinc-800 outline-none focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:focus:border-zinc-500"
                      />
                    </label>
                    <label className="block">
                      <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Token lifetime</span>
                      <div className="relative mt-1.5">
                        <select
                          value={enrollMinutes}
                          onChange={event => setEnrollMinutes(Number(event.target.value))}
                          className="h-9 w-full appearance-none rounded-lg border border-zinc-200 bg-white pl-3 pr-8 text-xs text-zinc-700 outline-none focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:focus:border-zinc-500"
                        >
                          <option value={15}>15 minutes</option>
                          <option value={60}>1 hour</option>
                          <option value={240}>4 hours</option>
                          <option value={1440}>24 hours</option>
                        </select>
                        <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
                      </div>
                    </label>
                  </div>

                  <div className="rounded-xl border border-zinc-100 bg-zinc-50/70 p-3 text-xs leading-relaxed text-zinc-500 dark:border-zinc-800/60 dark:bg-zinc-900/40 dark:text-zinc-400">
                    <div className="flex items-start gap-2">
                      <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                      <div>
                        <span className="font-medium text-zinc-700 dark:text-zinc-200">Secure by design.</span>{' '}
                        The dashboard never stores the agent's private key. The agent generates an Ed25519 keypair locally,
                        registers only the public key, and signs every heartbeat and telemetry request. Tokens are hashed at rest,
                        single-use, and expire.
                      </div>
                    </div>
                  </div>

                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={closeEnroll}
                      className="inline-flex h-9 items-center rounded-xl border border-zinc-200 px-3 text-xs font-medium text-zinc-600 hover:border-zinc-300 cursor-pointer dark:border-zinc-700 dark:text-zinc-300"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={createEnrollment}
                      disabled={enrollLoading}
                      className="inline-flex h-9 items-center gap-1.5 rounded-xl bg-zinc-900 px-3.5 text-xs font-semibold text-white disabled:opacity-50 cursor-pointer dark:bg-zinc-100 dark:text-zinc-900"
                    >
                      {enrollLoading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <KeyRound className="h-3.5 w-3.5" />}
                      Generate enrollment token
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-3 dark:border-emerald-900/60 dark:bg-emerald-950/30">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-300">
                        <Check className="h-4 w-4" /> Token created
                      </div>
                      {tokenTimeRemaining && (
                        <span className="inline-flex items-center gap-1 rounded-md bg-emerald-100 px-2 py-0.5 font-mono text-[11px] font-bold text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-300">
                          <Clock className="h-3 w-3" /> {tokenTimeRemaining}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-[11px] text-emerald-700/80 dark:text-emerald-300/80">
                      Active until {formatDate(enrollment.expiresAt)}. Token tetap aktif jika modal ditutup hingga waktu habis.
                    </p>
                    <p className="mt-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
                      {enrollment.applicationName
                        ? `Bound to ${enrollment.applicationName} (${enrollment.applicationDomain}) in ${currentOrg?.name || 'this organization'}.`
                        : currentOrg
                          ? `Open enrollment token for ${currentOrg.name}. Agent will automatically register detected websites.`
                          : 'Open enrollment: organisasi akan otomatis terdaftar dan dibuat saat agent terpasang di server.'}
                    </p>
                    <div className="mt-2 flex items-center gap-2 rounded-lg border border-emerald-200/70 bg-white px-2.5 py-2 dark:border-emerald-900/60 dark:bg-zinc-950">
                      <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-zinc-700 dark:text-zinc-200">{enrollment.token}</code>
                      <button
                        type="button"
                        onClick={() => copyText(enrollment.token, 'token')}
                        className="shrink-0 rounded p-1 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"
                        title="Copy token"
                      >
                        {copied === 'token' ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200 bg-zinc-50/70 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <label className="block text-[11px] font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400 mb-1">
                      Agent server URL
                    </label>
                    <input
                      type="url"
                      value={serverBaseUrl}
                      onChange={e => setServerBaseUrl(e.target.value)}
                      placeholder="https://security.example.com"
                      className="h-8 w-full rounded-lg border border-zinc-200 bg-white px-2.5 font-mono text-[11px] text-zinc-800 placeholder-zinc-400 focus:outline-none focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-200 dark:placeholder-zinc-500"
                    />
                    <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-400 dark:text-zinc-500">
                      Use the address the target host can reach. <code className="font-mono">localhost</code> only works for an agent on this machine. Plain HTTP to a remote host needs the lab-only option below.
                    </p>
                    <label className="mt-2 inline-flex items-start gap-2 text-[11px] text-zinc-500 dark:text-zinc-400">
                      <input
                        type="checkbox"
                        checked={allowInsecure}
                        onChange={e => setAllowInsecure(e.target.checked)}
                        className="mt-0.5 h-3.5 w-3.5 rounded border-zinc-300 accent-zinc-900 dark:border-zinc-600 dark:accent-zinc-100"
                      />
                      <span>
                        Append <code className="font-mono">--insecure</code> / <code className="font-mono">-Insecure</code> (allows plain HTTP or skips TLS verification; lab only)
                      </span>
                    </label>
                  </div>

                  <div className="flex items-center gap-1 rounded-xl bg-zinc-100 p-1 dark:bg-zinc-900">
                    {(['linux', 'windows'] as PlatformTab[]).map(tab => (
                      <button
                        key={tab}
                        type="button"
                        onClick={() => setPlatform(tab)}
                        className={`flex-1 rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition ${
                          platform === tab
                            ? 'bg-white text-zinc-900 shadow-sm dark:bg-zinc-800 dark:text-zinc-100'
                            : 'text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200'
                        }`}
                      >
                        {tab === 'linux' ? 'Linux (systemd)' : 'Windows (PowerShell)'}
                      </button>
                    ))}
                  </div>

                  <div>
                    <div className="mb-1.5 flex items-center justify-between">
                      <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                        {platform === 'linux' ? 'Run as root' : 'Run in elevated PowerShell'}
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText(platform === 'linux' ? linuxCommand : windowsCommand, platform)}
                        className="inline-flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-200"
                      >
                        {copied === platform ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                        {copied === platform ? 'Copied' : 'Copy command'}
                      </button>
                    </div>
                    <pre className="max-h-44 overflow-auto rounded-xl border border-zinc-200 bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-100 dark:border-zinc-800">
{platform === 'linux' ? linuxCommand : windowsCommand}
                    </pre>
                    <p className="mt-2 text-[11px] leading-relaxed text-zinc-400 dark:text-zinc-500">
                      {platform === 'linux'
                        ? 'The installer downloads the signed endpoint agent from the server URL above, enrolls with the one-time token, and creates a hardened systemd service.'
                        : 'The installer downloads the agent, enrolls it, and registers a SYSTEM scheduled task that restarts on failure.'}{' '}
                      The agent will appear here within ~30 seconds.
                    </p>
                  </div>

                  <div className="flex items-center justify-between gap-2 border-t border-zinc-100 pt-3 dark:border-zinc-800/60">
                    <div className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 dark:text-zinc-500">
                      <ExternalLink className="h-3 w-3" />
                      Need a private CA? Add <code className="font-mono">--ca /path/ca.pem</code> on Linux
                      or <code className="font-mono">-CAFile C:\path\ca.pem</code> on Windows.
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        closeEnroll();
                        fetchAgents(true);
                      }}
                      className="inline-flex h-9 items-center rounded-xl bg-zinc-900 px-3.5 text-xs font-semibold text-white dark:bg-zinc-100 dark:text-zinc-900"
                    >
                      Done
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Revoke confirmation */}
      {revokeTarget && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-zinc-950/50 backdrop-blur-[2px] dark:bg-black/75" onClick={() => setRevokeTarget(null)} />
          <div role="dialog" aria-modal="true" className="relative w-full max-w-md overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-[#0b0b0d]">
            <div className="px-5 py-4">
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-rose-50 text-rose-600 dark:bg-rose-950/40 dark:text-rose-400">
                  <AlertTriangle className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Remove “{revokeTarget.name}”?</h3>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">
                    The agent entry, its WAF and firewall deployment state, and its enrollment reference are deleted.
                    The endpoint is rejected on its next check-in, and re-enrolling it requires a new token.
                  </p>
                </div>
              </div>

              <label className="mt-3 flex cursor-pointer items-start gap-2 rounded-lg border border-zinc-200 bg-zinc-50 px-2.5 py-2 dark:border-zinc-800 dark:bg-zinc-900/50">
                <input
                  type="checkbox"
                  checked={purgeAgentData}
                  onChange={event => setPurgeAgentData(event.target.checked)}
                  className="mt-0.5 h-3.5 w-3.5 rounded border-zinc-300 text-rose-600 focus:ring-rose-500 dark:border-zinc-600 dark:bg-zinc-800"
                />
                <span className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                  <span className="font-semibold text-zinc-700 dark:text-zinc-200">Also delete the telemetry it collected</span>
                  <br />
                  Off by default: the events and logs it already sent stay in the tenant timeline, only the link to this agent is removed.
                </span>
              </label>
              {revokeError && (
                <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[11px] text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300">
                  {revokeError}
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 border-t border-zinc-100 px-5 py-3 dark:border-zinc-800/60">
              <button
                type="button"
                onClick={() => setRevokeTarget(null)}
                className="inline-flex h-8 items-center rounded-lg border border-zinc-200 px-3 text-xs font-medium text-zinc-600 hover:border-zinc-300 cursor-pointer dark:border-zinc-700 dark:text-zinc-300"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmRevoke}
                disabled={revoking}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-rose-600 px-3 text-xs font-semibold text-white hover:bg-rose-500 cursor-pointer disabled:opacity-50"
              >
                {revoking && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                Remove agent
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

function DetailItem({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  const isMulti = value && value.includes(',');
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">{label}</div>
      {isMulti ? (
        <div className={`mt-0.5 flex flex-col gap-0.5 text-zinc-700 dark:text-zinc-200 ${mono ? 'font-mono text-[11px]' : 'text-xs'}`}>
          {value.split(',').map((part, idx) => (
            <span key={idx} className="truncate" title={part.trim()}>
              {part.trim()}
            </span>
          ))}
        </div>
      ) : (
        <div className={`mt-0.5 truncate text-zinc-700 dark:text-zinc-200 ${mono ? 'font-mono text-[11px]' : 'text-xs'}`} title={value}>
          {value || '—'}
        </div>
      )}
    </div>
  );
}
