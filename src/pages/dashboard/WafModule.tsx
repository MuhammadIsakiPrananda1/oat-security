import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Shield, 
  Plus, 
  Search, 
  RefreshCw, 
  SlidersHorizontal, 
  Server, 
  X, 
  Trash2,
  Terminal,
  Radio,
  AlertTriangle,
  ArrowUpRight,
  Globe,
  ChevronDown,
  Check
} from 'lucide-react';
import { securityApi, telemetryStreamManager, normalizeRealtimeSecurityEvent } from '../../services/api';
import { WafRule, ProtectedApplication, WafDeploymentView, AgentDetectedSite, SecurityEvent } from '../../types';
import { CountryFlag } from '../../components/common/CountryFlag';
import { Activity } from 'lucide-react';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldVirus } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader, ModulePageBadge } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime, formatTime } from '../../utils/dateTime';

interface WafModuleProps {
  onNavigate?: (view: 'agents') => void;
}

export const WafModule: React.FC<WafModuleProps> = ({ onNavigate }) => {
  const { isBackendOffline } = useAuth();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>(null);
  const [showTabDropdown, setShowTabDropdown] = useState(false);
  const [activeTab, setActiveTab] = useState<'rules' | 'apps' | 'policies'>('rules');
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showLogModal, setShowLogModal] = useState(false);
  const [drawerTab, setDrawerTab] = useState<'logs' | 'diagnostics'>('logs');
  const [firewallAuditLogs, setFirewallAuditLogs] = useState<any[]>([]);
  const wafSyncTimer = useRef<number | null>(null);

  // Protected Domain Add State
  const [showAddAppModal, setShowAddAppModal] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newAppDomain, setNewAppDomain] = useState('');
  const [newAppOriginIp, setNewAppOriginIp] = useState('');
  const [newAppPort, setNewAppPort] = useState(443);
  const [newAppProtocol, setNewAppProtocol] = useState<'HTTPS' | 'HTTP'>('HTTPS');
  const [addingApp, setAddingApp] = useState(false);

  // Fetch error & deployment logs specifically for Firewall, WAF, nftables, and agent installation
  const fetchFirewallDeploymentLogs = useCallback(async () => {
    try {
      const res = await securityApi.getLogs({ limit: 60, page: 1 });
      const list = res.logs || [];
      // Filter for firewall, waf, nftables, apache, policy deployment and errors
      const filtered = list.filter((l: any) => {
        const src = String(l.source || '').toLowerCase();
        const msg = String(l.message || '').toLowerCase();
        const type = String(l.eventType || '').toLowerCase();
        return (
          src === 'firewall' || src === 'waf' ||
          msg.includes('firewall') || msg.includes('waf') || msg.includes('nftables') ||
          msg.includes('apache') || msg.includes('policy') || msg.includes('deploy') ||
          msg.includes('fail') || msg.includes('error') || msg.includes('revision') ||
          type.includes('firewall') || type.includes('waf')
        );
      });
      setFirewallAuditLogs(filtered);
    } catch (err) {
      console.warn('[WAF] Failed to fetch firewall logs:', err);
    }
  }, []);

  // Sync firewall deployment logs while drawer is open
  useEffect(() => {
    if (!showLogModal) return;
    fetchFirewallDeploymentLogs();

    const unsub = telemetryStreamManager.subscribe((msg: any) => {
      const type = String(msg.type || '');
      const data = msg.data || msg;
      if (
        type === 'log.created' ||
        type === 'agent.updated' ||
        type === 'waf.status' ||
        type === 'firewall.status'
      ) {
        fetchFirewallDeploymentLogs();
      }
    });

    const timer = window.setInterval(fetchFirewallDeploymentLogs, 2500);
    return () => {
      unsub();
      window.clearInterval(timer);
    };
  }, [showLogModal, fetchFirewallDeploymentLogs]);
  const [showSitePicker, setShowSitePicker] = useState(false);
  const [switchingSite, setSwitchingSite] = useState(false);
  const [policyFeedback, setPolicyFeedback] = useState<{ tone: 'ok' | 'warn' | 'err'; text: string } | null>(null);
  const [savingRule, setSavingRule] = useState(false);
  const [isSyncingServer, setIsSyncingServer] = useState(false);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const [newRule, setNewRule] = useState({
    name: '',
    category: 'SQL Injection',
    severity: 'High',
    action: 'Block',
    pattern: ''
  });

  // Server WAF Policy State
  const [engineEnabled, setEngineEnabled] = useState(true);
  const [mode, setMode] = useState<'block' | 'monitor'>('block');
  const [rateLimitRequests, setRateLimitRequests] = useState(100);
  const [rateLimitWindow, setRateLimitWindow] = useState(10);
  const [ipAllowlist, setIpAllowlist] = useState('');
  const [ipBlocklist, setIpBlocklist] = useState('');
  const [geoBlockCountries, setGeoBlockCountries] = useState('');
  const [botProtectionEnabled, setBotProtectionEnabled] = useState(true);
  const [lastAppliedAt, setLastAppliedAt] = useState<string | null>(null);
  const [serverLog, setServerLog] = useState<string | null>(null);

  const fetchWaf = async (showLoader = true) => {
    if (showLoader) setLoading(true);
    try {
      const [wafData, policyRes] = await Promise.all([
        securityApi.getWafData(),
        securityApi.getWafPolicy().catch(() => null)
      ]);
      setData(wafData);

      if (policyRes?.policy) {
        const p = policyRes.policy;
        setEngineEnabled(Boolean(p.engine_enabled));
        setMode(p.mode === 'monitor' ? 'monitor' : 'block');
        setRateLimitRequests(p.rate_limit_requests ?? 100);
        setRateLimitWindow(p.rate_limit_window_s ?? 10);
        setIpAllowlist(p.ip_allowlist || '');
        setIpBlocklist(p.ip_blocklist || '');
        setGeoBlockCountries(p.geo_block_countries || '');
        setBotProtectionEnabled(Boolean(p.bot_protection_enabled));
        setLastAppliedAt(p.last_applied_at);
        setServerLog(p.server_log);
      }
    } catch (e) {
      console.error(e);
    } finally {
      if (showLoader) setLoading(false);
    }
  };

  useEffect(() => {
    void fetchWaf(true);
    // Real-time listener for instant agent status & WAF rule sync without manual refresh
    const unsub = telemetryStreamManager.subscribe((msg: any) => {
      const type = String(msg?.type || '');
      const isWafOrAgentEvent =
        type === 'waf.agent_status' ||
        type === 'waf.deployment_queued' ||
        type === 'agent.status' ||
        type === 'agent.heartbeat' ||
        type === 'agent.updated' ||
        type === 'agent.enrolled' ||
        type === 'endpoint.status' ||
        (type === 'rule.updated' && String(msg?.data?.ruleType || '') === 'WAF');

      if (isWafOrAgentEvent) {
        if (wafSyncTimer.current) window.clearTimeout(wafSyncTimer.current);
        wafSyncTimer.current = window.setTimeout(() => {
          void fetchWaf(false);
        }, 300);
      }
    });

    // Fallback polling every 3 seconds to immediately catch changes if queue is pending
    const timer = window.setInterval(() => {
      void fetchWaf(false);
    }, 3_000);

    return () => {
      unsub();
      window.clearInterval(timer);
      if (wafSyncTimer.current) window.clearTimeout(wafSyncTimer.current);
    };
  }, [isBackendOffline]);

  // Close log drawer on ESC
  useEffect(() => {
    if (!showLogModal) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowLogModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showLogModal]);

  const deploymentNotice = (prefix: string, deployment?: WafDeploymentView) => {
    if (!deployment || deployment.totalAgents === 0) {
      return {
        tone: 'warn' as const,
        text: `${prefix} No endpoint agent is connected yet. Open Endpoint Agents and install the OAT agent on the Debian website host.`
      };
    }
    const unsupported = deployment.unsupportedAgents || 0;
    const state = deployment.failedAgents > 0
      ? `${deployment.failedAgents} agent(s) reported an error`
      : deployment.appliedAgents === deployment.totalAgents
        ? `${deployment.appliedAgents}/${deployment.totalAgents} agent(s) applied revision ${deployment.revision}`
        : unsupported > 0
          ? `${deployment.appliedAgents}/${deployment.totalAgents} agent(s) applied · ${unsupported} unsupported`
          : `${deployment.appliedAgents}/${deployment.totalAgents} agent(s) applied · ${deployment.pendingAgents} pending`;
    return {
      tone: deployment.failedAgents > 0 || unsupported > 0 ? 'warn' as const : 'ok' as const,
      text: `${prefix} Revision ${deployment.revision} queued for ${deployment.totalAgents} agent(s). ${state}.`
    };
  };

  // Quick toggle Engine (ON / OFF) -> queues a signed revision for the agents
  const handleToggleEngine = async () => {
    const next = !engineEnabled;
    setEngineEnabled(next);
    setIsSyncingServer(true);
    try {
      const res = await securityApi.saveWafPolicy({
        engine_enabled: next ? 1 : 0
      });
      await fetchWaf(false);
      setPolicyFeedback(deploymentNotice(next ? 'WAF engine enabled.' : 'WAF engine disabled (passthrough).', res.deployment));
    } catch (err: any) {
      setPolicyFeedback({ tone: 'err', text: `Failed to update engine state: ${err.message}` });
    } finally {
      setIsSyncingServer(false);
    }
  };

  // Quick toggle Mode (BLOCK / MONITOR) -> queues a signed revision
  const handleToggleMode = async () => {
    const nextMode = mode === 'block' ? 'monitor' : 'block';
    setMode(nextMode);
    setIsSyncingServer(true);
    try {
      const res = await securityApi.saveWafPolicy({ mode: nextMode });
      await fetchWaf(false);
      setPolicyFeedback(deploymentNotice(
        nextMode === 'block'
          ? 'Mode set to BLOCK: Apache returns 403 for matching requests.'
          : 'Mode set to MONITOR: matching traffic is observed but not blocked.',
        res.deployment
      ));
    } catch (err: any) {
      setPolicyFeedback({ tone: 'err', text: `Failed to change mode: ${err.message}` });
    } finally {
      setIsSyncingServer(false);
    }
  };

  const [deployState, setDeployState] = useState<'idle' | 'deploying' | 'success' | 'error'>('idle');
  const [deployErrorMsg, setDeployErrorMsg] = useState<string | null>(null);

  // Force a new revision so every agent re-applies the current policy (1x deploy with polling until success/timeout)
  const handleForceSync = async () => {
    if (deployState === 'deploying') return;
    setDeployState('deploying');
    setDeployErrorMsg(null);
    setIsSyncingServer(true);

    try {
      const res = await securityApi.syncWafToServer();
      const targetRevision = res.deployment?.revision;

      // Poll up to 30 seconds for agent to report APPLIED or FAILED
      const startTime = Date.now();
      let finished = false;

      while (Date.now() - startTime < 30000) {
        await new Promise(r => setTimeout(r, 2000));
        const updated = await securityApi.getWafData();
        setData(updated);

        const currentDeployment = updated?.deployment;
        if (!currentDeployment) break;

        const agents = currentDeployment.agents || [];
        const hasFailed = agents.some((a: any) => a.status === 'FAILED');
        const isApplied = currentDeployment.appliedAgents > 0 && currentDeployment.appliedAgents === currentDeployment.totalAgents;

        if (isApplied) {
          setDeployState('success');
          finished = true;
          // Auto reset to idle after 4 seconds
          setTimeout(() => setDeployState('idle'), 4000);
          break;
        }

        if (hasFailed) {
          setDeployState('error');
          setDeployErrorMsg('Agent reported deployment error');
          finished = true;
          break;
        }
      }

      if (!finished) {
        setDeployState('error');
        setDeployErrorMsg('Deployment timed out waiting for agent');
      }
    } catch (err: any) {
      setDeployState('error');
      setDeployErrorMsg(err?.message || 'Deploy failed');
    } finally {
      setIsSyncingServer(false);
    }
  };

  // Point the agent at another website of the same server
  const handleSelectSite = async (site: AgentDetectedSite) => {
    const owner = wafAgents.find(agent => (agent.detectedSites || []).some(item => item.domain === site.domain)) || wafAgents[0];
    if (!owner) {
      setPolicyFeedback({ tone: 'warn', text: 'No endpoint agent is connected yet, so the website cannot be selected.' });
      setShowSitePicker(false);
      return;
    }
    setSwitchingSite(true);
    try {
      await securityApi.setAgentApplication(owner.id, {
        domain: site.domain,
        protocol: site.protocol,
        port: site.port
      });
      await fetchWaf(false);
      setPolicyFeedback({ tone: 'ok', text: `Now monitoring ${site.domain}.` });
    } catch (err: any) {
      setPolicyFeedback({ tone: 'err', text: `Failed to switch website: ${err.message}` });
    } finally {
      setSwitchingSite(false);
      setShowSitePicker(false);
    }
  };

  // Toggle single rule -> queues a signed revision
  const handleToggleRule = async (ruleId: string, currentStatus: 'Active' | 'Disabled') => {
    const next = currentStatus === 'Active' ? 'Disabled' : 'Active';
    try {
      const res = await securityApi.toggleWafRule(ruleId, next);
      await fetchWaf(false);
      setPolicyFeedback(deploymentNotice(`Rule state updated to ${next}.`, res.deployment));
    } catch (e) {
      alert('Failed to update WAF rule state on backend.');
    }
  };

  // Delete rule -> queues a signed revision
  const handleDeleteRule = async (ruleId: string, ruleName: string) => {
    if (!confirm(`Delete rule "${ruleName}"? Every connected endpoint agent will remove it at the next check-in.`)) {
      return;
    }
    try {
      const res = await securityApi.deleteWafRule(ruleId);
      await fetchWaf(false);
      setPolicyFeedback(deploymentNotice(`Rule "${ruleName}" deleted.`, res.deployment));
    } catch (e: any) {
      alert(`Failed to delete rule: ${e.message}`);
    }
  };

  // Save Policy Form -> queues a signed revision
  const handleSavePolicies = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSyncingServer(true);
    try {
      const res = await securityApi.saveWafPolicy({
        rate_limit_requests: rateLimitRequests,
        rate_limit_window_s: rateLimitWindow,
        ip_allowlist: ipAllowlist,
        ip_blocklist: ipBlocklist,
        geo_block_countries: geoBlockCountries,
        bot_protection_enabled: botProtectionEnabled ? 1 : 0,
        mode,
        engine_enabled: engineEnabled ? 1 : 0
      });
      await fetchWaf(false);
      setPolicyFeedback(deploymentNotice('WAF policy published.', res.deployment));
    } catch (err: any) {
      setPolicyFeedback({
        tone: 'err',
        text: `Failed to publish policies: ${err.message}`
      });
    } finally {
      setIsSyncingServer(false);
    }
  };

  const handleAddApp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAppName.trim() || !newAppDomain.trim()) return;
    setAddingApp(true);
    try {
      await securityApi.createApplication({
        name: newAppName.trim(),
        domain: newAppDomain.trim(),
        originIp: newAppOriginIp.trim() || '127.0.0.1',
        port: Number(newAppPort) || 443,
        protocol: newAppProtocol,
        environment: 'Production'
      });
      setShowAddAppModal(false);
      setNewAppName('');
      setNewAppDomain('');
      setNewAppOriginIp('');
      await fetchWaf(false);
    } catch (err: any) {
      alert(`Gagal menambahkan domain: ${err?.message || 'Error'}`);
    } finally {
      setAddingApp(false);
    }
  };

  const handleDeleteApp = async (appId: string, appDomain: string) => {
    if (!confirm(`Hapus domain "${appDomain}" dari proteksi WAF?`)) return;
    try {
      await securityApi.removeApplication(appId);
      await fetchWaf(false);
    } catch (err: any) {
      alert(`Gagal menghapus domain: ${err?.message || 'Error'}`);
    }
  };

  // Create new rule -> queues a signed revision
  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = newRule.name.trim();
    const pattern = newRule.pattern.trim();
    if (!name) {
      setRuleError('Rule name is required.');
      return;
    }
    if (newRule.category === 'Custom Policy' && !pattern) {
      setRuleError('A match pattern is required for Custom Policy rules.');
      return;
    }
    setSavingRule(true);
    setRuleError(null);
    try {
      const res = await securityApi.createWafRule({
        name,
        category: newRule.category,
        severity: newRule.severity as any,
        action: newRule.action as any,
        pattern
      });
      setShowCreateModal(false);
      setNewRule({ name: '', category: 'SQL Injection', severity: 'High', action: 'Block', pattern: '' });
      await fetchWaf(false);
      setPolicyFeedback(deploymentNotice(`Rule "${name}" created.`, res.deployment));
    } catch (err: any) {
      setRuleError(err?.message || 'The server engine rejected the rule. No rule was created.');
    } finally {
      setSavingRule(false);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchWaf} />;
  }

  const rules: WafRule[] = data?.rules || [];
  const apps: ProtectedApplication[] = data?.protectedApplications || [];
  const deployment: WafDeploymentView | undefined = data?.deployment;
  const wafAgents = deployment?.agents || [];

  // Websites the agent found on its host. A server can host many websites, so
  // the operator picks the one that should be monitored.
  const siteOptions: AgentDetectedSite[] = (() => {
    const map = new Map<string, AgentDetectedSite>();
    for (const agent of wafAgents) {
      for (const site of agent.detectedSites || []) {
        const domain = String(site?.domain || '').trim();
        if (!domain || map.has(domain)) continue;
        map.set(domain, { ...site, domain });
      }
    }
    for (const app of apps) {
      const domain = String(app.domain || '').trim();
      if (domain && !map.has(domain)) map.set(domain, { domain });
    }
    return Array.from(map.values());
  })();
  const monitoredSite = wafAgents.find(agent => agent.applicationDomain)?.applicationDomain || siteOptions[0]?.domain || '';

  const targetLabel = wafAgents.length === 0
    ? 'No endpoint agent'
    : monitoredSite
      ? monitoredSite
      : wafAgents.length === 1
        ? (wafAgents[0].hostname || wafAgents[0].name)
        : `${wafAgents.length} endpoint agents`;
  const targetHint = wafAgents
    .map(agent => `${agent.hostname || agent.name} (${agent.os || 'linux'})${agent.applicationDomain ? ` · ${agent.applicationDomain}` : ''}`)
    .join(' · ');
  const appliedOnAll = Boolean(deployment && deployment.totalAgents > 0 && deployment.appliedAgents === deployment.totalAgents);
  const deploymentFailed = deployment?.status === 'FAILED';
  const deploymentPending = !deployment || deployment.status === 'PENDING' || deployment.status === 'NO_AGENT';
  const deploymentUnsupported = deployment?.status === 'UNSUPPORTED';
  const wafUpdateRequired = wafAgents.some(agent => (
    agent.status === 'PENDING' && agent.wafCapable === null
  ));

  const term = (search || '').trim().toLowerCase();
  const filteredRules = rules.filter(r =>
    String(r.name || '').toLowerCase().includes(term) ||
    String(r.id || '').toLowerCase().includes(term) ||
    String(r.ruleId || '').toLowerCase().includes(term) ||
    String(r.category || '').toLowerCase().includes(term)
  );

  const blockRatio = data?.totalRequests24h > 0
    ? (((data.blockedRequests24h ?? 0) / data.totalRequests24h) * 100).toFixed(2) + '%'
    : '0.00%';

  const headerState = isSyncingServer
    ? { label: 'Queuing deployment…', className: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20', dot: 'bg-amber-500 animate-pulse' }
    : !deployment || deployment.totalAgents === 0
      ? { label: 'Awaiting endpoint agent', className: 'bg-zinc-500/10 text-zinc-500 border-zinc-500/20', dot: 'bg-zinc-400' }
      : deploymentFailed
        ? { label: 'Deploy failed', className: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20', dot: 'bg-rose-500' }
        : deploymentUnsupported
          ? { label: 'Host unsupported', className: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20', dot: 'bg-amber-500' }
          : deploymentPending
            ? { label: 'Deploy pending', className: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20', dot: 'bg-amber-500 animate-pulse' }
            : deployment.status === 'PARTIAL'
              ? { label: `Partial · ${deployment.appliedAgents}/${deployment.totalAgents} applied`, className: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20', dot: 'bg-amber-500' }
              : !engineEnabled
              ? { label: 'Disabled (passthrough)', className: 'bg-zinc-500/10 text-zinc-500 border-zinc-500/20', dot: 'bg-zinc-400' }
              : { label: `${mode === 'block' ? 'Enforced' : 'Monitoring'} on ${deployment.appliedAgents} host(s)`, className: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20', dot: 'bg-emerald-500' };

  const engineStateLabel = deploymentFailed
    ? 'Error'
    : !deployment || deployment.totalAgents === 0
      ? 'Offline'
      : deploymentUnsupported
        ? 'Unsupported'
        : deployment.status === 'PARTIAL'
          ? 'Partial'
          : !appliedOnAll
            ? 'Queued'
            : !engineEnabled
              ? 'Offline'
              : mode === 'block' ? 'Active Block' : 'Monitor Only';

  const engineStateDot = deploymentFailed
    ? 'bg-rose-500'
    : (!deployment || deployment.totalAgents === 0 || !engineEnabled)
      ? 'bg-zinc-400'
      : !appliedOnAll
        ? 'bg-amber-400'
        : mode === 'block' ? 'bg-emerald-500' : 'bg-amber-400';

  const deploymentChipClass = deploymentFailed
    ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20'
    : !deployment || deployment.totalAgents === 0
      ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500 border-zinc-200 dark:border-zinc-700'
      : deployment.status === 'APPLIED'
        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'
        : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20';

  const summaryTiles = [
    {
      label: 'Server Engine',
      value: engineStateLabel,
      dot: engineStateDot
    },
    { label: 'Target Host', value: targetLabel, dot: wafAgents.some(agent => agent.agentStatus === 'ONLINE') ? 'bg-blue-500' : 'bg-zinc-400' },
    { label: '24H Ingress', value: (data?.totalRequests24h ?? 0).toLocaleString(), dot: 'bg-zinc-400' },
    { label: 'Blocked Attacks', value: (data?.blockedRequests24h ?? 0).toLocaleString(), dot: 'bg-rose-500' },
    { label: 'Threat Ratio', value: blockRatio, dot: 'bg-amber-400' },
    { label: 'Active Rules', value: rules.filter(r => r.status === 'Active').length.toString(), dot: 'bg-purple-500' }
  ];

  const tabOptions = [
    { id: 'rules' as const, label: 'Inspection Rules' },
    { id: 'policies' as const, label: 'WAF Settings' },
    { id: 'apps' as const, label: 'Protected Domains' }
  ];

  return (
    <div className="space-y-5" id="waf-engine-container">
      {/* ── Header — dashboard identity: neutral tenant-style chip with status
          dot, one-line subtitle ── */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faShieldVirus} />}
        title="Web Application Firewall"
        titleTail="(WAF)"
        badge={
          <ModulePageBadge>
            <span className={`w-1.5 h-1.5 rounded-full ${headerState.dot}`} />
            {headerState.label}
          </ModulePageBadge>
        }
        subtitle="Signed rule delivery to enrolled agents — Apache and nftables are applied on the host automatically — no SSH credentials stored."
        actions={
          <button
            onClick={() => setShowCreateModal(true)}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Rule
          </button>
        }
      />

      {/* ── Endpoint Agent WAF Controller Bar ── */}
      <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 shadow-2xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 shrink-0">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100 tracking-wide uppercase">
                  Endpoint Agent WAF Controller
                </span>
              </div>
              <div className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-1 flex items-center gap-2 flex-wrap">
                <span>Enforcement: <strong className="text-zinc-600 dark:text-zinc-300">Apache 2 mod_rewrite + nftables</strong></span>
                <span>• {deployment ? `${deployment.appliedAgents}/${deployment.totalAgents} agent(s) applied` : 'waiting for an agent'}</span>
              </div>
              {wafUpdateRequired && (
                <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-amber-500/25 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>An agent has not reported WAF support. Reinstall the current agent without <code className="font-mono">--no-waf</code>, or enable WAF in its config, then revoke any old agent entry.</span>
                  <button
                    type="button"
                    onClick={() => onNavigate?.('agents')}
                    className="inline-flex items-center gap-1 font-semibold underline underline-offset-2 cursor-pointer"
                  >
                    Update agent
                    <ArrowUpRight className="w-3 h-3" />
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
            {/* Engine Switch Button */}
            <label className="inline-flex h-9 cursor-pointer items-center gap-2.5 rounded-xl border border-zinc-200/80 bg-white px-3 text-xs font-medium text-neutral-950 has-disabled:cursor-not-allowed shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-neutral-50 hover:bg-zinc-50 dark:hover:bg-zinc-900 transition">
              <span className="group/sw relative inline-grid shrink-0 grid-cols-1 items-center has-disabled:opacity-50">
                <input
                  type="checkbox"
                  role="switch"
                  aria-label="WAF Engine"
                  checked={engineEnabled}
                  onChange={handleToggleEngine}
                  disabled={isSyncingServer}
                  className="col-start-1 row-start-1 h-6 w-10 cursor-pointer appearance-none rounded-full bg-neutral-100 ring-1 ring-neutral-500 transition-colors duration-150 ring-inset checked:bg-zinc-950 checked:ring-0 hover:bg-neutral-200 checked:hover:bg-zinc-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 disabled:cursor-not-allowed disabled:hover:bg-neutral-100 checked:disabled:hover:bg-zinc-950 motion-reduce:transition-none dark:bg-neutral-800 dark:checked:bg-zinc-50 dark:hover:bg-neutral-700 dark:checked:hover:bg-zinc-200 dark:focus-visible:outline-zinc-50 dark:disabled:hover:bg-neutral-800 dark:checked:disabled:hover:bg-zinc-50"
                />
                <span className="pointer-events-none col-start-1 row-start-1 size-4 translate-x-1 rounded-full bg-neutral-500 group-has-checked/sw:size-5 group-has-checked/sw:translate-x-[18px] group-has-checked/sw:bg-white group-has-checked/sw:shadow-md motion-safe:transition-transform motion-safe:duration-150 dark:bg-neutral-400 dark:group-has-checked/sw:bg-neutral-950" />
              </span>
              <span className="text-zinc-600 dark:text-zinc-400">Engine</span>
              <span className={`font-mono font-semibold ${engineEnabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-zinc-400 dark:text-zinc-500'}`}>
                {engineEnabled ? 'ON' : 'OFF'}
              </span>
            </label>

            {/* Enforcement Mode Switch */}
            <label
              title={mode === 'block' ? 'Requests matching a rule are blocked — toggle switch to switch to monitoring' : 'Suspicious traffic is only recorded — toggle switch to switch to blocking'}
              className="inline-flex h-9 cursor-pointer items-center gap-2.5 rounded-xl border border-zinc-200/80 bg-white px-3 text-xs font-medium text-neutral-950 has-disabled:cursor-not-allowed shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-neutral-50 hover:bg-zinc-50 dark:hover:bg-zinc-900 transition"
            >
              <span className="group/sw relative inline-grid shrink-0 grid-cols-1 items-center has-disabled:opacity-50">
                <input
                  type="checkbox"
                  role="switch"
                  aria-label="WAF Enforcement Mode"
                  checked={mode === 'block'}
                  onChange={handleToggleMode}
                  disabled={isSyncingServer || !engineEnabled}
                  className="col-start-1 row-start-1 h-6 w-10 cursor-pointer appearance-none rounded-full bg-neutral-100 ring-1 ring-neutral-500 transition-colors duration-150 ring-inset checked:bg-zinc-950 checked:ring-0 hover:bg-neutral-200 checked:hover:bg-zinc-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 disabled:cursor-not-allowed disabled:hover:bg-neutral-100 checked:disabled:hover:bg-zinc-950 motion-reduce:transition-none dark:bg-neutral-800 dark:checked:bg-zinc-50 dark:hover:bg-neutral-700 dark:checked:hover:bg-zinc-200 dark:focus-visible:outline-zinc-50 dark:disabled:hover:bg-neutral-800 dark:checked:disabled:hover:bg-zinc-50"
                />
                <span className="pointer-events-none col-start-1 row-start-1 size-4 translate-x-1 rounded-full bg-neutral-500 group-has-checked/sw:size-5 group-has-checked/sw:translate-x-[18px] group-has-checked/sw:bg-white group-has-checked/sw:shadow-md motion-safe:transition-transform motion-safe:duration-150 dark:bg-neutral-400 dark:group-has-checked/sw:bg-neutral-950" />
              </span>
              <span className={`h-2 w-2 shrink-0 rounded-full transition-colors ${mode === 'block' ? 'bg-rose-500 shadow-[0_0_5px] shadow-rose-500/50' : 'bg-amber-500 shadow-[0_0_5px] shadow-amber-500/50'}`} />
              <span className="text-zinc-600 dark:text-zinc-400">Mode</span>
              <span className={`font-mono font-semibold ${mode === 'block' ? 'text-rose-600 dark:text-rose-400' : 'text-amber-600 dark:text-amber-400'}`}>
                {mode.toUpperCase()}
              </span>
            </label>

            {/* Deployment diagnostics Logs Button */}
            <button
              type="button"
              onClick={() => setShowLogModal(true)}
              title="View endpoint agent deployment diagnostics"
              className="inline-flex h-9 items-center gap-1.5 rounded-xl border border-zinc-200/80 bg-white px-3 text-xs font-medium text-zinc-700 transition hover:bg-zinc-50 cursor-pointer disabled:opacity-50 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-zinc-300 dark:hover:bg-zinc-900"
            >
              <Terminal className="w-3.5 h-3.5 text-zinc-500" />
              <span>Logs</span>
            </button>
          </div>
        </div>
      </div>

      {/* ── Policy Feedback Banner ── */}
      {policyFeedback && (
        <div className={`p-3 rounded-xl border text-xs flex items-center justify-between gap-3 ${
          policyFeedback.tone === 'ok'
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400'
            : policyFeedback.tone === 'warn'
              ? 'bg-amber-500/10 border-amber-500/20 text-amber-600 dark:text-amber-400'
              : 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400'
        }`}>
          <span>{policyFeedback.text}</span>
          <button
            type="button"
            onClick={() => setPolicyFeedback(null)}
            className="text-current opacity-60 hover:opacity-100 cursor-pointer font-bold px-1"
          >
            ×
          </button>
        </div>
      )}

      {/* ── Minimalist Summary Tiles ── */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-6">
        {summaryTiles.map(tile => (
          <div
            key={tile.label}
            className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 shadow-2xs transition-colors"
          >
            <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              {tile.dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${tile.dot}`} />}
              {tile.label}
            </div>
            <div className="mt-1.5 text-lg font-semibold leading-snug tracking-tight text-zinc-900 dark:text-zinc-100 font-mono break-words">
              {tile.value}
            </div>
          </div>
        ))}
      </div>

      {/* ── Tab Selector Dropdown ── */}
      <div className="relative w-fit">
        <button
          type="button"
          onClick={() => setShowTabDropdown(prev => !prev)}
          className="h-9 px-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold text-zinc-800 dark:text-zinc-200 inline-flex items-center gap-2.5 transition cursor-pointer shadow-xs"
        >
          <SlidersHorizontal className="w-4 h-4 text-zinc-500 dark:text-zinc-400" />
          <span className="text-[13px]">
            {tabOptions.find(t => t.id === activeTab)?.label}
          </span>
          <ChevronDown className={`w-4 h-4 text-zinc-400 transition-transform ${showTabDropdown ? 'rotate-180' : ''}`} />
        </button>

        {showTabDropdown && (
          <>
            <div
              className="fixed inset-0 z-20 cursor-default"
              onClick={() => setShowTabDropdown(false)}
            />
            <div className="absolute left-0 top-full mt-2 w-64 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1.5 z-30">
              {tabOptions.map(tab => {
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(tab.id);
                      setShowTabDropdown(false);
                    }}
                    className={`w-full px-3 py-2 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                      isActive
                        ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                        : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                    }`}
                  >
                    <span className="text-[13px]">{tab.label}</span>
                    {isActive && <Check className="w-4 h-4 text-emerald-500 shrink-0" />}
                  </button>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* ── TAB 1: Inspection Rules ── */}
      {activeTab === 'rules' && (
        <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
          <header className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
                Managed Inspection Rules
              </h2>
              <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5">
                Every change creates a signed policy revision. Connected agents apply it on their next check-in (about 15 seconds).
              </p>
            </div>
            <div className="relative w-full sm:w-auto">
              <Search className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search rule ID, category, or name…"
                className="h-8 w-full sm:w-64 rounded-lg border border-zinc-200/80 bg-white pl-8 pr-3 text-xs text-zinc-800 placeholder-zinc-400 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder-zinc-500 dark:focus:border-zinc-600"
              />
            </div>
          </header>

          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full min-w-[780px] text-left text-xs">
              <thead>
                <tr className="border-b border-zinc-100 dark:border-zinc-800 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/40 dark:bg-zinc-900/20">
                  <th className="py-3 px-4">Rule ID</th>
                  <th className="py-3 px-4">Rule Name & Details</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Agent Status</th>
                  <th className="py-3 px-4 text-right">Controls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/80 font-mono">
                {filteredRules.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-10 text-center font-sans text-xs text-zinc-400 dark:text-zinc-500">
                      No WAF rules matching your search.
                    </td>
                  </tr>
                ) : (
                  filteredRules.map(rule => (
                    <tr key={rule.id} className="hover:bg-zinc-50/80 dark:hover:bg-zinc-900/40 transition-colors">
                      <td className="py-3 px-4 text-zinc-700 dark:text-zinc-300 font-bold">{rule.ruleId || rule.id}</td>
                      <td className="py-3 px-4 font-sans">
                        <div className="font-medium text-zinc-900 dark:text-zinc-100">{rule.name}</div>
                        {rule.pattern && (
                          <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-mono mt-0.5 break-all">
                            pattern: {rule.pattern}
                          </div>
                        )}
                        {rule.description && (
                          <div className="text-[11px] text-zinc-400 dark:text-zinc-500 font-mono mt-0.5">{rule.description}</div>
                        )}
                      </td>
                      <td className="py-3 px-4 font-sans">
                        <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">
                          {rule.category}
                        </span>
                      </td>
                      <td className="py-3 px-4"><StatusBadge type="severity" value={rule.severity} /></td>
                      <td className="py-3 px-4"><StatusBadge type="action" value={rule.action} /></td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-semibold ${
                          rule.status === 'Active'
                            ? appliedOnAll
                              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                              : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                            : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${
                            rule.status === 'Active'
                              ? appliedOnAll ? 'bg-emerald-500' : 'bg-amber-500'
                              : 'bg-zinc-400'
                          }`} />
                          {rule.status === 'Active' ? (appliedOnAll ? 'Active' : 'Queued') : 'Disabled'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right font-sans">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleToggleRule(rule.id, rule.status)}
                            className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-medium border transition cursor-pointer ${
                              rule.status === 'Active'
                                ? 'border-zinc-200 dark:border-zinc-700 text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20'
                                : 'border-zinc-200 dark:border-zinc-700 text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/20'
                            }`}
                          >
                            {rule.status === 'Active' ? 'Disable' : 'Enable'}
                          </button>
                          {rule.id.startsWith('WAF-R-') && (
                            <button
                              type="button"
                              onClick={() => handleDeleteRule(rule.id, rule.name)}
                              title="Delete rule from every endpoint agent"
                              className="inline-flex items-center p-1 rounded-lg border border-zinc-200 dark:border-zinc-700 text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── TAB 2: WAF Policies ── */}
      {activeTab === 'policies' && (
        <form onSubmit={handleSavePolicies} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Rate Limiting */}
            <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
              <div className="flex items-center gap-2 mb-1">
                <SlidersHorizontal className="w-4 h-4 text-zinc-500" />
                <h3 className="text-[13px] font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-200">
                  Rate Limiting (nftables on agents)
                </h3>
              </div>
              <p className="text-[12px] text-zinc-400 dark:text-zinc-500 mb-4">
                Each connected Debian endpoint agent applies a global new-connection limit at the Linux kernel layer to absorb bursts before they reach Apache
              </p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-zinc-500 mb-1">Max Requests</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={rateLimitRequests}
                    onChange={e => setRateLimitRequests(Number(e.target.value.replace(/\D/g, '')))}
                    className="h-9 w-full rounded-lg border border-zinc-200/80 bg-zinc-50 px-3 text-[13px] text-zinc-800 font-mono dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-zinc-500 mb-1">Window (Seconds)</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={rateLimitWindow}
                    onChange={e => setRateLimitWindow(Number(e.target.value.replace(/\D/g, '')))}
                    className="h-9 w-full rounded-lg border border-zinc-200/80 bg-zinc-50 px-3 text-[13px] text-zinc-800 font-mono dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>
            </div>

            {/* Automated Bot & Scanner Defense */}
            <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
              <div className="flex items-center gap-2 mb-1">
                <Shield className="w-4 h-4 text-zinc-500" />
                <h3 className="text-[13px] font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-200">
                  Bot & Scanner Defense (Apache on agents)
                </h3>
              </div>
              <p className="text-[12px] text-zinc-400 dark:text-zinc-500 mb-4">
                Each endpoint agent returns 403 for scanner user-agents (Nikto, sqlmap, nmap, BurpSuite, Dirbuster) through Apache mod_rewrite
              </p>
              <div className="flex items-center justify-between p-3 rounded-xl border border-zinc-200/80 bg-zinc-50/50 dark:border-zinc-800 dark:bg-zinc-900/50">
                <div>
                  <div className="text-[13px] font-semibold text-zinc-900 dark:text-zinc-100">
                    Security Scanner & Bot Filtering
                  </div>
                  <div className="text-[12px] text-zinc-400 dark:text-zinc-500 mt-0.5">
                    RewriteCond user-agent heuristics applied by the endpoint agent
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setBotProtectionEnabled(!botProtectionEnabled)}
                  className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none ${
                    botProtectionEnabled ? 'bg-zinc-900 dark:bg-white' : 'bg-zinc-200 dark:bg-zinc-700'
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white dark:bg-zinc-900 shadow transition-transform ${
                      botProtectionEnabled ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>
            </div>

            {/* IP Allowlist */}
            <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
              <div className="text-[13px] font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-200 mb-1">
                IP Allowlist (Bypass Inspection)
              </div>
              <p className="text-[12px] text-zinc-400 dark:text-zinc-500 mb-3">
                Exact IPs bypass Apache inspection on the agent host (comma or newline separated). CIDR allowlisting is not applied locally.
              </p>
              <textarea
                rows={3}
                value={ipAllowlist}
                onChange={e => setIpAllowlist(e.target.value)}
                placeholder="Masukkan IP address, pisahkan dengan koma atau baris baru"
                className="w-full p-2.5 rounded-lg border border-zinc-200/80 bg-zinc-50 font-mono text-[13px] text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 resize-none focus:outline-none focus:border-zinc-400"
              />
            </div>

            {/* IP Blocklist */}
            <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
              <div className="text-[13px] font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-200 mb-1">
                IP Blocklist (nftables + Apache)
              </div>
              <p className="text-[12px] text-zinc-400 dark:text-zinc-500 mb-3">
                IPs and CIDRs dropped by nftables at the kernel layer; exact IPs are also denied by Apache. Applied by every connected endpoint agent.
              </p>
              <textarea
                rows={3}
                value={ipBlocklist}
                onChange={e => setIpBlocklist(e.target.value)}
                placeholder="Masukkan IP address atau CIDR, pisahkan dengan koma"
                className="w-full p-2.5 rounded-lg border border-zinc-200/80 bg-zinc-50 font-mono text-[13px] text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 resize-none focus:outline-none focus:border-zinc-400"
              />
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSyncingServer}
              className="inline-flex h-8 items-center gap-2 rounded-lg bg-zinc-900 px-4 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncingServer ? 'animate-spin' : ''}`} />
              {isSyncingServer ? 'Saving policy…' : 'Save Policy Changes'}
            </button>
          </div>
        </form>
      )}

      {/* ── TAB 3: Protected Applications ── */}
      {activeTab === 'apps' && (
        <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
          <header className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
                Protected Domains & Ingress Applications
              </h2>
              <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5">
                Websites and domains inspected by the WAF engine. Add new domains to enforce protection across all endpoint agents.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setShowAddAppModal(true)}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Domain
            </button>
          </header>

          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full min-w-[780px] text-left text-xs">
              <thead>
                <tr className="border-b border-zinc-100 dark:border-zinc-800 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/40 dark:bg-zinc-900/20">
                  <th className="py-3 px-4">Application</th>
                  <th className="py-3 px-4">Domain / Path</th>
                  <th className="py-3 px-4">Origin IP</th>
                  <th className="py-3 px-4">Agents</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Port</th>
                  <th className="py-3 px-4">WAF Status</th>
                  <th className="py-3 px-4">Threat Level</th>
                  <th className="py-3 px-4 text-right">24H Requests</th>
                  <th className="py-3 px-4 text-right">Aksi</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/80 font-mono">
                {apps.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="py-8 text-center text-zinc-400 font-sans">
                      Belum ada domain yang didaftarkan. Klik "Add Domain" untuk menambahkan domain yang diproteksi.
                    </td>
                  </tr>
                ) : (
                  apps.map(app => (
                    <tr key={app.id} className="hover:bg-zinc-50/80 dark:hover:bg-zinc-900/40 transition-colors">
                      <td className="py-3 px-4 font-sans font-semibold text-zinc-900 dark:text-zinc-100">{app.name}</td>
                      <td className="py-3 px-4 text-blue-600 dark:text-blue-400 font-medium">{app.domain}</td>
                      <td className="py-3 px-4 text-zinc-600 dark:text-zinc-300">{app.ipAddress || app.originIp || '—'}</td>
                      <td className="py-3 px-4 text-zinc-600 dark:text-zinc-300">{app.agentCount ?? 0}</td>
                      <td className="py-3 px-4 text-zinc-600 dark:text-zinc-300">{app.protocol}</td>
                      <td className="py-3 px-4 text-zinc-400 dark:text-zinc-500">{app.port}</td>
                      <td className="py-3 px-4"><StatusBadge type="health" value={app.wafStatus} /></td>
                      <td className="py-3 px-4"><StatusBadge type="severity" value={app.threatLevel} /></td>
                      <td className="py-3 px-4 text-right text-zinc-900 dark:text-zinc-100 font-semibold">
                        {(app.requests24h ?? 0).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          type="button"
                          onClick={() => handleDeleteApp(app.id, app.domain)}
                          title="Hapus domain dari proteksi WAF"
                          className="inline-flex items-center p-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 transition cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── Drawer: Endpoint Agent Diagnostics — inspector panel; slides in from the right and closes on any click outside the panel ── */}
      {showLogModal && (
        <div className="fixed inset-0 z-50">
          {/* Dimmed backdrop — clicking anywhere outside the panel closes the drawer. */}
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200"
            onClick={() => setShowLogModal(false)}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Endpoint agent deployment diagnostics"
            className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-zinc-200/80 bg-white text-zinc-900 shadow-2xl animate-in slide-in-from-right duration-300 ease-out dark:border-zinc-800 dark:bg-[#0b0b0d] dark:text-zinc-100 sm:max-w-[560px] lg:max-w-[640px]"
          >
            {/* Mobile grab handle */}
            <div className="flex justify-center pb-0.5 pt-2.5 sm:hidden">
              <div className="h-1 w-10 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            </div>

            {/* Drawer Header in clean user-requested style */}
            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pt-5 pb-4 dark:border-zinc-800 dark:bg-[#0c0c0e] sm:px-6">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
                    WAF & Firewall Inspection
                  </h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                    {targetLabel || 'Enterprise website host protection'}
                  </p>
                </div>
              </div>

              {/* Two Pill Tabs: "Logs" (with count badge) and "Diagnostics" */}
              <div className="flex items-center gap-2 mt-4">
                <button
                  type="button"
                  onClick={() => setDrawerTab('logs')}
                  className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold transition cursor-pointer ${
                    drawerTab === 'logs'
                      ? 'bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 shadow-2xs'
                      : 'bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80 dark:bg-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-700'
                  }`}
                >
                  Logs
                  <span className={`text-[11px] font-mono font-bold tabular-nums ${
                    drawerTab === 'logs' ? 'text-zinc-300 dark:text-zinc-600' : 'text-zinc-400'
                  }`}>
                    {firewallAuditLogs.length + wafAgents.length}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setDrawerTab('diagnostics')}
                  className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold transition cursor-pointer ${
                    drawerTab === 'diagnostics'
                      ? 'bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 shadow-2xs'
                      : 'bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80 dark:bg-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-700'
                  }`}
                >
                  Diagnostics
                </button>
              </div>
            </header>

            {/* Scrollable Body in Clean Card List Style */}
            <div className="flex-1 overflow-y-auto divide-y divide-zinc-100 dark:divide-zinc-800/80 custom-scrollbar">
              {drawerTab === 'logs' ? (() => {
                // Build deployment & error log items from agent status + backend audit logs
                const items: Array<{
                  id: string;
                  avatar: string;
                  tone: 'error' | 'ok' | 'warn';
                  title: string;
                  subtitle: string;
                  desc: string;
                  timestamp: string;
                  isFailed: boolean;
                }> = [];

                // 1. Agent firewall & WAF installation status items
                for (const agent of wafAgents) {
                  const isFailed = agent.status === 'FAILED';
                  const isApplied = agent.status === 'APPLIED';
                  const isPending = agent.status === 'PENDING';
                  const host = agent.hostname || agent.name || 'Debian Host';

                  if (isFailed) {
                    items.push({
                      id: `agent-fail-${agent.id}`,
                      avatar: 'ERROR',
                      tone: 'error',
                      title: `${host} · Firewall Installation Failed`,
                      subtitle: 'Firewall / WAF Rule Installation Error',
                      desc: agent.message || 'Failed to apply nftables / mod_rewrite kernel rules on the host.',
                      timestamp: agent.lastSeen ? formatTime(agent.lastSeen) : 'Live',
                      isFailed: true
                    });
                  } else if (isApplied) {
                    items.push({
                      id: `agent-app-${agent.id}`,
                      avatar: 'APPLIED',
                      tone: 'ok',
                      title: `${host} · Firewall Applied Successfully`,
                      subtitle: `Status: APPLIED · Revision ${agent.appliedRevision || 1}`,
                      desc: `nftables firewall rules and Apache virtual patches loaded (${agent.rulesApplied || 0} active rules).`,
                      timestamp: agent.appliedAt ? formatTime(agent.appliedAt) : (agent.lastSeen ? formatTime(agent.lastSeen) : 'Active'),
                      isFailed: false
                    });
                  } else if (isPending) {
                    items.push({
                      id: `agent-pen-${agent.id}`,
                      avatar: 'PENDING',
                      tone: 'warn',
                      title: `${host} · Awaiting Firewall Deployment`,
                      subtitle: 'Status: PENDING · Waiting for Agent Check-in',
                      desc: agent.message || 'Endpoint agent is downloading firewall policy from the console.',
                      timestamp: agent.lastSeen ? formatTime(agent.lastSeen) : 'Waiting',
                      isFailed: false
                    });
                  }
                }

                // 2. Audit & error logs from database
                for (const log of firewallAuditLogs) {
                  const isErr = String(log.level || '').toUpperCase() === 'ERROR' || String(log.level || '').toUpperCase() === 'CRITICAL';
                  const isWarn = String(log.level || '').toUpperCase() === 'WARN' || String(log.level || '').toUpperCase() === 'WARNING';
                  const host = log.host || 'Endpoint Host';

                  items.push({
                    id: log.id,
                    avatar: isErr ? 'ERROR' : isWarn ? 'WARNING' : 'OPERATIONAL',
                    tone: isErr ? 'error' : isWarn ? 'warn' : 'ok',
                    title: `${host} · ${log.eventType || 'Firewall Engine'}`,
                    subtitle: isErr ? 'Error Firewall / WAF' : 'Firewall Operational Event',
                    desc: log.message || 'Firewall status check event.',
                    timestamp: log.timestamp ? formatTime(log.timestamp) : 'Live',
                    isFailed: isErr
                  });
                }

                if (items.length === 0) {
                  return (
                    <div className="py-20 text-center text-xs text-zinc-400 dark:text-zinc-500 px-6">
                      <Terminal className="w-8 h-8 mx-auto mb-2 opacity-40 text-zinc-400" />
                      <p className="font-semibold text-zinc-700 dark:text-zinc-300">No Firewall Error Logs Recorded</p>
                      <p className="mt-1 text-[11px]">Any rule deployment failure or kernel firewall error will appear here automatically.</p>
                    </div>
                  );
                }

                return items.map(item => (
                  <div
                    key={item.id}
                    className="p-4 hover:bg-zinc-50/80 dark:hover:bg-zinc-900/40 transition-colors cursor-pointer space-y-2"
                  >
                    {/* Top Row: Status Badge on top + Timestamp */}
                    <div className="flex items-center justify-between gap-2">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-semibold tracking-wide ${
                        item.tone === 'error'
                          ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                          : item.tone === 'warn'
                            ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          item.tone === 'error' ? 'bg-rose-500' : item.tone === 'warn' ? 'bg-amber-500' : 'bg-emerald-500'
                        }`} />
                        {item.avatar}
                      </span>
                      <span className="text-xs text-zinc-400 dark:text-zinc-500 tabular-nums">
                        {item.timestamp}
                      </span>
                    </div>

                    {/* Middle details */}
                    <div>
                      <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                        {item.title}
                      </h3>
                      <p className={`text-xs font-medium mt-0.5 truncate ${
                        item.tone === 'error' ? 'text-rose-600 dark:text-rose-400' : 'text-zinc-700 dark:text-zinc-300'
                      }`}>
                        {item.subtitle}
                      </p>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 line-clamp-2 leading-relaxed">
                        {item.desc}
                      </p>
                    </div>
                  </div>
                ));
              })() : (
                <div className="p-5 space-y-5">
                  {/* Deployment status */}
                  <section>
                    <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                      Deployment status
                    </div>
                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                      <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                        <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Policy status</div>
                        <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{deployment?.status || 'NO_AGENT'}</div>
                      </div>
                      <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                        <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Agents online</div>
                        <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                          {deployment ? `${deployment.onlineAgents}/${deployment.totalAgents}` : '0/0'}
                        </div>
                      </div>
                      <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                        <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Last applied</div>
                        <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                          {(deployment?.lastAppliedAt || lastAppliedAt) ? formatDateTime(deployment?.lastAppliedAt || lastAppliedAt || '') : 'Never'}
                        </div>
                      </div>
                      <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                        <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Engine</div>
                        <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                          {engineEnabled ? `Enabled (${mode.toUpperCase()})` : 'Disabled'}
                        </div>
                      </div>
                    </div>
                  </section>

                  {/* Enrolled agents */}
                  <section>
                    <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                      Enrolled endpoint agents
                    </div>
                    <div className="max-h-72 space-y-2 overflow-y-auto custom-scrollbar">
                      {wafAgents.length === 0 ? (
                        <div className="p-3 rounded-xl border border-amber-500/20 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-[11px]">
                          No agent is enrolled for this organization yet. Open Endpoint Agents to deploy one to the Debian website host.
                        </div>
                      ) : wafAgents.map(agent => (
                        <div key={agent.id} className="p-3 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-zinc-900 dark:text-zinc-100">{agent.hostname || agent.name}</span>
                            <span className={`text-[10px] font-bold ${agent.status === 'APPLIED' ? 'text-emerald-500' : agent.status === 'FAILED' ? 'text-rose-500' : 'text-amber-500'}`}>
                              {agent.status}
                            </span>
                          </div>
                          <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 font-mono">
                            {agent.os || 'linux'} · applied rev {agent.appliedRevision || 0} / desired {agent.desiredRevision || 0} · {agent.rulesApplied || 0} rule(s)
                          </div>
                          <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 break-words">
                            {agent.message || 'Waiting for the agent to report.'}
                          </div>
                          <div className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500">
                            Target: {agent.target || 'not reported'} · Last check-in: {agent.lastSeen ? formatDateTime(agent.lastSeen) : 'never'}
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                </div>
              )}
            </div>

            {/* Footer matching reference style: "Showing all X logs" */}
            <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50/60 px-5 py-3 dark:border-zinc-800 dark:bg-[#0c0c0e] sm:px-6">
              <div className="flex items-center justify-between font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                <span className="font-sans">
                  {drawerTab === 'logs' ? `Showing all ${firewallAuditLogs.length + wafAgents.length} deployment & error logs` : 'Apache 2 mod_rewrite & nftables diagnostics'}
                </span>
                <span className="text-[10px] uppercase text-zinc-400 font-mono tracking-wider">
                  {drawerTab === 'logs' ? 'LIVE STREAM' : 'APPLIED'}
                </span>
              </div>
            </footer>
          </aside>
        </div>
      )}

      {/* ── Modal: Add Protected Domain ── */}
      {showAddAppModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="relative w-full max-w-lg rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-zinc-500" />
                <h3 className="text-sm font-semibold">Add Protected Domain / Website</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddAppModal(false)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddApp} className="space-y-3.5 pt-4 text-xs">
              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Application Name</label>
                <input
                  type="text"
                  required
                  value={newAppName}
                  onChange={e => setNewAppName(e.target.value)}
                  placeholder="Contoh: Customer Portal API"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Domain Name / FQDN</label>
                <input
                  type="text"
                  required
                  value={newAppDomain}
                  onChange={e => setNewAppDomain(e.target.value)}
                  placeholder="Contoh: portal.company.co.id"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Origin IP</label>
                  <input
                    type="text"
                    value={newAppOriginIp}
                    onChange={e => setNewAppOriginIp(e.target.value)}
                    placeholder="127.0.0.1"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Protocol</label>
                  <select
                    value={newAppProtocol}
                    onChange={e => setNewAppProtocol(e.target.value as any)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="HTTPS">HTTPS</option>
                    <option value="HTTP">HTTP</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Port</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={newAppPort || ''}
                    onChange={e => setNewAppPort(Number(e.target.value.replace(/\D/g, '')))}
                    placeholder="443"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <div className="pt-3 flex items-center justify-end gap-2 border-t border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  onClick={() => setShowAddAppModal(false)}
                  className="inline-flex h-8 items-center rounded-lg border border-zinc-200/80 bg-white px-3 text-xs text-zinc-600 hover:bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addingApp}
                  className="inline-flex h-8 items-center rounded-lg bg-zinc-900 px-3.5 text-xs font-medium text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 disabled:opacity-60 cursor-pointer"
                >
                  {addingApp ? 'Adding Domain…' : 'Protect Domain'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Add WAF Rule ── */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="relative w-full max-w-lg rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-zinc-500" />
                <h3 className="text-sm font-semibold">Add Enterprise WAF Rule</h3>
              </div>
              <button
                type="button"
                onClick={() => { setShowCreateModal(false); setRuleError(null); }}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3.5 pt-4 text-xs">
              {ruleError && (
                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-600 dark:text-rose-400">
                  {ruleError}
                </div>
              )}

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={newRule.name}
                  onChange={e => setNewRule(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Masukkan nama rule (contoh: Block SQL Injection)"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Category</label>
                  <select
                    value={newRule.category}
                    onChange={e => setNewRule(prev => ({ ...prev, category: e.target.value }))}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option>SQL Injection</option>
                    <option>XSS Filter</option>
                    <option>Path Traversal</option>
                    <option>Command Injection</option>
                    <option>Bad Bot</option>
                    <option>Custom Policy</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Action</label>
                  <select
                    value={newRule.action}
                    onChange={e => setNewRule(prev => ({ ...prev, action: e.target.value }))}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="Block">BLOCK</option>
                    <option value="Log">LOG</option>
                    <option value="Challenge">CHALLENGE</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={e => setNewRule(prev => ({ ...prev, severity: e.target.value }))}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                    <option>Info</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">
                    Match Pattern (PCRE regex, optional)
                  </label>
                  <input
                    type="text"
                    value={newRule.pattern}
                    onChange={e => setNewRule(prev => ({ ...prev, pattern: e.target.value }))}
                    placeholder="Masukkan pola regex (contoh: (?i)union\s+select)"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 font-mono text-xs text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <p className="text-[10px] text-zinc-400 dark:text-zinc-500">
                Leave empty to use the selected category&apos;s built-in detector. Custom Policy requires a pattern.
              </p>

              <div className="pt-3 flex items-center justify-end gap-2 border-t border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  onClick={() => { setShowCreateModal(false); setRuleError(null); }}
                  className="inline-flex h-8 items-center rounded-lg border border-zinc-200/80 bg-white px-3 text-xs text-zinc-600 hover:bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingRule}
                  className="inline-flex h-8 items-center rounded-lg bg-zinc-900 px-3.5 text-xs font-medium text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 disabled:opacity-60 cursor-pointer"
                >
                  {savingRule ? 'Queuing revision…' : 'Commit Rule to WAF'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
