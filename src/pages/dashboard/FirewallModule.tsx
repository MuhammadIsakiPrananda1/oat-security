import React, { useState, useEffect, useRef } from 'react';
import { 
  Flame, 
  Plus, 
  RefreshCw,
  Search,
  Network,
  Trash2,
  X,
  SlidersHorizontal,
  ChevronDown,
  Check,
  Terminal,
  Scan
} from 'lucide-react';
import { securityApi, globalRealtimeClient, normalizeRealtimeSecurityEvent } from '../../services/api';
import { FirewallRule, FirewallDeployment, NetworkInventory, NatRule } from '../../types';
import { useLiveConnectionState } from '../../hooks/useRealtimeStatus';
import { formatTime } from '../../utils/dateTime';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { useAuth } from '../../context/AuthContext';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFire } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader, ModulePageBadge } from '../../components/common/ModulePageHeader';



export const FirewallModule: React.FC = () => {
  const { isBackendOffline } = useAuth();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>(null);
  const [showTabDropdown, setShowTabDropdown] = useState(false);
  const [activeTab, setActiveTab] = useState<'rules' | 'fail2ban' | 'zones' | 'nat' | 'access'>('rules');
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [search, setSearch] = useState('');
  const [showLogModal, setShowLogModal] = useState(false);
  const [drawerTab, setDrawerTab] = useState<'logs' | 'diagnostics'>('logs');
  const [firewallAuditLogs, setFirewallAuditLogs] = useState<any[]>([]);
  const [detectingServer, setDetectingServer] = useState(false);

  // Security Zone modal & CRUD state
  const [showAddZoneModal, setShowAddZoneModal] = useState(false);
  const [zoneSaving, setZoneSaving] = useState(false);
  const [zoneFormError, setZoneFormError] = useState<string | null>(null);
  const [newZoneName, setNewZoneName] = useState('');
  const [newZoneCidr, setNewZoneCidr] = useState('');
  const [newZoneGateway, setNewZoneGateway] = useState('');
  const [newZoneInterface, setNewZoneInterface] = useState('eth0');
  const [newZoneType, setNewZoneType] = useState('DMZ');
  const [newZoneFirewall, setNewZoneFirewall] = useState('OAT NGFW');
  const [newZoneDesc, setNewZoneDesc] = useState('');

  const handleCreateZone = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newZoneName.trim() || !newZoneCidr.trim()) {
      setZoneFormError('Zone name and subnet CIDR are required.');
      return;
    }
    setZoneSaving(true);
    setZoneFormError(null);
    try {
      await securityApi.createNetwork({
        name: newZoneName.trim(),
        cidr: newZoneCidr.trim(),
        gateway: newZoneGateway.trim() || '10.240.10.1',
        interface: newZoneInterface.trim() || 'eth0',
        zone: newZoneType,
        firewall: newZoneFirewall,
        description: newZoneDesc.trim()
      });
      setShowAddZoneModal(false);
      setNewZoneName('');
      setNewZoneCidr('');
      setNewZoneGateway('');
      setNewZoneDesc('');
      await fetchFirewall();
    } catch (err: any) {
      setZoneFormError(err?.message || 'Failed to create security zone.');
    } finally {
      setZoneSaving(false);
    }
  };

  const handleDeleteZone = async (zoneId: string, zoneName: string) => {
    if (!window.confirm(`Delete security zone "${zoneName}"?`)) return;
    try {
      await securityApi.deleteNetwork(zoneId);
      await fetchFirewall();
    } catch (err: any) {
      alert(err?.message || 'Failed to delete security zone.');
    }
  };

  // NAT & Port Forwarding state
  const [showAddNatModal, setShowAddNatModal] = useState(false);
  const [natSaving, setNatSaving] = useState(false);
  const [natFormError, setNatFormError] = useState<string | null>(null);
  const [newNatName, setNewNatName] = useState('');
  const [newNatVip, setNewNatVip] = useState('0.0.0.0');
  const [newNatExtPort, setNewNatExtPort] = useState('');
  const [newNatIntIp, setNewNatIntIp] = useState('');
  const [newNatIntPort, setNewNatIntPort] = useState('');
  const [newNatProtocol, setNewNatProtocol] = useState<'TCP' | 'UDP' | 'TCP/UDP'>('TCP');
  const [newNatMode, setNewNatMode] = useState<'DNAT' | 'Full Cone NAT' | 'SNAT'>('DNAT');
  const [newNatDesc, setNewNatDesc] = useState('');

  const handleCreateNatRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNatExtPort.trim() || !newNatIntIp.trim() || !newNatIntPort.trim()) {
      setNatFormError('External port, Internal target IP, dan Internal port wajib diisi.');
      return;
    }
    setNatSaving(true);
    setNatFormError(null);
    try {
      await securityApi.createNatRule({
        name: newNatName.trim() || `NAT-${newNatExtPort}->${newNatIntPort}`,
        external_vip: newNatVip.trim() || '0.0.0.0',
        external_port: newNatExtPort.trim(),
        internal_ip: newNatIntIp.trim(),
        internal_port: newNatIntPort.trim(),
        protocol: newNatProtocol,
        nat_mode: newNatMode,
        description: newNatDesc.trim()
      });
      setShowAddNatModal(false);
      setNewNatName('');
      setNewNatVip('0.0.0.0');
      setNewNatExtPort('');
      setNewNatIntIp('');
      setNewNatIntPort('');
      setNewNatDesc('');
      await fetchFirewall();
    } catch (err: any) {
      setNatFormError(err?.message || 'Gagal menambahkan aturan NAT.');
    } finally {
      setNatSaving(false);
    }
  };

  const handleToggleNatRule = async (ruleId: string) => {
    try {
      await securityApi.toggleNatRule(ruleId);
      await fetchFirewall();
    } catch (err: any) {
      alert(err?.message || 'Gagal mengubah status NAT rule.');
    }
  };

  const handleDeleteNatRule = async (ruleId: string, ruleName: string) => {
    if (!window.confirm(`Hapus aturan port forwarding "${ruleName}"?`)) return;
    try {
      await securityApi.deleteNatRule(ruleId);
      await fetchFirewall();
    } catch (err: any) {
      alert(err?.message || 'Gagal menghapus aturan NAT.');
    }
  };

  // Fail2ban state
  const [f2bLoading, setF2bLoading] = useState(false);
  const [f2bConfig, setF2bConfig] = useState<{
    enabled: boolean;
    bantime: number;
    findtime: number;
    maxretry: number;
    ignore_ips: string;
  }>({
    enabled: true,
    bantime: 3600,
    findtime: 600,
    maxretry: 5,
    ignore_ips: '127.0.0.1/8, ::1, 10.0.0.0/8, 192.168.0.0/16'
  });
  const [f2bBans, setF2bBans] = useState<any[]>([]);
  const [f2bMsg, setF2bMsg] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null);
  const [manualBanIp, setManualBanIp] = useState('');
  const [manualBanReason, setManualBanReason] = useState('');

  // Real-time perimeter stream: /ws pushes firewall decisions the moment the
  // engine emits them; REST is only a fallback while the socket is offline.
  const liveConnection = useLiveConnectionState();
  
  const seenEventIds = useRef<Set<string>>(new Set());
  const ruleSyncTimer = useRef<number | null>(null);

  // New Rule Form
  const [priority, setPriority] = useState(25);
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [port, setPort] = useState('');
  const [protocol, setProtocol] = useState<'TCP' | 'UDP' | 'ICMP' | 'ANY'>('TCP');
  const [action, setAction] = useState<'ALLOW' | 'DENY' | 'LOG'>('DENY');
  const [description, setDescription] = useState('');

  const fetchFirewallDeploymentLogs = React.useCallback(async () => {
    try {
      const res = await securityApi.getLogs({ limit: 60, page: 1 });
      const list = res.logs || [];
      const filtered = list.filter((l: any) => {
        const src = String(l.source || '').toLowerCase();
        const msg = String(l.message || '').toLowerCase();
        const type = String(l.eventType || '').toLowerCase();
        return (
          src === 'firewall' || src === 'waf' ||
          msg.includes('firewall') || msg.includes('nftables') ||
          msg.includes('policy') || msg.includes('deploy') ||
          msg.includes('fail') || msg.includes('error') || msg.includes('revision') ||
          type.includes('firewall')
        );
      });
      setFirewallAuditLogs(filtered);
    } catch (err) {
      console.warn('[Firewall] Failed to fetch logs:', err);
    }
  }, []);

  useEffect(() => {
    if (!showLogModal) return;
    fetchFirewallDeploymentLogs();
    const unsub = globalRealtimeClient.subscribe((msg: any) => {
      const type = String(msg?.type || '');
      if (type === 'log.created' || type === 'agent.updated' || type === 'firewall.status' || type === 'firewall.agent_status') {
        fetchFirewallDeploymentLogs();
      }
    });
    const timer = window.setInterval(fetchFirewallDeploymentLogs, 2500);
    return () => {
      unsub();
      window.clearInterval(timer);
    };
  }, [showLogModal, fetchFirewallDeploymentLogs]);

  useEffect(() => {
    if (!showLogModal) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowLogModal(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showLogModal]);

  const fetchFirewall = async () => {
    setLoading(true);
    try {
      const res = await securityApi.getFirewallData();
      setData(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFirewall();
  }, [isBackendOffline]);

  // REST polling is belt-and-braces only — a slow 60s refresh while the
  // socket is not live, mirroring the dashboard's fallback cadence.
  useEffect(() => {
    if (isBackendOffline || liveConnection === 'live') return;
    const timer = window.setInterval(fetchFirewall, 3000);
    return () => window.clearInterval(timer);
  }, [isBackendOffline, liveConnection]);

  // Live stream — firewall-sourced decisions arrive over /ws instantly.
  // The bus broadcasts the same row under two message types
  // ('security_event' and 'security_event.created'), so count each physical
  // event once by its id.
  useEffect(() => {
    if (isBackendOffline) return;
    const unsub = globalRealtimeClient.subscribe(payload => {
      const msgType = String(payload?.type || '');
      if (msgType !== 'security_event' && msgType !== 'security_event.created') return;

      const evt = normalizeRealtimeSecurityEvent(payload.data || payload);
      if (!/^firewall$/i.test(String(evt.source || ''))) return;

      const id = String(evt.id || '');
      if (id) {
        if (seenEventIds.current.has(id)) return;
        seenEventIds.current.add(id);
        if (seenEventIds.current.size > 2000) seenEventIds.current.clear();
      }

      const action = String(evt.action || '').toUpperCase();
      const blocked = ['DENY', 'DROP', 'BLOCK'].includes(action);

      // Optimistic tiles: counters move on the wire, ahead of any DB poll.
      setData(prev => prev ? {
        ...prev,
        activeConnections: Number(prev.activeConnections ?? 0) + 1,
        blockedConnections: Number(prev.blockedConnections ?? 0) + (blocked ? 1 : 0),
        allowedConnections: Number(prev.allowedConnections ?? 0) + (blocked ? 0 : 1),
        rulesTriggeredToday: Number(prev.rulesTriggeredToday ?? 0) + 1,
        threatEventsCount: Number(prev.threatEventsCount ?? prev.blockedConnections ?? 0) + (blocked ? 1 : 0)
      } : prev);


    });
    return unsub;
  }, [isBackendOffline]);

  // Rule lifecycle sync — when any operator creates or toggles an NGFW rule,
  // the server broadcasts 'rule.updated'. Deployment progress (queue + agent
  // ack) arrives as 'firewall.deployment_queued' / 'firewall.agent_status'.
  // Refetch once per burst so every console shows the same ACL and the same
  // enforcement status without touching Refresh.
  useEffect(() => {
    if (isBackendOffline) return;
    const unsub = globalRealtimeClient.subscribe(payload => {
      const type = payload?.type || '';
      const isRuleLifeCycle =
        type === 'rule.updated' && String(payload.data?.ruleType || '') === 'Firewall';
      const isDeploymentProgress = type === 'firewall.deployment_queued' || type === 'firewall.agent_status' || type === 'agent.status' || type === 'agent.heartbeat' || type === 'agent.updated';
      if (!isRuleLifeCycle && !isDeploymentProgress) return;
      if (ruleSyncTimer.current) window.clearTimeout(ruleSyncTimer.current);
      ruleSyncTimer.current = window.setTimeout(() => fetchFirewall(), 250);
    });
    return () => {
      unsub();
      if (ruleSyncTimer.current) window.clearTimeout(ruleSyncTimer.current);
    };
  }, [isBackendOffline]);

  const fetchFail2ban = async () => {
    try {
      setF2bLoading(true);
      const res = await securityApi.getFail2banData();
      if (res?.config) {
        setF2bConfig({
          enabled: Boolean(res.config.enabled),
          bantime: Number(res.config.bantime) || 3600,
          findtime: Number(res.config.findtime) || 600,
          maxretry: Number(res.config.maxretry) || 5,
          ignore_ips: res.config.ignore_ips || ''
        });
      }
      setF2bBans(res?.bans || []);
    } catch (e) {
      console.warn('[Firewall] Failed to load fail2ban data:', e);
    } finally {
      setF2bLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'fail2ban') {
      fetchFail2ban();
    }
  }, [activeTab]);

  const handleSaveFail2ban = async (e: React.FormEvent) => {
    e.preventDefault();
    setF2bMsg(null);
    try {
      await securityApi.updateFail2banConfig(f2bConfig);
      setF2bMsg({ tone: 'ok', text: 'Konfigurasi Fail2ban & Allowlist berhasil disimpan.' });
      setTimeout(() => setF2bMsg(null), 3500);
    } catch {
      setF2bMsg({ tone: 'err', text: 'Gagal menyimpan konfigurasi Fail2ban.' });
    }
  };

  const handleManualBan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualBanIp) return;
    try {
      await securityApi.fail2banBan({ ip: manualBanIp, reason: manualBanReason || 'Manual Admin Ban' });
      setManualBanIp('');
      setManualBanReason('');
      fetchFail2ban();
      fetchFirewall();
    } catch {
      alert('Gagal membanned IP.');
    }
  };

  const handleUnban = async (id: string, ip: string) => {
    try {
      await securityApi.fail2banUnban({ id, ip });
      fetchFail2ban();
      fetchFirewall();
    } catch {
      alert('Gagal me-unban IP.');
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await securityApi.createFirewallRule({
        priority,
        source,
        destination,
        port,
        protocol,
        action,
        description
      });
      setShowAddRuleModal(false);
      setSource('');
      setDestination('');
      setPort('');
      setDescription('');
      fetchFirewall();
    } catch (e) {
      alert('Failed to add firewall rule to backend.');
    }
  };

  // Enable/disable an applied ACL entry — optimistic local echo, then the
  // server's 'rule.updated' broadcast keeps every other console in sync.
  const handleToggleRule = async (rule: FirewallRule) => {
    const enabling = rule.status === 'Disabled';
    try {
      await securityApi.toggleFirewallRule(rule.id, enabling);
      setData(prev => prev ? {
        ...prev,
        rules: (prev.rules || []).map(r => r.id === rule.id
          ? { ...r, enabled: enabling ? 1 : 0, status: enabling ? 'Active' as const : 'Disabled' as const }
          : r)
      } : prev);
    } catch (e) {
      alert('Failed to update firewall rule.');
    }
  };

  // Remove a rule that was misconfigured and already applied. Deleting also
  // removes it from every console over the rule.updated broadcast; the audit
  // log records who deleted it.
  const handleDeleteRule = async (rule: FirewallRule) => {
    if (!confirm(`Delete rule "${rule.id}" (${rule.source} → ${rule.destination}:${rule.port})? The applied entry is removed immediately and cannot be restored.`)) {
      return;
    }
    try {
      await securityApi.deleteFirewallRule(rule.id);
      fetchFirewall();
    } catch (e) {
      alert('Failed to delete firewall rule.');
    }
  };

  const handleDetectServerFirewall = async () => {
    setDetectingServer(true);
    try {
      const res = await securityApi.detectServerFirewall();
      await fetchFirewall();
      if (res?.importedCount && res.importedCount > 0) {
        alert(`Berhasil mendeteksi & mengimpor ${res.importedCount} aturan firewall dari server.`);
      } else {
        alert('Deteksi selesai. Tidak ada aturan firewall server baru yang ditemukan.');
      }
    } catch {
      alert('Gagal mendeteksi aturan firewall server.');
    } finally {
      setDetectingServer(false);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchFirewall} />;
  }

  const rules: FirewallRule[] = data?.rules || [];
  const deployment: FirewallDeployment | undefined = data?.deployment;
  const zones: NetworkInventory[] = data?.zones || data?.networkZones || [];
  const natRules: NatRule[] = data?.natRules || [];

  const term = search.trim().toLowerCase();
  const filteredRules = rules.filter(r =>
    String(r.id || '').toLowerCase().includes(term) ||
    String(r.source || '').toLowerCase().includes(term) ||
    String(r.destination || '').toLowerCase().includes(term) ||
    String(r.port || '').toLowerCase().includes(term) ||
    String(r.description || '').toLowerCase().includes(term)
  );

  const deploymentFailed = deployment?.status === 'FAILED';
  const deploymentOffline = !deployment || deployment.totalAgents === 0 || deployment.status === 'NO_AGENT';

  const firewallStatusLabel = deploymentFailed
    ? 'Error'
    : deploymentOffline
      ? 'Offline'
      : deployment.status === 'APPLIED'
        ? 'Operational'
        : 'Queued';

  const firewallStatusDot = deploymentFailed
    ? 'bg-rose-500'
    : deploymentOffline
      ? 'bg-zinc-400'
      : deployment.status === 'APPLIED'
        ? 'bg-emerald-500'
        : 'bg-amber-400';

  const summaryTiles = [
    { label: 'Firewall Status', value: firewallStatusLabel, dot: firewallStatusDot },
    { label: 'Active Sessions', value: (data?.activeConnections ?? 0).toLocaleString(), dot: 'bg-blue-500' },
    { label: 'Blocked Sessions', value: (data?.blockedConnections ?? 0).toLocaleString(), dot: 'bg-rose-500' },
    { label: 'Allowed Flows', value: (data?.allowedConnections ?? 0).toLocaleString(), dot: 'bg-emerald-500' },
    { label: 'Threat Events', value: (data?.threatEventsCount ?? (data?.blockedConnections ?? 0)).toLocaleString(), dot: 'bg-amber-400' },
    { label: 'Rules Triggered', value: (data?.rulesTriggeredToday ?? 0).toLocaleString(), dot: 'bg-zinc-400' }
  ];

  const tabOptions = [
    { id: 'rules' as const, label: `Firewall Rules (${rules.length})` },
    { id: 'fail2ban' as const, label: `Fail2ban & Allowlist (${f2bBans.filter(b => b.status === 'BANNED').length} active)` },
    { id: 'zones' as const, label: `Security Zones (${zones.length})` },
    { id: 'nat' as const, label: `NAT & Port Forwarding (${natRules.length})` },
    { id: 'access' as const, label: 'Access Control Policies' }
  ];

  return (
    <div className="space-y-5" id="firewall-module-container">
      {/* ── Header — dashboard identity: neutral tenant-style chip ── */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faFire} />}
        title="Next-Gen Firewall"
        titleTail="(NGFW)"
        badge={
          <ModulePageBadge>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Stateful Inspection
          </ModulePageBadge>
        }
        subtitle="Hardware-accelerated packet filtering, zero-trust network zoning, and NAT routing."
        actions={
          <>
            <button
              type="button"
              onClick={handleDetectServerFirewall}
              disabled={detectingServer}
              title="Deteksi aturan firewall aktif di server host (nftables / ufw / iptables)"
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-700 transition hover:bg-zinc-50 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800 disabled:opacity-50"
            >
              <Scan className={`w-3.5 h-3.5 text-zinc-500 ${detectingServer ? 'animate-spin' : ''}`} />
              {detectingServer ? 'Mendeteksi...' : 'Sync Server'}
            </button>
            <button
              type="button"
              onClick={() => setShowLogModal(true)}
              title="View firewall deployment logs & diagnostics"
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-700 transition hover:bg-zinc-50 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              <Terminal className="w-3.5 h-3.5 text-zinc-500" />
              Logs
            </button>
            <button
              onClick={() => setShowAddRuleModal(true)}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Rule
            </button>
          </>
        }
      />

      {/* ── Summary Tiles ── */}
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
            <div className="mt-1.5 text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100 font-mono">
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

      {/* ── Tab 1: Firewall Rules ── */}
      {activeTab === 'rules' && (
        <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
          <header className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
                Perimeter Access Control List (ACL)
              </h2>
              <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5">
                Evaluated top-down by priority number (lowest priority number executed first)
              </p>
              {deployment && (
                <p
                  title={
                    deployment.totalAgents === 0
                      ? 'No endpoint agent is enrolled; the ACL is enforced nowhere yet.'
                      : deployment.agents
                          .map(a => `${a.hostname || a.name} · ${a.status} (${a.ip || 'no ip'})${a.message ? ` — ${a.message}` : ''}`)
                          .join('\n')
                  }
                  className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] font-semibold"
                >
                  <span className={`
                    h-1.5 w-1.5 rounded-full shrink-0 ${
                      deployment.status === 'APPLIED'
                        ? 'bg-emerald-500'
                        : deployment.status === 'FAILED'
                          ? 'bg-rose-500'
                          : deployment.status === 'NO_AGENT'
                            ? 'bg-zinc-400'
                            : 'bg-amber-500'
                    }
                    ${deployment.status === 'PENDING' || deployment.status === 'FAILED' ? 'animate-pulse' : ''}`}
                  />
                  <span className="text-zinc-500 dark:text-zinc-400">
                    {deployment.status === 'NO_AGENT'
                      ? 'No endpoint agent enrolled'
                      : deployment.status === 'APPLIED'
                        ? `Revision ${deployment.revision} applied on ${deployment.appliedAgents}/${deployment.totalAgents}`
                        : deployment.status === 'PENDING'
                          ? `Revision ${deployment.revision} queued · ${deployment.appliedAgents}/${deployment.totalAgents} applied`
                          : deployment.status === 'FAILED'
                            ? `Revision ${deployment.revision} — ${deployment.failedAgents} agent(s) failed`
                            : deployment.status === 'PARTIAL'
                              ? `Revision ${deployment.revision} applied on ${deployment.appliedAgents}/${deployment.totalAgents} (unsupported hosts: ${deployment.unsupportedAgents})`
                              : `Revision ${deployment.revision} queued — no agent can enforce it`}
                  </span>
                  {deployment.totalAgents > 0 && (
                    <span className="font-medium text-zinc-400 dark:text-zinc-500">
                      · {deployment.onlineAgents} agent(s) online
                    </span>
                  )}
                </p>
              )}
            </div>
            <div className="relative w-full sm:w-auto">
              <Search className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search rule ID, IP, port, description…"
                className="h-8 w-full sm:w-64 rounded-lg border border-zinc-200/80 bg-white pl-8 pr-3 text-xs text-zinc-800 placeholder-zinc-400 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder-zinc-500 dark:focus:border-zinc-600"
              />
            </div>
          </header>

          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full min-w-[980px] text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-zinc-100 dark:border-zinc-800 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/40 dark:bg-zinc-900/20">
                  <th className="py-3 px-4">Priority</th>
                  <th className="py-3 px-4">Rule ID</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Destination</th>
                  <th className="py-3 px-4">Port</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4">Description</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/80">
                {filteredRules.length === 0 ? (
                  <tr>
                    <td colSpan={11} className="py-10 text-center font-sans text-xs text-zinc-400 dark:text-zinc-500">
                      No firewall rules matching your search.
                    </td>
                  </tr>
                ) : (
                  filteredRules.map(r => (
                    <tr key={r.id} className="hover:bg-zinc-50/80 dark:hover:bg-zinc-900/40 transition-colors">
                      <td className="py-3 px-4 font-bold text-zinc-800 dark:text-zinc-200">{r.priority}</td>
                      <td className="py-3 px-4 text-zinc-600 dark:text-zinc-400">{r.id}</td>
                      <td className="py-3 px-4 text-zinc-800 dark:text-zinc-200">{r.source}</td>
                      <td className="py-3 px-4 text-zinc-800 dark:text-zinc-200">{r.destination}</td>
                      <td className="py-3 px-4 text-amber-600 dark:text-amber-400">{r.port}</td>
                      <td className="py-3 px-4 text-zinc-700 dark:text-zinc-300 font-semibold">{r.protocol}</td>
                      <td className="py-3 px-4"><StatusBadge type="action" value={r.action} /></td>
                      <td className="py-3 px-4"><StatusBadge type="health" value={r.status || 'Active'} /></td>
                      <td className="py-3 px-4 text-zinc-400 dark:text-zinc-500 font-sans text-[11px]">{r.created}</td>
                      <td className="py-3 px-4 font-sans text-zinc-500 dark:text-zinc-400 text-[11px]">{r.description}</td>
                      <td className="py-3 px-4 text-right font-sans">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleToggleRule(r)}
                            title={r.status === 'Disabled' ? 'Enable this firewall rule' : 'Disable this firewall rule without deleting it'}
                            className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-medium border transition cursor-pointer ${
                              r.status === 'Disabled'
                                ? 'border-zinc-200 dark:border-zinc-700 text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/20'
                                : 'border-zinc-200 dark:border-zinc-700 text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20'
                            }`}
                          >
                            {r.status === 'Disabled' ? 'Enable' : 'Disable'}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteRule(r)}
                            title="Delete the applied firewall rule"
                            className="inline-flex items-center p-1 rounded-lg border border-zinc-200 dark:border-zinc-700 text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 transition cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
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

      {/* ── Tab: Fail2ban & Allowlist ── */}
      {activeTab === 'fail2ban' && (
        <div className="space-y-5">
          {f2bMsg && (
            <div className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
              f2bMsg.tone === 'ok'
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400'
                : 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400'
            }`}>
              <span>{f2bMsg.text}</span>
              <button type="button" onClick={() => setF2bMsg(null)} className="cursor-pointer font-bold">×</button>
            </div>
          )}

          {/* Form Konfigurasi Fail2ban & Allowlist */}
          <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
            <div className="flex items-center justify-between pb-3.5 border-b border-zinc-100 dark:border-zinc-800">
              <div>
                <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  Fail2ban Engine & IP Allowlist Configuration
                </h3>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                  Configure automated ban thresholds and trusted IP exclusion lists (whitelist / allowlist).
                </p>
              </div>
              <label className="flex items-center gap-2 cursor-pointer text-xs font-semibold">
                <input
                  type="checkbox"
                  checked={f2bConfig.enabled}
                  onChange={e => setF2bConfig(c => ({ ...c, enabled: e.target.checked }))}
                  className="rounded text-zinc-900 focus:ring-0"
                />
                Fail2ban Active
              </label>
            </div>

            <form onSubmit={handleSaveFail2ban} className="mt-4 space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    Max Retry (Failure Threshold)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={f2bConfig.maxretry}
                    onChange={e => setF2bConfig(c => ({ ...c, maxretry: Number(e.target.value) }))}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 font-mono"
                  />
                  <p className="text-[10px] text-zinc-400 mt-1">Number of failed attempts before an IP address is banned.</p>
                </div>

                <div>
                  <label className="block font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    Find Time (Detection Window)
                  </label>
                  <div className="flex items-center gap-1.5">
                    <input
                      type="number"
                      min={10}
                      value={f2bConfig.findtime}
                      onChange={e => setF2bConfig(c => ({ ...c, findtime: Number(e.target.value) }))}
                      className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 font-mono"
                    />
                    <span className="text-[11px] text-zinc-400">seconds</span>
                  </div>
                  <p className="text-[10px] text-zinc-400 mt-1">Time window to accumulate failed attempts.</p>
                </div>

                <div>
                  <label className="block font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    Ban Time (Block Duration)
                  </label>
                  <div className="flex items-center gap-1.5">
                    <input
                      type="number"
                      min={60}
                      value={f2bConfig.bantime}
                      onChange={e => setF2bConfig(c => ({ ...c, bantime: Number(e.target.value) }))}
                      className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 font-mono"
                    />
                    <span className="text-[11px] text-zinc-400">seconds</span>
                  </div>
                  <p className="text-[10px] text-zinc-400 mt-1">Duration of the ban (3600 = 1 hour).</p>
                </div>
              </div>

              <div>
                <label className="block font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  Allowlist IPs / Subnets (Ignore IP)
                </label>
                <textarea
                  rows={2}
                  value={f2bConfig.ignore_ips}
                  onChange={e => setF2bConfig(c => ({ ...c, ignore_ips: e.target.value }))}
                  placeholder="e.g. 127.0.0.1/8, ::1, 10.0.0.0/8, 192.168.1.50"
                  className="w-full rounded-lg border border-zinc-200/80 bg-white p-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200"
                />
                <p className="text-[10px] text-zinc-400 mt-1">
                  List of IP addresses or CIDR subnets that will never be banned (separated by commas or newlines).
                </p>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  className="h-8 px-4 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold hover:opacity-90 cursor-pointer"
                >
                  Save Fail2ban Configuration
                </button>
              </div>
            </form>
          </section>

          {/* Manual Ban Box */}
          <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
              Manual Fail2ban IP Ban
            </h3>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-3">
              Enter the attacker IP address to immediately ban in Fail2ban jails and perimeter firewall.
            </p>
            <form onSubmit={handleManualBan} className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                required
                value={manualBanIp}
                onChange={e => setManualBanIp(e.target.value)}
                placeholder="IP Address (e.g. 198.51.100.77)"
                className="h-8 w-60 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200"
              />
              <input
                type="text"
                value={manualBanReason}
                onChange={e => setManualBanReason(e.target.value)}
                placeholder="Ban reason (optional)"
                className="h-8 w-72 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200"
              />
              <button
                type="submit"
                className="h-8 px-3.5 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold cursor-pointer"
              >
                Ban IP Now
              </button>
            </form>
          </section>

          {/* Daftar Banned IPs & Tombol Unban */}
          <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
            <header className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  Active Banned IP Inventory ({f2bBans.length})
                </h3>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                  IP addresses currently blocked by Fail2ban. Click "Unban" to restore network access.
                </p>
              </div>
            </header>

            <div className="overflow-x-auto custom-scrollbar">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-zinc-100 dark:border-zinc-800 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/40 dark:bg-zinc-900/20">
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">IP Address</th>
                    <th className="py-3 px-4">Jail</th>
                    <th className="py-3 px-4">Ban Reason</th>
                    <th className="py-3 px-4">Ban Time</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
                  {f2bBans.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-zinc-400 font-sans">
                        No IP addresses are currently banned by Fail2ban.
                      </td>
                    </tr>
                  ) : (
                    f2bBans.map(b => (
                      <tr key={b.id} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/30">
                        <td className="py-2.5 px-4 font-sans">
                          {b.status === 'BANNED' ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                              Banned
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border border-zinc-500/20">
                              Unbanned
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-bold text-zinc-900 dark:text-zinc-100">
                          {b.ip}
                        </td>
                        <td className="py-2.5 px-4 text-zinc-600 dark:text-zinc-400">
                          {b.jail || 'sshd'}
                        </td>
                        <td className="py-2.5 px-4 text-zinc-600 dark:text-zinc-400 max-w-xs truncate font-sans">
                          {b.reason || 'Multiple failed authentication attempts'}
                        </td>
                        <td className="py-2.5 px-4 text-zinc-400 text-[11px]">
                          {b.banned_at || '-'}
                        </td>
                        <td className="py-2.5 px-4 text-right font-sans">
                          {b.status === 'BANNED' ? (
                            <button
                              type="button"
                              onClick={() => handleUnban(b.id, b.ip)}
                              className="px-2.5 py-1 rounded-lg bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 hover:bg-emerald-100 dark:hover:bg-emerald-900/40 text-xs font-semibold cursor-pointer transition"
                            >
                              Unban IP
                            </button>
                          ) : (
                            <span className="text-zinc-400 text-[11px] italic">Sudah di-unban</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}

      {/* ── Tab 2: Security Zones ── */}
      {activeTab === 'zones' && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
                Security Zones & Zero-Trust Segmentation
              </h2>
              <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5">
                Perimeter isolation, CIDR boundaries, and ingress/egress policy enforcement across environments.
              </p>
            </div>
            <button
              onClick={() => {
                setZoneFormError(null);
                setShowAddZoneModal(true);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:hover:bg-zinc-100 text-white dark:text-zinc-900 text-xs font-medium cursor-pointer transition shadow-2xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Security Zone</span>
            </button>
          </div>

          {zones.length === 0 ? (
            <div className="p-10 text-center rounded-2xl border border-dashed border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-3">
              <Network className="w-10 h-10 text-zinc-300 dark:text-zinc-600 mx-auto" />
              <div>
                <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">No Security Zones Configured</h3>
                <p className="text-xs text-zinc-400 dark:text-zinc-500 mt-1">
                  Create network security zones (DMZ, Internal Core, Database, etc.) to enforce zero-trust perimeter segmentation.
                </p>
              </div>
              <button
                onClick={() => {
                  setZoneFormError(null);
                  setShowAddZoneModal(true);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 text-xs font-medium cursor-pointer hover:opacity-90 transition"
              >
                <Plus className="w-3.5 h-3.5" />
                Add Security Zone
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {zones.map(zone => (
                <div key={zone.id} className="p-5 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-3 shadow-2xs flex flex-col justify-between">
                  <div>
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="font-semibold text-zinc-900 dark:text-white flex items-center gap-2">
                        <Network className="w-4 h-4 text-emerald-500 shrink-0" />
                        <span className="truncate">{zone.name}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <StatusBadge type="health" value={zone.status} />
                        <button
                          onClick={() => handleDeleteZone(zone.id, zone.name)}
                          title="Delete Security Zone"
                          className="p-1 rounded text-zinc-400 hover:text-rose-500 dark:hover:text-rose-400 transition cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    {zone.description && (
                      <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mb-3 line-clamp-2">
                        {zone.description}
                      </p>
                    )}
                    <div className="grid grid-cols-2 gap-2 text-xs font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-50/60 dark:bg-zinc-900/40 p-3 rounded-xl border border-zinc-100 dark:border-zinc-800/60">
                      <div><span className="text-zinc-400 dark:text-zinc-500 block text-[10px]">CIDR</span> {zone.cidr}</div>
                      <div><span className="text-zinc-400 dark:text-zinc-500 block text-[10px]">GATEWAY</span> {zone.gateway}</div>
                      <div><span className="text-zinc-400 dark:text-zinc-500 block text-[10px]">INTERFACE</span> {zone.interface || 'eth0'}</div>
                      <div><span className="text-zinc-400 dark:text-zinc-500 block text-[10px]">FIREWALL</span> {zone.firewall}</div>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between text-xs">
                    <span className="text-zinc-500 dark:text-zinc-400">
                      Zone: <span className="text-zinc-800 dark:text-zinc-200 font-mono font-medium">{zone.zone}</span>
                    </span>
                    <StatusBadge type="severity" value={zone.riskLevel} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* ── Tab 3: NAT Configuration ── */}
      {activeTab === 'nat' && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
                Carrier-Grade NAT & Port Redirection Policies
              </h2>
              <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5">
                Translates external ingress VIP / WAN ports to internal DMZ backend applications.
              </p>
            </div>
            <button
              onClick={() => {
                setNatFormError(null);
                setShowAddNatModal(true);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:hover:bg-zinc-100 text-white dark:text-zinc-900 text-xs font-medium cursor-pointer transition shadow-2xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Port Forwarding Rule</span>
            </button>
          </div>

          <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
            <div className="overflow-x-auto custom-scrollbar">
              <table className="w-full min-w-[760px] text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-zinc-100 dark:border-zinc-800 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/40 dark:bg-zinc-900/20">
                    <th className="py-3 px-4">Rule Name</th>
                    <th className="py-3 px-4">Protocol</th>
                    <th className="py-3 px-4">External Ingress</th>
                    <th className="py-3 px-4">Internal Target</th>
                    <th className="py-3 px-4">NAT Mode</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/80 text-zinc-800 dark:text-zinc-200">
                  {natRules.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-xs text-zinc-400 font-sans">
                        No port forwarding or NAT rules configured. Click "Add Port Forwarding Rule" to create one.
                      </td>
                    </tr>
                  ) : (
                    natRules.map(rule => (
                      <tr key={rule.id} className="hover:bg-zinc-50/80 dark:hover:bg-zinc-900/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-sans font-semibold text-zinc-900 dark:text-zinc-100">{rule.name}</div>
                          {rule.description && (
                            <div className="text-[11px] text-zinc-400 dark:text-zinc-500 font-sans truncate max-w-xs">{rule.description}</div>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                            {rule.protocol}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-zinc-700 dark:text-zinc-300">
                          <span>{rule.external_vip}</span>
                          <span className="text-amber-600 dark:text-amber-400 font-bold">:{rule.external_port}</span>
                        </td>
                        <td className="py-3 px-4 text-zinc-700 dark:text-zinc-300">
                          <span>{rule.internal_ip}</span>
                          <span className="text-emerald-600 dark:text-emerald-400 font-bold">:{rule.internal_port}</span>
                        </td>
                        <td className="py-3 px-4 text-zinc-600 dark:text-zinc-400 font-sans">
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                            {rule.nat_mode}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <button
                            type="button"
                            onClick={() => handleToggleNatRule(rule.id)}
                            className={`cursor-pointer inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium transition ${
                              rule.enabled
                                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20'
                                : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-400 border border-zinc-200 dark:border-zinc-700 hover:bg-zinc-200 dark:hover:bg-zinc-700'
                            }`}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-emerald-500' : 'bg-zinc-400'}`} />
                            {rule.enabled ? 'Active' : 'Disabled'}
                          </button>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => handleDeleteNatRule(rule.id, rule.name)}
                            title="Hapus Rule NAT"
                            className="p-1 rounded text-zinc-400 hover:text-rose-500 dark:hover:text-rose-400 transition cursor-pointer"
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
          </div>
        </section>
      )}

      {/* ── Tab 4: Access Control ── */}
      {activeTab === 'access' && (
        <div className="space-y-4">
          <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-5 shadow-2xs">
            <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-200 mb-1">
              Strict Layer 4 Protocol Enforcements
            </h3>
            <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mb-4">
              In accordance with Zero Trust posture, all non-explicitly allowed protocols are dropped by default at ingress
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl border border-zinc-200/80 bg-zinc-50/50 dark:border-zinc-800 dark:bg-zinc-900/50">
                <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 mb-1">TCP SYN Flood Mitigation</div>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">SYN Cookies active with sliding threshold at 150,000 pps.</p>
                <div className="mt-2 text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-medium">ACTIVE: ENFORCING</div>
              </div>
              <div className="p-4 rounded-xl border border-zinc-200/80 bg-zinc-50/50 dark:border-zinc-800 dark:bg-zinc-900/50">
                <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 mb-1">UDP Amplification Drop</div>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Blocks unrequested NTP, DNS (53), and SNMP reflection packets.</p>
                <div className="mt-2 text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-medium">ACTIVE: ENFORCING</div>
              </div>
              <div className="p-4 rounded-xl border border-zinc-200/80 bg-zinc-50/50 dark:border-zinc-800 dark:bg-zinc-900/50">
                <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 mb-1">ICMP Ping Sweep Suppression</div>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Suppresses external discovery pings across perimeter subnets.</p>
                <div className="mt-2 text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-medium">ACTIVE: LOGGING</div>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* ── Modal: Add Port Forwarding / NAT Rule ── */}
      {showAddNatModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="relative w-full max-w-md rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-amber-500" />
                <h3 className="text-sm font-semibold">Add Port Forwarding (NAT) Rule</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddNatModal(false)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {natFormError && (
              <div className="mt-3 p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-600 dark:text-rose-400 text-xs">
                {natFormError}
              </div>
            )}

            <form onSubmit={handleCreateNatRule} className="space-y-3.5 pt-4 text-xs">
              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={newNatName}
                  onChange={e => setNewNatName(e.target.value)}
                  placeholder="e.g. Web Ingress HTTPS, Bastion SSH, DB Proxy"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">External VIP / Ingress IP</label>
                  <input
                    type="text"
                    required
                    value={newNatVip}
                    onChange={e => setNewNatVip(e.target.value)}
                    placeholder="0.0.0.0 or 172.67.182.90"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">External Port</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    required
                    value={newNatExtPort}
                    onChange={e => setNewNatExtPort(e.target.value.replace(/\D/g, ''))}
                    placeholder="443"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Internal Target IP</label>
                  <input
                    type="text"
                    required
                    value={newNatIntIp}
                    onChange={e => setNewNatIntIp(e.target.value)}
                    placeholder="10.240.10.14"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Internal Target Port</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    required
                    value={newNatIntPort}
                    onChange={e => setNewNatIntPort(e.target.value.replace(/\D/g, ''))}
                    placeholder="8443"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Protocol</label>
                  <select
                    value={newNatProtocol}
                    onChange={e => setNewNatProtocol(e.target.value as any)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="TCP/UDP">TCP/UDP</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">NAT Mode</label>
                  <select
                    value={newNatMode}
                    onChange={e => setNewNatMode(e.target.value as any)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="DNAT">Destination NAT (DNAT)</option>
                    <option value="Full Cone NAT">Full Cone NAT</option>
                    <option value="SNAT">Source NAT (SNAT)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Description (Optional)</label>
                <input
                  type="text"
                  value={newNatDesc}
                  onChange={e => setNewNatDesc(e.target.value)}
                  placeholder="e.g. Redirect public port 443 to internal mTLS service"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  onClick={() => setShowAddNatModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={natSaving}
                  className="px-3.5 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:hover:bg-zinc-100 text-white dark:text-zinc-900 font-medium cursor-pointer disabled:opacity-50"
                >
                  {natSaving ? 'Saving...' : 'Add Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Add Security Zone ── */}
      {showAddZoneModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="relative w-full max-w-md rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-emerald-500" />
                <h3 className="text-sm font-semibold">Add Security Zone</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddZoneModal(false)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {zoneFormError && (
              <div className="mt-3 p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-600 dark:text-rose-400 text-xs">
                {zoneFormError}
              </div>
            )}

            <form onSubmit={handleCreateZone} className="space-y-3.5 pt-4 text-xs">
              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Zone / Subnet Name</label>
                <input
                  type="text"
                  required
                  value={newZoneName}
                  onChange={e => setNewZoneName(e.target.value)}
                  placeholder="e.g. Edge DMZ, Internal Microservices, DB Cluster"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Subnet CIDR</label>
                  <input
                    type="text"
                    required
                    value={newZoneCidr}
                    onChange={e => setNewZoneCidr(e.target.value)}
                    placeholder="10.240.10.0/24"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Default Gateway</label>
                  <input
                    type="text"
                    value={newZoneGateway}
                    onChange={e => setNewZoneGateway(e.target.value)}
                    placeholder="10.240.10.1"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Zone Classification</label>
                  <select
                    value={newZoneType}
                    onChange={e => setNewZoneType(e.target.value)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="DMZ">DMZ (Ingress)</option>
                    <option value="Internal Core">Internal Core</option>
                    <option value="Database Cluster">Database Cluster</option>
                    <option value="Cloud VPC">Cloud VPC</option>
                    <option value="Corporate Office">Corporate Office</option>
                    <option value="Payment Gateway">Payment Gateway</option>
                    <option value="Edge Proxy">Edge Proxy</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Firewall Engine</label>
                  <select
                    value={newZoneFirewall}
                    onChange={e => setNewZoneFirewall(e.target.value)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="OAT NGFW">OAT NGFW</option>
                    <option value="Linux nftables">Linux nftables</option>
                    <option value="Cloud Security Group">Cloud Security Group</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">NIC Interface</label>
                <input
                  type="text"
                  value={newZoneInterface}
                  onChange={e => setNewZoneInterface(e.target.value)}
                  placeholder="eth0"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Description (Optional)</label>
                <input
                  type="text"
                  value={newZoneDesc}
                  onChange={e => setNewZoneDesc(e.target.value)}
                  placeholder="e.g. Scoped perimeter network for public web services"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  onClick={() => setShowAddZoneModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={zoneSaving}
                  className="px-3.5 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:hover:bg-zinc-100 text-white dark:text-zinc-900 font-medium cursor-pointer disabled:opacity-50"
                >
                  {zoneSaving ? 'Saving...' : 'Create Zone'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Add Firewall Rule ── */}
      {showAddRuleModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="relative w-full max-w-lg rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-zinc-500" />
                <h3 className="text-sm font-semibold">Add Enterprise Firewall Rule</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddRuleModal(false)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3.5 pt-4 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Priority (1 - 1000)</label>
                  <input
                    type="number"
                    required
                    value={priority}
                    onChange={e => setPriority(Number(e.target.value))}
                    placeholder="Masukkan prioritas rule (1 - 1000)"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 font-mono dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Action</label>
                  <select 
                    value={action}
                    onChange={e => setAction(e.target.value as any)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY</option>
                    <option value="LOG">LOG</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Source (IP or CIDR)</label>
                  <input
                    type="text"
                    required
                    value={source}
                    onChange={e => setSource(e.target.value)}
                    placeholder="Masukkan source IP atau CIDR (contoh: 203.0.113.0/24 atau ANY)"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Destination (IP or CIDR)</label>
                  <input
                    type="text"
                    required
                    value={destination}
                    onChange={e => setDestination(e.target.value)}
                    placeholder="Masukkan destination IP atau CIDR (contoh: 203.0.113.0/24 atau ANY)"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Port</label>
                  <input
                    type="text"
                    required
                    value={port}
                    onChange={e => setPort(e.target.value)}
                    placeholder="Masukkan port (contoh: 443, 8443, atau ANY)"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Protocol</label>
                  <select 
                    value={protocol}
                    onChange={e => setProtocol(e.target.value as any)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 font-mono dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="ANY">ANY</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Rule Description</label>
                <input
                  type="text"
                  required
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  placeholder="Masukkan deskripsi rule (contoh: Isolate DMZ from core database)"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="pt-3 flex items-center justify-end gap-2 border-t border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  onClick={() => setShowAddRuleModal(false)}
                  className="inline-flex h-8 items-center rounded-lg border border-zinc-200/80 bg-white px-3 text-xs text-zinc-600 hover:bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="inline-flex h-8 items-center rounded-lg bg-zinc-900 px-3.5 text-xs font-medium text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 cursor-pointer"
                >
                  Commit Rule to Firewall
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      {/* ── Drawer: Firewall Diagnostics & Logs ── */}
      {showLogModal && (
        <div className="fixed inset-0 z-50">
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200"
            onClick={() => setShowLogModal(false)}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Firewall deployment diagnostics"
            className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-zinc-200/80 bg-white text-zinc-900 shadow-2xl animate-in slide-in-from-right duration-300 ease-out dark:border-zinc-800 dark:bg-[#0b0b0d] dark:text-zinc-100 sm:max-w-[560px] lg:max-w-[640px]"
          >
            <div className="flex justify-center pb-0.5 pt-2.5 sm:hidden">
              <div className="h-1 w-10 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            </div>

            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pt-5 pb-4 dark:border-zinc-800 dark:bg-[#0c0c0e] sm:px-6">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
                    Firewall Inspection & Logs
                  </h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                    NGFW packet filtering & perimeter kernel deployment
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowLogModal(false)}
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-800 dark:hover:text-zinc-200 transition cursor-pointer"
                  title="Close (Esc)"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

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
                    {firewallAuditLogs.length + (deployment?.agents?.length || 0)}
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

            <div className="flex-1 overflow-y-auto divide-y divide-zinc-100 dark:divide-zinc-800/80 custom-scrollbar">
              {drawerTab === 'logs' ? (() => {
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

                for (const agent of (deployment?.agents || [])) {
                  const isFailed = agent.status === 'FAILED';
                  const isApplied = agent.status === 'APPLIED';
                  const host = agent.hostname || agent.name || 'Host';

                  if (isFailed) {
                    items.push({
                      id: `agent-fail-${agent.id}`,
                      avatar: 'ERROR',
                      tone: 'error',
                      title: `${host} · Firewall Installation Failed`,
                      subtitle: 'Firewall / nftables Installation Error',
                      desc: agent.message || 'Failed to apply nftables kernel rules on the host.',
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
                      desc: `nftables perimeter rules loaded (${agent.rulesApplied || 0} active rules).`,
                      timestamp: agent.appliedAt ? formatTime(agent.appliedAt) : (agent.lastSeen ? formatTime(agent.lastSeen) : 'Active'),
                      isFailed: false
                    });
                  } else {
                    items.push({
                      id: `agent-pend-${agent.id}`,
                      avatar: 'PENDING',
                      tone: 'warn',
                      title: `${host} · Awaiting Agent Check-in`,
                      subtitle: `Queue Revision ${deployment?.revision || 1}`,
                      desc: agent.message || 'Agent has not acknowledged applying firewall rules to kernel.',
                      timestamp: agent.lastSeen ? formatTime(agent.lastSeen) : 'Waiting',
                      isFailed: false
                    });
                  }
                }

                for (const log of firewallAuditLogs) {
                  const msg = String(log.message || '');
                  const isError = log.severity === 'HIGH' || log.severity === 'CRITICAL' || msg.toLowerCase().includes('fail') || msg.toLowerCase().includes('error');
                  const avatar = isError ? 'ERROR' : 'OPERATIONAL';
                  items.push({
                    id: `audit-${log.id || Math.random()}`,
                    avatar,
                    tone: isError ? 'error' : 'ok',
                    title: log.source ? `Firewall ${String(log.source).toUpperCase()}` : 'Firewall Event',
                    subtitle: log.eventType || 'Perimeter Inspection',
                    desc: msg,
                    timestamp: log.timestamp ? formatTime(log.timestamp) : 'Recent',
                    isFailed: isError
                  });
                }

                if (items.length === 0) {
                  return (
                    <div className="p-8 text-center text-xs text-zinc-400">
                      No error logs or firewall installation events recorded yet.
                    </div>
                  );
                }

                return items.map(item => (
                  <div key={item.id} className="p-4 hover:bg-zinc-50/60 dark:hover:bg-zinc-900/40 transition space-y-2">
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
                      <span className="text-[10px] text-zinc-400 font-mono shrink-0">
                        {item.timestamp}
                      </span>
                    </div>

                    {/* Middle details */}
                    <div>
                      <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                        {item.title}
                      </h3>
                      <p className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mt-0.5">
                        {item.subtitle}
                      </p>
                      <p className="text-xs text-zinc-600 dark:text-zinc-300 mt-1.5 font-mono break-all bg-zinc-50 dark:bg-zinc-900/60 p-2 rounded-lg border border-zinc-100 dark:border-zinc-800">
                        {item.desc}
                      </p>
                    </div>
                  </div>
                ));
              })() : (
                <div className="p-5 space-y-4 text-xs font-mono">
                  <div className="p-3.5 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/30">
                    <div className="font-semibold text-zinc-900 dark:text-zinc-100 font-sans mb-1">State Kernel nftables</div>
                    <div className="text-zinc-500 text-[11px]">Table: inet oat_ngfw</div>
                    <div className="text-zinc-500 text-[11px]">Revision: {deployment?.revision || 1}</div>
                    <div className="text-zinc-500 text-[11px]">Status: {deployment?.status || 'READY'}</div>
                    <div className="text-zinc-500 text-[11px]">Enforcement: {deployment?.appliedAgents || 0} / {deployment?.totalAgents || 0} host</div>
                  </div>
                </div>
              )}
            </div>
          </aside>
        </div>
      )}
    </div>
  );
};
