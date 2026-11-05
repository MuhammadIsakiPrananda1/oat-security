import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Network,
  Plus,
  Search,
  RefreshCw,
  X,
  Trash2,
  Pencil,
  ShieldCheck,
  Server,
  Activity,
  TriangleAlert,
  Info
} from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { NetworkInventory } from '../../types';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faNetworkWired } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';
import { parseCidr, suggestGateway, isIpv4 } from '../../utils/network';

const ZONE_OPTIONS = [
  'DMZ',
  'Internal Core',
  'Cloud VPC',
  'Corporate Office',
  'Database Cluster',
  'Payment Gateway',
  'Edge Proxy'
];

const FIREWALL_OPTIONS = [
  'OAT NGFW',
  'OAT WAF + NGFW',
  'Linux nftables',
  'Cloud Security Group'
];

const formatNumber = (value: number | undefined): string =>
  Number(value || 0).toLocaleString();

const formatClock = (date: Date | null): string =>
  date ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';

export const NetworksModule: React.FC = () => {
  const { isBackendOffline } = useAuth();
  const [networks, setNetworks] = useState<NetworkInventory[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState('');
  const [error, setError] = useState('');
  const [lastSynced, setLastSynced] = useState<Date | null>(null);

  // Add / edit form
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<NetworkInventory | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [gateway, setGateway] = useState('');
  const [zone, setZone] = useState('DMZ');
  const [firewall, setFirewall] = useState('OAT NGFW');
  const [iface, setIface] = useState('eth0');
  const [description, setDescription] = useState('');

  const realtimeTimer = useRef<number | null>(null);

  const fetchNetworks = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    try {
      const res = await securityApi.getNetworks();
      setNetworks(res?.networks || []);
      setError('');
      setLastSynced(new Date());
    } catch (err: any) {
      setError(err?.message || 'Unable to load the network inventory.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchNetworks();
  }, [fetchNetworks, isBackendOffline]);

  // Keep derived telemetry (hosts, traffic, risk) fresh while the page is open.
  useEffect(() => {
    if (isBackendOffline) return;
    const timer = window.setInterval(() => fetchNetworks(true), 5000);
    return () => window.clearInterval(timer);
  }, [fetchNetworks, isBackendOffline]);

  // Refresh shortly after real telemetry arrives, debounced so bursts of
  // events cause a single inventory reload.
  useEffect(() => {
    if (isBackendOffline) return;
    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      const type = String(msg?.type || '');
      const relevant =
        type === 'network.updated' ||
        type === 'network.created' ||
        type === 'network.deleted' ||
        type === 'security_event' ||
        type === 'security_event.created' ||
        type === 'log.created' ||
        type === 'agent.updated' ||
        type === 'agent.heartbeat';
      if (!relevant) return;
      if (realtimeTimer.current) return;
      realtimeTimer.current = window.setTimeout(() => {
        realtimeTimer.current = null;
        fetchNetworks(true);
      }, 1000);
    });

    return () => {
      unsubscribe();
      if (realtimeTimer.current) {
        window.clearTimeout(realtimeTimer.current);
        realtimeTimer.current = null;
      }
    };
  }, [fetchNetworks, isBackendOffline]);

  const resetForm = () => {
    setName('');
    setCidr('');
    setGateway('');
    setZone('DMZ');
    setFirewall('OAT NGFW');
    setIface('eth0');
    setDescription('');
    setFormError('');
  };

  const openAdd = () => {
    setEditing(null);
    resetForm();
    setShowForm(true);
  };

  const openEdit = (net: NetworkInventory) => {
    setEditing(net);
    setName(net.name || '');
    setCidr(net.cidr || '');
    setGateway(net.gateway || '');
    setZone(net.zone || 'DMZ');
    setFirewall(net.firewall || 'OAT NGFW');
    setIface(net.interface || 'eth0');
    setDescription(net.description || '');
    setFormError('');
    setShowForm(true);
  };

  const closeForm = () => {
    if (saving) return;
    setShowForm(false);
    setEditing(null);
    setFormError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');

    const trimmedName = name.trim();
    if (!trimmedName) {
      setFormError('Subnet name is required.');
      return;
    }

    const parsed = parseCidr(cidr);
    if (!parsed) {
      setFormError('CIDR is invalid. Use IPv4 notation such as 10.240.10.0/24 (or a single address for /32).');
      return;
    }

    const gatewayValue = gateway.trim();
    if (gatewayValue && !isIpv4(gatewayValue)) {
      setFormError('Default gateway must be a valid IPv4 address, e.g. 10.240.10.1.');
      return;
    }

    const payload: Partial<NetworkInventory> = {
      name: trimmedName,
      cidr: parsed.cidr,
      gateway: gatewayValue || suggestGateway(parsed.cidr),
      zone,
      firewall,
      interface: iface.trim() || 'eth0',
      description: description.trim()
    };

    setSaving(true);
    try {
      if (editing) {
        await securityApi.updateNetwork(editing.id, payload);
      } else {
        await securityApi.createNetwork(payload);
      }
      setShowForm(false);
      setEditing(null);
      resetForm();
      await fetchNetworks(true);
    } catch (err: any) {
      setFormError(err?.message || 'Failed to save the subnet.');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteNetwork = async (net: NetworkInventory) => {
    if (!window.confirm(`Hapus subnet ${net.name} (${net.cidr})?`)) return;
    try {
      await securityApi.deleteNetwork(net.id);
      await fetchNetworks(true);
    } catch (err: any) {
      setError(err?.message || 'Gagal menghapus subnet.');
    }
  };

  const filtered = useMemo(() => {
    const term = (search || '').trim().toLowerCase();
    if (!term) return networks;
    return networks.filter(n =>
      String(n.name || '').toLowerCase().includes(term) ||
      String(n.cidr || '').toLowerCase().includes(term) ||
      String(n.zone || '').toLowerCase().includes(term) ||
      String(n.gateway || '').toLowerCase().includes(term) ||
      String(n.firewall || '').toLowerCase().includes(term)
    );
  }, [networks, search]);

  const totals = useMemo(() => {
    const totalHosts = networks.reduce((acc, n) => acc + (Number(n.devicesCount) || 0), 0);
    const totalTraffic = networks.reduce((acc, n) => acc + (Number(n.trafficVolume) || 0), 0);
    const dmzCount = networks.filter(n => String(n.zone || '').includes('DMZ')).length;
    const atRisk = networks.filter(n => n.riskLevel === 'High' || n.riskLevel === 'Critical').length;
    return { totalHosts, totalTraffic, dmzCount, atRisk };
  }, [networks]);

  const summaryTiles = [
    { label: 'Subnet Segments', value: formatNumber(networks.length), icon: Network, dot: 'bg-emerald-500' },
    { label: 'Connected Hosts', value: formatNumber(totals.totalHosts), icon: Server, dot: 'bg-blue-500' },
    { label: 'Requests (24h)', value: formatNumber(totals.totalTraffic), icon: Activity, dot: 'bg-cyan-500' },
    { label: 'At Risk', value: formatNumber(totals.atRisk), icon: TriangleAlert, dot: totals.atRisk > 0 ? 'bg-rose-500' : 'bg-zinc-400' }
  ];

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => fetchNetworks()} />;
  }

  return (
    <div className="space-y-5" id="networks-module-container">
      {/* ── Header ── */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faNetworkWired} />}
        title="Protected Networks & Subnet Zones"
        subtitle="Declare the corporate subnets, DMZ perimeters and VPC interconnects under firewall control. Hosts, traffic and risk are derived from real endpoint and firewall telemetry."
        actions={
          <button
            onClick={openAdd}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Subnet
          </button>
        }
      />

      {error && (
        <div className="flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-xs text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
          <TriangleAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError('')} className="cursor-pointer text-rose-500 hover:text-rose-700" title="Dismiss">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ── Summary Tiles ── */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        {summaryTiles.map(tile => {
          const Icon = tile.icon;
          return (
            <div
              key={tile.label}
              className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-4 shadow-2xs transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                  {tile.dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${tile.dot}`} />}
                  {tile.label}
                </div>
                <Icon className="w-3.5 h-3.5 text-zinc-300 dark:text-zinc-600" />
              </div>
              <div className="mt-1.5 text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100 font-mono">
                {tile.value}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Network Subnets Table Container ── */}
      <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
        <header className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
              Registered Network Subnets
            </h2>
            <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5">
              Live counters from the last 24 hours · synced {formatClock(lastSynced)}
            </p>
          </div>
          <div className="relative w-full sm:w-auto">
            <Search className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search subnet name, CIDR, zone, gateway…"
              className="h-8 w-full sm:w-72 rounded-lg border border-zinc-200/80 bg-white pl-8 pr-3 text-xs text-zinc-800 placeholder-zinc-400 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder-zinc-500 dark:focus:border-zinc-600"
            />
          </div>
        </header>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[980px] text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-100 dark:border-zinc-800 text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/40 dark:bg-zinc-900/20">
                <th className="py-3 px-4">Network Name</th>
                <th className="py-3 px-4">CIDR Range</th>
                <th className="py-3 px-4">Gateway</th>
                <th className="py-3 px-4">Zone</th>
                <th className="py-3 px-4">Firewall Engine</th>
                <th className="py-3 px-4">Hosts</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Traffic (24H)</th>
                <th className="py-3 px-4 text-right w-20">Aksi</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/80">
              {loading && networks.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-10 text-center font-sans text-xs text-zinc-400 dark:text-zinc-500">
                    Loading network inventory…
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center font-sans">
                    <div className="mx-auto flex max-w-md flex-col items-center gap-2">
                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-zinc-100 dark:bg-zinc-800">
                        <Network className="h-5 w-5 text-zinc-400" />
                      </div>
                      <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
                        {networks.length === 0 ? 'No protected subnets yet' : 'No subnets match your search'}
                      </p>
                      <p className="text-[11px] leading-relaxed text-zinc-400 dark:text-zinc-500">
                        {networks.length === 0
                          ? 'Add the CIDR of the network you want OAT to protect. Hosts, requests and risk appear here as soon as the endpoint agent or firewall reports telemetry.'
                          : 'Try a different name, CIDR, zone or gateway.'}
                      </p>
                      {networks.length === 0 && (
                        <button
                          onClick={openAdd}
                          className="mt-1 inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 cursor-pointer"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          Add your first subnet
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map(net => (
                  <tr key={net.id} className="hover:bg-zinc-50/80 dark:hover:bg-zinc-900/40 transition-colors">
                    <td className="py-3 px-4 font-sans">
                      <div className="font-semibold text-zinc-900 dark:text-zinc-100">{net.name}</div>
                      {net.description && (
                        <div className="text-[10px] text-zinc-400 dark:text-zinc-500 truncate max-w-[220px]" title={net.description}>
                          {net.description}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-zinc-700 dark:text-zinc-300 font-bold">{net.cidr}</td>
                    <td className="py-3 px-4 text-zinc-600 dark:text-zinc-400">
                      {net.gateway}
                      {net.interface && (
                        <span className="ml-1.5 rounded bg-zinc-100 px-1 py-0.5 text-[9px] font-sans text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
                          {net.interface}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                        {net.zone || 'DMZ'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-emerald-600 dark:text-emerald-400 font-sans">
                      <span className="inline-flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3" />
                        {net.firewall || 'OAT NGFW'}
                      </span>
                    </td>
                    <td
                      className="py-3 px-4 text-zinc-600 dark:text-zinc-400 font-sans"
                      title="Distinct hosts observed inside this CIDR in the last 24h (endpoint agents + destination IPs)."
                    >
                      {formatNumber(net.devicesCount)} <span className="text-[10px] text-zinc-400">hosts</span>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge type="severity" value={net.riskLevel || 'Low'} />
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge type="health" value={net.status || 'Online'} />
                    </td>
                    <td
                      className="py-3 px-4 text-right text-zinc-900 dark:text-zinc-100 font-semibold"
                      title="Security events whose destination falls inside this subnet in the last 24h."
                    >
                      {formatNumber(net.trafficVolume)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button
                          type="button"
                          onClick={() => openEdit(net)}
                          className="p-1 rounded text-zinc-400 hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-950/30 transition cursor-pointer"
                          title="Edit subnet"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteNetwork(net)}
                          className="p-1 rounded text-zinc-400 hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition cursor-pointer"
                          title="Hapus subnet"
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

        {networks.length > 0 && (
          <div className="flex items-start gap-2 border-t border-zinc-100 dark:border-zinc-800/80 px-5 py-2.5 text-[10px] text-zinc-400 dark:text-zinc-500">
            <Info className="w-3 h-3 shrink-0 mt-0.5" />
            <span>
              Hosts, traffic and risk are calculated from events addressed to each subnet. A subnet stays at
              <span className="font-medium text-zinc-500 dark:text-zinc-400"> Low</span> risk until real traffic inside it is observed.
            </span>
          </div>
        )}
      </section>

      {/* ── Modal: Add / Edit Subnet ── */}
      {showForm && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="relative w-full max-w-lg rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100 max-h-[90vh] overflow-y-auto custom-scrollbar">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-zinc-500" />
                <h3 className="text-sm font-semibold">
                  {editing ? `Edit Subnet · ${editing.name}` : 'Add Protected Network Subnet'}
                </h3>
              </div>
              <button
                type="button"
                onClick={closeForm}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3.5 pt-4 text-xs">
              {formError && (
                <div className="flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
                  <TriangleAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  <span>{formError}</span>
                </div>
              )}

              <div>
                <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Subnet Name</label>
                <input
                  type="text"
                  required
                  maxLength={255}
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g. Core Database Subnet"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">CIDR Block</label>
                  <input
                    type="text"
                    required
                    value={cidr}
                    onChange={e => setCidr(e.target.value)}
                    onBlur={() => {
                      const parsed = parseCidr(cidr);
                      if (parsed) setCidr(parsed.cidr);
                    }}
                    placeholder="e.g. 10.240.10.0/24"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                  <p className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500">
                    IPv4 only. A bare address is stored as /32.
                  </p>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">
                    Default Gateway <span className="font-normal text-zinc-400">(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={gateway}
                    onChange={e => setGateway(e.target.value)}
                    placeholder={cidr ? suggestGateway(cidr) || 'auto' : 'auto (first host)'}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                  <p className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500">
                    Leave blank to use the first usable host.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Security Zone</label>
                  <select
                    value={zone}
                    onChange={e => setZone(e.target.value)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none cursor-pointer"
                  >
                    {ZONE_OPTIONS.map(option => (
                      <option key={option} value={option}>{option}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Firewall Engine</label>
                  <input
                    type="text"
                    list="oat-firewall-engines"
                    maxLength={128}
                    value={firewall}
                    onChange={e => setFirewall(e.target.value)}
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                  <datalist id="oat-firewall-engines">
                    {FIREWALL_OPTIONS.map(option => (
                      <option key={option} value={option} />
                    ))}
                  </datalist>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">Interface</label>
                  <input
                    type="text"
                    maxLength={64}
                    value={iface}
                    onChange={e => setIface(e.target.value)}
                    placeholder="eth0"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-mono text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
                <div>
                  <label className="block font-medium text-zinc-600 dark:text-zinc-300 mb-1">
                    Description <span className="font-normal text-zinc-400">(optional)</span>
                  </label>
                  <input
                    type="text"
                    maxLength={1000}
                    value={description}
                    onChange={e => setDescription(e.target.value)}
                    placeholder="e.g. Primary PostgreSQL cluster"
                    className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-800 placeholder-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 focus:outline-none focus:border-zinc-400"
                  />
                </div>
              </div>

              <div className="pt-3 flex items-center justify-end gap-2 border-t border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  onClick={closeForm}
                  disabled={saving}
                  className="inline-flex h-8 items-center rounded-lg border border-zinc-200/80 bg-white px-3 text-xs text-zinc-600 hover:bg-zinc-50 disabled:opacity-50 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3.5 text-xs font-medium text-white hover:bg-zinc-800 disabled:opacity-60 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 cursor-pointer"
                >
                  {saving && <RefreshCw className="w-3 h-3 animate-spin" />}
                  {editing ? 'Save changes' : 'Enroll Subnet'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
