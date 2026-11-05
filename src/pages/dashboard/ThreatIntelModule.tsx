import React, { useEffect, useState, useCallback, useMemo } from 'react';
import {
  RefreshCw,
  Plus,
  Radio,
  Search,
  Bug,
  Database,
  Layers,
  ChevronDown,
  ChevronUp,
  Info,
  ShieldCheck,
  Zap,
  Globe,
  Check
} from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faGlobe } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader, ModulePageBadge } from '../../components/common/ModulePageHeader';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { getLanguage } from '../../i18n/translator';
import {
  ThreatIntelMetrics,
  ThreatFeedsOverview,
  IocLiveStreamTable,
  ThreatLookupInvestigator,
  CveMitigationMatrix,
  AddIocModal,
  ThreatFeedSource,
  ThreatIntelligenceFeed,
  CveMitigationItem,
  ThreatIntelStats,
  ThreatIntelTab
} from '../../components/threat-intel';

export const ThreatIntelModule: React.FC = () => {
  const { isBackendOffline } = useAuth();

  // Core Data States
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [serverStatus, setServerStatus] = useState('ONLINE');
  const [stats, setStats] = useState<ThreatIntelStats>({
    totalIocs: 0,
    blockedIocs: 0,
    monitoredIocs: 0,
    activeFeeds: 0,
    criticalCves: 0
  });
  const [feeds, setFeeds] = useState<ThreatFeedSource[]>([]);
  const [indicators, setIndicators] = useState<ThreatIntelligenceFeed[]>([]);
  const [cves, setCves] = useState<CveMitigationItem[]>([]);
  const [lastSyncTime, setLastSyncTime] = useState<string>('');

  // UI States
  const [activeTab, setActiveTab] = useState<ThreatIntelTab>('iocs');
  const [showTabDropdown, setShowTabDropdown] = useState(false);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [showFeedsOverview, setShowFeedsOverview] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('oat_threat_intel_show_feeds');
      return saved !== null ? saved === 'true' : true;
    } catch {
      return true;
    }
  });
  const [showGuide, setShowGuide] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('oat_threat_intel_show_guide');
      return saved !== null ? saved === 'true' : false;
    } catch {
      return false;
    }
  });
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [feedback, setFeedback] = useState<{ tone: 'ok' | 'warn' | 'err'; text: string } | null>(null);

  const toggleGuide = () => {
    setShowGuide(prev => {
      const next = !prev;
      try { localStorage.setItem('oat_threat_intel_show_guide', String(next)); } catch {}
      return next;
    });
  };

  const toggleFeedsOverview = () => {
    setShowFeedsOverview(prev => {
      const next = !prev;
      try {
        localStorage.setItem('oat_threat_intel_show_feeds', String(next));
      } catch {}
      return next;
    });
  };

  // Investigator prefill
  const [investigatorPrefill, setInvestigatorPrefill] = useState<{
    query: string;
    type: 'ip' | 'domain' | 'url';
  }>({
    query: '',
    type: 'ip'
  });

  // Load initial threat intelligence state
  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [intelRes, iocsRes, cvesRes] = await Promise.all([
        securityApi.getThreatIntel().catch(() => null),
        securityApi.getThreatIntelIocs().catch(() => ({ indicators: [] })),
        securityApi.getThreatIntelCves().catch(() => ({ cves: [] }))
      ]);

      if (intelRes) {
        setServerStatus(intelRes.status || 'CONNECTED');
        if (intelRes.feeds) setFeeds(intelRes.feeds);
        if (intelRes.stats) setStats(intelRes.stats);
      }

      if (iocsRes?.indicators) {
        setIndicators(iocsRes.indicators);
      }

      if (cvesRes?.cves) {
        setCves(cvesRes.cves);
      }

      setLastSyncTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    } catch (err) {
      console.error('[ThreatIntel] Error loading intel data:', err);
      setFeedback({ tone: 'err', text: 'Failed to load Threat Intelligence feed data.' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData, isBackendOffline]);

  // Real-time WebSocket event subscription
  useEffect(() => {
    const unsubWs = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;
      const type = msg.type || '';
      // WebSocket broadcasts `{ type, data }`; the SSE fallback forwards the
      // raw bus payload. Normalize both transports here.
      const data = msg.data || msg.payload || msg;

      if (type === 'threat_intel.synced') {
        if (data.feeds) setFeeds(data.feeds);
        const syncedAt = data.syncedAt || data.timestamp;
        if (syncedAt) {
          setLastSyncTime(new Date(syncedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
        }
        // Refetch indicators to get deduplicated set
        securityApi.getThreatIntelIocs().then(res => {
          if (res?.indicators) setIndicators(res.indicators);
        }).catch(() => {});
        securityApi.getThreatIntel().then(res => {
          if (res?.stats) setStats(res.stats);
        }).catch(() => {});

        setFeedback({
          tone: 'ok',
          text: data.latestIoc?.indicator
            ? `Threat feeds synchronized in real-time — new IOC ${data.latestIoc.indicator} ingested from ${data.latestIoc.reportedBy || 'a global feed'}.`
            : 'Threat feeds synchronized in real-time.'
        });
      } else if (type === 'threat_intel.ioc_created') {
        const newIoc = data;
        if (newIoc && newIoc.id) {
          setIndicators(prev => {
            if (prev.some(item => item.id === newIoc.id || item.indicator === newIoc.indicator)) return prev;
            return [newIoc, ...prev].slice(0, 50);
          });
          setStats(prev => ({
            ...prev,
            totalIocs: prev.totalIocs + 1,
            blockedIocs: newIoc.status === 'Blocked' ? prev.blockedIocs + 1 : prev.blockedIocs,
            monitoredIocs: newIoc.status === 'Monitored' ? prev.monitoredIocs + 1 : prev.monitoredIocs
          }));
          const fromAgent = String(newIoc.reportedBy || '').includes('OAT Endpoint Agent');
          setFeedback({
            tone: 'ok',
            text: fromAgent
              ? `Agent incident detected: ${newIoc.indicator} (${newIoc.type} - ${newIoc.status})`
              : `New threat indicator received: ${newIoc.indicator} (${newIoc.type} - ${newIoc.status})`
          });
        }
      } else if (type === 'threat_intel.updated') {
        const updatedIoc = data;
        if (updatedIoc && updatedIoc.id) {
          setIndicators(prev =>
            prev.map(item => (item.id === updatedIoc.id ? { ...item, ...updatedIoc } : item))
          );
        }
      } else if (type === 'rule.updated') {
        const rule = data || {};
        if (rule.source && rule.action === 'DENY') {
          setIndicators(prev =>
            prev.map(item =>
              item.indicator.toLowerCase() === rule.source.toLowerCase()
                ? { ...item, status: 'Blocked' }
                : item
            )
          );
        }
      }
    });

    return () => {
      unsubWs();
    };
  }, []);

  // Filtered Indicators
  const filteredIndicators = useMemo(() => {
    return indicators.filter(item => {
      // Type filter
      if (typeFilter !== 'ALL' && item.type.toLowerCase() !== typeFilter.toLowerCase()) {
        return false;
      }
      // Status filter
      if (statusFilter !== 'ALL' && item.status.toLowerCase() !== statusFilter.toLowerCase()) {
        return false;
      }
      // Search
      if (search.trim()) {
        const q = search.trim().toLowerCase();
        const inIndicator = item.indicator.toLowerCase().includes(q);
        const inReporter = item.reportedBy.toLowerCase().includes(q);
        const inSector = (item.targetSector || '').toLowerCase().includes(q);
        const inCountry = (item.country || '').toLowerCase().includes(q);
        const inTags = item.tags.some(t => t.toLowerCase().includes(q));
        if (!inIndicator && !inReporter && !inSector && !inCountry && !inTags) {
          return false;
        }
      }
      return true;
    });
  }, [indicators, typeFilter, statusFilter, search]);

  // Actions
  const handleSyncFeeds = async () => {
    try {
      setSyncing(true);
      setFeedback(null);
      const res = await securityApi.syncThreatIntel();
      if (res.feeds) setFeeds(res.feeds);
      setLastSyncTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));

      // Refresh IOCs and stats
      const iocsRes = await securityApi.getThreatIntelIocs();
      if (iocsRes?.indicators) setIndicators(iocsRes.indicators);
      const intelRes = await securityApi.getThreatIntel();
      if (intelRes?.stats) setStats(intelRes.stats);

      setFeedback({
        tone: 'ok',
        text: `Successfully synced ${res.addedIndicatorsCount ?? 'all'} threat indicators across 6 global threat feeds.`
      });
    } catch (err: any) {
      setFeedback({
        tone: 'err',
        text: err?.message || 'Failed to sync threat feeds from remote providers.'
      });
    } finally {
      setSyncing(false);
    }
  };

  const handleBlockIndicator = async (indicatorVal: string) => {
    try {
      const res = await securityApi.blockThreatIntelIndicator(indicatorVal, 'Manual Containment via Threat Intel Live Feed');
      // Update local indicator status
      setIndicators(prev =>
        prev.map(i => (i.indicator.toLowerCase() === indicatorVal.toLowerCase() ? { ...i, status: 'Blocked' } : i))
      );
      setStats(prev => ({ ...prev, blockedIocs: prev.blockedIocs + 1 }));
      setFeedback({
        tone: 'ok',
        text: res.message || `Firewall DENY rule generated for ${indicatorVal}.`
      });
    } catch (err: any) {
      setFeedback({
        tone: 'err',
        text: err?.message || `Failed to block indicator ${indicatorVal}.`
      });
    }
  };

  const handleUpdateStatus = async (id: string, newStatus: 'Active' | 'Blocked' | 'Monitored') => {
    try {
      await securityApi.updateThreatIntelIocStatus(id, newStatus);
      setIndicators(prev =>
        prev.map(i => (i.id === id ? { ...i, status: newStatus } : i))
      );
      setFeedback({
        tone: 'ok',
        text: `Indicator status changed to ${newStatus}.`
      });
    } catch (err: any) {
      setFeedback({
        tone: 'err',
        text: err?.message || 'Failed to update IOC status.'
      });
    }
  };

  const handleAddIocSubmit = async (data: {
    indicator: string;
    type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'CVE';
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    status: 'Blocked' | 'Active' | 'Monitored';
    threatScore: number;
    confidence: number;
    targetSector: string;
    country: string;
    tags: string[];
    autoBlockFirewall: boolean;
  }) => {
    const res = await securityApi.addThreatIntelIoc({
      indicator: data.indicator,
      type: data.type === 'IP' ? 'Malicious IP' : data.type === 'Domain' ? 'Phishing Domain' : data.type === 'Hash' ? 'Malware Hash' : data.type,
      severity: data.severity,
      status: data.status,
      threatScore: data.threatScore,
      confidence: data.confidence,
      targetSector: data.targetSector,
      country: data.country,
      tags: data.tags
    });

    if (data.autoBlockFirewall) {
      await securityApi.blockThreatIntelIndicator(data.indicator, 'Auto Firewall Containment on Custom IOC Creation');
    }

    if (res.ioc) {
      setIndicators(prev => [res.ioc, ...prev]);
      setStats(prev => ({
        ...prev,
        totalIocs: prev.totalIocs + 1,
        blockedIocs: data.status === 'Blocked' || data.autoBlockFirewall ? prev.blockedIocs + 1 : prev.blockedIocs
      }));
    }

    setFeedback({
      tone: 'ok',
      text: `Threat indicator ${data.indicator} registered and propagated to edge defense engines.`
    });
  };

  const handleInvestigateIndicator = (indicatorVal: string, typeVal: 'ip' | 'domain' | 'url') => {
    setInvestigatorPrefill({ query: indicatorVal, type: typeVal });
    setActiveTab('lookup');
  };

  const handlePerformLookup = async (query: string, type: 'ip' | 'domain' | 'url') => {
    try {
      const res = await securityApi.lookupThreatIntel(query, type);
      return res;
    } catch (err) {
      console.error('[ThreatIntel] Lookup error:', err);
      return null;
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={loadData} />;
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faGlobe} />}
        title={getLanguage() === 'id' ? 'Intelijen Ancaman' : 'Threat Intelligence'}
        titleTail={getLanguage() === 'id' ? '& Aliran IOC' : '& IOC Stream'}
        badge={
          <ModulePageBadge>{indicators.length} IOCs</ModulePageBadge>
        }
        subtitle={
          getLanguage() === 'id'
            ? 'Pusat pengumpulan ancaman dari endpoint agent, CERT global, ISAC perbankan, dan node honeynet.'
            : 'Aggregated threat intelligence from endpoint agents, global CERTs, banking ISACs, and honeynet nodes.'
        }
        actions={
          <button
            type="button"
            onClick={() => setIsAddModalOpen(true)}
            className="inline-flex h-9 shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg bg-zinc-950 px-3.5 text-sm font-medium whitespace-nowrap text-white shadow-md transition-colors duration-150 hover:bg-zinc-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 active:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-50 motion-safe:active:translate-y-px motion-reduce:transition-none dark:bg-zinc-50 dark:text-zinc-950 dark:hover:bg-zinc-200 dark:focus-visible:outline-zinc-50 dark:active:bg-zinc-300"
          >
            <Plus className="size-4 shrink-0" />
            <span>{getLanguage() === 'id' ? 'Tambah Indikator' : 'Add Indicator'}</span>
          </button>
        }
      />

      {/* Real-time Feedback Banner */}
      {feedback && (
        <div
          className={`p-3 sm:p-3.5 rounded-xl border text-xs sm:text-sm flex items-center justify-between gap-3 animate-in fade-in duration-200 ${
            feedback.tone === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
              : feedback.tone === 'warn'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 shrink-0 animate-pulse" />
            <span className="font-medium">{feedback.text}</span>
          </div>
          <button
            onClick={() => setFeedback(null)}
            className="text-xs opacity-70 hover:opacity-100 underline shrink-0 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Guide & Architecture Explainer Card (Collapsible for cleaner dashboard) */}
      <div className="rounded-2xl border border-zinc-200/80 bg-zinc-50/60 p-4 dark:border-zinc-800 dark:bg-zinc-900/30 shadow-xs transition">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
              <Info className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                <span>
                  {getLanguage() === 'id'
                    ? 'Panduan & Cara Kerja Threat Intelligence'
                    : 'Threat Intelligence Architecture & Guide'}
                </span>
                <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  {getLanguage() === 'id' ? 'Proteksi Aktif' : 'Active Protection'}
                </span>
              </h3>
              {!showGuide && (
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
                  {getLanguage() === 'id'
                    ? 'Deteksi dini dan penegakan blokir otomatis dari feed intelijen global.'
                    : 'Early threat detection and automated perimeter blocking from global intelligence feeds.'}
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={toggleGuide}
            className="inline-flex h-8 shrink-0 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-neutral-200 bg-white px-2.5 text-xs font-medium text-neutral-800 shadow-xs hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-200 dark:hover:bg-neutral-800"
          >
            <span>{showGuide ? (getLanguage() === 'id' ? 'Sembunyikan' : 'Hide') : (getLanguage() === 'id' ? 'Buka Panduan' : 'Open Guide')}</span>
            {showGuide ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
          </button>
        </div>

        {showGuide && (
          <div className="mt-3.5 pt-3 border-t border-zinc-200/70 dark:border-zinc-800/80 space-y-3 animate-in fade-in duration-150">
            <p className="text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
              {getLanguage() === 'id' ? (
                <>
                  Modul ini mengumpulkan dan menyinkronkan <strong>Indicators of Compromise (IOC)</strong> seperti IP penyerang, domain phishing, dan C2 server secara otomatis dari feed intelijen global serta endpoint agent. Setiap IOC yang berstatus <strong className="text-rose-600 dark:text-rose-400">Blocked</strong> langsung ditegakkan di Perimeter Firewall untuk mencegah akses sebelum serangan mencapai aplikasi Anda.
                </>
              ) : (
                <>
                  This module aggregates and synchronizes <strong>Indicators of Compromise (IOC)</strong> such as attacker IPs, phishing domains, and C2 servers automatically from global intelligence feeds and endpoint agents. Every indicator in <strong className="text-rose-600 dark:text-rose-400">Blocked</strong> status is immediately enforced on the Perimeter Firewall to neutralize threats before they reach your applications.
                </>
              )}
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1 text-xs">
              <div className="flex items-start gap-2">
                <Globe className="w-3.5 h-3.5 text-blue-500 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-zinc-800 dark:text-zinc-200 block text-[11px]">
                    {getLanguage() === 'id' ? '1. Ingesti Multi-Feed' : '1. Multi-Feed Ingestion'}
                  </span>
                  <span className="text-[11px] text-zinc-500 dark:text-zinc-400">
                    {getLanguage() === 'id'
                      ? 'Sinkronisasi reputasi IP dari FS-ISAC, CERT, & Honeynet.'
                      : 'Live reputation sync from FS-ISAC, CERTs, & Honeynet nodes.'}
                  </span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <Zap className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-zinc-800 dark:text-zinc-200 block text-[11px]">
                    {getLanguage() === 'id' ? '2. Korelasi Otomatis' : '2. Automated Correlation'}
                  </span>
                  <span className="text-[11px] text-zinc-500 dark:text-zinc-400">
                    {getLanguage() === 'id'
                      ? 'Mendeteksi serangan berulang & menghitung Threat Score (0–100).'
                      : 'Recurring pattern detection with dynamic Threat Scoring (0–100).'}
                  </span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-zinc-800 dark:text-zinc-200 block text-[11px]">
                    {getLanguage() === 'id' ? '3. Mitigasi 1-Klik' : '3. 1-Click Mitigation'}
                  </span>
                  <span className="text-[11px] text-zinc-500 dark:text-zinc-400">
                    {getLanguage() === 'id'
                      ? "Tombol 'Block IP' langsung menambahkan rule blokir permanen."
                      : "'Block IP' action instantly installs permanent drop rule on edge firewall."}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Metrics Row */}
      <ThreatIntelMetrics
        stats={stats}
        lastSyncTime={lastSyncTime}
      />

      {/* Sleek Workspace/Profile-Style Dropdown Navigation Bar */}
      {(() => {
        const isId = getLanguage() === 'id';
        const tabOptions = [
          {
            id: 'iocs' as const,
            label: isId ? 'Aliran IOC & Feed Intelijen' : 'Live Threat IOC Stream & Feeds',
            description: isId
              ? 'Daftar indikator ancaman aktif, integrasi multi-feed, dan penegakan firewall otomatis'
              : 'Active threat indicators, multi-feed integration, and automated edge firewall drop rules',
            icon: Database,
            badgeText: `${indicators.length} IOCs`,
            badgeStyle: 'bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300'
          },
          {
            id: 'lookup' as const,
            label: isId ? 'Pencarian Ancaman Interaktif' : 'Interactive Threat Lookup',
            description: isId
              ? 'Mesin pengayaan reputasi IP, domain malicious, dan forensik hash global'
              : 'Enrichment engine for forensic IP reputation, malicious domains, and hash lookups',
            icon: Search,
            badgeText: 'ENRICHMENT ENGINE',
            badgeStyle: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20'
          },
          {
            id: 'cves' as const,
            label: isId ? 'Perisai Kerentanan & CVE' : 'CVE Shield & Mitigations',
            description: isId
              ? 'Katalog kerentanan berisiko tinggi dan mitigasi virtual patch perimeter'
              : 'High-risk CVE vulnerability matrix and edge perimeter virtual patching',
            icon: Bug,
            badgeText: `${cves.length} ${isId ? 'dipantau' : 'tracked'}`,
            badgeStyle: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
          }
        ];

        const currentTab = tabOptions.find(t => t.id === activeTab) || tabOptions[0];
        const CurrentIcon = currentTab.icon;

        return (
          <div className="flex flex-wrap items-center justify-between gap-3 p-2 rounded-2xl bg-zinc-100/80 dark:bg-zinc-900/80 border border-zinc-200/80 dark:border-zinc-800">
            <div className="relative w-full sm:w-auto">
              <button
                type="button"
                onClick={() => setShowTabDropdown(!showTabDropdown)}
                className="w-full sm:w-auto h-9 px-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] hover:bg-zinc-50 dark:hover:bg-zinc-900 text-xs font-semibold text-zinc-900 dark:text-white inline-flex items-center justify-between sm:justify-start gap-3 transition cursor-pointer shadow-xs"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <CurrentIcon className="w-4 h-4 text-zinc-600 dark:text-zinc-300 shrink-0" />
                  <span className="font-semibold text-zinc-800 dark:text-zinc-100 truncate">
                    {currentTab.label}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold shrink-0 ${currentTab.badgeStyle}`}>
                    {currentTab.badgeText}
                  </span>
                  <ChevronDown className={`w-3.5 h-3.5 text-zinc-400 transition-transform duration-200 shrink-0 ${showTabDropdown ? 'rotate-180' : ''}`} />
                </div>
              </button>

              {showTabDropdown && (
                <>
                  <div
                    className="fixed inset-0 z-30 cursor-default"
                    onClick={() => setShowTabDropdown(false)}
                  />
                  <div className="absolute left-0 top-full mt-2 w-80 sm:w-96 max-w-[calc(100vw-2rem)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-2 z-40 animate-in fade-in zoom-in-95 duration-150 text-zinc-900 dark:text-zinc-100 space-y-1">
                    {/* Header Card Profile-Style */}
                    <div className="flex items-center gap-2.5 p-2 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/80 dark:bg-zinc-900/60 mb-2">
                      <div className="w-8 h-8 rounded-lg bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center shrink-0">
                        <CurrentIcon className="w-4 h-4 text-zinc-700 dark:text-zinc-300" />
                      </div>
                      <div className="min-w-0 flex-1 leading-tight">
                        <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100 truncate">
                          {currentTab.label}
                        </p>
                        <span className="block text-[11px] text-zinc-500 dark:text-zinc-400 truncate mt-0.5">
                          {currentTab.description}
                        </span>
                      </div>
                    </div>

                    {/* Tab Options */}
                    <div className="space-y-0.5">
                      <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 font-mono">
                        {isId ? 'Navigasi Intelijen' : 'Intelligence Views'}
                      </div>
                      {tabOptions.map(opt => {
                        const isActive = activeTab === opt.id;
                        const Icon = opt.icon;
                        return (
                          <button
                            key={opt.id}
                            type="button"
                            onClick={() => {
                              setActiveTab(opt.id);
                              setShowTabDropdown(false);
                            }}
                            className={`w-full p-2 flex items-center gap-2.5 rounded-lg transition-colors text-left cursor-pointer ${
                              isActive
                                ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-zinc-100 font-semibold'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-900/60 hover:text-zinc-900 dark:hover:text-zinc-200'
                            }`}
                          >
                            <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${isActive ? 'bg-zinc-200 dark:bg-zinc-700' : 'bg-zinc-100 dark:bg-zinc-800/50'}`}>
                              <Icon className="w-3.5 h-3.5" />
                            </div>
                            <div className="min-w-0 flex-1 leading-tight">
                              <div className="flex items-center justify-between gap-1">
                                <span className="text-xs font-semibold truncate">{opt.label}</span>
                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold shrink-0 ${opt.badgeStyle}`}>
                                  {opt.badgeText}
                                </span>
                              </div>
                              <span className="block text-[10px] text-zinc-500 dark:text-zinc-400 truncate mt-0.5">
                                {opt.description}
                              </span>
                            </div>
                            {isActive && <Check className="w-4 h-4 text-emerald-500 shrink-0 ml-1" />}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Feeds Collapsible Toggle (only when in iocs tab) */}
            {activeTab === 'iocs' && (
              <button
                type="button"
                onClick={toggleFeedsOverview}
                className="inline-flex h-9 shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg border border-neutral-200 bg-white px-3.5 text-xs font-medium whitespace-nowrap text-neutral-950 shadow-sm transition-colors duration-150 hover:bg-neutral-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 active:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50 motion-safe:active:translate-y-px motion-reduce:transition-none dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-50 dark:hover:bg-neutral-800 dark:focus-visible:outline-zinc-50 dark:active:bg-neutral-700"
              >
                <Layers className="size-4 shrink-0 text-neutral-600 dark:text-neutral-400" />
                <span>{showFeedsOverview ? (isId ? 'Sembunyikan Grid Feed' : 'Hide Feeds Grid') : (isId ? 'Tampilkan Grid Feed' : 'Show Feeds Grid')}</span>
                {showFeedsOverview ? <ChevronUp className="size-3.5 shrink-0" /> : <ChevronDown className="size-3.5 shrink-0" />}
              </button>
            )}
          </div>
        );
      })()}

      {/* Tab 1 Content: IOC Stream & Feeds */}
      {activeTab === 'iocs' && (
        <div className="space-y-5 animate-in fade-in duration-150">
          {/* Synchronized Threat Feeds Section */}
          {showFeedsOverview && (
            <ThreatFeedsOverview
              feeds={feeds}
              serverStatus={serverStatus}
              onSync={handleSyncFeeds}
              syncing={syncing}
            />
          )}

          {/* Live IOC Stream Table */}
          <IocLiveStreamTable
            indicators={filteredIndicators}
            search={search}
            onSearchChange={setSearch}
            typeFilter={typeFilter}
            onTypeFilterChange={setTypeFilter}
            statusFilter={statusFilter}
            onStatusFilterChange={setStatusFilter}
            onOpenAddModal={() => setIsAddModalOpen(true)}
            onBlockIndicator={handleBlockIndicator}
            onUpdateStatus={handleUpdateStatus}
            onInvestigate={handleInvestigateIndicator}
            busy={syncing || loading}
          />
        </div>
      )}

      {/* Tab 2 Content: Interactive Threat Lookup */}
      {activeTab === 'lookup' && (
        <div className="animate-in fade-in duration-150">
          <ThreatLookupInvestigator
            onLookup={handlePerformLookup}
            onBlockIp={handleBlockIndicator}
            loading={loading}
            initialQuery={investigatorPrefill.query}
            initialType={investigatorPrefill.type}
          />
        </div>
      )}

      {/* Tab 3 Content: CVE Mitigation Matrix */}
      {activeTab === 'cves' && (
        <div className="animate-in fade-in duration-150">
          <CveMitigationMatrix cves={cves} />
        </div>
      )}

      {/* Modal: Add Threat Indicator */}
      <AddIocModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddIocSubmit}
      />
    </div>
  );
};
