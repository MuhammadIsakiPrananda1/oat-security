import React, { useState, useEffect, useCallback, useRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faBuilding,
  faMagnifyingGlass,
  faGlobe,

  faBell,
  faCheck,
  faCheckDouble,
  faVolumeHigh,
  faVolumeXmark,
  faTrashCan,
  faExpand,
  faChevronDown,
  faShieldHalved,
  faRightFromBracket,
  faXmark,
  faArrowRight,
  faFilter,
  faBars,
  faUserPen,

  faAt,
  faPhone,
  faPaperPlane,
  faCommentDots,
  faCamera,
  faCircleCheck,
  faSpinner
} from '@fortawesome/free-solid-svg-icons';
import {
  faLinkedin,
  faGithub,
  faXTwitter,
  faInstagram
} from '@fortawesome/free-brands-svg-icons';
import { useAuth } from '../../context/AuthContext';
import { useEndpointConnection } from '../../context/EndpointConnectionContext';
import { DashboardView } from './DashboardSidebar';
import { telemetryStreamManager, normalizeRealtimeSecurityEvent } from '../../services/api';
import { SecurityEvent } from '../../types';
import notifSoundUrl from '../../assets/audio/mixkit-correct-answer-tone-2870.wav';
import { ToastContainer, ToastItem } from '../common/ToastNotification';
import { getLanguage, setLanguage } from '../../i18n/translator';

interface DashboardTopNavProps {
  onOpenSearch: () => void;
  onNavigatePublic: () => void;
  onNavigateView: (view: DashboardView) => void;
  /** Toggles the off-canvas sidebar (shown as a hamburger below `lg`). */
  onOpenSidebar?: () => void;
}

interface TopNotification {
  id: string;
  title: string;
  desc: string;
  timestamp: number;
  severity: string;
  read: boolean;
  view: DashboardView;
}

function notificationViewFor(source?: string, action?: string): DashboardView {
  const src = (source || '').toLowerCase();
  const act = (action || '').toLowerCase();
  if (src.includes('waf')) return 'waf';
  if (src.includes('firewall')) return 'firewall';
  if (act.includes('block')) return 'threats';
  return 'security-events';
}

/**
 * Notifications are reserved for genuine security incidents only.
 *
 * Rules:
 * - Skip any event older than 15 minutes (replay protection)
 * - Skip pure LOG / ALLOW / INFO actions — these are telemetry, not attacks
 * - Only notify when: BLOCK/DENY/DROP/QUARANTINE action  OR  HIGH/CRITICAL severity
 *   OR malware/incident/threat event type  OR  repeated auth failures (brute force signal)
 */
function isNotifiableIncident(evt: SecurityEvent): boolean {
  const occurredAt = Date.parse(String(evt.timestamp || ''));
  const MAX_NOTIFICATION_AGE_MS = 15 * 60 * 1000;
  if (Number.isFinite(occurredAt) && Date.now() - occurredAt > MAX_NOTIFICATION_AGE_MS) {
    // Replayed backlog after a sensor resync or reconnect: still visible in
    // the event lists, but it must not ring the bell out of the blue.
    return false;
  }

  const eventType = String(evt.eventType || '').toLowerCase();
  const action = String(evt.action || '').toUpperCase();
  const severity = String(evt.severity || '').toUpperCase();

  // Explicitly exclude pure log/allow entries — these are routine telemetry
  if (['LOG', 'ALLOW', 'ALLOWED', 'PASS', 'MONITOR'].includes(action)) return false;
  if (severity === 'LOW' || severity === 'INFO' || severity === 'DEBUG') return false;

  const isMitigation = ['BLOCK', 'BLOCKED', 'DENY', 'DROP', 'QUARANTINE'].includes(action);
  const isElevated = severity === 'CRITICAL' || severity === 'HIGH';
  const isThreatOrIncident = (
    eventType === 'threat' || eventType === 'incident' ||
    eventType === 'malware' || eventType.includes('malware') ||
    evt.source === 'threat' || evt.source === 'correlation'
  );
  const isAuthFailure = [
    'ssh_failed_login',
    'ssh_invalid_user',
    'authentication_failure'
  ].includes(eventType);

  if (isAuthFailure || isThreatOrIncident) return true;

  return isMitigation || isElevated;
}

function actionLabelFor(action?: string): string {
  const act = String(action || '').toUpperCase();
  if (['BLOCK', 'BLOCKED'].includes(act)) return 'Diblokir';
  if (['DENY', 'DROP'].includes(act)) return 'Dijatuhkan';
  if (act === 'CHALLENGE') return 'Ditantang';
  if (act === 'RATE_LIMIT') return 'Dibatasi';
  if (['ALLOW', 'ALLOWED'].includes(act)) return 'Diizinkan';
  if (act === 'QUARANTINE') return 'Dikarantina';
  if (act === 'ALERT') return 'Peringatan';
  return 'Terdeteksi';
}

function timeAgo(timestamp: number): string {
  const diffSec = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (diffSec < 60) return 'Baru saja';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m lalu`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}j lalu`;
  return `${Math.floor(diffHour / 24)}h lalu`;
}

function initialsOf(name?: string): string {
  const parts = (name || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

const NOTIF_STORAGE_KEY = 'oat-notifications';

// ---------------------------------------------------------------------------
// Deduplication: prevent bursts from generating multiple stacked toasts.
// Only 1 toast is shown at a time, with a minimum 6-second cooldown between popups.
// ---------------------------------------------------------------------------
const toastDedupCache = new Map<string, number>();
const TOAST_DEDUP_TTL_MS = 20_000; // 20 seconds cooldown per unique event key
let lastGlobalToastTime = 0;

function cleanThreatTitle(rawThreat: string): string {
  const t = (rawThreat || '').trim();
  const lower = t.toLowerCase();
  if (lower === 'web' || lower === 'web_attack') return 'Serangan Web (WAF)';
  if (lower.includes('xss') || lower.includes('cross-site')) return 'Serangan Cross-Site Scripting (XSS)';
  if (lower.includes('sqli') || lower.includes('sql injection')) return 'Serangan SQL Injection';
  if (lower.includes('brute') || lower.includes('ssh_failed')) return 'Serangan Brute Force SSH';
  if (lower.includes('endpoint')) return 'Ancaman Terdeteksi di Endpoint';
  if (lower.includes('firewall')) return 'Kegagalan Firewall Engine';
  if (lower.includes('malware')) return 'Malware Terdeteksi';
  if (t) return t;
  return 'Insiden Keamanan Terdeteksi';
}

function makeToastDedupKey(evt: SecurityEvent): string {
  const srcIp = (evt.sourceIp || evt.source || '').toString().slice(0, 64);
  const threat = (evt.threat || evt.eventType || evt.action || '').toString().slice(0, 64);
  const src = (evt.source || '').toString().slice(0, 16);
  return `${src}:${srcIp}:${threat}`;
}

function isToastDuplicateWithin(key: string): boolean {
  const now = Date.now();
  const last = toastDedupCache.get(key);
  if (last !== undefined && now - last < TOAST_DEDUP_TTL_MS) return true;
  toastDedupCache.set(key, now);
  // Prune stale entries to prevent unbounded growth
  if (toastDedupCache.size > 200) {
    for (const [k, ts] of toastDedupCache) {
      if (now - ts > TOAST_DEDUP_TTL_MS * 5) toastDedupCache.delete(k);
    }
  }
  return false;
}

function loadStoredNotifications(): TopNotification[] {
  try {
    const raw = localStorage.getItem(NOTIF_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed as TopNotification[];
    }
  } catch {
    // fallback
  }
  return [];
}

export const DashboardTopNav: React.FC<DashboardTopNavProps> = ({
  onOpenSearch,

  onNavigateView,
  onOpenSidebar
}) => {
  const { user, currentOrg, organizations, switchOrg, logout, updateProfile } = useAuth();
  const { hasConnectedEndpoints, connectedCount } = useEndpointConnection();
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showActivityModal, setShowActivityModal] = useState(false);
  const [showEditProfileModal, setShowEditProfileModal] = useState(false);
  const [notifTab, setNotifTab] = useState<'all' | 'unread'>('all');

  const closeAllDropdowns = () => {
    setShowOrgDropdown(false);
    setShowUserDropdown(false);
    setShowNotifications(false);
    setShowActivityModal(false);
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeAllDropdowns();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const isAnyDropdownOpen = showOrgDropdown || showUserDropdown || showNotifications;
  const activeLanguage = getLanguage();

  const [notifications, setNotifications] = useState<TopNotification[]>(() => {
    const stored = loadStoredNotifications();
    return stored.length > 0 ? stored : [];
  });

  // Sound notifications state: true by default so every incoming notification chimes
  const [soundEnabled, setSoundEnabled] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem('oat-notif-sound');
      return stored !== null ? stored === 'true' : true;
    } catch {
      return true;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('oat-notif-sound', String(soundEnabled));
    } catch {
      // ignore
    }
  }, [soundEnabled]);

  useEffect(() => {
    try {
      localStorage.setItem(NOTIF_STORAGE_KEY, JSON.stringify(notifications.slice(0, 100)));
    } catch {
      // ignore
    }
  }, [notifications]);

  // Play audio chime: 1 notification = 1 sound chime, chime again on subsequent notification
  const playNotificationSound = () => {
    if (!soundEnabled) return;
    try {
      const audio = new Audio(notifSoundUrl);
      audio.volume = 0.6;
      audio.play().catch(() => {});
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    const unsubscribe = telemetryStreamManager.subscribe(
      (data: any) => {
        const normalized = normalizeRealtimeSecurityEvent(data);
        if (!normalized) return;
        if (!isNotifiableIncident(normalized)) return;

        // ── Deduplication: skip if same attack appeared within 20s ────────
        const dedupKey = makeToastDedupKey(normalized);
        if (isToastDuplicateWithin(dedupKey)) return;

        const srcIp = normalized.sourceIp || (normalized as any).source_ip || 'IP Eksternal';
        const dest = normalized.destination || (normalized as any).destination_ip || 'Gateway';
        const rawThreat = normalized.threat || (normalized as any).threat_name || (normalized as any).signature || 'Perimeter Alert';
        const threatName = cleanThreatTitle(rawThreat);
        const srcName = normalized.source?.toUpperCase() || (normalized as any).category?.toUpperCase() || 'SECURITY';

        const newNotif: TopNotification = {
          id: normalized.id || `notif-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          title: `[${srcName}] ${threatName}`,
          desc: `${actionLabelFor(normalized.action)} • Dari ${srcIp} menuju ${dest}`,
          timestamp: Date.now(),
          severity: normalized.severity || 'Medium',
          read: false,
          view: notificationViewFor(normalized.source, normalized.action)
        };

        setNotifications(prev => [newNotif, ...prev.slice(0, 99)]);

        // ── Single Toast pop-up with burst throttle: only 1 popup every 6s ───
        const nowMs = Date.now();
        if (nowMs - lastGlobalToastTime >= 6000) {
          lastGlobalToastTime = nowMs;
          const toastItem: ToastItem = {
            id: newNotif.id,
            title: newNotif.title,
            desc: newNotif.desc,
            severity: newNotif.severity,
            timestamp: newNotif.timestamp,
            onNavigate: () => onNavigateView(newNotif.view),
          };
          setToasts([toastItem]); // Strictly 1 toast visible
          playNotificationSound();
        }
      },
      () => {}
    );

    return () => unsubscribe();
  }, [soundEnabled]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const severityCountsPopover = {
    critical: notifications.filter(n => n.severity.toUpperCase() === 'CRITICAL').length,
    high: notifications.filter(n => n.severity.toUpperCase() === 'HIGH').length,
    medium: notifications.filter(n => n.severity.toUpperCase() === 'MEDIUM').length,
    low: notifications.filter(n => n.severity.toUpperCase() === 'LOW').length,
    info: notifications.filter(n => n.severity.toUpperCase() === 'INFO').length,
  };

  const [popoverSeverityFilter, setPopoverSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'>('all');
  const [showPopoverSeverityDropdown, setShowPopoverSeverityDropdown] = useState(false);

  // ── Toast (pop-up) notifications ──────────────────────────────────────────
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // ── Global event bridge: window.dispatchEvent(new CustomEvent('oat:notify', { detail: {...} }))
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail as Partial<ToastItem>;
      if (!detail?.title) return;
      const toast: ToastItem = {
        id: detail.id || `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        title: detail.title,
        desc: detail.desc || '',
        severity: detail.severity || 'Medium',
        timestamp: detail.timestamp || Date.now(),
      };
      setToasts([toast]);
    };
    window.addEventListener('oat:notify', handler);
    return () => window.removeEventListener('oat:notify', handler);
  }, []);

  const displayedNotifications = notifTab === 'unread'
    ? notifications.filter(n => !n.read)
    : notifications.filter(n => {
        if (popoverSeverityFilter === 'all') return true;
        return n.severity.toUpperCase() === popoverSeverityFilter.toUpperCase();
      });

  return (
    <>
      {/* Toast pop-up notifications (top-right, auto-dismiss) */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      <header className="h-14 sm:h-16 shrink-0 border-b border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] px-2 sm:px-4 lg:px-6 flex items-center justify-between gap-1.5 sm:gap-4 z-40 sticky top-0 transition-colors duration-200">
        {/* Backdrop overlay for closing open dropdowns */}
        {isAnyDropdownOpen && (
          <div className="fixed inset-0 z-40 cursor-default" onClick={closeAllDropdowns} />
        )}

        {/* Left: Mobile menu + Organization Switcher */}
        <div className="flex items-center gap-2 sm:gap-2.5 min-w-0 shrink-0">
          {onOpenSidebar && (
            <button
              type="button"
              onClick={onOpenSidebar}
              title="Buka navigasi"
              className="lg:hidden w-8 h-8 sm:w-10 sm:h-10 shrink-0 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-200 flex items-center justify-center shadow-2xs cursor-pointer"
            >
              <FontAwesomeIcon icon={faBars} className="text-sm" />
            </button>
          )}
          <div className="relative min-w-0 max-w-[110px] xs:max-w-[140px] sm:max-w-none sm:w-56 md:w-64">
            <button
              type="button"
              onClick={() => {
                setShowOrgDropdown(prev => !prev);
                setShowUserDropdown(false);
                setShowNotifications(false);
              }}
              title={currentOrg ? `Organisasi Aktif: ${currentOrg.name}` : 'Pilih Organisasi'}
              className="w-full h-8 sm:h-10 px-2 sm:px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:bg-zinc-50 dark:hover:bg-zinc-800/80 transition flex items-center justify-between gap-1 sm:gap-2.5 text-left group shadow-2xs cursor-pointer"
            >
              <div className="flex items-center gap-2.5 min-w-0 flex-1">
                <span className="w-6 h-6 rounded-md bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 flex items-center justify-center shrink-0 text-xs">
                  <FontAwesomeIcon icon={faBuilding} className="w-3 h-3" />
                </span>
                <div className="min-w-0 flex-1 leading-tight">
                  <div className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                    {organizations.length > 0 && currentOrg?.name ? currentOrg.name : 'Belum ada endpoint'}
                  </div>
                  <div className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate mt-0.5 tabular-nums hidden sm:block">
                    {organizations.length > 0 && currentOrg?.domain ? `${currentOrg.domain} • ${currentOrg.tier}` : 'Daftarkan endpoint agent dahulu'}
                  </div>
                </div>
              </div>
              <FontAwesomeIcon
                icon={faChevronDown}
                className={`text-[11px] text-zinc-400 transition-transform shrink-0 ${showOrgDropdown ? 'rotate-180' : ''}`}
              />
            </button>

            {/* Organization Dropdown Popover */}
            {showOrgDropdown && (
              <div className="absolute left-0 mt-2 w-72 sm:w-80 max-w-[calc(100vw-24px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-2.5 z-50">
                <div className="text-[11px] font-semibold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider px-2 py-1.5 border-b border-zinc-100 dark:border-zinc-800 mb-1.5 flex items-center justify-between">
                  <span>Switch Organization</span>
                  <span className="text-[11px] text-zinc-400 tabular-nums">{organizations.length > 0 ? `${organizations.length} Tenant` : 'Belum ada'}</span>
                </div>

                <div className="space-y-1 max-h-64 overflow-y-auto custom-scrollbar">
                  {organizations.length === 0 ? (
                    <div className="px-3 py-6 text-center text-xs text-zinc-500 dark:text-zinc-400">
                      <div className="mb-2 text-2xl">🖥️</div>
                      <div className="font-semibold text-zinc-700 dark:text-zinc-200 mb-1">Belum ada endpoint terdaftar</div>
                      <div className="text-[11px] text-zinc-400 dark:text-zinc-500 leading-relaxed">
                        Install dan daftarkan <strong>Endpoint Agent</strong> di perangkat yang ingin dipantau untuk mengaktifkan organisasi.
                      </div>
                    </div>
                  ) : (
                    organizations.map(org => {
                      const isSelected = org.id === currentOrg?.id;
                      return (
                        <button
                          key={org.id}
                          onClick={() => {
                            switchOrg(org.id);
                            setShowOrgDropdown(false);
                          }}
                          className={`w-full text-left p-2.5 rounded-lg text-sm flex items-center justify-between gap-2 transition cursor-pointer ${
                            isSelected
                              ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold'
                              : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <div className="min-w-0 flex-1">
                            <div className="font-semibold truncate">{org.name}</div>
                            <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5 tabular-nums">
                              {org.domain} • <span className="font-medium">{org.tier}</span>
                            </div>
                          </div>
                          {isSelected && <FontAwesomeIcon icon={faCheck} className="text-blue-600 dark:text-blue-400 text-xs shrink-0" />}
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Center: Global Search */}
        <div className="hidden sm:flex flex-1 justify-center px-1 sm:px-2 min-w-0">
          <button
            onClick={onOpenSearch}
            title="Navigasi cepat modul (Ctrl+K)"
            className="w-full max-w-lg h-10 px-3.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/70 dark:bg-zinc-900/60 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 text-sm transition flex items-center gap-2.5 shadow-2xs cursor-pointer"
          >
            <FontAwesomeIcon icon={faMagnifyingGlass} className="text-xs text-zinc-400 shrink-0" />
            <span className="flex-1 text-left truncate">
              Cari modul atau perintah...
            </span>
            <kbd className="hidden sm:inline-flex px-1.5 py-0.5 rounded border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-[10px] font-mono text-zinc-500 dark:text-zinc-400 font-medium shadow-2xs">
              ⌘K
            </kbd>
          </button>
        </div>

        {/* Right Section: Action Controls */}
        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {/* Mobile Search Modal Trigger */}
          <button
            type="button"
            onClick={onOpenSearch}
            title="Cari modul atau perintah (Cmd+K)"
            className="sm:hidden w-8 h-8 sm:w-10 sm:h-10 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-200 flex items-center justify-center shadow-2xs cursor-pointer shrink-0"
          >
            <FontAwesomeIcon icon={faMagnifyingGlass} className="text-xs text-zinc-500 dark:text-zinc-400" />
          </button>

          {/* Language quick switch (full selector lives in Settings) */}
          <button
            type="button"
            onClick={() => setLanguage(activeLanguage === 'id' ? 'en' : 'id')}
            title="Change language / Ganti bahasa"
            aria-label="Change language / Ganti bahasa"
            className="hidden sm:flex h-10 px-2.5 items-center gap-1.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-200 transition shadow-2xs cursor-pointer"
          >
            <FontAwesomeIcon icon={faGlobe} className="text-xs text-zinc-500 dark:text-zinc-400" />
            <span className="text-[10px] font-mono font-bold">{activeLanguage === 'id' ? 'ID' : 'EN'}</span>
          </button>

          {/* Unified Notification & Sound Button */}
          <div className="relative">
            <button
              onClick={() => {
                setShowNotifications(prev => !prev);
                setShowOrgDropdown(false);
                setShowUserDropdown(false);
              }}
              title="Notifikasi & Pengaturan Suara"
              className="h-8 sm:h-10 px-2.5 sm:px-3 flex items-center gap-1.5 sm:gap-2 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-200 relative transition shadow-2xs cursor-pointer shrink-0"
            >
              <FontAwesomeIcon icon={faBell} className="text-sm" />
              {unreadCount > 0 ? (
                <span className="px-1.5 py-0.5 rounded-full bg-rose-600 text-[10px] font-bold text-white leading-none">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              ) : (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              )}
            </button>

            {/* Notification Popover Dropdown (Simple, Clean, Integrated Sound) */}
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 max-w-[calc(100vw-24px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-2xl z-50 overflow-hidden text-zinc-900 dark:text-zinc-100">
                {/* Header: Title + Sound Control + Bulk Action */}
                <div className="px-4 py-3 border-b border-zinc-100 dark:border-zinc-800 flex items-center justify-between gap-2 bg-zinc-50/50 dark:bg-zinc-900/50">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold">Notifikasi</span>
                    {unreadCount > 0 && (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 dark:bg-rose-950/40 dark:text-rose-400">
                        {unreadCount} baru
                      </span>
                    )}
                  </div>

                  {/* Minimalist Sound Toggle Button (Inside Notifications Header) */}
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setSoundEnabled(prev => !prev)}
                      title={soundEnabled ? 'Suara notifikasi aktif (klik untuk membisukan)' : 'Suara notifikasi dibisukan (klik untuk menyalakan)'}
                      className={`h-7 px-2 rounded-md border text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
                        soundEnabled
                          ? 'border-zinc-200/80 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/80 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-700'
                          : 'border-zinc-200/40 dark:border-zinc-800/40 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300'
                      }`}
                    >
                      <FontAwesomeIcon icon={soundEnabled ? faVolumeHigh : faVolumeXmark} className={`text-xs ${soundEnabled ? 'text-emerald-500' : 'text-zinc-400'}`} />
                      <span className="text-[11px]">{soundEnabled ? 'Suara' : 'Mute'}</span>
                    </button>

                    {unreadCount > 0 && (
                      <button
                        type="button"
                        onClick={() => setNotifications(prev => prev.map(item => ({ ...item, read: true })))}
                        title="Tandai semua telah dibaca"
                        className="h-7 w-7 rounded-md text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 flex items-center justify-center transition cursor-pointer"
                      >
                        <FontAwesomeIcon icon={faCheckDouble} className="text-xs" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Sub-header: Simple Tabs + Severity Filter */}
                <div className="px-4 py-2 border-b border-zinc-100 dark:border-zinc-800 flex items-center justify-between text-xs bg-white dark:bg-zinc-900">
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setNotifTab('all')}
                      className={`px-2.5 py-1 rounded-md font-medium transition cursor-pointer ${
                        notifTab === 'all'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold'
                          : 'text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200'
                      }`}
                    >
                      Semua ({notifications.length})
                    </button>
                    <button
                      type="button"
                      onClick={() => setNotifTab('unread')}
                      className={`px-2.5 py-1 rounded-md font-medium transition cursor-pointer ${
                        notifTab === 'unread'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold'
                          : 'text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200'
                      }`}
                    >
                      Belum Dibaca ({unreadCount})
                    </button>
                  </div>

                  {/* Severity Filter Dropdown */}
                  <div className="relative ml-2">
                    <button
                      type="button"
                      onClick={() => setShowPopoverSeverityDropdown(prev => !prev)}
                      className="h-7 px-2.5 rounded-md border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-[11px] font-medium text-zinc-700 dark:text-zinc-200 flex items-center gap-1.5 transition cursor-pointer shadow-2xs"
                    >
                      <FontAwesomeIcon icon={faFilter} className="text-[9px] text-zinc-400" />
                      <span>
                        {popoverSeverityFilter === 'all'
                          ? 'All'
                          : popoverSeverityFilter === 'critical'
                            ? 'Critical'
                            : popoverSeverityFilter === 'high'
                              ? 'High'
                              : popoverSeverityFilter === 'medium'
                                ? 'Medium'
                                : popoverSeverityFilter === 'low'
                                  ? 'Low'
                                  : 'Info'}
                      </span>
                      <FontAwesomeIcon
                        icon={faChevronDown}
                        className={`text-[8px] text-zinc-400 ml-0.5 transition-transform ${showPopoverSeverityDropdown ? 'rotate-180' : ''}`}
                      />
                    </button>

                    {showPopoverSeverityDropdown && (
                      <>
                        <div
                          className="fixed inset-0 z-20 cursor-default"
                          onClick={() => setShowPopoverSeverityDropdown(false)}
                        />
                        <div className="absolute right-0 mt-1 w-40 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                          <button
                            type="button"
                            onClick={() => {
                              setPopoverSeverityFilter('all');
                              setShowPopoverSeverityDropdown(false);
                            }}
                            className={`w-full px-2.5 py-1.5 rounded-lg text-[11px] text-left flex items-center justify-between transition cursor-pointer ${
                              popoverSeverityFilter === 'all'
                                ? 'bg-zinc-100 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-zinc-100'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                            }`}
                          >
                            <span>All</span>
                            <span className="text-[10px] text-zinc-400 tabular-nums">({notifications.length})</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setPopoverSeverityFilter('critical');
                              setShowPopoverSeverityDropdown(false);
                            }}
                            className={`w-full px-2.5 py-1.5 rounded-lg text-[11px] text-left flex items-center justify-between transition cursor-pointer ${
                              popoverSeverityFilter === 'critical'
                                ? 'bg-rose-50 dark:bg-rose-950/40 font-semibold text-rose-600 dark:text-rose-400'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                            }`}
                          >
                            <span className="flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-rose-500" />
                              <span>Critical</span>
                            </span>
                            <span className="text-[10px] text-rose-500 tabular-nums">({severityCountsPopover.critical})</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setPopoverSeverityFilter('high');
                              setShowPopoverSeverityDropdown(false);
                            }}
                            className={`w-full px-2.5 py-1.5 rounded-lg text-[11px] text-left flex items-center justify-between transition cursor-pointer ${
                              popoverSeverityFilter === 'high'
                                ? 'bg-amber-50 dark:bg-amber-950/40 font-semibold text-amber-600 dark:text-amber-400'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                            }`}
                          >
                            <span className="flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-amber-500" />
                              <span>High</span>
                            </span>
                            <span className="text-[10px] text-amber-500 tabular-nums">({severityCountsPopover.high})</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setPopoverSeverityFilter('medium');
                              setShowPopoverSeverityDropdown(false);
                            }}
                            className={`w-full px-2.5 py-1.5 rounded-lg text-[11px] text-left flex items-center justify-between transition cursor-pointer ${
                              popoverSeverityFilter === 'medium'
                                ? 'bg-blue-50 dark:bg-blue-950/40 font-semibold text-blue-600 dark:text-blue-400'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                            }`}
                          >
                            <span className="flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-blue-500" />
                              <span>Medium</span>
                            </span>
                            <span className="text-[10px] text-blue-500 tabular-nums">({severityCountsPopover.medium})</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setPopoverSeverityFilter('low');
                              setShowPopoverSeverityDropdown(false);
                            }}
                            className={`w-full px-2.5 py-1.5 rounded-lg text-[11px] text-left flex items-center justify-between transition cursor-pointer ${
                              popoverSeverityFilter === 'low'
                                ? 'bg-emerald-50 dark:bg-emerald-950/40 font-semibold text-emerald-600 dark:text-emerald-400'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                            }`}
                          >
                            <span className="flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-emerald-500" />
                              <span>Low</span>
                            </span>
                            <span className="text-[10px] text-emerald-500 tabular-nums">({severityCountsPopover.low})</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setPopoverSeverityFilter('info');
                              setShowPopoverSeverityDropdown(false);
                            }}
                            className={`w-full px-2.5 py-1.5 rounded-lg text-[11px] text-left flex items-center justify-between transition cursor-pointer ${
                              popoverSeverityFilter === 'info'
                                ? 'bg-zinc-100 dark:bg-slate-950/40 font-semibold text-zinc-700 dark:text-slate-400'
                                : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                            }`}
                          >
                            <span className="flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-slate-500" />
                              <span>Info</span>
                            </span>
                            <span className="text-[10px] text-zinc-400 dark:text-slate-500 tabular-nums">({severityCountsPopover.info})</span>
                          </button>
                        </div>
                      </>
                    )}
                  </div>

                  {notifications.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setNotifications([])}
                      className="text-[11px] text-zinc-400 hover:text-rose-600 transition cursor-pointer"
                    >
                      Clear
                    </button>
                  )}
                </div>

                {/* Notifications Scroll List */}
                <div className="max-h-80 overflow-y-auto divide-y divide-zinc-100 dark:divide-zinc-800/60 custom-scrollbar">
                  {displayedNotifications.length === 0 ? (
                    <div className="p-8 text-center">
                      <FontAwesomeIcon icon={faBell} className="text-2xl text-zinc-300 dark:text-zinc-600 mx-auto mb-2" />
                      <div className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">
                        {notifTab === 'unread'
                          ? 'All notifications read'
                          : popoverSeverityFilter !== 'all'
                            ? `No ${popoverSeverityFilter.charAt(0).toUpperCase() + popoverSeverityFilter.slice(1)} notifications`
                            : 'No new notifications'}
                      </div>
                      <div className="text-[11px] text-zinc-500 mt-1">
                        Perimeter security systems active and monitoring normally.
                      </div>
                    </div>
                  ) : (
                    displayedNotifications.map(n => {
                      const sevUpper = n.severity.toUpperCase();
                      const sevBadge =
                        sevUpper === 'CRITICAL'
                          ? 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900/40 dark:bg-rose-950/40 dark:text-rose-400'
                          : sevUpper === 'HIGH'
                            ? 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/40 dark:bg-amber-950/40 dark:text-amber-400'
                            : 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900/40 dark:bg-blue-950/40 dark:text-blue-400';

                      return (
                        <div
                          key={n.id}
                          onClick={() => {
                            setNotifications(prev =>
                              prev.map(item => (item.id === n.id ? { ...item, read: true } : item))
                            );
                            setShowNotifications(false);
                            onNavigateView(n.view);
                          }}
                          className={`p-3.5 hover:bg-zinc-50 dark:hover:bg-zinc-800/60 transition cursor-pointer group ${
                            !n.read ? 'bg-blue-50/20 dark:bg-blue-950/20' : ''
                          }`}
                        >
                          <div className="flex items-start justify-between gap-2.5">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-1.5 mb-1">
                                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${sevBadge}`}>
                                  {n.severity}
                                </span>
                                <h4 className="text-xs font-semibold truncate group-hover:text-blue-600 dark:group-hover:text-blue-400 transition">
                                  {n.title}
                                </h4>
                                {!n.read && (
                                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 shrink-0" />
                                )}
                              </div>
                              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-snug line-clamp-2">
                                {n.desc}
                              </p>
                              <div className="flex items-center gap-2 mt-1.5 text-[10px] text-zinc-400 font-mono">
                                <span>{timeAgo(n.timestamp)}</span>
                                <span>•</span>
                                <span className="text-blue-600 dark:text-blue-400 font-sans font-medium group-hover:underline">
                                  Buka Modul →
                                </span>
                              </div>
                            </div>

                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setNotifications(prev => prev.filter(item => item.id !== n.id));
                              }}
                              title="Hapus"
                              className="text-zinc-300 hover:text-rose-500 transition p-1"
                            >
                              <FontAwesomeIcon icon={faTrashCan} className="text-xs" />
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Popover Footer: Open Simplified Full Activity Drawer */}
                <div className="p-2.5 border-t border-zinc-100 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 text-center">
                  <button
                    type="button"
                    onClick={() => {
                      setShowNotifications(false);
                      setShowActivityModal(true);
                    }}
                    className="w-full py-1.5 px-3 rounded-lg text-xs font-semibold text-zinc-700 dark:text-zinc-300 hover:bg-white dark:hover:bg-zinc-800 border border-zinc-200/80 dark:border-zinc-800 transition flex items-center justify-center gap-1.5 shadow-2xs cursor-pointer"
                  >
                    <FontAwesomeIcon icon={faExpand} className="text-[10px]" />
                    <span>Lihat Riwayat Lengkap</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* User Account Dropdown */}
          {/* User Account Dropdown */}
          <div className="relative">
            <button
              onClick={() => {
                setShowUserDropdown(prev => !prev);
                setShowOrgDropdown(false);
                setShowNotifications(false);
              }}
              title="Profil Akun"
              className="h-8 sm:h-10 px-2 sm:px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition flex items-center gap-1.5 sm:gap-2.5 shadow-2xs cursor-pointer group shrink-0"
            >
              <div className="w-7 h-7 rounded-full overflow-hidden bg-zinc-900 text-white dark:bg-zinc-800 dark:text-zinc-200 text-[11px] font-bold flex items-center justify-center shrink-0 border border-zinc-200 dark:border-zinc-700">
                {user?.avatarUrl ? (
                  <img src={user.avatarUrl} alt={user?.name || 'User'} className="w-full h-full object-cover" />
                ) : (
                  initialsOf(user?.name)
                )}
              </div>
              <div className="hidden lg:block text-left leading-tight min-w-0">
                <div className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate max-w-[120px] xl:max-w-[140px]">
                  {user?.name || 'User'}
                </div>
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-medium truncate max-w-[120px] xl:max-w-[140px] mt-0.5">
                  {user?.role || 'Security Analyst'}
                </div>
              </div>
              <FontAwesomeIcon
                icon={faChevronDown}
                className={`text-[11px] text-zinc-400 group-hover:text-zinc-600 dark:group-hover:text-zinc-200 transition-transform shrink-0 ${showUserDropdown ? 'rotate-180' : ''}`}
              />
            </button>

            {/* Dropdown Menu matching user specification */}
            {showUserDropdown && (
              <div
                id="dropdown-menu"
                className="absolute right-0 p-2 mt-2 min-w-64 w-72 max-w-[calc(100vw-24px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl z-50 overflow-hidden text-zinc-900 dark:text-zinc-100 animate-in fade-in zoom-in-95 duration-150"
              >
                {/* Header card with user avatar, name & email */}
                <div className="flex items-center gap-2.5 p-2 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/80 dark:bg-zinc-900/60 mb-2">
                  <div className="relative w-9 h-9 shrink-0">
                    <div className="w-full h-full rounded-full border border-zinc-200 dark:border-zinc-700 overflow-hidden bg-zinc-900 text-white dark:bg-zinc-800 text-xs font-bold flex items-center justify-center shadow-xs">
                      {user?.avatarUrl ? (
                        <img src={user.avatarUrl} alt={user?.name || 'User'} className="w-full h-full object-cover" />
                      ) : (
                        initialsOf(user?.name)
                      )}
                    </div>
                  </div>
                  <div className="min-w-0 flex-1 leading-tight">
                    <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                      {user?.name || 'User'}
                    </p>
                    <span className="block text-xs text-zinc-500 dark:text-zinc-400 font-mono truncate mt-0.5">
                      {user?.email || 'user@oat.security'}
                    </span>
                  </div>
                </div>

                {/* Menu items: Hanya Setting Profile dan Keluar */}
                <ul
                  aria-labelledby="dropdown-toggle"
                  className="text-zinc-700 dark:text-zinc-300 text-sm font-medium space-y-0.5"
                >
                  <li>
                    <button
                      type="button"
                      onClick={() => {
                        setShowUserDropdown(false);
                        setShowEditProfileModal(true);
                      }}
                      className="w-full p-2 flex items-center gap-2.5 rounded-lg transition-colors hover:text-zinc-900 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 dark:hover:text-zinc-100 text-left cursor-pointer"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="size-[17px] fill-current shrink-0 overflow-visible text-zinc-400 dark:text-zinc-500" viewBox="0 0 512 512" aria-hidden="true">
                        <path d="M253.414 103.434c48.556 0 87.919 40.52 87.919 90.505s-39.363 90.505-87.919 90.505-87.919-40.521-87.919-90.505 39.363-90.505 87.919-90.505m0 36.202c-28.324 0-51.717 24.081-51.717 54.303s23.393 54.303 51.717 54.303 51.717-24.081 51.717-54.303-23.393-54.303-51.717-54.303" />
                        <path d="M253.414 0c139.957 0 253.414 113.457 253.414 253.414 0 94.285-51.491 176.544-127.886 220.19-35.728 20.575-77.036 32.582-121.104 33.199l-4.423.025C113.457 506.828 0 393.371 0 253.414S113.457 0 253.414 0m-23.676 346.505c-46.331 0-87.479 29.378-102.607 73.008l-2.339 7.571c35.919 27.232 80.165 42.893 126.504 43.522l5.709-.009c38.24-.62 74.079-11.122 105.072-29.064l19.977-13.243-2.237-6.866c-14.371-44.046-55.062-74.052-101.239-74.901zm23.676-310.303c-119.963 0-217.212 97.249-217.212 217.212 0 57.493 22.337 109.77 58.807 148.624 21.668-55.072 74.965-91.735 134.73-91.735h46.831c59.905 0 113.311 36.835 134.885 92.121 36.686-38.892 59.172-91.325 59.172-149.01-.001-119.963-97.25-217.212-217.213-217.212" />
                      </svg>
                      <span>Setting Profile</span>
                    </button>
                  </li>

                  <li className="border-t border-zinc-100 dark:border-zinc-800 my-1 pt-1">
                    <button
                      type="button"
                      onClick={() => {
                        logout();
                        setShowUserDropdown(false);
                      }}
                      className="w-full p-2 flex items-center gap-2.5 rounded-lg text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/30 text-left transition-colors cursor-pointer"
                    >
                      <FontAwesomeIcon icon={faRightFromBracket} className="size-[17px] shrink-0 text-center" />
                      <span>Keluar</span>
                    </button>
                  </li>
                </ul>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Edit Profile Modal */}
      {showEditProfileModal && (
        <EditProfileModal
          user={user}
          currentOrg={currentOrg}
          onClose={() => setShowEditProfileModal(false)}
          onSave={async (payload) => {
            return await updateProfile(payload);
          }}
        />
      )}

      {/* Simplified, Clear Activity Center Modal (Revamped so anyone can check without confusion) */}
      {showActivityModal && (
        <SimplifiedActivityModal
          notifications={notifications}
          soundEnabled={soundEnabled}
          onToggleSound={() => setSoundEnabled(prev => !prev)}
          onMarkAllRead={() => setNotifications(prev => prev.map(n => ({ ...n, read: true })))}
          onMarkRead={(id) => setNotifications(prev => prev.map(n => (n.id === id ? { ...n, read: true } : n)))}
          onClearAll={() => setNotifications([])}
          onDelete={(id) => setNotifications(prev => prev.filter(n => n.id !== id))}
          onNavigateView={onNavigateView}
          onClose={() => setShowActivityModal(false)}
        />
      )}
    </>
  );
};

// ---------------------------------------------------------------------------
// Edit Profile Modal
// ---------------------------------------------------------------------------
function EditProfileModal({
  user,
  currentOrg,
  onClose,
  onSave
}: {
  user: any;
  currentOrg: any;
  onClose: () => void;
  onSave: (payload: {
    name?: string;
    avatarUrl?: string | null;
    username?: string;
    phone?: string;
    telegramBotToken?: string;
    bio?: string;
    linkedinUrl?: string;
    githubUrl?: string;
    twitterUrl?: string;
    instagramUrl?: string;
  }) => Promise<void>;
}) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [name, setName] = useState<string>(user?.name || '');
  const [username, setUsername] = useState<string>(user?.username || '');
  const [phone, setPhone] = useState<string>(user?.phone || '');
  const [telegramBotToken, setTelegramBotToken] = useState<string>(user?.telegramBotToken || '');
  const [bio, setBio] = useState<string>(user?.bio || '');
  const [linkedinUrl, setLinkedinUrl] = useState<string>(user?.linkedinUrl || '');
  const [githubUrl, setGithubUrl] = useState<string>(user?.githubUrl || '');
  const [twitterUrl, setTwitterUrl] = useState<string>(user?.twitterUrl || '');
  const [instagramUrl, setInstagramUrl] = useState<string>(user?.instagramUrl || '');
  const [avatarPreview, setAvatarPreview] = useState<string | null>(user?.avatarUrl || null);
  const [avatarRemoved, setAvatarRemoved] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFileError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setFileError('Ukuran foto melebihi batas 5 MB. Pilih foto yang lebih kecil.');
      e.target.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      setAvatarPreview(ev.target?.result as string);
      setAvatarRemoved(false);
    };
    reader.readAsDataURL(file);
  };

  const handleRemoveAvatar = () => {
    setAvatarPreview(null);
    setAvatarRemoved(true);
    setFileError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      const payload: {
        name?: string;
        avatarUrl?: string | null;
        username?: string;
        phone?: string;
        telegramBotToken?: string;
        bio?: string;
        linkedinUrl?: string;
        githubUrl?: string;
        twitterUrl?: string;
        instagramUrl?: string;
      } = {
        name: name.trim(),
        username: username.trim(),
        phone: phone.trim(),
        telegramBotToken: telegramBotToken.trim(),
        bio: bio.trim(),
        linkedinUrl: linkedinUrl.trim(),
        githubUrl: githubUrl.trim(),
        twitterUrl: twitterUrl.trim(),
        instagramUrl: instagramUrl.trim()
      };
      if (avatarRemoved) {
        payload.avatarUrl = null;
      } else if (avatarPreview !== (user?.avatarUrl || null)) {
        payload.avatarUrl = avatarPreview;
      }
      await onSave(payload);
      setSaved(true);
      setTimeout(() => {
        onClose();
      }, 900);
    } catch (err) {
      setFileError(err instanceof Error && err.message ? err.message : 'Gagal menyimpan profil. Coba lagi.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      {/* Backdrop — sengaja tidak bisa diklik untuk keluar (hindari tertutup sembarangan) */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

      {/* Modal Panel */}
      <div className="relative w-full max-w-md sm:max-w-2xl md:max-w-3xl sm:mx-6 rounded-2xl bg-white dark:bg-zinc-900 border border-zinc-200/80 dark:border-zinc-800 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center px-5 py-4 border-b border-zinc-100 dark:border-zinc-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center text-zinc-600 dark:text-zinc-300 text-sm">
              <FontAwesomeIcon icon={faUserPen} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">Edit Profil</h2>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Perubahan disimpan permanen</p>
            </div>
          </div>
        </div>

        {/* Body — satu kolom di mobile (urutan natural), dua kolom di desktop */}
        <div className="px-5 py-5 max-h-[65vh] overflow-y-auto custom-scrollbar">
          <div className="space-y-5 sm:grid sm:grid-cols-2 sm:gap-x-6 sm:space-y-0 sm:items-start">
            {/* Kolom kiri — foto & identitas */}
            <div className="space-y-5">
          {/* Avatar Section */}
          <div className="flex items-center gap-4">
            {/* Avatar Preview */}
            <div className="relative shrink-0 group">
              <div className="w-20 h-20 rounded-full overflow-hidden border-2 border-zinc-200 dark:border-zinc-700 bg-zinc-900 text-white dark:bg-zinc-800 flex items-center justify-center text-xl font-bold shadow-inner">
                {avatarPreview ? (
                  <img src={avatarPreview} alt="Preview" className="w-full h-full object-cover" />
                ) : (
                  <span className="text-white dark:text-zinc-200">
                    {(name || user?.name || '?').trim().split(/\s+/).map((p: string) => p[0]).join('').slice(0, 2).toUpperCase()}
                  </span>
                )}
              </div>
              {/* Camera overlay */}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="absolute inset-0 rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition flex items-center justify-center text-white cursor-pointer"
                title="Ganti foto"
              >
                <FontAwesomeIcon icon={faCamera} className="text-lg" />
              </button>
            </div>

            {/* Upload controls */}
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Foto Profil</p>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mb-2.5">PNG, JPG, WebP · Maks. 5 MB</p>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="px-3 py-1.5 rounded-lg border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition cursor-pointer flex items-center gap-1.5"
                >
                  <FontAwesomeIcon icon={faCamera} className="text-[10px]" />
                  <span>Ganti Foto</span>
                </button>
                {avatarPreview && (
                  <button
                    type="button"
                    onClick={handleRemoveAvatar}
                    className="px-3 py-1.5 rounded-lg border border-rose-200 dark:border-rose-800/60 bg-rose-50 dark:bg-rose-950/30 text-xs font-medium text-rose-600 dark:text-rose-400 hover:bg-rose-100 dark:hover:bg-rose-950/50 transition cursor-pointer flex items-center gap-1.5"
                  >
                    <FontAwesomeIcon icon={faTrashCan} className="text-[10px]" />
                    <span>Hapus</span>
                  </button>
                )}
              </div>
              {fileError && (
                <p className="text-[11px] text-rose-600 dark:text-rose-400 mt-2 leading-relaxed">{fileError}</p>
              )}
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/gif"
              className="hidden"
              onChange={handleFileChange}
            />
          </div>

          {/* Divider */}
          <div className="border-t border-zinc-100 dark:border-zinc-800" />

          {/* Name field */}
          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1.5">
              Nama Lengkap
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Masukkan nama lengkap"
              className="w-full px-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-300 dark:focus:ring-zinc-600 transition"
            />
          </div>

          {/* Username & phone */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1.5">Username</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400 dark:text-zinc-500">
                  <FontAwesomeIcon icon={faAt} className="text-xs" />
                </span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  maxLength={32}
                  placeholder="isaki_prananda"
                  className="w-full pl-8 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-300 dark:focus:ring-zinc-600 transition"
                />
              </div>
              <p className="text-[10px] text-zinc-400 dark:text-zinc-500 mt-1">3–32 karakter: huruf, angka, titik, _ atau -</p>
            </div>
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1.5">Nomor HP</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400 dark:text-zinc-500">
                  <FontAwesomeIcon icon={faPhone} className="text-xs" />
                </span>
                <input
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  maxLength={24}
                  placeholder="+62 812 3456 7890"
                  className="w-full pl-8 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-300 dark:focus:ring-zinc-600 transition"
                />
              </div>
            </div>
          </div>
            </div>

            {/* Kolom kanan — info akun & integrasi */}
            <div className="space-y-5">

          {/* Read-only info */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-zinc-500 dark:text-zinc-500 mb-1.5">Email Akun</label>
              <div className="px-3 py-2 rounded-xl border border-zinc-100 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/50 text-xs text-zinc-500 dark:text-zinc-400 font-mono truncate" title={user?.email || '-'}>
                {user?.email || '-'}
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-zinc-500 dark:text-zinc-500 mb-1.5">Role</label>
              <div className="px-3 py-2 rounded-xl border border-zinc-100 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/50 text-xs text-zinc-500 dark:text-zinc-400 truncate flex items-center gap-1.5">
                <FontAwesomeIcon icon={faShieldHalved} className="text-[10px] text-zinc-400 shrink-0" />
                <span className="truncate">{user?.role || 'Security Analyst'}</span>
              </div>
            </div>
          </div>

          {currentOrg && (
            <div>
              <label className="block text-xs font-semibold text-zinc-500 dark:text-zinc-500 mb-1.5">Organisasi</label>
              <div className="px-3 py-2 rounded-xl border border-zinc-100 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/50 text-xs text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5">
                <FontAwesomeIcon icon={faBuilding} className="text-[10px] text-zinc-400 shrink-0" />
                <span className="truncate">{currentOrg.name}</span>
                <span className="ml-auto shrink-0 px-1.5 py-0.5 rounded-full bg-zinc-200 dark:bg-zinc-700 text-[9px] font-semibold text-zinc-600 dark:text-zinc-300 uppercase">{currentOrg.tier || 'Enterprise'}</span>
              </div>
            </div>
          )}

          {/* Integrasi & identitas tambahan */}
          <div className="border-t border-zinc-100 dark:border-zinc-800" />

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1.5">API Key Bot Telegram</label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400 dark:text-zinc-500">
                <FontAwesomeIcon icon={faPaperPlane} className="text-xs" />
              </span>
              <input
                type="text"
                value={telegramBotToken}
                onChange={(e) => setTelegramBotToken(e.target.value)}
                maxLength={255}
                placeholder="123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                className="w-full pl-8 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-xs font-mono text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-300 dark:focus:ring-zinc-600 transition"
              />
            </div>
            <p className="text-[10px] text-zinc-400 dark:text-zinc-500 mt-1">Token dari @BotFather — dipakai bot untuk mengirim alert ke chat Telegram Anda.</p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-2">Tautan Sosial Media</label>
            <div className="grid grid-cols-1 gap-2.5">
              {/* LinkedIn */}
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[#0A66C2]">
                  <FontAwesomeIcon icon={faLinkedin} className="text-sm" />
                </span>
                <input
                  type="url"
                  value={linkedinUrl}
                  onChange={(e) => setLinkedinUrl(e.target.value)}
                  maxLength={512}
                  placeholder="https://linkedin.com/in/username"
                  className="w-full pl-9 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-[#0A66C2]/40 transition"
                />
              </div>
              {/* GitHub */}
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-800 dark:text-zinc-200">
                  <FontAwesomeIcon icon={faGithub} className="text-sm" />
                </span>
                <input
                  type="url"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  maxLength={512}
                  placeholder="https://github.com/username"
                  className="w-full pl-9 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-400/40 transition"
                />
              </div>
              {/* X / Twitter */}
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-900 dark:text-zinc-100">
                  <FontAwesomeIcon icon={faXTwitter} className="text-sm" />
                </span>
                <input
                  type="url"
                  value={twitterUrl}
                  onChange={(e) => setTwitterUrl(e.target.value)}
                  maxLength={512}
                  placeholder="https://x.com/username"
                  className="w-full pl-9 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-400/40 transition"
                />
              </div>
              {/* Instagram */}
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-pink-500">
                  <FontAwesomeIcon icon={faInstagram} className="text-sm" />
                </span>
                <input
                  type="url"
                  value={instagramUrl}
                  onChange={(e) => setInstagramUrl(e.target.value)}
                  maxLength={512}
                  placeholder="https://instagram.com/username"
                  className="w-full pl-9 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-pink-400/40 transition"
                />
              </div>
            </div>
            <p className="text-[10px] text-zinc-400 dark:text-zinc-500 mt-1.5">Wajib berawalan https://</p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1.5">Bio</label>
            <div className="relative">
              <span className="absolute left-3 top-3 text-zinc-400 dark:text-zinc-500">
                <FontAwesomeIcon icon={faCommentDots} className="text-xs" />
              </span>
              <textarea
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                maxLength={500}
                rows={3}
                placeholder="Ceritakan sedikit tentang Anda — jabatan, fokus keamanan, tim."
                className="w-full pl-8 pr-3 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-300 dark:focus:ring-zinc-600 transition resize-none"
              />
            </div>
            <p className="text-[10px] text-zinc-400 dark:text-zinc-500 mt-1 text-right">{bio.length}/500</p>
          </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-zinc-100 dark:border-zinc-800 flex items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="px-4 py-2 rounded-xl border border-zinc-200/80 dark:border-zinc-700 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition cursor-pointer disabled:opacity-50"
          >
            Batal
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving || !name.trim() || saved}
            className="px-5 py-2 rounded-xl bg-zinc-900 dark:bg-zinc-100 text-sm font-semibold text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-200 transition cursor-pointer disabled:opacity-60 flex items-center gap-2 min-w-[100px] justify-center"
          >
            {saved ? (
              <>
                <FontAwesomeIcon icon={faCircleCheck} className="text-emerald-400 dark:text-emerald-600" />
                <span>Tersimpan</span>
              </>
            ) : saving ? (
              <>
                <FontAwesomeIcon icon={faSpinner} className="animate-spin text-xs" />
                <span>Menyimpan...</span>
              </>
            ) : (
              <span>Simpan Profil</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Simplified, Super-Clear Activity Center Modal
// ---------------------------------------------------------------------------
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';

function SimplifiedActivityModal({
  notifications,
  soundEnabled,
  onToggleSound,
  onMarkAllRead,
  onMarkRead,
  onClearAll,
  onDelete,
  onNavigateView,
  onClose
}: {
  notifications: TopNotification[];
  soundEnabled: boolean;
  onToggleSound: () => void;
  onMarkAllRead: () => void;
  onMarkRead: (id: string) => void;
  onClearAll: () => void;
  onDelete: (id: string) => void;
  onNavigateView: (view: DashboardView) => void;
  onClose: () => void;
}) {
  const [filter, setFilter] = useState<'all' | 'unread' | SeverityFilter>('all');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);

  const unreadCount = notifications.filter(n => !n.read).length;
  const severityCounts = {
    critical: notifications.filter(n => n.severity.toUpperCase() === 'CRITICAL').length,
    high: notifications.filter(n => n.severity.toUpperCase() === 'HIGH').length,
    medium: notifications.filter(n => n.severity.toUpperCase() === 'MEDIUM').length,
    low: notifications.filter(n => n.severity.toUpperCase() === 'LOW').length,
    info: notifications.filter(n => n.severity.toUpperCase() === 'INFO').length,
  };

  const filtered = notifications.filter(n => {
    if (filter === 'unread' && n.read) return false;
    if (filter !== 'all' && filter !== 'unread' && n.severity.toUpperCase() !== filter.toUpperCase()) return false;
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-fadeIn">
      <div className="relative w-full max-w-2xl min-h-[400px] max-h-[82vh] rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl overflow-hidden flex flex-col text-zinc-900 dark:text-zinc-100 transition-colors">
        {/* Modal Top Bar - Clean & Minimalist */}
        <div className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800 flex items-center justify-between gap-3 bg-white dark:bg-[#0c0c0e]">
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="w-8 h-8 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 flex items-center justify-center shrink-0">
              <FontAwesomeIcon icon={faBell} className="text-xs" />
            </span>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                Pusat Notifikasi Keamanan
              </h3>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                Peringatan perimeter langsung &amp; telemetri
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            {/* Minimalist Sound Toggle */}
            <button
              type="button"
              onClick={onToggleSound}
              title={soundEnabled ? 'Suara notifikasi aktif (klik untuk membisukan)' : 'Suara notifikasi dibisukan (klik untuk menyalakan)'}
              className={`h-8 px-2.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ${
                soundEnabled
                  ? 'border-zinc-200/80 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/80 text-zinc-800 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-700'
                  : 'border-zinc-200/40 dark:border-zinc-800/40 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300'
              }`}
            >
              <FontAwesomeIcon
                icon={soundEnabled ? faVolumeHigh : faVolumeXmark}
                className={`text-xs ${soundEnabled ? 'text-emerald-500' : 'text-zinc-400'}`}
              />
              <span className="text-[11px]">{soundEnabled ? 'Suara' : 'Mute'}</span>
            </button>

            <button
              onClick={onClose}
              title="Tutup"
              className="w-8 h-8 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition cursor-pointer"
            >
              <FontAwesomeIcon icon={faXmark} className="text-xs" />
            </button>
          </div>
        </div>

        {/* Action Controls & Filters: Minimalist Dropdown & Quick Actions */}
        <div className="px-5 py-2.5 border-b border-zinc-100 dark:border-zinc-800 flex items-center justify-between gap-3 bg-zinc-50/40 dark:bg-zinc-900/40">
          {/* Dropdown Filter */}
          <div className="flex items-center gap-2.5">
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowFilterDropdown(prev => !prev)}
                className="h-8 px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <FontAwesomeIcon icon={faFilter} className="text-[10px] text-zinc-400" />
                <span>
                  {filter === 'unread'
                    ? `Unread (${unreadCount})`
                    : filter === 'all'
                      ? `All (${notifications.length})`
                      : filter === 'critical'
                        ? `Critical (${severityCounts.critical})`
                        : filter === 'high'
                          ? `High (${severityCounts.high})`
                          : filter === 'medium'
                            ? `Medium (${severityCounts.medium})`
                            : filter === 'low'
                              ? `Low (${severityCounts.low})`
                              : filter === 'info'
                                ? `Info (${severityCounts.info})`
                                : `All (${notifications.length})`}
                </span>
                <FontAwesomeIcon
                  icon={faChevronDown}
                  className={`text-[9px] text-zinc-400 ml-0.5 transition-transform ${showFilterDropdown ? 'rotate-180' : ''}`}
                />
              </button>

              {showFilterDropdown && (
                <>
                  <div
                    className="fixed inset-0 z-20 cursor-default"
                    onClick={() => setShowFilterDropdown(false)}
                  />
                  <div className="absolute left-0 mt-1.5 w-48 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('all');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'all'
                          ? 'bg-zinc-100 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-zinc-100'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span>All</span>
                      <span className="text-[10px] text-zinc-400 tabular-nums">({notifications.length})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('unread');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'unread'
                          ? 'bg-zinc-100 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-zinc-100'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span>Unread</span>
                      <span className="text-[10px] text-zinc-400 tabular-nums">({unreadCount})</span>
                    </button>
                    <div className="border-t border-zinc-100 dark:border-zinc-800 my-1" />
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('critical');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'critical'
                          ? 'bg-rose-50 dark:bg-rose-950/40 font-semibold text-rose-600 dark:text-rose-400'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-rose-500" />
                        <span>Critical</span>
                      </span>
                      <span className="text-[10px] text-rose-500 tabular-nums">({severityCounts.critical})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('high');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'high'
                          ? 'bg-amber-50 dark:bg-amber-950/40 font-semibold text-amber-600 dark:text-amber-400'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-amber-500" />
                        <span>High</span>
                      </span>
                      <span className="text-[10px] text-amber-500 tabular-nums">({severityCounts.high})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('medium');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'medium'
                          ? 'bg-blue-50 dark:bg-blue-950/40 font-semibold text-blue-600 dark:text-blue-400'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-blue-500" />
                        <span>Medium</span>
                      </span>
                      <span className="text-[10px] text-blue-500 tabular-nums">({severityCounts.medium})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('low');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'low'
                          ? 'bg-emerald-50 dark:bg-emerald-950/40 font-semibold text-emerald-600 dark:text-emerald-400'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span>Low</span>
                      </span>
                      <span className="text-[10px] text-emerald-500 tabular-nums">({severityCounts.low})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFilter('info');
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        filter === 'info'
                          ? 'bg-zinc-100 dark:bg-slate-950/40 font-semibold text-zinc-700 dark:text-slate-400'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-slate-500" />
                        <span>Info</span>
                      </span>
                      <span className="text-[10px] text-zinc-400 dark:text-slate-500 tabular-nums">({severityCounts.info})</span>
                    </button>
                  </div>
                </>
              )}
            </div>

            <span className="text-[11px] text-zinc-400 tabular-nums hidden sm:inline">
              Menampilkan {filtered.length} dari {notifications.length}
            </span>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center gap-1.5">
            {unreadCount > 0 && (
              <button
                type="button"
                onClick={onMarkAllRead}
                title="Tandai semua telah dibaca"
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-xs text-zinc-600 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition cursor-pointer shadow-2xs flex items-center gap-1.5"
              >
                <FontAwesomeIcon icon={faCheck} className="text-[10px]" />
                <span className="text-[11px] font-medium">Tandai Dibaca</span>
              </button>
            )}

            {notifications.length > 0 && (
              <button
                type="button"
                onClick={onClearAll}
                title="Bersihkan riwayat notifikasi"
                className="h-8 px-2.5 rounded-lg text-xs text-zinc-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50/50 dark:hover:bg-rose-950/20 transition cursor-pointer flex items-center gap-1.5"
              >
                <FontAwesomeIcon icon={faTrashCan} className="text-[10px]" />
                <span className="text-[11px] font-medium">Bersihkan</span>
              </button>
            )}
          </div>
        </div>

        {/* Notification Cards List: Clean, intuitive, actionable cards */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2.5 custom-scrollbar">
          {filtered.length === 0 ? (
            <div className="py-16 text-center">
              <FontAwesomeIcon icon={faBell} className="text-3xl text-zinc-300 dark:text-zinc-700 mx-auto mb-3" />
              <div className="text-sm font-bold text-zinc-700 dark:text-zinc-300">
                Tidak ada notifikasi yang sesuai
              </div>
              <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                {filter === 'unread'
                  ? 'Hebat! Anda telah membaca semua notifikasi keamanan.'
                  : filter === 'critical'
                    ? 'Tidak ada insiden berstatus kritis saat ini.'
                    : 'Semua sistem perimeter berjalan aman.'}
              </p>
            </div>
          ) : (
            filtered.map(n => {
              const sevUpper = n.severity.toUpperCase();
              const isCrit = sevUpper === 'CRITICAL';
              const isHigh = sevUpper === 'HIGH';

              const badgeColor = isCrit
                ? 'border-rose-200 bg-rose-100 text-rose-800 dark:border-rose-900/60 dark:bg-rose-950/60 dark:text-rose-400'
                : isHigh
                  ? 'border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/60 dark:text-amber-400'
                  : 'border-blue-200 bg-blue-100 text-blue-800 dark:border-blue-900/60 dark:bg-blue-950/60 dark:text-blue-400';

              return (
                <div
                  key={n.id}
                  className={`p-4 rounded-xl border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs ${
                    !n.read
                      ? 'border-blue-200/80 bg-blue-50/30 dark:border-blue-900/40 dark:bg-blue-950/20'
                      : 'border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-zinc-300 dark:hover:border-zinc-700'
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${badgeColor}`}>
                        {n.severity}
                      </span>
                      <h4 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 truncate">
                        {n.title}
                      </h4>
                      {!n.read && (
                        <span className="w-2 h-2 rounded-full bg-blue-600 shrink-0" title="Belum dibaca" />
                      )}
                    </div>

                    <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed font-mono">
                      {n.desc}
                    </p>

                    <div className="flex items-center gap-3 mt-2 text-[11px] text-zinc-400 font-mono">
                      <span>{timeAgo(n.timestamp)}</span>
                      <span>•</span>
                      <span className="text-zinc-500 font-sans">
                        Modul tujuan: <strong className="uppercase">{n.view}</strong>
                      </span>
                    </div>
                  </div>

                  {/* Actions: One big clear Inspect button, plus check and delete */}
                  <div className="flex items-center gap-2 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-zinc-100 dark:border-zinc-800">
                    <button
                      type="button"
                      onClick={() => {
                        onMarkRead(n.id);
                        onClose();
                        onNavigateView(n.view);
                      }}
                      className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-2 transition cursor-pointer shadow-2xs"
                    >
                      <span>Periksa &amp; Buka</span>
                      <FontAwesomeIcon icon={faArrowRight} className="text-[10px]" />
                    </button>

                    {!n.read && (
                      <button
                        type="button"
                        onClick={() => onMarkRead(n.id)}
                        title="Tandai telah dibaca"
                        className="w-8 h-8 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-500 hover:text-emerald-600 transition flex items-center justify-center cursor-pointer shadow-2xs"
                      >
                        <FontAwesomeIcon icon={faCheck} className="text-xs" />
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => onDelete(n.id)}
                      title="Hapus notifikasi"
                      className="w-8 h-8 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-400 hover:text-rose-600 hover:border-rose-300 transition flex items-center justify-center cursor-pointer shadow-2xs"
                    >
                      <FontAwesomeIcon icon={faTrashCan} className="text-xs" />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
