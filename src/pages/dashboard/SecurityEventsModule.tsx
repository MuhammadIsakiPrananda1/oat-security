import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  RefreshCw,
  Search,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Filter,
  Download,
  WifiOff,
  FileCode2,
  Copy,
  Check,
  ShieldCheck,
  Cpu,
  Layers
} from 'lucide-react';
import {
  securityApi,
  telemetryStreamManager,
  globalRealtimeClient,
  normalizeRealtimeSecurityEvent,
  RealtimeStreamStatus
} from '../../services/api';
import { SecurityEvent } from '../../types';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faHeartPulse, faPaperPlane, faShieldVirus, faFilePdf } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { getLanguage } from '../../i18n/translator';
import { CountryFlag } from '../../components/common/CountryFlag';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime, formatTime } from '../../utils/dateTime';
import { classifyLocalIp, getCountryName, extractIpOnly } from '../../utils/ip';

type ActionFilterValue = 'ALL' | 'BLOCKED' | 'ALLOWED' | 'CHALLENGED' | 'LOGGED';
type ActionGroup = 'BLOCKED' | 'ALLOWED' | 'CHALLENGED' | 'LOGGED' | 'OTHER';

const actionGroupOf = (action?: string | null): ActionGroup => {
  const value = String(action || '').toUpperCase();
  if (['BLOCK', 'BLOCKED', 'DENY', 'DROP'].includes(value)) return 'BLOCKED';
  if (['ALLOW', 'ALLOWED', 'PASS'].includes(value)) return 'ALLOWED';
  if (['CHALLENGE', 'CHALLENGED', 'RATE_LIMIT'].includes(value)) return 'CHALLENGED';
  if (['LOG', 'LOGGED'].includes(value)) return 'LOGGED';
  return 'OTHER';
};

const ACTION_FILTER_OPTIONS: {
  value: ActionFilterValue;
  label: string;
  dot: string;
  activeBg: string;
  activeText: string;
  countColor: string;
}[] = [
  { value: 'ALL', label: 'All Actions', dot: 'bg-zinc-400', activeBg: '', activeText: 'text-zinc-900 dark:text-zinc-100', countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'BLOCKED', label: 'Blocked', dot: 'bg-rose-500', activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400', countColor: 'text-rose-500' },
  { value: 'ALLOWED', label: 'Allowed', dot: 'bg-emerald-500', activeBg: 'bg-emerald-50 dark:bg-emerald-950/40', activeText: 'text-emerald-600 dark:text-emerald-400', countColor: 'text-emerald-500' },
  { value: 'CHALLENGED', label: 'Challenged', dot: 'bg-amber-400', activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'LOGGED', label: 'Logged Only', dot: 'bg-zinc-400', activeBg: 'bg-zinc-100 dark:bg-zinc-800', activeText: 'text-zinc-700 dark:text-zinc-200', countColor: 'text-zinc-500' },
];

type SeverityFilterValue = 'ALL' | 'Critical' | 'High' | 'Medium' | 'Low';

const SEVERITY_FILTER_OPTIONS: {
  value: SeverityFilterValue;
  label: string;
  dot: string;
  activeBg: string;
  activeText: string;
  countColor: string;
}[] = [
  { value: 'ALL', label: 'All Severities', dot: 'bg-zinc-400', activeBg: '', activeText: 'text-zinc-900 dark:text-zinc-100', countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'Critical', label: 'Critical', dot: 'bg-rose-500', activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400', countColor: 'text-rose-500' },
  { value: 'High', label: 'High', dot: 'bg-amber-400', activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'Medium', label: 'Medium', dot: 'bg-yellow-400', activeBg: 'bg-yellow-50 dark:bg-yellow-950/40', activeText: 'text-yellow-600 dark:text-yellow-300', countColor: 'text-yellow-500' },
  { value: 'Low', label: 'Low', dot: 'bg-sky-400', activeBg: 'bg-sky-50 dark:bg-sky-950/40', activeText: 'text-sky-600 dark:text-sky-300', countColor: 'text-sky-500' },
];

type SourceFilterValue = 'ALL' | 'waf' | 'firewall' | 'agent';

const SOURCE_FILTER_OPTIONS: { value: SourceFilterValue; label: string; dot: string }[] = [
  { value: 'ALL', label: 'All Engines', dot: 'bg-zinc-400' },
  { value: 'waf', label: 'WAF Engine', dot: 'bg-violet-500' },
  { value: 'firewall', label: 'Firewall', dot: 'bg-amber-500' },
  { value: 'agent', label: 'Endpoint Agents', dot: 'bg-cyan-500' }
];

export const SecurityEventsModule: React.FC = () => {
  const { currentOrg, isBackendOffline } = useAuth();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [recordedTotal, setRecordedTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  // Filters
  const [actionFilter, setActionFilter] = useState<ActionFilterValue>('ALL');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilterValue>('ALL');
  const [sourceFilter, setSourceFilter] = useState<SourceFilterValue>('ALL');
  const [appFilter, setAppFilter] = useState<string>('ALL');
  const [search, setSearch] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Dropdown states
  const [showActionDropdown, setShowActionDropdown] = useState(false);
  const [showSeverityDropdown, setShowSeverityDropdown] = useState(false);
  const [showSourceDropdown, setShowSourceDropdown] = useState(false);
  const [showAppDropdown, setShowAppDropdown] = useState(false);

  // Real-time connection & inspector
  const [realtimeStatus, setRealtimeStatus] = useState<RealtimeStreamStatus>('CONNECTED');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [eventDetail, setEventDetail] = useState<any | null>(null);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [escalatingSoc, setEscalatingSoc] = useState(false);
  const [escalateSuccess, setEscalateSuccess] = useState<string | null>(null);

  // Mobile swipe-to-dismiss gesture state (mobile only)
  const [swipeTranslateX, setSwipeTranslateX] = useState(0);
  const [isSwiping, setIsSwiping] = useState(false);
  const touchStartRef = useRef<{ x: number; y: number; time: number } | null>(null);

  const handleTouchStart = (e: React.TouchEvent) => {
    if (typeof window !== 'undefined' && window.innerWidth >= 640) return;
    const touch = e.touches[0];
    touchStartRef.current = {
      x: touch.clientX,
      y: touch.clientY,
      time: Date.now()
    };
    setIsSwiping(false);
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!touchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) return;
    const touch = e.touches[0];
    const deltaX = touch.clientX - touchStartRef.current.x;
    const deltaY = touch.clientY - touchStartRef.current.y;

    if (deltaX > 8 && deltaX > Math.abs(deltaY) * 1.1) {
      setIsSwiping(true);
      setSwipeTranslateX(Math.max(0, deltaX));
    } else if (deltaX <= 0 && isSwiping) {
      setSwipeTranslateX(0);
    }
  };

  const handleTouchEnd = () => {
    if (!touchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) {
      touchStartRef.current = null;
      setIsSwiping(false);
      setSwipeTranslateX(0);
      return;
    }

    const elapsed = Date.now() - touchStartRef.current.time;
    const shouldDismiss = swipeTranslateX > 80 || (swipeTranslateX > 40 && elapsed < 250);

    if (shouldDismiss) {
      setSwipeTranslateX(window.innerWidth || 400);
      setTimeout(() => {
        setSelectedEvent(null);
        setEventDetail(null);
        setSwipeTranslateX(0);
        setIsSwiping(false);
      }, 150);
    } else {
      setIsSwiping(false);
      setSwipeTranslateX(0);
    }
    touchStartRef.current = null;
  };

  // Database-wide aggregates for side rail & filter badges
  const [aggregateActions, setAggregateActions] = useState<{
    blocked: number;
    allowed: number;
    challenged: number;
    logged: number;
    other: number;
    total: number;
  } | null>(null);

  const [aggregateSeverities, setAggregateSeverities] = useState<{
    critical: number;
    high: number;
    medium: number;
    low: number;
  } | null>(null);

  const [topSourceIpsAgg, setTopSourceIpsAgg] = useState<Array<{
    ip: string;
    count: number;
    sourceCountry?: string;
    sourceCountryCode?: string;
  }>>([]);
  const [topApplicationsAgg, setTopApplicationsAgg] = useState<Array<{ application: string; count: number }>>([]);

  // Debounce search input
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearchTerm(search.trim());
      setCurrentPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  // Load events for the current page and active filters
  const fetchEvents = useCallback(async () => {
    if (isBackendOffline) return;
    setLoading(true);
    try {
      const res = await securityApi.getSecurityEvents({
        limit: pageSize,
        page: currentPage,
        action: actionFilter === 'ALL' ? undefined : actionFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        source: sourceFilter === 'ALL' ? undefined : sourceFilter,
        application: appFilter === 'ALL' ? undefined : appFilter,
        search: searchTerm || undefined
      });

      if (res.events) {
        setEvents(prev => {
          const serverIds = new Set(res.events.map(e => e.id));
          const pendingLive = prev.filter(e => !serverIds.has(e.id));
          return [...pendingLive, ...res.events].slice(0, pageSize);
        });
      }
      if (typeof res.total === 'number') {
        setRecordedTotal(res.total);
      }
    } catch (err) {
      console.error('[SecurityEvents] Fetch failed:', err);
    } finally {
      setLoading(false);
    }
  }, [isBackendOffline, pageSize, currentPage, actionFilter, severityFilter, sourceFilter, appFilter, searchTerm]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Periodic background refresh every 2.5s on page 1 so events sync without manual refresh
  useEffect(() => {
    if (isBackendOffline) return;
    const timer = window.setInterval(async () => {
      if (currentPage !== 1) return;
      try {
        const res = await securityApi.getSecurityEvents({
          limit: pageSize,
          page: 1,
          action: actionFilter === 'ALL' ? undefined : actionFilter,
          severity: severityFilter === 'ALL' ? undefined : severityFilter,
          source: sourceFilter === 'ALL' ? undefined : sourceFilter,
          application: appFilter === 'ALL' ? undefined : appFilter,
          search: searchTerm || undefined
        });
        if (res.events && res.events.length > 0) {
          setEvents(prev => {
            const serverIds = new Set(res.events.map(e => e.id));
            const pendingLive = prev.filter(e => !serverIds.has(e.id));
            const merged = [...pendingLive, ...res.events].slice(0, pageSize);
            if (prev.length === merged.length && prev.every((e, i) => e.id === merged[i]?.id)) {
              return prev;
            }
            return merged;
          });
          if (typeof res.total === 'number') {
            setRecordedTotal(res.total);
          }
        }
      } catch {}
    }, 2500);
    return () => window.clearInterval(timer);
  }, [isBackendOffline, currentPage, pageSize, actionFilter, severityFilter, sourceFilter, appFilter, searchTerm]);

  // Load aggregates for the side rail from full DB
  const fetchAggregates = useCallback(async () => {
    if (isBackendOffline) return;
    try {
      const res = await securityApi.getSecurityEventsAggregates({ limit: 10 });
      setTopSourceIpsAgg(res.topSourceIps || []);
      setTopApplicationsAgg(res.topApplications || []);
      setAggregateActions(res.actions ? { ...res.actions, total: res.total } : null);
      setAggregateSeverities(res.severities || null);
    } catch (err) {
      console.error('[SecurityEvents] Aggregates fetch failed:', err);
    }
  }, [isBackendOffline]);

  useEffect(() => {
    fetchAggregates();
    const interval = window.setInterval(fetchAggregates, 60000);
    return () => window.clearInterval(interval);
  }, [fetchAggregates]);

  // Real-time WebSocket event subscription
  useEffect(() => {
    if (isBackendOffline) return;

    const unsubStatus = globalRealtimeClient.onStatusChange(status => {
      setRealtimeStatus(status);
    });

    const matchesActiveView = (evt: SecurityEvent) => {
      if (actionFilter !== 'ALL' && actionGroupOf(evt.action) !== actionFilter) return false;
      if (severityFilter !== 'ALL' && String(evt.severity || '').toLowerCase() !== severityFilter.toLowerCase()) return false;
      if (sourceFilter !== 'ALL') {
        const src = String(evt.source || evt.category || '').toLowerCase();
        if (!src.includes(sourceFilter.toLowerCase())) return false;
      }
      if (appFilter !== 'ALL' && evt.application !== appFilter) return false;
      const term = searchTerm.trim().toLowerCase();
      if (!term) return true;
      return [evt.sourceIp, evt.application, evt.threat, evt.id]
        .some(val => String(val || '').toLowerCase().includes(term));
    };

    const unsubEvents = telemetryStreamManager.subscribe((msg: any) => {
      const newEvent = normalizeRealtimeSecurityEvent(msg);
      if (!newEvent || !matchesActiveView(newEvent)) return;

      setRecordedTotal(prev => prev + 1);

      // Instantly update aggregated counts and rail metrics in real-time (0ms delay)
      const group = actionGroupOf(newEvent.action);
      setAggregateActions(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          total: prev.total + 1,
          blocked: group === 'BLOCKED' ? prev.blocked + 1 : prev.blocked,
          allowed: group === 'ALLOWED' ? prev.allowed + 1 : prev.allowed,
          challenged: group === 'CHALLENGED' ? prev.challenged + 1 : prev.challenged,
          logged: group === 'LOGGED' ? prev.logged + 1 : prev.logged,
          other: group === 'OTHER' ? prev.other + 1 : prev.other
        };
      });

      const sev = String(newEvent.severity || '').toLowerCase();
      setAggregateSeverities(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          critical: sev === 'critical' ? prev.critical + 1 : prev.critical,
          high: sev === 'high' ? prev.high + 1 : prev.high,
          medium: sev === 'medium' ? prev.medium + 1 : prev.medium,
          low: sev === 'low' ? prev.low + 1 : prev.low
        };
      });

      if (newEvent.sourceIp && newEvent.sourceIp !== '0.0.0.0') {
        setTopSourceIpsAgg(prev => {
          const idx = prev.findIndex(item => item.ip === newEvent.sourceIp);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = { ...next[idx], count: next[idx].count + 1 };
            return next.sort((a, b) => b.count - a.count);
          }
          return [...prev, {
            ip: newEvent.sourceIp,
            count: 1,
            sourceCountry: newEvent.sourceCountry,
            sourceCountryCode: newEvent.sourceCountryCode
          }].sort((a, b) => b.count - a.count).slice(0, 10);
        });
      }

      // Prepend event live if user is currently looking at page 1
      if (currentPage === 1) {
        setEvents(prev => {
          if (prev.some(e => e.id === newEvent.id)) return prev;
          return [newEvent, ...prev.slice(0, pageSize - 1)];
        });
      }
    });

    return () => {
      unsubStatus();
      unsubEvents();
    };
  }, [isBackendOffline, currentPage, pageSize, actionFilter, severityFilter, sourceFilter, appFilter, searchTerm]);

  const extractReadableMessage = (raw?: string): string => {
    if (!raw) return '';
    const s = String(raw).trim();
    if (s.startsWith('{') || s.includes('"MESSAGE"') || s.includes('"SYSLOG_IDENTIFIER"')) {
      try {
        const jsonCandidate = s.startsWith('{') ? (s.endsWith('}') ? s : s + '}') : '{' + s + '}';
        const obj = JSON.parse(jsonCandidate);
        if (obj.threat || obj.threatName) return String(obj.threat || obj.threatName);
        if (obj.message || obj.MESSAGE) {
          const id = obj.SYSLOG_IDENTIFIER || obj.ident || obj.application || '';
          return id ? `${id}: ${obj.message || obj.MESSAGE}` : String(obj.message || obj.MESSAGE);
        }
        if (obj.rawLog) return String(obj.rawLog);
      } catch {
        const msgMatch = s.match(/"(?:MESSAGE|message)"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/);
        const idMatch = s.match(/"(?:SYSLOG_IDENTIFIER|ident|application)"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/);
        if (msgMatch && msgMatch[1]) {
          const cleanMsg = msgMatch[1].replace(/\\"/g, '"');
          return idMatch && idMatch[1] ? `${idMatch[1]}: ${cleanMsg}` : cleanMsg;
        }
      }
    }
    return s;
  };

  const wrapLines = (text: string, maxLen = 65, maxLines = 4): string[] => {
    const clean = text.replace(/[()\\]/g, '').trim();
    if (!clean) return [''];
    const lines: string[] = [];
    let remaining = clean;
    while (remaining.length > 0 && lines.length < maxLines) {
      if (remaining.length <= maxLen || lines.length === maxLines - 1) {
        lines.push(remaining.length > maxLen ? remaining.slice(0, maxLen - 3) + '...' : remaining);
        break;
      }
      let splitIdx = remaining.lastIndexOf(' ', maxLen);
      if (splitIdx < Math.floor(maxLen * 0.4)) {
        splitIdx = maxLen;
      }
      lines.push(remaining.slice(0, splitIdx).trim());
      remaining = remaining.slice(splitIdx).trim();
    }
    return lines;
  };

  const wrapTwoLines = (text: string, maxLen = 65): [string, string] => {
    const lines = wrapLines(text, maxLen, 2);
    return [lines[0] || '', lines[1] || ''];
  };

  const classifyAttackType = (threat?: string, uri?: string, payload?: string, category?: string, isEnglish = false) => {
    const readable = extractReadableMessage(threat);
    const text = [threat, uri, payload, category, readable]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    if (text.includes('webshell') || text.includes('b374k') || text.includes('c99') || text.includes('r57')) {
      return {
        type: 'Webshell Injection & Persistence',
        note: isEnglish
          ? 'Backdoor webshell script upload targeting unauthorized arbitrary command execution.'
          : 'Upload skrip backdoor webshell untuk eksekusi perintah tak sah pada server.'
      };
    }
    if (text.includes('trojan') || text.includes('dropper')) {
      return {
        type: 'Malware (Trojan / Dropper)',
        note: isEnglish
          ? 'Stealthy executable / script payload dropper targeting underlying host assets.'
          : 'Payload dropper pembawa malware executable / script terselubung.'
      };
    }
    if (text.includes('malware') || text.includes('eicar')) {
      return {
        type: 'Malware (Malicious Payload)',
        note: isEnglish
          ? 'Malicious file artifact injection or unauthorized malware upload attempt.'
          : 'Injeksi artefak file berbahaya atau malware upload pada sistem.'
      };
    }
    if (text.includes('sqli') || text.includes('sql injection') || text.includes('union select') || text.includes('sqlmap')) {
      return {
        type: 'SQL Injection (SQLi)',
        note: isEnglish
          ? 'SQL query parameter exploitation intended for database extraction or manipulation.'
          : 'Eksploitasi parameter query SQL untuk ekstraksi atau manipulasi basis data.'
      };
    }
    if (text.includes('csrf') || text.includes('cross-site request forgery') || text.includes('xsrf')) {
      return {
        type: 'Cross-Site Request Forgery (CSRF)',
        note: isEnglish
          ? 'Cross-site unauthorized state-changing request using victim authenticated credentials.'
          : 'Eksploitasi pemalsuan request lintas situs menggunakan kredensial korban.'
      };
    }
    if (text.includes('xss') || text.includes('cross-site scripting') || text.includes('<script')) {
      return {
        type: 'Cross-Site Scripting (XSS)',
        note: isEnglish
          ? 'Client-side script payload injection targeting session hijacking and cookie theft.'
          : 'Injeksi payload skrip client-side untuk pembajakan session browser.'
      };
    }
    if (text.includes('traversal') || text.includes('lfi') || text.includes('../') || text.includes('etc/passwd') || text.includes('etc/shadow')) {
      return {
        type: 'Path Traversal / LFI',
        note: isEnglish
          ? 'Directory traversal attempt to bypass root bounds and access sensitive OS files.'
          : 'Percobaan penelusuran path direktori untuk mengakses file sensitif OS.'
      };
    }
    if (text.includes('ssh') || text.includes('brute') || text.includes('hydra')) {
      return {
        type: 'Authentication Attack (SSH Brute Force)',
        note: isEnglish
          ? 'Automated high-frequency dictionary attack targeting system authentication endpoints.'
          : 'Serangan kamus kredensial otomatis berulang pada port autentikasi.'
      };
    }
    if (text.includes('rate limit') || text.includes('flood') || text.includes('ddos')) {
      return {
        type: 'Availability Attack (Layer 7 Flood / DDoS)',
        note: isEnglish
          ? 'Anomalous high-volume request bursts aimed at overwhelming backend service capacity.'
          : 'Lonjakan volume permintaan tinggi yang membanjiri kapasitas server.'
      };
    }

    const cleanFallback = readable || (isEnglish ? 'Perimeter Security Event' : 'Event Keamanan Perimeter');
    return {
      type: cleanFallback.length > 100 ? cleanFallback.slice(0, 97) + '...' : cleanFallback,
      note: isEnglish
        ? 'Perimeter telemetry event inspected and recorded by OAT Security Engine.'
        : 'Event telemetri perimeter diinspeksi dan dicatat oleh OAT Security Engine.'
    };
  };

  const downloadMitigationPdfReport = (evt: SecurityEvent, incidentId?: string) => {
    const isEn = getLanguage() === 'en';
    const reportDate = new Date().toLocaleString(isEn ? 'en-US' : 'id-ID', { dateStyle: 'full', timeStyle: 'medium' });
    const eventDate = new Date(evt.timestamp).toLocaleString(isEn ? 'en-US' : 'id-ID', { dateStyle: 'full', timeStyle: 'medium' });
    const refCode = incidentId || ('DISPATCH-' + String(evt.id || '').slice(0, 12));
    const asset = (evt.application || 'Perimeter Gateway') + ' (' + evt.destination + ')';
    const timestampStr = new Date(evt.timestamp).toISOString();
    const cleanSourceIp = String(evt.sourceIp || '10.10.10.8').replace(/[()\\]/g, '');
    const cleanDest = String(evt.destination || '192.168.1.2').replace(/[()\\]/g, '');
    const cleanCountry = String(evt.sourceCountry || 'Indonesia').replace(/[()\\]/g, '');
    const cleanAction = String(evt.action || 'LOG').toUpperCase().replace(/[()\\]/g, '');
    const cleanSeverity = String(evt.severity || 'Medium').toUpperCase().replace(/[()\\]/g, '');
    const readableThreat = extractReadableMessage(evt.threat);
    const readablePayload = extractReadableMessage(evt.payloadSnippet || evt.threat);
    const classified = classifyAttackType(readableThreat, evt.uri, readablePayload, evt.category, isEn);
    const [threatLine1, threatLine2] = wrapTwoLines(classified.type, 64);
    const rawLogSource = evt.rawLog || (evt.metadata && (evt.metadata.rawLog || evt.metadata.logMessage)) || evt.threat || evt.payloadSnippet || '-';
    const logMsgLines = wrapLines(rawLogSource, 74, 18);
    const logRowHeight = Math.max(26, logMsgLines.length * 10.5 + 8);
    const sec2Height = 20 + logRowHeight + 20 + 20 + 20;
    const sec2Bottom = 507 - sec2Height;
    const sec2Divider1 = 487;
    const sec2Divider2 = sec2Divider1 - logRowHeight;
    const sec2Divider3 = sec2Divider2 - 20;
    const sec2Divider4 = sec2Divider3 - 20;

    const sec3Top = sec2Bottom - 10;
    const sec3HeaderY = sec3Top - 19;
    const sec3TableTop = sec3HeaderY - 5;
    const sec3TableBottom = sec3TableTop - 86;

    const sec4Top = sec3TableBottom - 10;
    const sec4Bottom = Math.max(48, sec4Top - 88);
    const footerLineY = sec4Bottom - 8;
    const footerTextY = footerLineY - 10;

    const cleanThreatNote = String(classified.note).slice(0, 80).replace(/[()\\]/g, '');
    const cleanUri = String(evt.uri || '/').slice(0, 68).replace(/[()\\]/g, '');
    const cleanPayload = String(readablePayload || '-').slice(0, 68).replace(/[()\\]/g, '');
    const cleanEventId = String(evt.id || '-').slice(0, 36).replace(/[()\\]/g, '');
    const cleanProtocol = String(evt.protocol || 'TCP').slice(0, 8).replace(/[()\\]/g, '');
    const cleanStatusCode = String(evt.statusCode || 200).replace(/[()\\]/g, '');
    const cleanAsset = String(asset).slice(0, 50).replace(/[()\\]/g, '');

    const logLinesOps: string[] = [];
    logMsgLines.forEach((line, idx) => {
      const cleanLine = line.replace(/[()\\]/g, '');
      if (idx === 0) {
        logLinesOps.push(`156 ${sec2Divider1 - 14} Td (${cleanLine}) Tj`);
      } else {
        logLinesOps.push(`0 -10.5 Td (${cleanLine}) Tj`);
      }
    });

    const streamContent = [
      'q',
      '0.06 0.09 0.16 rg',
      '0 760 595.28 82 re f',
      '0.14 0.38 0.95 rg',
      '0 756 595.28 4 re f',
      'Q',
      'BT',
      '1 1 1 rg',
      '/F2 16 Tf',
      '36 804 Td (OAT SECURITY  |  ENTERPRISE SOC INCIDENT BRIEF) Tj',
      '/F1 8.5 Tf',
      '0.80 0.85 0.95 rg',
      '0 -16 Td (' + (isEn ? 'Automated Security Event Mitigation & Incident Escalation Dossier' : 'Dossier Mitigasi Peristiwa Keamanan & Eskalasi Insiden Otomatis') + ') Tj',
      'ET',
      'BT',
      '1 1 1 rg',
      '/F2 8 Tf',
      '420 808 Td (' + (isEn ? 'INCIDENT REF:' : 'REF INSIDEN:') + ') Tj',
      '/F1 8 Tf',
      '0.80 0.85 0.95 rg',
      '0 -11 Td (' + refCode + ') Tj',
      '0 -11 Td (' + (isEn ? 'Issued: ' : 'Terbit: ') + reportDate.slice(0, 24) + ') Tj',
      'ET',
      'q',
      '0.93 0.95 0.98 rg',
      '36 718 523 20 re f',
      '0.10 0.15 0.25 rg',
      '36 718 4 20 re f',
      'Q',
      'BT',
      '0.08 0.12 0.20 rg',
      '/F2 9.5 Tf',
      '46 724 Td (' + (isEn ? '1. INCIDENT TELEMETRY & ATTACK ATTRIBUTION' : '1. TELEMETRI INSIDEN & ATRIBUSI SERANGAN') + ') Tj',
      'ET',
      'q',
      '0.97 0.98 0.99 rg',
      '0.85 0.89 0.94 RG',
      '0.5 w',
      '36 542 523 165 re b',
      '36 673 523 0.1 re s',
      '36 621 523 0.1 re s',
      '36 569 523 0.1 re s',
      '148 542 0.1 165 re s',
      'Q',
      'BT',
      '/F2 8 Tf',
      '0.38 0.42 0.50 rg',
      '44 688 Td (Event ID) Tj',
      '0 -26 Td (' + (isEn ? 'Severity Level' : 'Tingkat Severity') + ') Tj',
      '0 -26 Td (' + (isEn ? 'Source & Location' : 'Sumber & Lokasi') + ') Tj',
      '0 -26 Td (' + (isEn ? 'Target Asset' : 'Target Aset') + ') Tj',
      '/F1 8 Tf',
      '0.12 0.14 0.18 rg',
      '112 78 Td (' + cleanEventId + '  |  Protocol: ' + cleanProtocol + ') Tj',
      'ET',
      'BT',
      '/F1 8 Tf',
      '0.12 0.14 0.18 rg',
      '156 637 Td (' + cleanSeverity + ' ALERT  |  Action: ' + cleanAction + ') Tj',
      '0 -26 Td (' + cleanSourceIp + ' [' + cleanCountry + ']   HTTP Code: ' + cleanStatusCode + ') Tj',
      '0 -26 Td (' + cleanAsset + ') Tj',
      'ET',
      'q',
      '0.93 0.95 0.98 rg',
      '36 512 523 19 re f',
      '0.10 0.15 0.25 rg',
      '36 512 4 19 re f',
      'Q',
      'BT',
      '0.08 0.12 0.20 rg',
      '/F2 9 Tf',
      '46 517 Td (' + (isEn ? '2. THREAT DETECTION & DEEP FORENSIC ANALYSIS' : '2. DETEKSI ANCAMAN & ANALISIS FORENSIK MENDALAM') + ') Tj',
      'ET',
      'q',
      '0.97 0.98 0.99 rg',
      '0.85 0.89 0.94 RG',
      '0.5 w',
      `36 ${sec2Bottom} 523 ${sec2Height} re b`,
      `36 ${sec2Divider1} 523 0.1 re s`,
      `36 ${sec2Divider2} 523 0.1 re s`,
      `36 ${sec2Divider3} 523 0.1 re s`,
      `36 ${sec2Divider4} 523 0.1 re s`,
      `148 ${sec2Bottom} 0.1 ${sec2Height} re s`,
      'Q',
      'BT',
      '/F2 8 Tf',
      '0.38 0.42 0.50 rg',
      '44 494 Td (' + (isEn ? 'Attack Type' : 'Tipe Serangan') + ') Tj',
      `44 ${sec2Divider1 - 14} Td (Raw Log Message) Tj`,
      `44 ${sec2Divider2 - 14} Td (URI / Endpoint) Tj`,
      `44 ${sec2Divider3 - 14} Td (Payload Snippet) Tj`,
      `44 ${sec2Divider4 - 14} Td (Analyst Verdict) Tj`,
      'ET',
      'BT',
      '/F2 8 Tf',
      '0.80 0.15 0.15 rg',
      '156 494 Td (' + threatLine1 + ') Tj',
      'ET',
      'BT',
      '/F1 7.5 Tf',
      '0.20 0.24 0.30 rg',
      ...logLinesOps,
      'ET',
      'BT',
      '/F1 8 Tf',
      '0.20 0.24 0.30 rg',
      `156 ${sec2Divider2 - 14} Td (${cleanUri}) Tj`,
      `0 -20 Td (${cleanPayload}) Tj`,
      `0 -20 Td (${cleanThreatNote}) Tj`,
      'ET',
      'BT',
      '/F1 7.5 Tf',
      '0.45 0.50 0.58 rg',
      `36 ${footerTextY} Td (` + (isEn ? 'Automatically issued by OAT Security Engine | ' + reportDate : 'Otomatis diterbitkan oleh OAT Security Engine | ' + reportDate) + ') Tj',
      'ET'
    ].join('\n');

    let pdf = '%PDF-1.4\n';
    const offsets: number[] = [];
    const addObj = (str: string) => {
      offsets.push(pdf.length);
      pdf += str + '\n';
    };
    addObj('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj');
    addObj('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj');
    addObj('3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj');
    addObj('4 0 obj\n<< /Length ' + streamContent.length + ' >>\nstream\n' + streamContent + '\nendstream\nendobj');
    addObj('5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj');
    addObj('6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj');
    const xrefOffset = pdf.length;
    pdf += 'xref\n0 7\n0000000000 65535 f \n';
    for (let i = 0; i < 6; i++) {
      pdf += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
    }
    pdf += 'trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n' + xrefOffset + '\n%%EOF';

    const blob = new Blob([pdf], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = isEn
      ? `SOC-L2-Mitigation-Report-${evt.id.slice(0, 8)}-${Date.now()}.pdf`
      : `Laporan-Mitigasi-SOC-L2-${evt.id.slice(0, 8)}-${Date.now()}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleEscalateToSocL2 = async () => {
    if (!selectedEvent || escalatingSoc) return;
    setEscalatingSoc(true);
    setEscalateSuccess(null);
    try {
      const isEn = getLanguage() === 'en';
      const readableThreat = extractReadableMessage(selectedEvent.threat);
      const shortThreat = (readableThreat || (isEn ? 'Threat Ingress' : 'Ancaman Ingress')).slice(0, 75);
      const appTarget = (selectedEvent.application || selectedEvent.destination || 'Server').slice(0, 60);

      const res = await securityApi.createIncident({
        title: isEn
          ? `[Incident Mitigation] ${shortThreat} on ${appTarget}`.slice(0, 240)
          : `[Mitigasi Insiden] ${shortThreat} pada ${appTarget}`.slice(0, 240),
        severity: selectedEvent.severity === 'Critical' ? 'Critical' : 'High',
        tier: 'L2',
        assignedTo: 'SOC L2 Analyst',
        affectedAsset: `${selectedEvent.application || 'Server'} (${selectedEvent.destination})`.slice(0, 240),
        notes: (() => {
          const det = classifyAttackType(readableThreat, selectedEvent.uri, selectedEvent.payloadSnippet, selectedEvent.category);
          if (isEn) {
            return `Automated mitigation report dispatched to SOC L2 Pipeline.\nAttack Classification: ${det.type}\nAnalyst Note: ${det.note}\nSource IP: ${selectedEvent.sourceIp} (${selectedEvent.sourceCountry || 'Unknown'})\nOrigin Threat: ${readableThreat}\nPerimeter Action: ${selectedEvent.action}\nTarget Host: ${selectedEvent.destination}\nEvent ID: ${selectedEvent.id}\nTimestamp: ${new Date(selectedEvent.timestamp).toISOString()}`;
          }
          return `Laporan mitigasi otomatis ke SOC L2 Pipeline.\nKlasifikasi Serangan: ${det.type}\nKeterangan Analis: ${det.note}\nIP Sumber: ${selectedEvent.sourceIp} (${selectedEvent.sourceCountry || 'Unknown'})\nAncaman Asal: ${readableThreat}\nAksi Perimeter: ${selectedEvent.action}\nTarget Host: ${selectedEvent.destination}\nEvent ID: ${selectedEvent.id}\nTimestamp: ${new Date(selectedEvent.timestamp).toISOString()}`;
        })()
      });

      const incidentId = res.incident?.id;
      downloadMitigationPdfReport(selectedEvent, incidentId);

      setEscalateSuccess(isEn
        ? `Automated mitigation PDF downloaded & dispatched to SOC L2 queue (${incidentId || 'Dispatched'}).`
        : `Laporan PDF mitigasi otomatis terunduh & berhasil dikirim ke antrean SOC L2 (${incidentId || 'Terkirim'}).`
      );
      setTimeout(() => setEscalateSuccess(null), 7000);
    } catch (err: any) {
      alert(err?.message || (getLanguage() === 'en' ? 'Failed to dispatch mitigation report to SOC L2' : 'Gagal mengirim laporan mitigasi ke SOC L2'));
    } finally {
      setEscalatingSoc(false);
    }
  };

  // Inspect event in drawer
  const handleInspectEvent = async (evt: SecurityEvent) => {
    setSelectedEvent(evt);
    setCopiedId(false);
    setCopiedRaw(false);
    try {
      const detail = await securityApi.getSecurityEventDetail(evt.id);
      setEventDetail(detail);
    } catch {
      setEventDetail(evt);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchEvents} />;
  }

  // Filter count helpers
  const actionFilterCounts: Record<ActionFilterValue, number> = {
    ALL: aggregateActions?.total ?? recordedTotal,
    BLOCKED: aggregateActions?.blocked ?? 0,
    ALLOWED: aggregateActions?.allowed ?? 0,
    CHALLENGED: aggregateActions?.challenged ?? 0,
    LOGGED: aggregateActions?.logged ?? 0
  };

  const severityFilterCounts: Record<SeverityFilterValue, number> = {
    ALL: aggregateActions?.total ?? recordedTotal,
    Critical: aggregateSeverities?.critical ?? 0,
    High: aggregateSeverities?.high ?? 0,
    Medium: aggregateSeverities?.medium ?? 0,
    Low: aggregateSeverities?.low ?? 0
  };

  // Side rail metrics
  const maxRailRows = 5;
  const topSourceIps = topSourceIpsAgg.slice(0, maxRailRows);
  const topApplications = topApplicationsAgg.slice(0, maxRailRows).map(r => [r.application, r.count] as [string, number]);
  const topSourceIpMax = topSourceIps.length > 0 ? topSourceIps[0].count : 0;
  const topApplicationMax = topApplications.length > 0 ? topApplications[0][1] : 0;

  const actionRailRows = [
    { label: 'Blocked', count: actionFilterCounts.BLOCKED, dot: 'bg-rose-500', bar: 'bg-rose-500' },
    { label: 'Allowed', count: actionFilterCounts.ALLOWED, dot: 'bg-emerald-500', bar: 'bg-emerald-500' },
    { label: 'Challenged', count: actionFilterCounts.CHALLENGED, dot: 'bg-amber-400', bar: 'bg-amber-400' },
    { label: 'Logged', count: actionFilterCounts.LOGGED, dot: 'bg-zinc-400', bar: 'bg-zinc-400' }
  ].sort((a, b) => b.count - a.count);
  const actionRailMax = actionRailRows[0]?.count ?? 0;

  const severityRailRows = [
    { label: 'Critical', count: severityFilterCounts.Critical, dot: 'bg-rose-500', bar: 'bg-rose-500' },
    { label: 'High', count: severityFilterCounts.High, dot: 'bg-amber-500', bar: 'bg-amber-500' },
    { label: 'Medium', count: severityFilterCounts.Medium, dot: 'bg-yellow-400', bar: 'bg-yellow-400' },
    { label: 'Low', count: severityFilterCounts.Low, dot: 'bg-sky-400', bar: 'bg-sky-400' }
  ];
  const severityRailMax = Math.max(...severityRailRows.map(r => r.count), 1);

  // Pagination bounds
  const totalPages = Math.max(1, Math.ceil(recordedTotal / pageSize));
  const startRecord = recordedTotal === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(currentPage * pageSize, recordedTotal);

  // Origin badge helper
  const getOriginBadge = (ip?: string, countryCode?: string, countryName?: string) => {
    let code = countryCode || (classifyLocalIp(ip) ? 'ID' : 'UN');
    if (code === 'LAN' || code === 'SYS') {
      code = 'ID';
    }
    return {
      badge: code,
      title: getCountryName(code, countryName),
      className: 'bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-200 border-zinc-200/80 dark:border-zinc-700/80 shadow-2xs'
    };
  };

  // Security Engine badge helper
  const getEngineBadge = (source?: string, category?: string) => {
    const s = String(source || category || '').toLowerCase();
    if (s.includes('waf')) {
      return {
        label: 'Cloud WAF',
        short: 'WAF',
        className: 'bg-violet-50 text-violet-700 border-violet-200/70 dark:bg-violet-950/40 dark:text-violet-300 dark:border-violet-800/60',
        dot: 'bg-violet-500'
      };
    }
    if (s.includes('firewall')) {
      return {
        label: 'Firewall',
        short: 'Firewall',
        className: 'bg-amber-50 text-amber-700 border-amber-200/70 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/60',
        dot: 'bg-amber-500'
      };
    }
    if (s.includes('agent')) {
      return {
        label: 'Endpoint Agent',
        short: 'Agent',
        className: 'bg-cyan-50 text-cyan-700 border-cyan-200/70 dark:bg-cyan-950/40 dark:text-cyan-300 dark:border-cyan-800/60',
        dot: 'bg-cyan-500'
      };
    }
    return {
      label: 'Perimeter',
      short: 'SEC',
      className: 'bg-zinc-100 text-zinc-600 border-zinc-200/70 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700/60',
      dot: 'bg-zinc-400'
    };
  };

  const applicationsList = Array.from(new Set(events.map(e => e.application || '').filter(Boolean)));

  // Export the ENTIRE security event log for this tenant — not just the visible
  // page. The API caps each response at 1000 rows, so walk the pagination until
  // exhausted (safeguard: 100 pages ≈ 100k events).
  const handleExportJson = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const pageSize = 1000;
      const all: SecurityEvent[] = [];
      let page = 1;
      while (page <= 100) {
        const res = await securityApi.getSecurityEvents({ limit: pageSize, page });
        const batch = (res?.events || []) as SecurityEvent[];
        all.push(...batch);
        if (batch.length < pageSize) break;
        page += 1;
      }

      const payload = {
        exportedAt: new Date().toISOString(),
        organization: currentOrg?.name || 'Unknown Tenant',
        organizationId: currentOrg?.id || null,
        total: all.length,
        events: all
      };

      const sanitize = (name: string) => name.trim().replace(/[^\w\d.-]+/g, '-') || 'OAT-Security';
      const orgName = sanitize(currentOrg?.name || 'OAT-Security');
      const dateStamp = new Date().toISOString().slice(0, 10);

      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${orgName}_security-events_${dateStamp}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch {
      // Best-effort export — the live feed keeps running regardless.
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-5" id="security-events-module">
      {/* Real-time Connection Banner if Lost */}
      {realtimeStatus === 'REAL-TIME CONNECTION LOST' && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-rose-700 dark:text-rose-200">
          <div className="flex items-center gap-3">
            <WifiOff className="w-5 h-5 text-rose-600 dark:text-rose-400 animate-pulse" />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">
                REAL-TIME TELEMETRY DISCONNECTED
              </div>
              <div className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">
                Ingress security socket disconnected. Background auto-reconnect active.
              </div>
            </div>
          </div>
          <button
            onClick={() => globalRealtimeClient.connect()}
            className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer"
          >
            Reconnect Now
          </button>
        </div>
      )}

      {/* Header — mirrors the dashboard page header style */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faHeartPulse} />}
        title="Security"
        titleTail="Events"
        subtitle="Unified live security telemetry captured across enrolled endpoint agents, the WAF inspection engine, and the perimeter firewall."
        actions={
          <button
            onClick={handleExportJson}
            disabled={exporting}
            title="Export the complete security event log (all pages) as JSON"
            className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:cursor-wait disabled:opacity-60 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
          >
            <Download className={`w-3.5 h-3.5 ${exporting ? 'animate-pulse' : ''}`} />
            {exporting ? 'Exporting…' : 'Export JSON'}
          </button>
        }
      />

      {/* Main Grid: Live feed on the left, telemetry summary rail on the right */}
      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_340px]">
        {/* Feed Card: Stream window and table */}
        <div className="flex min-w-0 flex-col overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
          {/* Stream Toolbar */}
          <div className="shrink-0 flex flex-wrap items-center gap-2 border-b border-zinc-100 bg-zinc-50/60 px-3 py-2.5 dark:border-zinc-800/80 dark:bg-zinc-900/40">
            {/* Action Filter */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowActionDropdown(prev => !prev);
                  setShowSeverityDropdown(false);
                  setShowSourceDropdown(false);
                  setShowAppDropdown(false);
                }}
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Filter className="w-3 h-3 text-zinc-400" />
                <span>
                  {(() => {
                    const opt = ACTION_FILTER_OPTIONS.find(o => o.value === actionFilter)!;
                    return `${opt.label} (${actionFilterCounts[actionFilter].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showActionDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showActionDropdown && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowActionDropdown(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {ACTION_FILTER_OPTIONS.map(opt => {
                      const isActive = actionFilter === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => {
                            setActionFilter(opt.value);
                            setCurrentPage(1);
                            setShowActionDropdown(false);
                          }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                            isActive
                              ? `font-semibold ${opt.activeBg || 'bg-zinc-100 dark:bg-zinc-800'} ${opt.activeText}`
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <span className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                            <span>{opt.label}</span>
                          </span>
                          <span className={`text-[10px] tabular-nums ${isActive ? opt.countColor : 'text-zinc-400'}`}>
                            ({actionFilterCounts[opt.value].toLocaleString()})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Severity Filter */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowSeverityDropdown(prev => !prev);
                  setShowActionDropdown(false);
                  setShowSourceDropdown(false);
                  setShowAppDropdown(false);
                }}
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_FILTER_OPTIONS.find(o => o.value === severityFilter)?.dot || 'bg-zinc-400'}`} />
                <span>
                  {(() => {
                    const opt = SEVERITY_FILTER_OPTIONS.find(o => o.value === severityFilter)!;
                    return `${opt.label} (${severityFilterCounts[severityFilter].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showSeverityDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showSeverityDropdown && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowSeverityDropdown(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {SEVERITY_FILTER_OPTIONS.map(opt => {
                      const isActive = severityFilter === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => {
                            setSeverityFilter(opt.value);
                            setCurrentPage(1);
                            setShowSeverityDropdown(false);
                          }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                            isActive
                              ? `font-semibold ${opt.activeBg || 'bg-zinc-100 dark:bg-zinc-800'} ${opt.activeText}`
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <span className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                            <span>{opt.label}</span>
                          </span>
                          <span className={`text-[10px] tabular-nums ${isActive ? opt.countColor : 'text-zinc-400'}`}>
                            ({severityFilterCounts[opt.value].toLocaleString()})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Source Engine Filter */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowSourceDropdown(prev => !prev);
                  setShowActionDropdown(false);
                  setShowSeverityDropdown(false);
                  setShowAppDropdown(false);
                }}
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Cpu className="w-3 h-3 text-zinc-400" />
                <span>{SOURCE_FILTER_OPTIONS.find(o => o.value === sourceFilter)?.label || 'All Engines'}</span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showSourceDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showSourceDropdown && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowSourceDropdown(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-44 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {SOURCE_FILTER_OPTIONS.map(opt => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => {
                          setSourceFilter(opt.value);
                          setCurrentPage(1);
                          setShowSourceDropdown(false);
                        }}
                        className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center gap-2 transition cursor-pointer ${
                          sourceFilter === opt.value
                            ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                        }`}
                      >
                        <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                        <span>{opt.label}</span>
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Application Filter (if apps exist) */}
            {applicationsList.length > 0 && (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => {
                    setShowAppDropdown(prev => !prev);
                    setShowActionDropdown(false);
                    setShowSeverityDropdown(false);
                    setShowSourceDropdown(false);
                  }}
                  className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
                >
                  <Layers className="w-3 h-3 text-zinc-400" />
                  <span className="max-w-[110px] truncate">{appFilter === 'ALL' ? 'All Apps' : appFilter}</span>
                  <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showAppDropdown ? 'rotate-180' : ''}`} />
                </button>

                {showAppDropdown && (
                  <>
                    <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowAppDropdown(false)} />
                    <div className="absolute left-0 top-full mt-1.5 w-48 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30 max-h-56 overflow-y-auto custom-scrollbar">
                      <button
                        type="button"
                        onClick={() => { setAppFilter('ALL'); setCurrentPage(1); setShowAppDropdown(false); }}
                        className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left transition cursor-pointer ${
                          appFilter === 'ALL'
                            ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                        }`}
                      >
                        All Applications
                      </button>
                      {applicationsList.map(app => (
                        <button
                          key={app}
                          type="button"
                          onClick={() => { setAppFilter(app); setCurrentPage(1); setShowAppDropdown(false); }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left transition cursor-pointer truncate ${
                            appFilter === app
                              ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          {app}
                        </button>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Quick Search */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder={getLanguage() === 'id' ? 'Cari...' : 'Search...'}
                className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white pl-8 pr-3 text-xs text-zinc-800 placeholder-zinc-400 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder-zinc-500 dark:focus:border-zinc-600"
              />
            </div>
          </div>

          {/* Table Container */}
          <div className="h-[580px] overflow-y-auto overflow-x-auto custom-scrollbar">
            <table className="w-full min-w-[860px] border-separate border-spacing-0 text-left text-xs">
              <thead>
                <tr className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                  <th className="sticky top-0 z-20 w-[90px] border-b border-zinc-200/80 bg-zinc-50 pl-4 pr-2 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Time
                  </th>
                  <th className="sticky top-0 z-20 w-[140px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Source IP
                  </th>
                  <th className="sticky top-0 z-20 w-[90px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">
                    Engine
                  </th>
                  <th className="sticky top-0 z-20 w-[150px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Application
                  </th>
                  <th className="sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Detected Threat
                  </th>
                  <th className="sticky top-0 z-20 w-[100px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">
                    Severity
                  </th>
                  <th className="sticky top-0 z-20 w-[100px] border-b border-zinc-200/80 bg-zinc-50 pl-2 pr-4 py-2.5 font-medium text-right dark:border-zinc-800 dark:bg-zinc-900">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading && events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="border-0 px-4 py-28 text-center">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                      <div className="text-xs text-zinc-400 dark:text-zinc-500">Loading security events...</div>
                    </td>
                  </tr>
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="border-0 px-4 py-28 text-center">
                      <div className="text-sm font-medium text-zinc-500 dark:text-zinc-400">
                        No security events match the current filter
                      </div>
                      <div className="mt-1 text-xs text-zinc-400 dark:text-zinc-500">
                        New incoming telemetry events appear here automatically.
                      </div>
                      {(actionFilter !== 'ALL' || severityFilter !== 'ALL' || sourceFilter !== 'ALL' || appFilter !== 'ALL' || search) && (
                        <button
                          type="button"
                          onClick={() => {
                            setActionFilter('ALL');
                            setSeverityFilter('ALL');
                            setSourceFilter('ALL');
                            setAppFilter('ALL');
                            setSearch('');
                            setCurrentPage(1);
                          }}
                          className="mt-3 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition cursor-pointer"
                        >
                          Reset Filters
                        </button>
                      )}
                    </td>
                  </tr>
                ) : (
                  events.map(evt => {
                    const engine = getEngineBadge(evt.source, evt.category);
                    const appLabel = (!evt.application || evt.application === 'failed') ? 'Edge Gateway' : evt.application;
                    const threatName = evt.threat || (evt as any).threatName || 'Inspection Event';

                    return (
                      <tr
                        key={evt.id}
                        onClick={() => handleInspectEvent(evt)}
                        className={`cursor-pointer transition hover:bg-zinc-50/70 dark:hover:bg-zinc-900/40 ${
                          selectedEvent?.id === evt.id ? 'bg-zinc-50 dark:bg-zinc-900/50' : ''
                        }`}
                      >
                        {/* Time */}
                        <td className="border-b border-zinc-100 pl-4 pr-3 py-2.5 font-mono text-[11px] text-zinc-400 whitespace-nowrap dark:border-zinc-800/60 dark:text-zinc-500">
                          {formatTime(evt.timestamp)}
                        </td>

                        {/* Source IP */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 font-mono text-[11px] whitespace-nowrap dark:border-zinc-800/60" title={evt.sourceIp}>
                          <span className="font-medium text-zinc-700 dark:text-zinc-300">
                            {evt.sourceIp === '0.0.0.0' ? '0.0.0.0 (Internal)' : evt.sourceIp}
                          </span>
                        </td>

                        {/* Engine */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 text-center whitespace-nowrap dark:border-zinc-800/60">
                          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${engine.className}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${engine.dot}`} />
                            {engine.short}
                          </span>
                        </td>

                        {/* Application */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 whitespace-nowrap dark:border-zinc-800/60" title={appLabel}>
                          <span className="text-[11px] font-medium text-zinc-700 dark:text-zinc-300">
                            {appLabel}
                          </span>
                        </td>

                        {/* Threat Description */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 dark:border-zinc-800/60" title={threatName}>
                          <span className="text-[11px] font-medium text-zinc-800 dark:text-zinc-200">
                            {threatName}
                          </span>
                        </td>

                        {/* Severity */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 text-center whitespace-nowrap dark:border-zinc-800/60">
                          <StatusBadge type="severity" value={evt.severity} size="sm" />
                        </td>

                        {/* Action */}
                        <td className="border-b border-zinc-100 pl-2 pr-4 py-2.5 text-right whitespace-nowrap dark:border-zinc-800/60">
                          <StatusBadge type="action" value={evt.action} size="sm" />
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Footer — Pinned Pagination Controls */}
          <div className="mt-auto shrink-0 flex flex-col items-center justify-between gap-3 border-t border-zinc-100 bg-zinc-50/60 p-3 sm:px-4 sm:py-3 text-xs text-zinc-500 dark:border-zinc-800/80 dark:bg-zinc-900/40 sm:flex-row text-center sm:text-left">
            <div>
              Showing <span className="font-medium text-zinc-700 dark:text-zinc-200">{startRecord.toLocaleString()}</span>
              {recordedTotal > 0 && (
                <>
                  {' '}-{' '}
                  <span className="font-medium text-zinc-700 dark:text-zinc-200">{endRecord.toLocaleString()}</span>
                </>
              )}{' '}
              of <span className="font-medium text-zinc-700 dark:text-zinc-200">{recordedTotal.toLocaleString()}</span>{' '}
              {actionFilter !== 'ALL' || severityFilter !== 'ALL' || sourceFilter !== 'ALL' || appFilter !== 'ALL' || searchTerm ? 'matching events' : 'recorded events'}
            </div>

            <div className="flex flex-wrap items-center justify-center sm:justify-end gap-2.5 w-full sm:w-auto sm:ml-auto">
              <div className="relative">
                <select
                  value={pageSize}
                  onChange={e => {
                    const newSize = Number(e.target.value);
                    setPageSize(newSize);
                    setCurrentPage(1);
                  }}
                  className="h-8 appearance-none rounded-lg border border-zinc-200/80 bg-white pl-2.5 pr-8 text-xs font-medium text-zinc-700 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 cursor-pointer"
                >
                  <option value={25}>25 per page</option>
                  <option value={50}>50 per page</option>
                  <option value={100}>100 per page</option>
                  <option value={250}>250 per page</option>
                </select>
                <span className="absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-zinc-400">
                  <ChevronDown className="w-3.5 h-3.5" />
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage <= 1 || loading}
                  className="inline-flex h-8 shrink-0 items-center gap-1 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:pointer-events-none disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
                  title="Previous page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Return
                </button>

                <span className="px-1.5 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                  Page <span className="font-semibold text-zinc-700 dark:text-zinc-200">{currentPage}</span> of{' '}
                  <span className="font-semibold text-zinc-700 dark:text-zinc-200">{totalPages.toLocaleString()}</span>
                </span>

                <button
                  type="button"
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages || loading}
                  className="inline-flex h-8 shrink-0 items-center gap-1 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:pointer-events-none disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
                  title="Next page"
                >
                  Next
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Side Rail: Summary insights like Live Traffic */}
        <aside className="grid content-start gap-5 sm:grid-cols-2 lg:grid-cols-1">
          {/* Telemetry Stream Health Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              <span>Telemetry Ingestion</span>
              <span className="inline-flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 normal-case font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Streaming
              </span>
            </div>
            <div className="mt-2.5">
              <div className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
                {recordedTotal.toLocaleString()}
              </div>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                Total events analyzed across all inspection engines.
              </p>
            </div>

            <div className="mt-3.5 pt-3 border-t border-zinc-100 dark:border-zinc-800/80 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-500" />
                  Endpoint Agent Channel
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">ONLINE</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-violet-500" />
                  Cloud WAF Engine
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">ACTIVE</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-500" />
                  Perimeter Firewall
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">FILTERING</span>
              </div>
            </div>
          </div>

          {/* Actions Taken Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Actions Taken
            </div>
            <div className="mt-3 space-y-2.5">
              {actionRailRows.map(row => {
                const pct = actionRailMax > 0 ? Math.round((row.count / actionRailMax) * 100) : 0;
                return (
                  <div key={row.label}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${row.dot}`} />
                        <span className="truncate text-xs text-zinc-600 dark:text-zinc-300">{row.label}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                        {row.count.toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                      <div
                        className={`h-full rounded-full ${row.bar}`}
                        style={{ width: `${row.count > 0 ? Math.max(2, pct) : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Severity Breakdown Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Severity Distribution
            </div>
            <div className="mt-3 space-y-2.5">
              {severityRailRows.map(row => {
                const pct = severityRailMax > 0 ? Math.round((row.count / severityRailMax) * 100) : 0;
                return (
                  <div key={row.label}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${row.dot}`} />
                        <span className="truncate text-xs text-zinc-600 dark:text-zinc-300">{row.label}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                        {row.count.toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                      <div
                        className={`h-full rounded-full ${row.bar}`}
                        style={{ width: `${row.count > 0 ? Math.max(2, pct) : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Busiest Source IPs Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Busiest Source IPs
            </div>
            <div className="mt-3 space-y-2.5">
              {topSourceIps.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No events loaded yet.</div>
              ) : (
                topSourceIps.map(({ ip, count, sourceCountryCode }) => {
                  const origin = getOriginBadge(ip, sourceCountryCode);
                  const ipStr = String(ip);
                  const cleanIp = extractIpOnly(ipStr);
                  let displayIp = cleanIp;
                  if (cleanIp.includes(':') && cleanIp.length > 20) {
                    displayIp = cleanIp.slice(0, 9) + '…' + cleanIp.slice(-5);
                  }
                  const pct = topSourceIpMax > 0 ? Math.round((count / topSourceIpMax) * 100) : 0;

                  return (
                    <div key={ip}>
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <CountryFlag
                            code={origin.badge}
                            title={origin.title}
                            width={22}
                            height={15}
                          />
                          <span className="truncate font-mono text-[11px] text-zinc-700 dark:text-zinc-200" title={ipStr}>
                            {displayIp}
                          </span>
                        </div>
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                          {Number(count).toLocaleString()}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                        <div
                          className="h-full rounded-full bg-blue-500 dark:bg-blue-400"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Most Targeted Applications */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Targeted Applications
            </div>
            <div className="mt-3 space-y-2.5">
              {topApplications.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No events loaded yet.</div>
              ) : (
                topApplications.map(([app, count]) => {
                  const pct = topApplicationMax > 0 ? Math.round((count / topApplicationMax) * 100) : 0;
                  return (
                    <div key={app}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-[11px] font-medium text-zinc-700 dark:text-zinc-200">{app}</span>
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                          {Number(count).toLocaleString()}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                        <div className="h-full rounded-full bg-emerald-400 dark:bg-emerald-500" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <p className="px-1 text-[11px] text-zinc-400 dark:text-zinc-500 sm:col-span-2 lg:col-span-1">
            Aggregated telemetry from the central security database.
          </p>
        </aside>
      </div>

      {/* Event Details Drawer — slides in cleanly when a row is clicked */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50">
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200 transition-opacity"
            style={{ opacity: swipeTranslateX > 0 ? Math.max(0.1, 1 - swipeTranslateX / 300) : undefined }}
            onClick={() => { setSelectedEvent(null); setEventDetail(null); }}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Security event details"
            onTouchStart={handleTouchStart}
            onTouchMove={handleTouchMove}
            onTouchEnd={handleTouchEnd}
            style={{
              transform: swipeTranslateX > 0 ? `translateX(${swipeTranslateX}px)` : undefined,
              transition: isSwiping ? 'none' : 'transform 0.2s ease-out'
            }}
            className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-zinc-200/80 bg-white text-zinc-900 shadow-2xl animate-in slide-in-from-right duration-300 ease-out dark:border-zinc-800 dark:bg-[#0b0b0d] dark:text-zinc-100 sm:max-w-[560px] lg:max-w-[640px]"
          >
            {/* Mobile swipe grab handle */}
            <div className="sm:hidden pt-2.5 pb-0.5 flex justify-center">
              <div className="h-1 w-10 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            </div>
            {/* Drawer Header */}
            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pb-4 pt-3.5 dark:border-zinc-800 dark:bg-[#0b0b0d] sm:px-6">
              <div className="flex min-w-0 items-center justify-between">
                <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500">
                  <span className="shrink-0">Security Events</span>
                  <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
                  <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
                    Event Details
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => { setSelectedEvent(null); setEventDetail(null); }}
                  className="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-800 dark:hover:text-zinc-200 transition cursor-pointer"
                >
                  <span className="sr-only">Close</span>
                  ✕
                </button>
              </div>

              <div className="mt-3 flex items-start gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400">
                  <FileCode2 className="w-5 h-5" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                      {selectedEvent.threat || 'Security Incident'}
                    </h2>
                    <StatusBadge type="severity" value={selectedEvent.severity} />
                    <StatusBadge type="action" value={selectedEvent.action} />
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-zinc-500 dark:text-zinc-400">
                    Full inspection record for this security telemetry event.
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Time · {formatTime(selectedEvent.timestamp)}</span>
                <span className="truncate">Source · {selectedEvent.sourceIp}</span>
                <span className="truncate">Engine · {selectedEvent.category || selectedEvent.source || 'SEC'}</span>
              </div>
            </header>

            {/* Scrollable Body */}
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6 custom-scrollbar">
              {/* Event Overview */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Event Overview
                </div>
                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Timestamp</div>
                    <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {formatDateTime(selectedEvent.timestamp)}
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Event ID</span>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(selectedEvent.id);
                          setCopiedId(true);
                          setTimeout(() => setCopiedId(false), 2000);
                        }}
                        className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
                        title="Copy Event ID"
                      >
                        {copiedId ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="mt-1.5 break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.id}
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Source Host</div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2">
                      <span className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.sourceIp}</span>
                      <span className="rounded border border-zinc-200 bg-white px-1.5 py-0.5 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-400">
                        {selectedEvent.sourceCountry || 'Unknown'} ({selectedEvent.sourceCountryCode || 'UN'})
                      </span>
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target Application</div>
                    <div className="mt-1.5 break-all text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.application || 'Edge Gateway'} ({selectedEvent.destination || '10.240.10.1'})
                    </div>
                  </div>
                </div>
              </section>

              {/* Log Message / Threat Name Box */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Log Message
                </div>
                <div className="whitespace-pre-wrap break-all rounded-xl border border-zinc-200/80 bg-zinc-50 p-3.5 font-mono text-[11px] leading-relaxed text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                  {selectedEvent.rawLog || (selectedEvent.metadata && (selectedEvent.metadata.rawLog || selectedEvent.metadata.logMessage)) || selectedEvent.payloadSnippet || selectedEvent.threat}
                </div>
              </section>

              {/* Inspection Result */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Inspection Verdict
                </div>
                <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/70">
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Threat</dt>
                    <dd className="min-w-0 break-all text-[11px] font-semibold text-rose-600 dark:text-rose-400">
                      {(() => {
                        const raw = selectedEvent.threat || 'Security Incident';
                        if (raw.startsWith('{') && raw.includes('"MESSAGE"')) {
                          try {
                            const parsed = JSON.parse(raw);
                            return parsed.MESSAGE || parsed.message || raw;
                          } catch {
                            const m = raw.match(/"MESSAGE"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/);
                            if (m?.[1]) return m[1].replace(/\\"/g, '"');
                          }
                        }
                        return raw;
                      })()}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Engine / Sensor</dt>
                    <dd className="text-[11px] font-medium text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.category || selectedEvent.source || 'Security'}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Enforcement</dt>
                    <dd className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                      The ingress traffic matched a threat pattern during continuous inspection. The policy engine applied{' '}
                      <span className="font-semibold text-zinc-800 dark:text-zinc-200">{selectedEvent.action}</span> action.
                    </dd>
                  </div>
                </dl>
              </section>

              {/* Request Details */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Request Telemetry
                </div>
                <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/70">
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Destination</dt>
                    <dd className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.destination || '10.240.10.1'}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Protocol / Port</dt>
                    <dd className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.protocol || 'TCP'}:{selectedEvent.port || 443}
                    </dd>
                  </div>
                  {selectedEvent.method && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">HTTP Method</dt>
                      <dd className="font-mono text-[11px] font-semibold text-zinc-800 dark:text-zinc-200">{selectedEvent.method}</dd>
                    </div>
                  )}
                  {selectedEvent.statusCode && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Status Code</dt>
                      <dd className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.statusCode}</dd>
                    </div>
                  )}
                  {selectedEvent.uri && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Request Path</dt>
                      <dd className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.uri}</dd>
                    </div>
                  )}
                </dl>
              </section>

              {/* Matched Payload Snippet */}
              {selectedEvent.payloadSnippet && (
                <section>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Matched Payload Signature
                  </div>
                  <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-rose-200 bg-rose-50/60 p-3 font-mono text-[11px] text-rose-600 dark:border-rose-900/40 dark:bg-rose-950/20 dark:text-rose-400">
                    {selectedEvent.payloadSnippet}
                  </pre>
                  <p className="mt-1.5 text-[11px] text-zinc-400 dark:text-zinc-500">
                    Inspected payload slice that triggered perimeter rule match.
                  </p>
                </section>
              )}

              {/* Mitigation & SOC L2 Escalation Action */}
              <section className="rounded-xl border border-indigo-200/80 bg-indigo-50/50 p-4 dark:border-indigo-900/40 dark:bg-indigo-950/20">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <FontAwesomeIcon icon={faShieldVirus} className="text-indigo-600 dark:text-indigo-400 text-xs" />
                      <h4 className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        Automated Mitigation &amp; SOC L2 Escalation
                      </h4>
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-400">
                      Generate PDF mitigation audit report and dispatch directly to SOC Level 2 (L2) analyst queue for deep forensic triage and perimeter enforcement.
                    </p>
                  </div>
                </div>

                {escalateSuccess && (
                  <div className="mt-3 flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-2 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                    <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span>{escalateSuccess}</span>
                  </div>
                )}

                <div className="mt-3.5 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleEscalateToSocL2}
                    disabled={escalatingSoc}
                    className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-indigo-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 transition cursor-pointer disabled:opacity-50"
                  >
                    <FontAwesomeIcon icon={faPaperPlane} className={escalatingSoc ? "text-xs animate-bounce" : "text-xs"} />
                    <span>{escalatingSoc ? "Downloading PDF & Dispatching to SOC L2…" : "Download PDF & Dispatch to SOC L2"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => downloadMitigationPdfReport(selectedEvent)}
                    className="inline-flex items-center gap-2 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 px-3 py-2 text-xs font-medium text-zinc-700 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 focus:outline-none transition cursor-pointer"
                  >
                    <FontAwesomeIcon icon={faFilePdf} className="text-rose-500 text-xs" />
                    <span>Download PDF Only</span>
                  </button>
                </div>
              </section>

              {/* Related Events */}
              {eventDetail?.relatedEvents && eventDetail.relatedEvents.length > 0 && (
                <section>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Correlated Events from {selectedEvent.sourceIp} ({eventDetail.relatedEvents.length})
                  </div>
                  <div className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/60">
                    {eventDetail.relatedEvents.map((r: any) => (
                      <div key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5 text-[11px]">
                        <span className="w-16 shrink-0 font-mono text-zinc-400 dark:text-zinc-500">
                          {formatTime(r.timestamp)}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-zinc-700 dark:text-zinc-200">
                          {r.threat_name || r.threat}
                        </span>
                        <StatusBadge type="severity" value={r.severity} size="sm" />
                        <StatusBadge type="action" value={r.action} size="sm" />
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Raw JSON Record */}
              <section>
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Raw Telemetry Record
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(JSON.stringify(eventDetail || selectedEvent, null, 2));
                      setCopiedRaw(true);
                      setTimeout(() => setCopiedRaw(false), 2000);
                    }}
                    className="inline-flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 cursor-pointer"
                  >
                    {copiedRaw ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-500" />
                        <span className="text-emerald-500">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy JSON</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="max-h-56 overflow-auto custom-scrollbar rounded-xl border border-zinc-200/80 bg-zinc-50 p-3 font-mono text-[11px] text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                  {JSON.stringify(eventDetail || selectedEvent, null, 2)}
                </pre>
              </section>
            </div>

            {/* Drawer Footer */}
            <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50/60 px-5 py-3 dark:border-zinc-800 dark:bg-zinc-900/30 sm:px-6">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Security Events · Telemetry Inspector</span>
                <span className="normal-case tracking-normal">
                  <span className="sm:hidden">Geser ke samping untuk keluar</span>
                  <span className="hidden sm:inline">Click outside or ✕ to close</span>
                </span>
              </div>
            </footer>
          </aside>
        </div>
      )}
    </div>
  );
};
