import { EN_TO_ID, ID_TO_EN, PAGE_TITLE_PAIRS } from './phrases';

export type Language = 'en' | 'id';

export const LANGUAGE_STORAGE_KEY = 'oat-language';

export function getLanguage(): Language {
  try {
    return localStorage.getItem(LANGUAGE_STORAGE_KEY) === 'id' ? 'id' : 'en';
  } catch {
    return 'en';
  }
}

export function setLanguage(language: Language): void {
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    // Storage can be unavailable in hardened/private browser contexts.
  }
  document.documentElement.lang = language;
  // A reload guarantees React re-renders the original source strings before
  // the translator applies the target language, avoiding stale translated
  // nodes when switching back to English.
  window.location.reload();
}

const COLLAPSE = /\s+/g;

function normalise(value: string): string {
  return value.replace(COLLAPSE, ' ').trim();
}

interface Lookup {
  /** Case-sensitive match: keeps "Results" and "results" distinct. */
  exact: Map<string, string>;
  /** Case-insensitive fallback for unknown casings, with a canonical spelling. */
  fallback: Map<string, string>;
}

/**
 * Dictionaries contain the same phrase in several casings (e.g. "Security
 * Events" for navigation and "SECURITY EVENTS" for a metric label). The old
 * case-insensitive map let the last entry win, so mixed-case labels could
 * inherit an all-caps translation. Exact matches now win; the fallback prefers
 * sentence/title case so unknown casings still read naturally.
 */
function sourceCaseScore(source: string): number {
  const letters = source.replace(/[^A-Za-z]/g, '');
  if (!letters) return 100;
  const upper = letters.replace(/[^A-Z]/g, '').length;
  if (upper === 0) return 50; // lower case: acceptable, but not a label style
  if (upper === letters.length) return 100; // all caps
  return upper; // mixed/title case: prefer sentence case (1 capital)
}

function buildLookup(dictionary: Record<string, string>): Lookup {
  const exact = new Map<string, string>();
  const canonical = new Map<string, { score: number; target: string }>();
  for (const [source, target] of Object.entries(dictionary)) {
    const normalised = normalise(source);
    exact.set(normalised, target);

    const key = normalised.toLowerCase();
    const score = sourceCaseScore(source);
    const existing = canonical.get(key);
    if (!existing || score < existing.score) {
      canonical.set(key, { score, target });
    }
  }
  const fallback = new Map<string, string>();
  for (const [key, entry] of canonical) fallback.set(key, entry.target);
  return { exact, fallback };
}

const EN_LOOKUP = buildLookup(EN_TO_ID);
const ID_LOOKUP = buildLookup(ID_TO_EN);

function preserveCase(source: string, translated: string): string {
  const letters = source.replace(/[^A-Za-z]/g, '');
  if (letters.length > 1 && letters === letters.toUpperCase()) return translated.toUpperCase();
  return translated;
}

function lookup(
  dictionary: Lookup,
  source: string
): string | undefined {
  const normalised = normalise(source);
  if (!normalised) return undefined;

  const direct =
    dictionary.exact.get(normalised) ??
    dictionary.fallback.get(normalised.toLowerCase());
  if (direct) return direct;

  // Labels frequently carry a trailing colon/question mark; translate the base
  // label and keep the punctuation so headers and form labels keep their shape.
  const last = normalised.slice(-1);
  if (last === ':' || last === '?') {
    const base = normalised.slice(0, -1).trim();
    const translated =
      dictionary.exact.get(base) ??
      dictionary.fallback.get(base.toLowerCase());
    if (translated) return `${translated}${last}`;
  }
  return undefined;
}

const ID_NOUNS: Record<string, string> = {
  event: 'peristiwa',
  events: 'peristiwa',
  log: 'log',
  logs: 'log',
  agent: 'agen',
  agents: 'agen',
  endpoint: 'endpoint',
  endpoints: 'endpoint',
  incident: 'insiden',
  incidents: 'insiden',
  threat: 'ancaman',
  threats: 'ancaman',
  application: 'aplikasi',
  applications: 'aplikasi',
  alert: 'peringatan',
  alerts: 'peringatan',
  rule: 'aturan',
  rules: 'aturan',
  session: 'sesi',
  sessions: 'sesi',
  result: 'hasil',
  results: 'hasil',
  feed: 'feed',
  feeds: 'feed',
  ioc: 'IOC',
  iocs: 'IOC',
  vulnerability: 'kerentanan',
  vulnerabilities: 'kerentanan',
};

const EN_NOUNS: Record<string, string> = {
  peristiwa: 'events',
  log: 'logs',
  agen: 'agents',
  endpoint: 'endpoints',
  insiden: 'incidents',
  ancaman: 'threats',
  aplikasi: 'applications',
  peringatan: 'alerts',
  aturan: 'rules',
  sesi: 'sessions',
  hasil: 'results',
  feed: 'feeds',
  ioc: 'IOCs',
  kerentanan: 'vulnerabilities',
};

const ID_STATUS: Record<string, string> = {
  online: 'online',
  offline: 'offline',
  active: 'aktif',
  pending: 'menunggu',
  blocked: 'diblokir',
  monitored: 'dipantau',
  suspicious: 'mencurigakan',
  critical: 'kritis',
  high: 'tinggi',
  medium: 'sedang',
  low: 'rendah',
};

const EN_STATUS: Record<string, string> = {
  online: 'online',
  offline: 'offline',
  aktif: 'active',
  menunggu: 'pending',
  diblokir: 'blocked',
  dipantau: 'monitored',
  mencurigakan: 'suspicious',
  kritis: 'critical',
  tinggi: 'high',
  sedang: 'medium',
  rendah: 'low',
};

const ID_TIME_UNITS: Record<string, string> = {
  second: 'detik',
  seconds: 'detik',
  sec: 'detik',
  secs: 'detik',
  minute: 'menit',
  minutes: 'menit',
  min: 'menit',
  mins: 'menit',
  hour: 'jam',
  hours: 'jam',
  hr: 'jam',
  hrs: 'jam',
  day: 'hari',
  days: 'hari',
};

type Pattern = { re: RegExp; to: (match: RegExpMatchArray) => string };

function localizedIncidentStatus(value: string): string {
  const map: Record<string, string> = {
    NEW: 'BARU',
    INVESTIGATING: 'DALAM INVESTIGASI',
    CONTAINED: 'DITANGANI',
    MITIGATED: 'TERMITIGASI',
    RESOLVED: 'SELESAI',
    CLOSED: 'DITUTUP'
  };
  return map[value.trim().toUpperCase()] ?? value;
}

function localizedIncidentRole(value: string): string {
  const map: Record<string, string> = {
    'Super Admin': 'Admin Super',
    'Security Admin': 'Admin Keamanan',
    'Security Analyst': 'Analis Keamanan',
    'Organization Admin': 'Admin Organisasi',
    'Viewer (Read-only)': 'Penampil (Hanya Baca)',
    Viewer: 'Penampil'
  };
  return map[value.trim()] ?? value;
}

function localizedContainmentAction(value: string): string {
  const map: Record<string, string> = {
    BLOCK_IP: 'Blokir IP',
    QUARANTINE_HOST: 'Karantina Host',
    WAF_CHALLENGE: 'Tantangan WAF',
    INVALIDATE_CREDENTIALS: 'Cabut Kredensial',
    'Edge Containment': 'Penanganan Edge'
  };
  return map[value.trim()] ?? value;
}

const EN_PATTERNS: Pattern[] = [
  {
    re: /^Fail2ban & Allowlist \((\d+)\s+active\)$/i,
    to: m => `Fail2ban & Allowlist (${m[1]} aktif)`,
  },
  {
    re: /^Active Banned IP Inventory \((\d+)\)$/i,
    to: m => `Daftar IP Terkena Ban (${m[1]})`,
  },
  {
    re: /^Security Zones \((\d+)\)$/i,
    to: m => `Zona Keamanan (${m[1]})`,
  },
  {
    re: /^NAT & Port Forwarding \((\d+)\)$/i,
    to: m => `NAT & Port Forwarding (${m[1]})`,
  },

  {
    re: /^Agent incident detected:\s*(.+)$/i,
    to: m => `Insiden agen terdeteksi: ${m[1]}`,
  },
  {
    re: /^New threat indicator received:\s*(.+)$/i,
    to: m => `Indikator ancaman baru diterima: ${m[1]}`,
  },
  {
    re: /^Threat feeds synchronized in real-time(.*)$/i,
    to: m => `Feed ancaman tersinkron secara real-time${m[1]}`,
  },
  {
    re: /^Critical Security Incident:\s*(.+)$/i,
    to: m => `Insiden Keamanan Kritis: ${m[1]}`,
  },
  {
    re: /^Bespoke enterprise license agreement and billing telemetry for (.+)\.$/i,
    to: m => {
      const org = m[1].trim().toLowerCase() === 'your organization' ? 'organisasi Anda' : m[1];
      return `Perjanjian lisensi enterprise khusus dan telemetri tagihan untuk ${org}.`;
    },
  },
  {
    re: /^Active Organization:\s*(.+)$/i,
    to: m => `Organisasi Aktif: ${m[1]}`,
  },
  {
    re: /^No menu matches “(.+)”\.$/i,
    to: m => `Tidak ada menu yang cocok “${m[1]}”.`,
  },
  {
    re: /^Incident spawned automatically:\s*(.+)$/i,
    to: m => `Insiden dibuat otomatis: ${m[1]}`,
  },
  {
    re: /^Showing\s+([\d,.]+)\s*(?:to|[-–])\s*([\d,.]+)\s+of\s+([\d,.]+)\s+(.+)$/i,
    to: m => {
      const noun = ID_NOUNS[m[4].toLowerCase()] || m[4];
      return `Menampilkan ${m[1]}–${m[2]} dari ${m[3]} ${noun}`;
    },
  },
  {
    re: /^Showing\s+([\d,.]+)\s+of\s+([\d,.]+)$/i,
    to: m => `Menampilkan ${m[1]} dari ${m[2]}`,
  },
  {
    re: /^Page\s+([\d,]+)\s+of\s+([\d,]+)$/i,
    to: m => `Halaman ${m[1]} dari ${m[2]}`,
  },
  {
    re: /^All \((\d+)\)$/i,
    to: m => `Semua (${m[1]})`,
  },
  {
    re: /^All severities \((\d+)\)$/i,
    to: m => `Semua tingkat keparahan (${m[1]})`,
  },
  {
    re: /^Unread \((\d+)\)$/i,
    to: m => `Belum Dibaca (${m[1]})`,
  },
  {
    re: /^No (Critical|High|Medium|Low|Info) notifications$/i,
    to: m => `Tidak ada notifikasi ${ID_STATUS[m[1].toLowerCase()] || m[1].toLowerCase()}`,
  },
  {
    re: /^SERVICE\s+(\d{1,2})$/i,
    to: m => `LAYANAN ${m[1]}`,
  },
  {
    re: /^Authorized Security Operators \((\d+)\)$/i,
    to: m => `Operator Keamanan Resmi (${m[1]})`,
  },
  {
    re: /^No operators registered for (.+) yet\. Accounts are provisioned by your organization owner\.$/i,
    to: m => `Belum ada operator terdaftar untuk ${m[1]}. Akun disediakan oleh pemilik organisasi Anda.`,
  },
  {
    re: /^([\d,]+)\s+per page$/i,
    to: m => `${m[1]} per halaman`,
  },
  {
    re: /^([\d,.]+)\s+of\s+([\d,.]+)$/i,
    to: m => `${m[1]} dari ${m[2]}`,
  },
  {
    re: /^([\d,.]+)\s+of\s+([\d,.]+)\s+(.+)$/i,
    to: m => {
      const noun = ID_NOUNS[m[3].toLowerCase()] || m[3];
      return `${m[1]} dari ${m[2]} ${noun}`;
    },
  },
  {
    re: /^([\d,]+)\s+(events?|logs?|agents?|endpoints?|incidents?|threats?|applications?|alerts?|rules?|iocs?|feeds?|sessions?|results?|vulnerabilities?)$/i,
    to: m => `${m[1]} ${ID_NOUNS[m[2].toLowerCase()] || m[2]}`,
  },
  {
    re: /^([\d,.]+[KMB+]?)\s+(requests?|attacks?|threats?|events?|logs?|agents?|incidents?)$/i,
    to: m => {
      const nouns: Record<string, string> = {
        request: 'permintaan',
        requests: 'permintaan',
        attack: 'serangan',
        attacks: 'serangan',
        threat: 'ancaman',
        threats: 'ancaman',
        event: 'peristiwa',
        events: 'peristiwa',
        log: 'log',
        logs: 'log',
        agent: 'agen',
        agents: 'agen',
        incident: 'insiden',
        incidents: 'insiden',
      };
      return `${m[1]} ${nouns[m[2].toLowerCase()] || m[2]}`;
    },
  },
  {
    re: /^([\d,]+)\s+(Active|Blocked|Monitored|Suspicious|Critical|High|Medium|Low)$/i,
    to: m => `${m[1]} ${ID_STATUS[m[2].toLowerCase()] || m[2]}`,
  },
  {
    re: /^([\d,]+)\s+awaiting first heartbeat$/i,
    to: m => `${m[1]} menunggu heartbeat pertama`,
  },
  {
    re: /^([\d,]+)\s+(online|offline|active|pending|blocked|monitored)$/i,
    to: m => `${m[1]} ${ID_STATUS[m[2].toLowerCase()] || m[2]}`,
  },
  {
    re: /^(\d+)\s+(second|seconds|sec|secs|minute|minutes|min|mins|hour|hours|hr|hrs|day|days)\s+ago$/i,
    to: m => `${m[1]} ${ID_TIME_UNITS[m[2].toLowerCase()] || m[2]} lalu`,
  },
  {
    re: /^Last (seen|sync|updated|check-in):?\s*(.+)$/i,
    to: m => {
      const verbs: Record<string, string> = {
        seen: 'terlihat',
        sync: 'sinkron',
        updated: 'diperbarui',
        'check-in': 'check-in',
      };
      return `Terakhir ${verbs[m[1].toLowerCase()] || m[1]}: ${m[2]}`;
    },
  },
  {
    re: /^([\d,.]+)\s+(Feeds?|IOCs?|Vulnerabilities?|Endpoints?|Agents?)$/i,
    to: m => `${m[1]} ${ID_NOUNS[m[2].toLowerCase()] || m[2]}`,
  },
  {
    re: /^([\d,]+)\s+tracked$/i,
    to: m => `${m[1]} terlacak`,
  },
  {
    re: /^([\d,]+)\s+active hosts$/i,
    to: m => `${m[1]} host aktif`,
  },
  {
    re: /^Just now$/i,
    to: () => 'Baru saja',
  },
  {
    re: /^Today$/i,
    to: () => 'Hari ini',
  },
  {
    re: /^Yesterday$/i,
    to: () => 'Kemarin',
  },
  {
    re: /^Copied to clipboard$/i,
    to: () => 'Disalin ke clipboard',
  },
  {
    re: /^Saved successfully$/i,
    to: () => 'Berhasil disimpan',
  },
  {
    re: /^No (.+) found$/i,
    to: m => `Tidak ada ${(ID_NOUNS[m[1].toLowerCase()] || m[1])} ditemukan`,
  },
  {
    re: /^(.+) is required$/i,
    to: m => `${m[1]} wajib diisi`,
  },
  {
    re: /^All Actions \(([\d,.]+)\)$/i,
    to: m => `Semua Tindakan (${m[1]})`,
  },
  {
    re: /^All levels \(([\d,.]+)\)$/i,
    to: m => `Semua level (${m[1]})`,
  },
  {
    re: /^Protected Domains \(([\d,.]+)\)$/i,
    to: m => `Domain Terlindungi (${m[1]})`,
  },
  {
    re: /^Manage enterprise operators, multi-factor authentication \(MFA\), and fine-grained zero trust permissions for (.+)\.$/i,
    to: m => `Kelola operator enterprise, autentikasi multi-faktor (MFA), dan izin zero trust terperinci untuk ${m[1]}.`,
  },
  {
    re: /^([\d,.]+) blocked of ([\d,.]+) requests today$/i,
    to: m => `${m[1]} diblokir dari ${m[2]} permintaan hari ini`,
  },
  {
    re: /^([\d,.]+) protected network zones$/i,
    to: m => `${m[1]} zona jaringan terlindungi`,
  },
  {
    re: /^([\d,.]+) correlated threat clusters$/i,
    to: m => `${m[1]} klaster ancaman terkorelasi`,
  },
  {
    re: /^([\d,.]+) segmented zones · ([\d,.]+) protected applications$/i,
    to: m => `${m[1]} zona tersegmentasi · ${m[2]} aplikasi terlindungi`,
  },
  {
    re: /^([\d,.]+) security events ingested$/i,
    to: m => `${m[1]} peristiwa keamanan diingesti`,
  },
  {
    re: /^([\d,.]+)\/([\d,.]+) agent\(s\) applied$/i,
    to: m => `${m[1]}/${m[2]} agen diterapkan`,
  },
  {
    re: /^•\s*([\d,.]+)\/([\d,.]+) agent\(s\) applied$/i,
    to: m => `• ${m[1]}/${m[2]} agen diterapkan`,
  },
  {
    re: /^([\d,.]+)\/([\d,.]+) agent\(s\) applied revision ([\d,.]+)$/i,
    to: m => `${m[1]}/${m[2]} agen diterapkan revisi ${m[3]}`,
  },
  {
    re: /^([\d,.]+)\/([\d,.]+) agent\(s\) applied · ([\d,.]+) (unsupported|pending)$/i,
    to: m => `${m[1]}/${m[2]} agen diterapkan · ${m[3]} ${m[4].toLowerCase() === 'unsupported' ? 'tidak didukung' : 'menunggu'}`,
  },
  {
    re: /^([\d,.]+) agent\(s\) reported an error$/i,
    to: m => `${m[1]} agen melaporkan kesalahan`,
  },
  {
    re: /^REVISION\s+([\d,.]+)\s+·\s+([A-Z_]+)$/i,
    to: m => {
      const statuses: Record<string, string> = {
        NO_AGENT: 'tanpa agen',
        PENDING: 'menunggu',
        APPLIED: 'diterapkan',
        FAILED: 'gagal',
        PARTIAL: 'sebagian',
        UNSUPPORTED: 'tidak didukung',
      };
      return `Revisi ${m[1]} · ${statuses[m[2].toUpperCase()] || m[2]}`;
    },
  },
  {
    re: /^Revision\s*·\s*(.+)$/i,
    to: m => `Revisi · ${m[1]}`,
  },
  {
    re: /^Target\s*·\s*(.+)$/i,
    to: m => `Target · ${m[1]}`,
  },
  {
    re: /^Engine\s*·\s*(.+)$/i,
    to: m => `Mesin · ${m[1]}`,
  },
  {
    re: /^Inspection Rules \((\d[\d,.]*)\)$/i,
    to: m => `Aturan Inspeksi (${m[1]})`,
  },
  {
    re: /^Firewall Rules \((\d[\d,.]*)\)$/i,
    to: m => `Aturan Firewall (${m[1]})`,
  },
  {
    re: /^Security Zones \((\d[\d,.]*)\)$/i,
    to: m => `Zona Keamanan (${m[1]})`,
  },
  {
    re: /^([\d,.]+) ingress requests recorded$/i,
    to: m => `${m[1]} permintaan ingress tercatat`,
  },
  {
    re: /^Save to \[SOC (.+)\] Queue$/i,
    to: m => `Simpan ke Antrean [SOC ${m[1]}]`,
  },
  {
    re: /^Myself \((.+)\)$/i,
    to: m => `Saya Sendiri (${m[1]})`,
  },
  {
    re: /^Incident "(.+)" declared into SOC \[(.+)\] queue\.$/i,
    to: m => `Insiden "${m[1]}" dideklarasikan ke antrean SOC [${m[2]}].`,
  },
  {
    re: /^Incident (.+) assigned to (.+)\.$/i,
    to: m => `Insiden ${m[1]} ditugaskan kepada ${m[2]}.`,
  },
  {
    re: /^Incident (.+) deleted\.$/i,
    to: m => `Insiden ${m[1]} dihapus.`,
  },
  {
    re: /^SLA Breached (\d+)m$/i,
    to: m => `SLA Terlampaui ${m[1]}m`,
  },
  {
    re: /^SLA Remaining: (\d+)m$/i,
    to: m => `Sisa SLA: ${m[1]}m`,
  },
  {
    re: /^(\d[\d,.]*) Active$/i,
    to: m => `${m[1]} Aktif`,
  },
  {
    re: /^Target: (.+) \(Current Tier: (.+)\)$/i,
    to: m => `Target: ${m[1]} (Tier Saat Ini: ${m[2]})`,
  },
  {
    re: /^Incident: (.+) • Asset: (.+)$/i,
    to: m => `Insiden: ${m[1]} • Aset: ${m[2]}`,
  },
  {
    re: /^Keep Current Assignee \((.+)\)$/i,
    to: m => `Pertahankan Penanggung Jawab Saat Ini (${m[1]})`,
  },
  {
    re: /^Confirm Escalation to \[SOC (.+)\]$/i,
    to: m => `Konfirmasi Eskalasi ke [SOC ${m[1]}]`,
  },
  {
    re: /^Dedicated Workspace — (.+) \((.+)\)$/i,
    to: m => `Ruang Kerja Khusus — ${m[1]} (${m[2]})`,
  },
  {
    re: /^The (.+) queue is clear or every incident has been mitigated\.$/i,
    to: m => `Antrean ${m[1]} kosong atau semua insiden telah ditangani.`,
  },
  {
    re: /^Incident (.+) status changed to \[(.+)\]\.$/i,
    to: m => `Status insiden ${m[1]} berubah menjadi [${localizedIncidentStatus(m[2])}].`,
  },
  {
    re: /^Incident (.+) escalated to \[SOC (.+)\]!$/i,
    to: m => `Insiden ${m[1]} ditingkatkan ke [SOC ${m[2]}]!`,
  },
  {
    re: /^Containment action executed successfully(.*)\.$/i,
    to: m => {
      const suffixes: Record<string, string> = {
        ' (Emergency perimeter firewall rule injected)': ' (Aturan firewall perimeter darurat disuntikkan)',
        ' (Host network isolation dispatched to agent)': ' (Isolasi jaringan host dikirim ke agen)'
      };
      return `Tindakan penanganan berhasil dijalankan${suffixes[m[1]] ?? m[1]}.`;
    },
  },
  {
    re: /^Delete incident (.+)\? The entire audit timeline history will be permanently removed\.$/i,
    to: m => `Hapus insiden ${m[1]}? Seluruh riwayat linimasa audit akan dihapus permanen.`,
  },
  {
    re: /^Status updated to \[(.+)\] by (.+)$/i,
    to: m => `Status diperbarui ke [${localizedIncidentStatus(m[1])}] oleh ${m[2]}`,
  },
  {
    re: /^Escalated to (L\d) for deeper analysis$/i,
    to: m => `Ditingkatkan ke ${m[1]} untuk analisis lebih dalam`,
  },
  {
    re: /^Assigned to (.+) \((.+)\)$/i,
    to: m => `Ditugaskan kepada ${m[1]} (${localizedIncidentRole(m[2])})`,
  },
  {
    re: /^Incident declared into SOC \[(.+)\] pipeline$/i,
    to: m => `Insiden dideklarasikan ke pipeline SOC [${m[1]}]`,
  },
  {
    re: /^SOC Tier escalated: \[(.+)\] → \[(.+)\](?: - Reason: (.*?))?(?: \(Assigned to (.+)\))?$/i,
    to: m => `Tier SOC ditingkatkan: [${m[1]}] → [${m[2]}]${m[3] ? ` - Alasan: ${m[3]}` : ''}${m[4] ? ` (Ditugaskan kepada ${m[4]})` : ''}`,
  },
  {
    re: /^Incident assigned to (.+?)(?:: (.+))?$/i,
    to: m => `Insiden ditugaskan kepada ${m[1]}${m[2] ? `: ${m[2]}` : ''}`,
  },
  {
    re: /^Containment action executed: \[(.+?)\] on target "(.+?)"(?: - (.+))?$/i,
    to: m => `Tindakan penanganan dijalankan: [${localizedContainmentAction(m[1])}] pada target "${m[2]}"${m[3] ? ` - ${m[3]}` : ''}`,
  },
  {
    re: /^(\d+) (?:needs|need) attention$/i,
    to: m => `${m[1]} perlu perhatian`,
  },
  {
    re: /^([\d,.]+) protected applications behind the edge$/i,
    to: m => `${m[1]} aplikasi terlindungi di belakang edge`,
  },
  {
    re: /^([\d,.]+) segmented network zones$/i,
    to: m => `${m[1]} zona jaringan tersegmentasi`,
  },
  {
    re: /^Telemetry correlated across (.+) & endpoint agents$/i,
    to: m => `Telemetri terkorelasi di ${m[1]} & agen endpoint`,
  },
  {
    re: /^Allowed: ([\d,.]+)$/i,
    to: m => `Diizinkan: ${m[1]}`,
  },
  {
    re: /^Challenged \/ Suspicious: ([\d,.]+)$/i,
    to: m => `Ditantang / Mencurigakan: ${m[1]}`,
  },
  {
    re: /^Blocked: ([\d,.]+)$/i,
    to: m => `Diblokir: ${m[1]}`,
  },
  {
    re: /^Technical control signals measured continuously from live perimeter telemetry(?: for (.+?))?\. Formal certification requires an external audit attestation — this page reports the measured state only\.$/i,
    to: m =>
      `Sinyal kontrol teknis diukur secara berkelanjutan dari telemetri perimeter langsung${m[1] ? ` untuk ${m[1]}` : ''}. Sertifikasi formal memerlukan atestasi audit eksternal — halaman ini hanya melaporkan status terukur.`,
  },
  {
    re: /^Create Incident \[(.+)\]$/i,
    to: m => `Buat Insiden [${m[1]}]`,
  },
  {
    re: /^Update Incident Status to (.+)$/i,
    to: m => `Perbarui Status Insiden menjadi ${localizedIncidentStatus(m[1])}`,
  },
  {
    re: /^Escalate Incident Tier to (.+)$/i,
    to: m => `Naikkan Tier Insiden ke ${m[1]}`,
  },
  {
    re: /^Assign Incident to (.+)$/i,
    to: m => `Tetapkan Insiden kepada ${m[1]}`,
  },
  {
    re: /^Execute Incident Containment \((.+)\)$/i,
    to: m => `Jalankan Penanganan Insiden (${localizedContainmentAction(m[1])})`,
  },
  {
    re: /^Update Threat Status \((.+)\)$/i,
    to: m => `Perbarui Status Ancaman (${m[1]})`,
  },
  {
    re: /^Mitigate Threat \((.+)\)$/i,
    to: m => `Mitigasi Ancaman (${m[1]})`,
  },
  {
    re: /^Malware Containment \((.+)\)$/i,
    to: m => `Penanganan Malware (${localizedContainmentAction(m[1])})`,
  },
  {
    re: /^Incident (INC-[A-Za-z0-9-]+) \((.*)\)$/i,
    to: m => `Insiden ${m[1]} (${m[2]})`,
  },
  {
    re: /^Incident (INC-[A-Za-z0-9-]+)$/i,
    to: m => `Insiden ${m[1]}`,
  },
];

const ID_PATTERNS: Pattern[] = [
  {
    re: /^Fail2ban & Allowlist \((\d+)\s+aktif\)$/i,
    to: m => `Fail2ban & Allowlist (${m[1]} active)`,
  },
  {
    re: /^Daftar IP Terkena Ban \((\d+)\)$/i,
    to: m => `Active Banned IP Inventory (${m[1]})`,
  },
  {
    re: /^Zona Keamanan \((\d+)\)$/i,
    to: m => `Security Zones (${m[1]})`,
  },
  {
    re: /^NAT & Port Forwarding \((\d+)\)$/i,
    to: m => `NAT & Port Forwarding (${m[1]})`,
  },

  {
    re: /^Insiden agen terdeteksi:\s*(.+)$/i,
    to: m => `Agent incident detected: ${m[1]}`,
  },
  {
    re: /^Indikator ancaman baru diterima:\s*(.+)$/i,
    to: m => `New threat indicator received: ${m[1]}`,
  },
  {
    re: /^Feed ancaman tersinkron secara real-time(.*)$/i,
    to: m => `Threat feeds synchronized in real-time${m[1]}`,
  },
  {
    re: /^Insiden Keamanan Kritis:\s*(.+)$/i,
    to: m => `Critical Security Incident: ${m[1]}`,
  },
  {
    re: /^Menampilkan\s+([\d,.]+)[–-]([\d,.]+)\s+dari\s+([\d,.]+)\s+(.+)$/i,
    to: m => {
      const noun = EN_NOUNS[m[4].toLowerCase()] || m[4];
      return `Showing ${m[1]} to ${m[2]} of ${m[3]} ${noun}`;
    },
  },
  {
    re: /^Menampilkan\s+([\d,.]+)\s+dari\s+([\d,.]+)$/i,
    to: m => `Showing ${m[1]} of ${m[2]}`,
  },
  {
    re: /^Organisasi Aktif:\s*(.+)$/i,
    to: m => `Active Organization: ${m[1]}`,
  },
  {
    re: /^Tidak ada menu yang cocok “(.+)”\.$/i,
    to: m => `No menu matches “${m[1]}”.`,
  },
  {
    re: /^Halaman\s+([\d,]+)\s+dari\s+([\d,]+)$/i,
    to: m => `Page ${m[1]} of ${m[2]}`,
  },
  {
    re: /^Semua \((\d+)\)$/i,
    to: m => `All (${m[1]})`,
  },
  {
    re: /^Belum Dibaca \((\d+)\)$/i,
    to: m => `Unread (${m[1]})`,
  },
  {
    re: /^Tidak ada notifikasi (kritis|tinggi|sedang|rendah|info)$/i,
    to: m => {
      const sev = m[1].toLowerCase() === 'info' ? 'Info' : EN_STATUS[m[1].toLowerCase()] || m[1];
      return `No ${sev} notifications`;
    },
  },
  {
    re: /^Semua tingkat keparahan \((\d+)\)$/i,
    to: m => `All severities (${m[1]})`,
  },
  {
    re: /^LAYANAN\s+(\d{1,2})$/i,
    to: m => `SERVICE ${m[1]}`,
  },
  {
    re: /^(\d+) baru$/i,
    to: m => `${m[1]} new`,
  },
  {
    re: /^([\d,]+)\s+per halaman$/i,
    to: m => `${m[1]} per page`,
  },
  {
    re: /^([\d,.]+)\s+dari\s+([\d,.]+)$/i,
    to: m => `${m[1]} of ${m[2]}`,
  },
  {
    re: /^([\d,.]+)\s+dari\s+([\d,.]+)\s+(.+)$/i,
    to: m => `${m[1]} of ${m[2]} ${EN_NOUNS[m[3].toLowerCase()] || m[3]}`,
  },
  {
    re: /^([\d,]+)\s+(peristiwa|log|agen|endpoint|insiden|ancaman|aplikasi|peringatan|aturan|ioc|feed|sesi|hasil|kerentanan)$/i,
    to: m => `${m[1]} ${EN_NOUNS[m[2].toLowerCase()] || m[2]}`,
  },
  {
    re: /^([\d,]+)\s+(aktif|online|offline|menunggu|diblokir|dipantau|mencurigakan|kritis|tinggi|sedang|rendah)$/i,
    to: m => `${m[1]} ${EN_STATUS[m[2].toLowerCase()] || m[2]}`,
  },
  {
    re: /^([\d,]+)\s+menunggu heartbeat pertama$/i,
    to: m => `${m[1]} awaiting first heartbeat`,
  },
  {
    re: /^(\d+)\s+(detik|menit|jam|hari)\s+lalu$/i,
    to: m => {
      const units: Record<string, string> = {
        detik: 'seconds',
        menit: 'minutes',
        jam: 'hours',
        hari: 'days',
      };
      return `${m[1]} ${units[m[2].toLowerCase()] || m[2]} ago`;
    },
  },
  {
    re: /^Terakhir (terlihat|sinkron|diperbarui|check-in):?\s*(.+)$/i,
    to: m => {
      const verbs: Record<string, string> = {
        terlihat: 'seen',
        sinkron: 'sync',
        diperbarui: 'updated',
        'check-in': 'check-in',
      };
      return `Last ${verbs[m[1].toLowerCase()] || m[1]}: ${m[2]}`;
    },
  },
  {
    re: /^Baru saja$/i,
    to: () => 'Just now',
  },
  {
    re: /^Hari ini$/i,
    to: () => 'Today',
  },
  {
    re: /^Kemarin$/i,
    to: () => 'Yesterday',
  },
  {
    re: /^Disalin ke clipboard$/i,
    to: () => 'Copied to clipboard',
  },
  {
    re: /^Berhasil disimpan$/i,
    to: () => 'Saved successfully',
  },
];

export function translatePhrase(source: string, language: Language = getLanguage()): string | undefined {
  const dictionary = language === 'id' ? EN_LOOKUP : ID_LOOKUP;
  const patterns = language === 'id' ? EN_PATTERNS : ID_PATTERNS;

  const direct = lookup(dictionary, source);
  if (direct) return preserveCase(source, direct);

  const normalised = normalise(source);
  for (const pattern of patterns) {
    const match = normalised.match(pattern.re);
    if (match) {
      return preserveCase(source, pattern.to(match));
    }
  }

  return undefined;
}

export function translate(source: string): string {
  return translatePhrase(source) ?? source;
}

/** Translate the combined bold/muted page title without breaking its layout. */
export function translatePageTitle(title: string, tail?: string): { main: string; tail?: string } | null {
  if (getLanguage() !== 'id') return null;
  const key = normalise(`${title} ${tail || ''}`);
  const direct = PAGE_TITLE_PAIRS[key];
  if (direct) return direct;
  const main = lookup(EN_LOOKUP, title);
  const tailTranslation = tail ? lookup(EN_LOOKUP, tail) : undefined;
  if (!main && !tailTranslation) return null;
  return {
    main: main || title,
    tail: tailTranslation || tail,
  };
}

// ---------------------------------------------------------------------------
// DOM translator
// ---------------------------------------------------------------------------

const SKIP_TAGS = new Set([
  'SCRIPT',
  'STYLE',
  'NOSCRIPT',
  'CODE',
  'PRE',
  'KBD',
  'SAMP',
  'SVG',
]);

const TRANSLATABLE_ATTRIBUTES = ['placeholder', 'title', 'aria-label', 'alt', 'value'];

function isSkipped(element: Element | null): boolean {
  let node = element;
  while (node) {
    if (SKIP_TAGS.has(node.tagName)) return true;
    if (
      node.hasAttribute('data-no-translate') ||
      node.getAttribute('translate') === 'no' ||
      node.classList.contains('notranslate')
    ) {
      return true;
    }
    if (node.getAttribute('contenteditable') === 'true') return true;
    if (node === document.body) break;
    node = node.parentElement;
  }
  return false;
}

function translateTextNode(node: Text, language: Language): void {
  const value = node.nodeValue;
  if (!value) return;
  const parent = node.parentElement;
  if (parent && isSkipped(parent)) return;
  // A textarea's child text node is its default value; attributes such as the
  // placeholder are still translated by translateElement.
  if (parent?.tagName === 'TEXTAREA') return;

  // Preserve indentation / surrounding whitespace that React or JSX owns.
  const match = value.match(/^(\s*)([\s\S]*?)(\s*)$/);
  if (!match || !match[2]) return;
  const leading = match[1];
  const body = match[2];
  const trailing = match[3];
  if (!body.trim()) return;

  const translated = translatePhrase(body, language);
  if (!translated || translated === body) return;
  const next = `${leading}${translated}${trailing}`;
  if (next !== value) node.nodeValue = next;
}

function translateAttribute(element: Element, attribute: string, language: Language): void {
  if (!element.hasAttribute(attribute)) return;
  const value = element.getAttribute(attribute);
  if (!value) return;

  if (attribute === 'value') {
    // Never touch the value of real form fields. Only the visible label of
    // button-like inputs is presentation copy.
    if (!(element instanceof HTMLInputElement)) return;
    if (!['button', 'submit', 'reset'].includes(element.type)) return;
  }

  const translated = translatePhrase(value, language);
  if (translated && translated !== value) {
    element.setAttribute(attribute, translated);
  }
}

function translateElement(element: Element, language: Language): void {
  if (isSkipped(element)) return;
  for (const attribute of TRANSLATABLE_ATTRIBUTES) {
    translateAttribute(element, attribute, language);
  }
  for (const child of Array.from(element.childNodes)) {
    translateNode(child, language);
  }
}

function translateNode(node: Node, language: Language): void {
  if (node.nodeType === Node.TEXT_NODE) {
    translateTextNode(node as Text, language);
    return;
  }
  if (node.nodeType === Node.ELEMENT_NODE) {
    translateElement(node as Element, language);
    return;
  }
  if (node.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
    for (const child of Array.from(node.childNodes)) translateNode(child, language);
  }
}

function translateDocument(language: Language): void {
  if (document.body) translateNode(document.body, language);
  const title = translatePhrase(document.title, language);
  if (title && title !== document.title) document.title = title;
}

/**
 * Translate the current document and every future React render. The observer
 * is intentionally scoped to presentation attributes so frequent class/style
 * changes from animations do not trigger work.
 */
export function startTranslator(language: Language): () => void {
  document.documentElement.lang = language;
  translateDocument(language);

  if (!document.body) return () => {};

  const observer = new MutationObserver(records => {
    for (const record of records) {
      if (record.type === 'characterData') {
        translateTextNode(record.target as Text, language);
        continue;
      }
      if (record.type === 'attributes') {
        const target = record.target as Element;
        if (record.attributeName) {
          translateAttribute(target, record.attributeName, language);
        }
        continue;
      }
      for (const added of Array.from(record.addedNodes)) {
        translateNode(added, language);
      }
    }
  });

  observer.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: TRANSLATABLE_ATTRIBUTES,
  });

  return () => observer.disconnect();
}
