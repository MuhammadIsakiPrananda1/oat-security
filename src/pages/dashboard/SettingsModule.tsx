import React, { useEffect, useState } from 'react';
import { 
  ShieldCheck, 
  Bell, 
  Lock, 
  CheckCircle2,
  Trash2,
  UserPlus,
  FlaskConical,
  AlertCircle,
  AlertTriangle,
  Languages,
  Check,
  RotateCcw,
  RefreshCw
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSliders } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { securityApi } from '../../services/api';
import { getLanguage, setLanguage as persistLanguage, type Language } from '../../i18n/translator';

// Real, on-page sections of this module. The sidebar renders them as a
// contextual sub-menu while Settings is open, and each entry scrolls to the
// section it names — no placeholder destinations.
export const SETTINGS_SECTIONS = [
  { id: 'settings-language', label: 'Language & Translation' },
  { id: 'settings-telemetry-injector', label: 'Telemetry Injector' },
  { id: 'settings-organization', label: 'Organization Setup' },
  { id: 'settings-waf-policy', label: 'WAF Paranoia & Automation' },
  { id: 'settings-alert-routing', label: 'Alert Routing & Paging' },
  { id: 'settings-session-retention', label: 'Session & Retention' },
  { id: 'settings-danger-zone', label: 'Danger Zone & Permanent Reset' }
] as const;

export const SettingsModule: React.FC = () => {
  const { organizations, currentOrg } = useAuth();
  const [saved, setSaved] = useState(false);
  const [orgNotice, setOrgNotice] = useState<string | null>(null);
  const [language, setLanguage] = useState<Language>(() => getLanguage());
  const [switchingLanguage, setSwitchingLanguage] = useState(false);

  const handleLanguageChange = (next: Language) => {
    if (next === language) return;
    setLanguage(next);
    setSwitchingLanguage(true);
    // Persist, update <html lang>, and reload so the entire React tree renders
    // from its original source before the new language layer is applied.
    persistLanguage(next);
  };

  // Settings form states
  const [autoMitigation, setAutoMitigation] = useState(true);
  const [owaspStrictness, setOwaspStrictness] = useState('Paranoia Level 2 (High)');
  const [alertEmail, setAlertEmail] = useState('');
  const [slackWebhook, setSlackWebhook] = useState('');
  const [logRetentionDays, setLogRetentionDays] = useState(365);
  const [sessionTimeoutMins, setSessionTimeoutMins] = useState(15);

  // Development telemetry injector (server rejects it on production builds).
  const [injecting, setInjecting] = useState<string | null>(null);
  const [injectFeedback, setInjectFeedback] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null);

  // Permanent Workspace Reset states
  const [showResetModal, setShowResetModal] = useState(false);
  const [resetConfirmationInput, setResetConfirmationInput] = useState('');
  const [resetting, setResetting] = useState(false);
  const [resetFeedback, setResetFeedback] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null);

  const handlePermanentReset = async () => {
    if (resetConfirmationInput !== 'RESET') return;
    setResetting(true);
    setResetFeedback(null);
    try {
      const res = await securityApi.resetWorkspace();
      setResetFeedback({ tone: 'ok', text: res?.message || 'Workspace has been permanently reset.' });
      setShowResetModal(false);
      setResetConfirmationInput('');
      try {
        sessionStorage.removeItem('oat_dashboard_data');
      } catch {}
      // Reload page cleanly to re-hydrate empty fresh workspace
      setTimeout(() => {
        window.location.reload();
      }, 1200);
    } catch (err: any) {
      setResetFeedback({ tone: 'err', text: err?.message || 'Failed to reset workspace.' });
    } finally {
      setResetting(false);
    }
  };

  // No server-side configuration service exists yet, so preferences are stored
  // per-organization in this browser and reported as exactly that.
  const settingsStorageKey = `oat-settings:${currentOrg?.id ?? 'unscoped'}`;

  useEffect(() => {
    try {
      const raw = localStorage.getItem(settingsStorageKey);
      if (!raw) return;
      const stored = JSON.parse(raw);
      if (typeof stored.autoMitigation === 'boolean') setAutoMitigation(stored.autoMitigation);
      if (typeof stored.owaspStrictness === 'string') setOwaspStrictness(stored.owaspStrictness);
      if (typeof stored.alertEmail === 'string') setAlertEmail(stored.alertEmail);
      if (typeof stored.slackWebhook === 'string') setSlackWebhook(stored.slackWebhook);
      if (typeof stored.logRetentionDays === 'number') setLogRetentionDays(stored.logRetentionDays);
      if (typeof stored.sessionTimeoutMins === 'number') setSessionTimeoutMins(stored.sessionTimeoutMins);
    } catch {
      // ignore malformed stored preferences
    }
  }, [settingsStorageKey]);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      localStorage.setItem(
        settingsStorageKey,
        JSON.stringify({ autoMitigation, owaspStrictness, alertEmail, slackWebhook, logRetentionDays, sessionTimeoutMins })
      );
    } catch {
      // storage unavailable
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 4000);
  };

  const handleInject = async (type: 'sqli' | 'xss' | 'ssh_brute' | 'normal') => {
    setInjecting(type);
    setInjectFeedback(null);
    try {
      const res = await securityApi.sendDevTestEvent(type);
      setInjectFeedback({ tone: 'ok', text: res?.message || `Event "${type}" injected through the ingest pipeline.` });
    } catch {
      setInjectFeedback({
        tone: 'err',
        text: 'Injection refused — the development ingest endpoint is disabled on this server.'
      });
    } finally {
      setInjecting(null);
    }
  };

  const handleRemoveOrg = async (orgId: string, orgName: string) => {
    if (!window.confirm(`Hapus organisasi "${orgName}" dan seluruh konfigurasi terkait?`)) return;
    try {
      await securityApi.deleteOrganization(orgId);
      setOrgNotice(`Organisasi "${orgName}" berhasil dihapus.`);
    } catch {
      setOrgNotice(`Gagal menghapus organisasi "${orgName}".`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faSliders} />}
        title="Platform Security"
        titleTail="Governance Settings"
        subtitle="Configure automated mitigation thresholds, notification routing, and audit retention policies."
      />

      {/* Language & Translation - applies to every route, including login and public pages. */}
      <div id="settings-language" className="scroll-mt-4 p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Languages className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <span className="text-sm font-semibold text-zinc-900 dark:text-white">Language & Translation</span>
          </div>
          <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded border border-zinc-200 dark:border-zinc-800 text-zinc-500 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-900/60">
            <Check className="w-3 h-3" />
            Active: {language === 'id' ? 'Bahasa Indonesia' : 'English'}
          </span>
        </div>
        <p className="text-xs text-zinc-500 dark:text-slate-400">
          Choose the language used across the entire console. The page reloads once and keeps your choice in this browser.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {([
            {
              code: 'en' as const,
              title: 'English',
              description: 'Use the original English interface.',
              badge: 'EN'
            },
            {
              code: 'id' as const,
              title: 'Bahasa Indonesia',
              description: 'Translate the entire console into Bahasa Indonesia.',
              badge: 'ID'
            }
          ]).map(option => {
            const active = language === option.code;
            return (
              <button
                key={option.code}
                type="button"
                aria-pressed={active}
                disabled={switchingLanguage}
                onClick={() => handleLanguageChange(option.code)}
                className={`text-left p-3 rounded-lg border transition-colors flex items-start gap-3 disabled:opacity-70 ${
                  active
                    ? 'border-sky-500/60 bg-sky-500/5 ring-1 ring-sky-500/20'
                    : 'border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-900/40'
                }`}
              >
                <span className={`mt-0.5 inline-flex h-7 w-9 shrink-0 items-center justify-center rounded-md text-[10px] font-mono font-bold border ${
                  active
                    ? 'bg-sky-500 text-white border-sky-500'
                    : 'bg-zinc-100 dark:bg-zinc-900 text-zinc-500 dark:text-zinc-400 border-zinc-200 dark:border-zinc-800'
                }`}>
                  {option.badge}
                </span>
                <span className="min-w-0">
                  <span className="flex items-center gap-2 text-xs font-semibold text-zinc-900 dark:text-white">
                    {option.title}
                    {active ? <Check className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" /> : null}
                  </span>
                  <span className="block mt-1 text-[11px] leading-normal text-zinc-500 dark:text-slate-400">
                    {option.description}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
        <p className="text-[11px] text-zinc-400 dark:text-zinc-500">
          Your preference is stored in this browser. Customer data, indicators, IP addresses and code are never translated.
        </p>
      </div>

      {saved && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          <span>Preferences stored in this browser for {currentOrg?.name ?? 'this organization'} — no server-side configuration service is connected yet.</span>
        </div>
      )}

      {/* Development telemetry injector — real events through the ingest path. */}
      <div id="settings-telemetry-injector" className="scroll-mt-4 p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
        <div className="flex items-center gap-2">
          <FlaskConical className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <span className="text-sm font-semibold text-zinc-900 dark:text-white">Development Telemetry Injector</span>
        </div>
        <p className="text-xs text-zinc-500 dark:text-slate-400">
          Pushes a genuine detection event through the same ingest pipeline used by endpoint agents, so the
          dashboard reflects real processed telemetry. Disabled automatically on production servers.
        </p>

        {injectFeedback && (
          <div
            className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
              injectFeedback.tone === 'ok'
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400'
                : 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400'
            }`}
          >
            {injectFeedback.tone === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
            <span>{injectFeedback.text}</span>
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          {([
            { key: 'sqli', label: 'SQL Injection (WAF)' },
            { key: 'xss', label: 'XSS Payload (WAF)' },
            { key: 'ssh_brute', label: 'SSH Brute Force (Agent)' },
            { key: 'normal', label: 'Allowed Traffic' }
          ] as const).map(item => (
            <button
              key={item.key}
              type="button"
              onClick={() => handleInject(item.key)}
              disabled={injecting !== null}
              className="px-3 py-1.5 rounded-lg bg-zinc-50 hover:bg-zinc-100 dark:bg-zinc-900/40 dark:hover:bg-zinc-800 border border-zinc-200 dark:border-zinc-800 text-xs font-semibold text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-white transition cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {injecting === item.key ? 'Injecting…' : item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Organization Management */}
      <div id="settings-organization" className="scroll-mt-4 p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <UserPlus className="w-4 h-4 text-zinc-700 dark:text-zinc-300" />
            <span className="text-sm font-semibold text-zinc-900 dark:text-white">Organization &amp; Collaborator Setup</span>
          </div>
        </div>

        {orgNotice && (
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-600 dark:text-amber-400 text-xs flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="flex-1">{orgNotice}</span>
            <button type="button" onClick={() => setOrgNotice(null)} className="opacity-60 hover:opacity-100 cursor-pointer">×</button>
          </div>
        )}

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[720px] text-left text-xs font-mono divide-y divide-zinc-200 dark:divide-zinc-800">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 text-zinc-500 dark:text-slate-400">
                <th className="p-3">ORGANIZATION NAME</th>
                <th className="p-3">DOMAIN</th>
                <th className="p-3">INDUSTRY</th>
                <th className="p-3">STATUS</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody>
              {organizations.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-zinc-400 dark:text-slate-500 text-[11px]">
                    No organizations yet. Organization data will appear automatically from the system.
                  </td>
                </tr>
              ) : (
                organizations.map(org => (
                  <tr key={org.id} className="hover:bg-zinc-100 dark:hover:bg-zinc-800 transition">
                    <td className="p-3 font-semibold text-zinc-900 dark:text-white">{org.name}</td>
                    <td className="p-3 text-zinc-700 dark:text-zinc-300">{org.domain || '-'}</td>
                    <td className="p-3 text-zinc-700 dark:text-zinc-300">{org.industry}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                        org.id === currentOrg?.id
                          ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                          : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 border border-zinc-300 dark:border-zinc-700'
                      }`}
                      >
                        {org.id === currentOrg?.id ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleRemoveOrg(org.id, org.name)}
                        className="p-1.5 rounded text-zinc-400 dark:text-slate-500 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-red-500/10 transition cursor-pointer"
                        title="Remove organization"
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

      <form onSubmit={handleSave} className="space-y-6">
        {/* WAF Policy Tuning */}
        <div id="settings-waf-policy" className="scroll-mt-4 p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
          <div className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-white">
            <ShieldCheck className="w-4 h-4 text-zinc-700 dark:text-zinc-300" />
            <span>WAF Core Rule Set Paranoia & Automation</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">OWASP ModSecurity Paranoia Level</label>
              <select
                value={owaspStrictness}
                onChange={e => setOwaspStrictness(e.target.value)}
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white"
              >
                <option>Paranoia Level 1 (Baseline)</option>
                <option>Paranoia Level 2 (High - Recommended for FinTech)</option>
                <option>Paranoia Level 3 (Extreme - Rigorous Validation)</option>
                <option>Paranoia Level 4 (Maximum Strictness)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Autonomous Threat Mitigation</label>
              <select
                value={autoMitigation ? 'true' : 'false'}
                onChange={e => setAutoMitigation(e.target.value === 'true')}
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white"
              >
                <option value="true">Active (Immediately block high-confidence heuristics)</option>
                <option value="false">Monitor Only (Log &amp; alert without dropping)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Incident Alerts Routing */}
        <div id="settings-alert-routing" className="scroll-mt-4 p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
          <div className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-white">
            <Bell className="w-4 h-4 text-amber-600 dark:text-amber-400" />
            <span>Incident Alert Routing &amp; Paging</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">SOC Emergency Email Group</label>
              <input
                type="email"
                value={alertEmail}
                onChange={e => setAlertEmail(e.target.value)}
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Slack Security Channel Webhook</label>
              <input
                type="url"
                value={slackWebhook}
                onChange={e => setSlackWebhook(e.target.value)}
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500"
              />
            </div>
          </div>
        </div>

        {/* Audit & Compliance Policies */}
        <div id="settings-session-retention" className="scroll-mt-4 p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
          <div className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-white">
            <Lock className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <span>Session Security &amp; Compliance Retention</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">SIEM Event Retention (Days)</label>
              <input
                type="number"
                value={logRetentionDays}
                onChange={e => setLogRetentionDays(Number(e.target.value))}
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500"
              />
              <span className="text-[10px] text-zinc-500 dark:text-slate-400 mt-1 block">Meets PCI DSS 10.5.1 requirements (minimum 365 days).</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Idle Operator Session Timeout (Minutes)</label>
              <input
                type="number"
                value={sessionTimeoutMins}
                onChange={e => setSessionTimeoutMins(Number(e.target.value))}
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500"
              />
              <span className="text-[10px] text-zinc-500 dark:text-slate-400 mt-1 block">Enforces automatic logout after an idle period.</span>
            </div>
          </div>
        </div>

        {/* 07 — Danger Zone: Permanent Reset */}
        <div id="settings-danger-zone" className="scroll-mt-4 p-5 rounded-xl border border-rose-200/80 dark:border-rose-900/50 bg-rose-50/30 dark:bg-rose-950/10 space-y-4 transition-colors">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-rose-700 dark:text-rose-400">
              <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
              <span>Danger Zone: Permanent Workspace Reset</span>
            </div>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-rose-100 dark:bg-rose-900/40 text-rose-700 dark:text-rose-300 font-semibold tracking-wider">
              Irreversible
            </span>
          </div>

          <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
            Hapus dan reset permanen seluruh telemetri, log lalu lintas (All Requests), security events, endpoints, aplikasi, dan aturan keamanan di workspace <strong>{currentOrg?.name || 'ini'}</strong> kembali ke keadaan awal bersih (fresh slate). Akun login Anda tetap aman.
          </p>

          {resetFeedback && (
            <div className={`p-3 rounded-lg text-xs font-medium border ${resetFeedback.tone === 'ok' ? 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800' : 'bg-rose-50 dark:bg-rose-950/20 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800'}`}>
              {resetFeedback.text}
            </div>
          )}

          <div className="pt-2">
            <button
              type="button"
              onClick={() => {
                setResetConfirmationInput('');
                setShowResetModal(true);
              }}
              className="px-4 py-2 rounded-lg bg-rose-600 text-white hover:bg-rose-700 text-xs font-semibold shadow-xs transition flex items-center gap-2 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Hapus Permanen &amp; Reset Workspace
            </button>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-zinc-900 text-white hover:bg-zinc-800 dark:bg-white dark:text-black dark:hover:bg-gray-200 text-xs font-semibold shadow-lg transition cursor-pointer"
          >
            Save Security &amp; Governance Configuration
          </button>
        </div>
      </form>

      {/* Confirmation Modal for Permanent Workspace Reset */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-zinc-950/60 backdrop-blur-xs">
          <div className="relative w-full max-w-md rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-rose-100 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">Konfirmasi Hapus Permanen</h3>
                <p className="text-xs text-zinc-500">Tindakan ini tidak dapat dibatalkan</p>
              </div>
            </div>

            <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
              Semua telemetri, All Requests, security events, endpoints, aplikasi, dan riwayat di workspace <strong>{currentOrg?.name}</strong> akan dihapus dan direset ke 0.
            </p>

            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                Ketik <span className="font-mono text-rose-600 dark:text-rose-400 font-bold">RESET</span> untuk konfirmasi:
              </label>
              <input
                type="text"
                value={resetConfirmationInput}
                onChange={e => setResetConfirmationInput(e.target.value)}
                placeholder="RESET"
                className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-hidden focus:ring-1 focus:ring-rose-500"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => {
                  setShowResetModal(false);
                  setResetConfirmationInput('');
                }}
                disabled={resetting}
                className="px-3.5 py-2 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={handlePermanentReset}
                disabled={resetConfirmationInput !== 'RESET' || resetting}
                className="px-4 py-2 rounded-lg bg-rose-600 text-white hover:bg-rose-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs font-semibold shadow-xs transition flex items-center gap-1.5 cursor-pointer"
              >
                {resetting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Mereset...
                  </>
                ) : (
                  'Ya, Hapus & Reset Permanen'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
