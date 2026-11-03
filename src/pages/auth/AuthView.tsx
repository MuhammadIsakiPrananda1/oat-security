import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Lock, 
  Mail, 
  AlertCircle, 
  Eye, 
  EyeOff, 
  Loader2, 
  CheckCircle2, 
  Globe, 
  Sun, 
  Moon, 
  Monitor,
  ShieldCheck,
  Server,
  Activity,
  Layers
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import type { User } from '../../types';
import { getLanguage, setLanguage, type Language } from '../../i18n/translator';

interface AuthViewProps {
  onSuccess: (user?: User) => void;
  onCancel?: () => void;
  variant?: 'modal' | 'page';
}

type ThemeMode = 'dark' | 'light' | 'system';

export const AuthView: React.FC<AuthViewProps> = ({ onSuccess, onCancel, variant = 'modal' }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Language state
  const [lang, setLang] = useState<Language>(() => getLanguage());

  // Theme state
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const stored = localStorage.getItem('theme');
      if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
    } catch {
      // fallback
    }
    return 'dark';
  });

  const isPage = variant === 'page';

  // Apply theme to document
  useEffect(() => {
    try {
      localStorage.setItem('theme', theme);
    } catch {}

    const root = document.documentElement;
    if (theme === 'system') {
      const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (systemDark) root.classList.add('dark');
      else root.classList.remove('dark');
    } else if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  const handleLanguageChange = (newLang: Language) => {
    setLang(newLang);
    setLanguage(newLang);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const authUser = await login(email.trim(), password);
      onSuccess(authUser);
    } catch (err: any) {
      setError(err?.message || (lang === 'id' ? 'Gagal masuk. Periksa kembali kredensial Anda.' : 'Sign in failed. Check your credentials.'));
    } finally {
      setLoading(false);
    }
  };

  const t = {
    badge: lang === 'id' ? 'PORTAL OPERASI KEAMANAN' : 'SECURITY OPERATIONS PORTAL',
    leftTitle: lang === 'id' ? 'Pusat Pertahanan & Kontrol SOC' : 'SOC Defense & Control Center',
    leftSubtitle: lang === 'id' 
      ? 'Pantau telemetri real-time, mitigasi serangan WAF secara otonom, dan kelola perimeter jaringan dalam satu konsol terpadu.'
      : 'Monitor live telemetry, mitigate WAF threats autonomously, and govern your network perimeter in one unified console.',
    feat1Title: lang === 'id' ? 'Akses Terbatas Terverifikasi' : 'Strict Role-Based Access',
    feat1Desc: lang === 'id' ? 'Hanya untuk operator berlisensi dan analis keamanan terverifikasi.' : 'Restricted to licensed operators and verified security analysts.',
    feat2Title: lang === 'id' ? 'Mitigasi Perimeter WAF & NGFW' : 'Autonomous WAF & NGFW Perimeter',
    feat2Desc: lang === 'id' ? 'Inspeksi paket real-time dan isolasi ancaman instan pada setiap node.' : 'Real-time packet inspection and instant threat isolation across nodes.',
    feat3Title: lang === 'id' ? 'Audit Trail Tidak Dapat Diubah' : 'Immutable Cryptographic Audit Trail',
    feat3Desc: lang === 'id' ? 'Setiap sesi dan riwayat perintah dicatat secara permanen.' : 'Every operator session and command history is permanently attested.',
    subHeading: lang === 'id' ? 'Masuk Dashboard' : 'Sign in to Dashboard',
    subDesc: lang === 'id' 
      ? 'Masukkan kredensial akun Anda untuk membuka konsol operasi keamanan.'
      : 'Enter your account credentials to access the security operations console.',
    tabAccount: lang === 'id' ? 'Akun Operator' : 'Operator Account',
    tabSec: lang === 'id' ? 'Verifikasi Keamanan' : 'Security Verification',
    userLabel: lang === 'id' ? 'Username / Email Operator' : 'Username / Operator Email',
    userPlaceholder: lang === 'id' ? 'admin atau email@perusahaan.com' : 'admin or email@company.com',
    passLabel: lang === 'id' ? 'Kata Sandi' : 'Password',
    passPlaceholder: lang === 'id' ? 'Masukkan kata sandi akun' : 'Enter your password',
    submitBtn: lang === 'id' ? 'Masuk ke Dashboard' : 'Sign In to Dashboard',
    submitting: lang === 'id' ? 'Memverifikasi Akses...' : 'Verifying Access...',
    securityNotice: lang === 'id' 
      ? 'Koneksi diamankan dengan TLS 1.3 & enkripsi end-to-end. Akses dipantau 24/7.'
      : 'Session secured with TLS 1.3 & end-to-end encryption. Monitored 24/7.',
    langLabel: lang === 'id' ? 'Bahasa' : 'Language',
    themeLabel: lang === 'id' ? 'Tema' : 'Theme',
    dark: lang === 'id' ? 'Mode Gelap' : 'Dark Mode',
    light: lang === 'id' ? 'Mode Terang' : 'Light Mode',
    system: lang === 'id' ? 'Sistem' : 'System',
    close: lang === 'id' ? 'Tutup' : 'Close'
  };

  const card = (
    <div
      className={`
        w-full max-w-5xl my-auto rounded-3xl overflow-hidden shadow-2xl transition-all duration-300
        border border-zinc-200/90 dark:border-white/10
        bg-white dark:bg-[#0c0c0e] text-zinc-900 dark:text-zinc-100
        flex flex-col md:flex-row relative
      `}
    >
      {!isPage && onCancel && (
        <button
          type="button"
          onClick={onCancel}
          className="absolute top-4 right-4 z-20 text-zinc-400 hover:text-zinc-900 dark:text-zinc-500 dark:hover:text-white text-xs px-2.5 py-1 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-sm transition cursor-pointer"
        >
          {t.close}
        </button>
      )}

      {/* ============================================================ */}
      {/* LEFT SECTION / PANEL (Branded Overview & Security Badges)     */}
      {/* ============================================================ */}
      <div className="md:w-5/12 bg-gradient-to-br from-zinc-900 via-[#18181b] to-[#09090b] text-white p-7 sm:p-10 flex flex-col justify-between border-b md:border-b-0 md:border-r border-zinc-800 relative overflow-hidden">
        {/* Subtle decorative glow */}
        <div className="absolute -top-24 -left-24 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -right-24 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10">
          {/* Logo & Platform Info */}
          <div className="flex items-center gap-3.5 mb-8">
            <div className="w-11 h-11 rounded-2xl bg-white/10 border border-white/15 flex items-center justify-center shadow-inner shrink-0 backdrop-blur-md">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div className="leading-tight">
              <div className="text-xl font-extrabold tracking-tight">
                OAT <span className="font-light text-zinc-400">SECURITY</span>
              </div>
              <div className="text-xs text-zinc-400 tracking-wide font-medium">Enterprise SOC Defense Platform</div>
            </div>
          </div>

          {/* Area / Security Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[11px] font-semibold text-emerald-400 uppercase tracking-wider mb-5">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{t.badge}</span>
          </div>

          {/* Hero Headline */}
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white leading-tight mb-3">
            {t.leftTitle}
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed mb-8">
            {t.leftSubtitle}
          </p>

          {/* Key Security Pillars / Feature Highlights */}
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-zinc-300 shrink-0 mt-0.5">
                <Lock className="w-4 h-4 text-emerald-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-zinc-200">{t.feat1Title}</div>
                <div className="text-[11px] text-zinc-400 mt-0.5 leading-snug">{t.feat1Desc}</div>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-zinc-300 shrink-0 mt-0.5">
                <Activity className="w-4 h-4 text-blue-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-zinc-200">{t.feat2Title}</div>
                <div className="text-[11px] text-zinc-400 mt-0.5 leading-snug">{t.feat2Desc}</div>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-zinc-300 shrink-0 mt-0.5">
                <CheckCircle2 className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-zinc-200">{t.feat3Title}</div>
                <div className="text-[11px] text-zinc-400 mt-0.5 leading-snug">{t.feat3Desc}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer info in left panel */}
        <div className="relative z-10 pt-8 mt-6 border-t border-white/10 flex items-center justify-between text-[11px] text-zinc-400">
          <div className="flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-zinc-400" />
            <span>NGFW / WAF v2.4 Active</span>
          </div>
          <span className="font-mono text-[10px] text-zinc-400">SOC Node-01</span>
        </div>
      </div>

      {/* ============================================================ */}
      {/* RIGHT SECTION / PANEL (Login Form + Preferences Dropdowns)   */}
      {/* ============================================================ */}
      <div className="md:w-7/12 p-7 sm:p-10 flex flex-col justify-between bg-white dark:bg-[#0c0c0e]">
        <div>
          {/* Subtle top category indicator like reference */}
          <div className="flex items-center gap-2 mb-2">
            <span className="h-0.5 w-5 bg-emerald-500 rounded-full" />
            <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 font-mono">
              PORTAL AUTENTIKASI RESMI
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-white">
            {t.subHeading}
          </h1>
          <p className="text-xs sm:text-sm text-zinc-500 dark:text-zinc-400 mt-1.5 leading-relaxed mb-6">
            {t.subDesc}
          </p>

          {/* Stepper bar indicator style from mockup */}
          <div className="flex items-center gap-4 pb-4 mb-6 border-b border-zinc-100 dark:border-zinc-800/80 text-xs font-medium">
            <div className="flex items-center gap-2 text-zinc-900 dark:text-white font-semibold">
              <span className="w-5 h-5 rounded-full bg-emerald-600 text-white flex items-center justify-center text-[10px] font-bold">
                1
              </span>
              <span>{t.tabAccount}</span>
            </div>
            <div className="h-px w-6 bg-zinc-200 dark:bg-zinc-800" />
            <div className="flex items-center gap-2 text-zinc-400 dark:text-zinc-500">
              <span className="w-5 h-5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-zinc-500 flex items-center justify-center text-[10px] font-bold">
                2
              </span>
              <span>{t.tabSec}</span>
            </div>
          </div>

          {error && (
            <div className="p-3.5 rounded-xl text-xs mb-5 flex items-center gap-2.5 bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-500/10 dark:text-rose-300 dark:border-rose-500/20">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-500" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4 text-left">
            {/* Username / Email */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="auth-email" className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                  {t.userLabel}
                </label>
                <span className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500">ID / Corporate Email</span>
              </div>
              <div className="relative">
                <Mail className="w-4 h-4 text-zinc-400 dark:text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  id="auth-email"
                  type="text"
                  required
                  autoComplete="username"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder={t.userPlaceholder}
                  className="w-full pl-10 pr-3.5 py-2.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 dark:focus:border-emerald-500 transition shadow-2xs"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="auth-password" className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                  {t.passLabel}
                </label>
                <span className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500">SHA-256 / Bcrypt</span>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-zinc-400 dark:text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  id="auth-password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder={t.passPlaceholder}
                  className="w-full pl-10 pr-11 py-2.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 dark:focus:border-emerald-500 transition shadow-2xs"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  aria-label={showPassword ? 'Sembunyikan kata sandi' : 'Tampilkan kata sandi'}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300 transition cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl text-sm font-bold text-white bg-zinc-900 hover:bg-zinc-800 dark:bg-emerald-600 dark:hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed transition flex items-center justify-center gap-2 mt-5 cursor-pointer shadow-md hover:shadow-lg"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>{t.submitting}</span>
                </>
              ) : (
                <span>{t.submitBtn}</span>
              )}
            </button>
          </form>
        </div>

        {/* ============================================================ */}
        {/* BOTTOM SECTION: 2 DROPDOWNS (LANGUAGE & THEME)               */}
        {/* ============================================================ */}
        <div className="mt-8 pt-5 border-t border-zinc-200/80 dark:border-zinc-800/80">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            {/* Left: Quick Security Text */}
            <p className="text-[11px] text-zinc-400 dark:text-zinc-500 leading-tight">
              {t.securityNotice}
            </p>

            {/* Right: 2 Dropdown Controls for Language & Theme */}
            <div className="flex items-center gap-2.5 shrink-0">
              {/* Dropdown 1: Bahasa / Language */}
              <div className="relative flex items-center">
                <Globe className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-2.5 pointer-events-none" />
                <select
                  value={lang}
                  onChange={e => handleLanguageChange(e.target.value as Language)}
                  aria-label={t.langLabel}
                  className="pl-8 pr-7 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 text-xs font-semibold text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 focus:outline-none focus:border-emerald-500 transition cursor-pointer appearance-none shadow-2xs"
                >
                  <option value="id">Bahasa Indonesia</option>
                  <option value="en">English (US)</option>
                </select>
                <div className="pointer-events-none absolute right-2 text-[10px] text-zinc-400">▼</div>
              </div>

              {/* Dropdown 2: Tema / Theme (Dark, Light, System) */}
              <div className="relative flex items-center">
                {theme === 'dark' ? (
                  <Moon className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-2.5 pointer-events-none" />
                ) : theme === 'light' ? (
                  <Sun className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-2.5 pointer-events-none" />
                ) : (
                  <Monitor className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-2.5 pointer-events-none" />
                )}
                <select
                  value={theme}
                  onChange={e => setTheme(e.target.value as ThemeMode)}
                  aria-label={t.themeLabel}
                  className="pl-8 pr-7 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 text-xs font-semibold text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 focus:outline-none focus:border-emerald-500 transition cursor-pointer appearance-none shadow-2xs"
                >
                  <option value="dark">{t.dark}</option>
                  <option value="light">{t.light}</option>
                  <option value="system">{t.system}</option>
                </select>
                <div className="pointer-events-none absolute right-2 text-[10px] text-zinc-400">▼</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  if (isPage) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-zinc-100 dark:bg-[#070709] p-4 sm:p-6 lg:p-8">
        {card}
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-sm flex items-start sm:items-center justify-center p-4 sm:p-6 overflow-y-auto custom-scrollbar"
      onMouseDown={e => {
        if (e.target === e.currentTarget && onCancel) onCancel();
      }}
    >
      {card}
    </div>
  );
};
