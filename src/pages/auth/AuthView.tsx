import React, { useState, useEffect, useRef } from 'react';
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
  Check,
  ChevronDown,
  RefreshCw
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

interface MathCaptcha {
  num1: number;
  num2: number;
  answer: number;
}

function generateMathCaptcha(): MathCaptcha {
  const n1 = Math.floor(Math.random() * 8) + 2; // 2 to 9
  const n2 = Math.floor(Math.random() * 7) + 1; // 1 to 7
  return { num1: n1, num2: n2, answer: n1 + n2 };
}

export const AuthView: React.FC<AuthViewProps> = ({ onSuccess, onCancel, variant = 'modal' }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState(() => {
    try {
      return localStorage.getItem('oat-remember-email') || '';
    } catch {
      return '';
    }
  });
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(() => {
    try {
      return localStorage.getItem('oat-remember-me') === 'true';
    } catch {
      return true;
    }
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Captcha state
  const [captcha, setCaptcha] = useState<MathCaptcha>(generateMathCaptcha);
  const [captchaInput, setCaptchaInput] = useState('');

  const refreshCaptcha = () => {
    setCaptcha(generateMathCaptcha());
    setCaptchaInput('');
  };

  // Custom Dropdown Open States
  const [langDropdownOpen, setLangDropdownOpen] = useState(false);
  const [themeDropdownOpen, setThemeDropdownOpen] = useState(false);
  const langRef = useRef<HTMLDivElement>(null);
  const themeRef = useRef<HTMLDivElement>(null);

  // Language state
  const [lang, setLang] = useState<Language>(() => getLanguage());

  // Theme state
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const stored = localStorage.getItem('theme');
      if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
    } catch {}
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

  // Click outside to close dropdowns
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (langRef.current && !langRef.current.contains(e.target as Node)) {
        setLangDropdownOpen(false);
      }
      if (themeRef.current && !themeRef.current.contains(e.target as Node)) {
        setThemeDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLanguageSelect = (newLang: Language) => {
    setLang(newLang);
    setLanguage(newLang);
    setLangDropdownOpen(false);
  };

  const handleThemeSelect = (newTheme: ThemeMode) => {
    setTheme(newTheme);
    setThemeDropdownOpen(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate Captcha
    if (parseInt(captchaInput.trim(), 10) !== captcha.answer) {
      setError(lang === 'id' ? 'Hasil verifikasi keamanan (captcha) salah.' : 'Security captcha answer is incorrect.');
      refreshCaptcha();
      return;
    }

    setLoading(true);
    try {
      // Handle Remember Me
      try {
        if (rememberMe) {
          localStorage.setItem('oat-remember-email', email.trim());
          localStorage.setItem('oat-remember-me', 'true');
        } else {
          localStorage.removeItem('oat-remember-email');
          localStorage.removeItem('oat-remember-me');
        }
      } catch {}

      const authUser = await login(email.trim(), password);
      onSuccess(authUser);
    } catch (err: any) {
      setError(err?.message || (lang === 'id' ? 'Gagal masuk. Periksa kembali kredensial Anda.' : 'Sign in failed. Check your credentials.'));
      refreshCaptcha();
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
    userLabel: lang === 'id' ? 'Username / Email Operator' : 'Username / Operator Email',
    userPlaceholder: lang === 'id' ? 'admin atau email@perusahaan.com' : 'admin or email@company.com',
    passLabel: lang === 'id' ? 'Kata Sandi' : 'Password',
    passPlaceholder: lang === 'id' ? 'Masukkan kata sandi akun' : 'Enter your password',
    rememberMe: lang === 'id' ? 'Ingat akun saya' : 'Remember me',
    captchaLabel: lang === 'id' ? 'Verifikasi Keamanan' : 'Human Verification',
    captchaPlaceholder: lang === 'id' ? 'Jawaban' : 'Answer',
    submitBtn: lang === 'id' ? 'Masuk ke Dashboard' : 'Sign In to Dashboard',
    submitting: lang === 'id' ? 'Memverifikasi Akses...' : 'Verifying Access...',
    securityNotice: lang === 'id' 
      ? 'Sesi diamankan TLS 1.3 & enkripsi end-to-end. Dipantau 24/7.'
      : 'Session secured with TLS 1.3 & end-to-end encryption. Monitored 24/7.',
    dark: lang === 'id' ? 'Mode Gelap' : 'Dark Mode',
    light: lang === 'id' ? 'Mode Terang' : 'Light Mode',
    system: lang === 'id' ? 'Ikuti Sistem' : 'System Default',
    close: lang === 'id' ? 'Tutup' : 'Close'
  };

  const card = (
    <div
      className={`
        w-full max-w-5xl my-auto rounded-2xl sm:rounded-3xl overflow-hidden shadow-xl dark:shadow-2xl transition-all duration-300
        border border-zinc-200/90 dark:border-zinc-800
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
      {/* LEFT PANEL: Cohesive Theme (Zinc Light / Dark #09090b)        */}
      {/* ============================================================ */}
      <div className="md:w-5/12 bg-zinc-50 dark:bg-[#09090b] text-zinc-900 dark:text-white p-7 sm:p-10 flex flex-col justify-between border-b md:border-b-0 md:border-r border-zinc-200/90 dark:border-zinc-800 relative">
        <div className="relative z-10">
          {/* Logo & Platform Info matching Dashboard Sidebar */}
          <div className="flex items-center gap-3.5 mb-8">
            <span className="w-11 h-11 shrink-0 rounded-xl bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 flex items-center justify-center shadow-xs">
              <Shield className="w-6 h-6" />
            </span>
            <div className="leading-tight">
              <div className="text-xl font-extrabold tracking-tight text-zinc-900 dark:text-white">
                OAT <span className="font-light text-zinc-500 dark:text-zinc-400">SECURITY</span>
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 tracking-wide font-medium">Enterprise SOC Defense Platform</div>
            </div>
          </div>

          {/* Area / Security Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-200/70 dark:bg-zinc-800/80 border border-zinc-300/80 dark:border-zinc-700/60 text-[11px] font-semibold text-zinc-800 dark:text-zinc-200 uppercase tracking-wider mb-5 shadow-2xs">
            <ShieldCheck className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            <span>{t.badge}</span>
          </div>

          {/* Hero Headline */}
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-white leading-tight mb-3">
            {t.leftTitle}
          </h2>
          <p className="text-xs sm:text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed mb-8">
            {t.leftSubtitle}
          </p>

          {/* Key Security Pillars / Feature Highlights matching OAT Design Tokens */}
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 flex items-center justify-center text-zinc-700 dark:text-zinc-300 shrink-0 mt-0.5 shadow-2xs">
                <Lock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-zinc-900 dark:text-zinc-200">{t.feat1Title}</div>
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5 leading-snug">{t.feat1Desc}</div>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 flex items-center justify-center text-zinc-700 dark:text-zinc-300 shrink-0 mt-0.5 shadow-2xs">
                <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-zinc-900 dark:text-zinc-200">{t.feat2Title}</div>
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5 leading-snug">{t.feat2Desc}</div>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 flex items-center justify-center text-zinc-700 dark:text-zinc-300 shrink-0 mt-0.5 shadow-2xs">
                <CheckCircle2 className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-zinc-900 dark:text-zinc-200">{t.feat3Title}</div>
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5 leading-snug">{t.feat3Desc}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer info in left panel */}
        <div className="relative z-10 pt-8 mt-6 border-t border-zinc-200 dark:border-zinc-800 flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400">
          <div className="flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5" />
            <span>NGFW / WAF v2.4 Active</span>
          </div>
          <span className="font-mono text-[10px]">SOC Node-01</span>
        </div>
      </div>

      {/* ============================================================ */}
      {/* RIGHT PANEL: Cohesive Theme (White / Dark #0c0c0e)           */}
      {/* ============================================================ */}
      <div className="md:w-7/12 p-7 sm:p-10 flex flex-col justify-between bg-white dark:bg-[#0c0c0e]">
        <div>
          {/* Top indicator line */}
          <div className="flex items-center gap-2 mb-2">
            <span className="h-0.5 w-5 bg-blue-600 dark:bg-blue-500 rounded-full" />
            <span className="text-[11px] font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400 font-mono">
              PORTAL AUTENTIKASI RESMI
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-white">
            {t.subHeading}
          </h1>
          <p className="text-xs sm:text-sm text-zinc-500 dark:text-zinc-400 mt-1.5 leading-relaxed mb-6">
            {t.subDesc}
          </p>

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
                  className="w-full pl-10 pr-3.5 py-2.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-900/10 dark:focus:ring-white/10 focus:border-zinc-400 dark:focus:border-zinc-600 transition shadow-2xs"
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
                  className="w-full pl-10 pr-11 py-2.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-900/10 dark:focus:ring-white/10 focus:border-zinc-400 dark:focus:border-zinc-600 transition shadow-2xs"
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

            {/* Row: Captcha & Remember Me */}
            <div className="pt-1 space-y-3">
              {/* Captcha Verification Widget */}
              <div className="p-3 rounded-xl border border-zinc-200/90 dark:border-zinc-800 bg-zinc-50/80 dark:bg-zinc-900/40 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 shadow-2xs">
                    <span className="font-mono text-sm font-bold text-zinc-800 dark:text-zinc-200 tracking-wider select-none">
                      {captcha.num1} + {captcha.num2} = ?
                    </span>
                    <button
                      type="button"
                      onClick={refreshCaptcha}
                      title="Ganti soal captcha"
                      className="ml-1 p-1 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition rounded"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400 hidden sm:inline">
                    {t.captchaLabel}
                  </span>
                </div>

                <div className="flex-1 sm:max-w-[120px]">
                  <input
                    type="number"
                    required
                    value={captchaInput}
                    onChange={e => setCaptchaInput(e.target.value)}
                    placeholder={t.captchaPlaceholder}
                    className="w-full px-3 py-1.5 bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 rounded-lg text-sm text-zinc-900 dark:text-white placeholder-zinc-400 text-center font-mono font-bold focus:outline-none focus:border-blue-500 transition shadow-2xs"
                  />
                </div>
              </div>

              {/* Remember Me Checkbox */}
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={e => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-900 dark:text-white accent-blue-600 focus:ring-0 cursor-pointer"
                  />
                  <span>{t.rememberMe}</span>
                </label>

                <span className="text-[11px] text-zinc-400 font-mono">SOC 2 Compliant</span>
              </div>
            </div>

            {/* Submit Button aligned with OAT Security Button Theme */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl text-sm font-semibold text-white bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200 disabled:opacity-60 disabled:cursor-not-allowed transition flex items-center justify-center gap-2 mt-5 cursor-pointer shadow-sm hover:shadow"
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
        {/* BOTTOM SECTION: 2 CUSTOM DROPDOWNS MATCHING DASHBOARD THEME   */}
        {/* ============================================================ */}
        <div className="mt-8 pt-5 border-t border-zinc-200/80 dark:border-zinc-800/80">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            {/* Left: Quick Security Text */}
            <p className="text-[11px] text-zinc-400 dark:text-zinc-500 leading-tight">
              {t.securityNotice}
            </p>

            {/* Right: Custom Dropdowns matching TopNav Popovers */}
            <div className="flex items-center gap-2 shrink-0">
              {/* Dropdown 1: Bahasa / Language */}
              <div className="relative" ref={langRef}>
                <button
                  type="button"
                  onClick={() => {
                    setLangDropdownOpen(prev => !prev);
                    setThemeDropdownOpen(false);
                  }}
                  className={`
                    h-8 sm:h-9 px-3 rounded-lg border text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-2xs
                    ${langDropdownOpen 
                      ? 'border-zinc-400 dark:border-zinc-600 bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white' 
                      : 'border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/90 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-200'
                    }
                  `}
                >
                  <Globe className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                  <span>{lang === 'id' ? 'Bahasa Indonesia' : 'English (US)'}</span>
                  <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform duration-150 ${langDropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                {/* Popover Menu: Styled exactly like TopNav User Menu */}
                {langDropdownOpen && (
                  <div className="absolute right-0 bottom-full mb-2 w-48 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xl p-1.5 z-50 animate-in fade-in zoom-in-95 duration-150">
                    <div className="px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 border-b border-zinc-100 dark:border-zinc-800/80 mb-1">
                      PILIH BAHASA
                    </div>
                    <button
                      type="button"
                      onClick={() => handleLanguageSelect('id')}
                      className={`w-full p-2 rounded-lg text-xs flex items-center justify-between transition cursor-pointer ${
                        lang === 'id'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono">🇮🇩</span>
                        <span>Bahasa Indonesia</span>
                      </div>
                      {lang === 'id' && <Check className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />}
                    </button>

                    <button
                      type="button"
                      onClick={() => handleLanguageSelect('en')}
                      className={`w-full p-2 rounded-lg text-xs flex items-center justify-between transition cursor-pointer ${
                        lang === 'en'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono">🇺🇸</span>
                        <span>English (US)</span>
                      </div>
                      {lang === 'en' && <Check className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />}
                    </button>
                  </div>
                )}
              </div>

              {/* Dropdown 2: Tema / Theme */}
              <div className="relative" ref={themeRef}>
                <button
                  type="button"
                  onClick={() => {
                    setThemeDropdownOpen(prev => !prev);
                    setLangDropdownOpen(false);
                  }}
                  className={`
                    h-8 sm:h-9 px-3 rounded-lg border text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-2xs
                    ${themeDropdownOpen 
                      ? 'border-zinc-400 dark:border-zinc-600 bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white' 
                      : 'border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/90 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-200'
                    }
                  `}
                >
                  {theme === 'dark' ? (
                    <Moon className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                  ) : theme === 'light' ? (
                    <Sun className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
                  ) : (
                    <Monitor className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                  )}
                  <span>{theme === 'dark' ? t.dark : theme === 'light' ? t.light : t.system}</span>
                  <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform duration-150 ${themeDropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                {/* Popover Menu: Styled exactly like TopNav User Menu */}
                {themeDropdownOpen && (
                  <div className="absolute right-0 bottom-full mb-2 w-44 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xl p-1.5 z-50 animate-in fade-in zoom-in-95 duration-150">
                    <div className="px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 border-b border-zinc-100 dark:border-zinc-800/80 mb-1">
                      PILIH TEMA
                    </div>
                    <button
                      type="button"
                      onClick={() => handleThemeSelect('dark')}
                      className={`w-full p-2 rounded-lg text-xs flex items-center justify-between transition cursor-pointer ${
                        theme === 'dark'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <Moon className="w-3.5 h-3.5 text-zinc-400" />
                        <span>{t.dark}</span>
                      </div>
                      {theme === 'dark' && <Check className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />}
                    </button>

                    <button
                      type="button"
                      onClick={() => handleThemeSelect('light')}
                      className={`w-full p-2 rounded-lg text-xs flex items-center justify-between transition cursor-pointer ${
                        theme === 'light'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <Sun className="w-3.5 h-3.5 text-zinc-500" />
                        <span>{t.light}</span>
                      </div>
                      {theme === 'light' && <Check className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />}
                    </button>

                    <button
                      type="button"
                      onClick={() => handleThemeSelect('system')}
                      className={`w-full p-2 rounded-lg text-xs flex items-center justify-between transition cursor-pointer ${
                        theme === 'system'
                          ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <Monitor className="w-3.5 h-3.5 text-zinc-400" />
                        <span>{t.system}</span>
                      </div>
                      {theme === 'system' && <Check className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  if (isPage) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-zinc-50 dark:bg-[#09090b] p-4 sm:p-6 lg:p-8 transition-colors duration-200">
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
