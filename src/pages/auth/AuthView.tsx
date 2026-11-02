import React, { useState } from 'react';
import { Shield, Lock, Mail, AlertCircle, Eye, EyeOff, Loader2, User as UserIcon, Sparkles } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import type { User } from '../../types';
import { getLanguage, setLanguage } from '../../i18n/translator';

export type AuthMode = 'login' | 'register';

interface AuthViewProps {
  initialMode?: AuthMode;
  onSuccess: (user?: User) => void;
  onCancel?: () => void;
  variant?: 'modal' | 'page';
}

export const AuthView: React.FC<AuthViewProps> = ({ initialMode = 'login', onSuccess, onCancel, variant = 'modal' }) => {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const language = getLanguage();

  const isPage = variant === 'page';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (mode === 'login') {
        const authUser = await login(email.trim(), password);
        onSuccess(authUser);
      } else {
        const authUser = await register({
          name: name.trim(),
          email: email.trim(),
          username: username.trim() || undefined,
          password
        });
        onSuccess(authUser);
      }
    } catch (err: any) {
      setError(err?.message || (mode === 'login' ? 'Gagal masuk. Periksa kembali kredensial Anda.' : 'Gagal mendaftar akun baru.'));
    } finally {
      setLoading(false);
    }
  };

  const card = (
    <div
      className={
        isPage
          ? 'w-full max-w-md'
          : 'w-full max-w-md my-auto rounded-2xl border border-zinc-200 bg-white dark:border-white/10 dark:bg-[#0a0a0a] shadow-2xl overflow-hidden p-6 sm:p-8 relative'
      }
    >
      {!isPage && onCancel && (
        <button
          type="button"
          onClick={onCancel}
          className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-900 dark:text-slate-400 dark:hover:text-white text-[11px] px-2 py-1 rounded border border-zinc-200 hover:border-zinc-300 dark:border-white/10 dark:hover:border-white/25 transition cursor-pointer"
        >
          Tutup
        </button>
      )}

      <div className={isPage ? 'rounded-2xl border border-zinc-200 bg-white p-6 sm:p-8 dark:border-white/10 dark:bg-white/[0.02]' : ''}>
        {/* Brand */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-zinc-100 border border-zinc-200 dark:bg-white/10 dark:border-white/15 flex items-center justify-center shadow-xs">
            <Shield className="w-5 h-5 text-zinc-900 dark:text-white" />
          </div>
          <div className="leading-tight">
            <div className="text-lg font-extrabold tracking-tight text-zinc-900 dark:text-white">
              OAT <span className="font-light text-zinc-600 dark:text-slate-200">SECURITY</span>
            </div>
            <div className="text-xs text-zinc-500 dark:text-slate-400">Enterprise Access Portal</div>
          </div>
        </div>

        {/* Tab Toggle: Masuk vs Daftar Akun Baru */}
        <div className="flex p-1 rounded-xl bg-zinc-100 dark:bg-zinc-800/80 mb-6">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setError(null);
            }}
            className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition cursor-pointer ${
              mode === 'login'
                ? 'bg-white dark:bg-zinc-900 text-zinc-900 dark:text-white shadow-xs'
                : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
            }`}
          >
            Masuk
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('register');
              setError(null);
            }}
            className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition cursor-pointer flex items-center justify-center gap-1.5 ${
              mode === 'register'
                ? 'bg-white dark:bg-zinc-900 text-zinc-900 dark:text-white shadow-xs'
                : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
            }`}
          >
            <Sparkles className="w-3 h-3 text-emerald-500" />
            <span>Daftar Akun Baru</span>
          </button>
        </div>

        {/* Heading */}
        <div className="mb-5">
          <h1 className="text-lg font-bold text-zinc-900 dark:text-white tracking-tight">
            {mode === 'login' ? 'Masuk ke Konsol Keamanan' : 'Daftar & Buat Workspace'}
          </h1>
          <p className="text-xs text-zinc-500 dark:text-slate-400 mt-1 leading-relaxed">
            {mode === 'login'
              ? 'Gunakan kredensial akun Anda untuk mengakses dashboard keamanan.'
              : 'Akun baru akan mendapatkan workspace terisolasi dengan sensor dan WAF tersendiri.'}
          </p>
        </div>

        {error && (
          <div className="p-3 rounded-lg text-xs mb-4 flex items-center gap-2 bg-rose-50 text-rose-600 border border-rose-200 dark:bg-rose-500/10 dark:text-rose-300 dark:border-rose-500/20">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5 text-left">
          {mode === 'register' && (
            <>
              {/* Nama Lengkap */}
              <div>
                <label htmlFor="auth-name" className="block text-xs font-semibold text-zinc-700 dark:text-slate-300 mb-1">
                  Nama Lengkap
                </label>
                <div className="relative">
                  <UserIcon className="w-4 h-4 text-zinc-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="auth-name"
                    type="text"
                    required
                    value={name}
                    onChange={e => setName(e.target.value)}
                    placeholder="Nama Lengkap Anda"
                    className="w-full pl-9 pr-3 py-2 bg-zinc-50 dark:bg-white/[0.03] border border-zinc-200 dark:border-white/10 rounded-lg text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-white/30 transition"
                  />
                </div>
              </div>

              {/* Username (Opsional) */}
              <div>
                <label htmlFor="auth-username" className="block text-xs font-semibold text-zinc-700 dark:text-slate-300 mb-1">
                  Username
                </label>
                <div className="relative">
                  <span className="text-xs font-mono text-zinc-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2">@</span>
                  <input
                    id="auth-username"
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="username_anda"
                    className="w-full pl-9 pr-3 py-2 bg-zinc-50 dark:bg-white/[0.03] border border-zinc-200 dark:border-white/10 rounded-lg text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-white/30 transition"
                  />
                </div>
              </div>
            </>
          )}

          {/* Email */}
          <div>
            <label htmlFor="auth-email" className="block text-xs font-semibold text-zinc-700 dark:text-slate-300 mb-1">
              {mode === 'login' ? 'Username / Email' : 'Alamat Email'}
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-zinc-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                id="auth-email"
                type={mode === 'register' ? 'email' : 'text'}
                required
                autoComplete={mode === 'login' ? 'username' : 'email'}
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder={mode === 'login' ? 'Masukkan username atau email' : 'contoh@perusahaan.com'}
                className="w-full pl-9 pr-3 py-2 bg-zinc-50 dark:bg-white/[0.03] border border-zinc-200 dark:border-white/10 rounded-lg text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-white/30 transition"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label htmlFor="auth-password" className="block text-xs font-semibold text-zinc-700 dark:text-slate-300 mb-1">
              Kata Sandi
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-zinc-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                id="auth-password"
                type={showPassword ? 'text' : 'password'}
                required
                minLength={6}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder={mode === 'login' ? 'Masukkan kata sandi' : 'Minimal 6 karakter'}
                className="w-full pl-9 pr-10 py-2 bg-zinc-50 dark:bg-white/[0.03] border border-zinc-200 dark:border-white/10 rounded-lg text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-white/30 transition"
              />
              <button
                type="button"
                onClick={() => setShowPassword(v => !v)}
                aria-label={showPassword ? 'Sembunyikan kata sandi' : 'Tampilkan kata sandi'}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:text-slate-500 dark:hover:text-slate-300 transition cursor-pointer"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg text-sm font-semibold text-white bg-zinc-900 hover:bg-zinc-800 dark:text-black dark:bg-white dark:hover:bg-slate-200 disabled:opacity-60 disabled:cursor-not-allowed transition flex items-center justify-center gap-2 mt-4 cursor-pointer shadow-xs"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>{mode === 'login' ? 'Memverifikasi...' : 'Mendaftarkan Workspace...'}</span>
              </>
            ) : (
              <span>{mode === 'login' ? 'Masuk ke Konsol' : 'Daftar & Buka Workspace Terisolasi'}</span>
            )}
          </button>
        </form>

        <p className="mt-5 pt-4 border-t border-zinc-200 dark:border-white/10 text-[11px] text-zinc-400 dark:text-slate-500 leading-relaxed">
          {mode === 'login'
            ? 'Akses dipantau dan tercatat. Pastikan Anda hanya memasukkan kredensial pada server resmi OAT Security.'
            : 'Workspace Anda terlindungi dengan enkripsi AES-256 dan terisolasi dari organisasi operator lain.'}
        </p>

        {/* Language access before login */}
        <div className="mt-3 flex items-center justify-center gap-2 text-[11px]">
          <button
            type="button"
            onClick={() => setLanguage('en')}
            aria-pressed={language === 'en'}
            className={`px-2 py-1 rounded border transition cursor-pointer ${
              language === 'en'
                ? 'border-zinc-300 dark:border-white/25 text-zinc-900 dark:text-white font-semibold'
                : 'border-transparent text-zinc-400 dark:text-slate-500 hover:text-zinc-700 dark:hover:text-slate-300'
            }`}
          >
            English
          </button>
          <span className="text-zinc-300 dark:text-zinc-700">·</span>
          <button
            type="button"
            onClick={() => setLanguage('id')}
            aria-pressed={language === 'id'}
            className={`px-2 py-1 rounded border transition cursor-pointer ${
              language === 'id'
                ? 'border-zinc-300 dark:border-white/25 text-zinc-900 dark:text-white font-semibold'
                : 'border-transparent text-zinc-400 dark:text-slate-500 hover:text-zinc-700 dark:hover:text-slate-300'
            }`}
          >
            Bahasa Indonesia
          </button>
        </div>
      </div>
    </div>
  );

  if (isPage) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-zinc-50 dark:bg-black p-4 sm:p-6">
        {card}
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-black/50 dark:bg-black/80 backdrop-blur-sm flex items-start sm:items-center justify-center p-4 sm:p-6 overflow-y-auto custom-scrollbar"
      onMouseDown={e => {
        if (e.target === e.currentTarget && onCancel) onCancel();
      }}
    >
      {card}
    </div>
  );
};
