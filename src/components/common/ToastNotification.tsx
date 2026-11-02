import React, { useEffect, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowRight } from '@fortawesome/free-solid-svg-icons';

export interface ToastItem {
  id: string;
  title: string;
  desc: string;
  severity: string;
  timestamp: number;
  /** Callback when user clicks "Lihat detail" */
  onNavigate?: () => void;
}

interface SingleToastProps {
  toast: ToastItem;
  onDismiss: (id: string) => void;
  /** Duration in ms before auto-dismiss. Default: 6000 */
  duration?: number;
}

function severityConfig(severity: string) {
  const s = severity?.toUpperCase?.() || '';
  if (s === 'SUCCESS' || s === 'RESOLVED') {
    return {
      bar: 'bg-emerald-500',
      iconSvg: (
        <svg xmlns="http://www.w3.org/2000/svg" className="size-[18px] fill-emerald-600 dark:fill-emerald-400 shrink-0 mt-0.5" viewBox="0 0 330 330" aria-hidden="true">
          <path d="M165 0C74.019 0 0 74.019 0 165s74.019 165 165 165 165-74.019 165-165S255.981 0 165 0m0 300c-74.44 0-135-60.561-135-135S90.56 30 165 30s135 60.561 135 135-60.561 135-135 135" />
          <path d="m226.872 106.664-84.854 84.853-38.89-38.891c-5.857-5.857-15.355-5.858-21.213-.001-5.858 5.858-5.858 15.355 0 21.213l49.496 49.498a15 15 0 0 0 10.606 4.394h.001c3.978 0 7.793-1.581 10.606-4.393l95.461-95.459c5.858-5.858 5.858-15.355 0-21.213s-15.355-5.859-21.213-.001" />
        </svg>
      ),
      badge: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
      label: 'Success',
    };
  }
  if (s === 'CRITICAL' || s === 'ERROR' || s === 'HIGH') {
    return {
      bar: 'bg-rose-500',
      iconSvg: (
        <svg xmlns="http://www.w3.org/2000/svg" className="size-[18px] fill-rose-600 dark:fill-rose-400 shrink-0 mt-0.5" viewBox="0 0 512 512" aria-hidden="true">
          <path d="M256 0C114.508 0 0 114.497 0 256c0 141.493 114.497 256 256 256 141.492 0 256-114.497 256-256C512 114.507 397.503 0 256 0m0 472c-119.384 0-216-96.607-216-216 0-119.385 96.607-216 216-216 119.384 0 216 96.607 216 216 0 119.385-96.607 216-216 216" />
          <path d="M343.586 315.302 284.284 256l59.302-59.302c7.81-7.81 7.811-20.473.001-28.284-7.812-7.811-20.475-7.81-28.284 0L256 227.716l-59.303-59.302c-7.809-7.811-20.474-7.811-28.284 0s-7.81 20.474.001 28.284L227.716 256l-59.302 59.302c-7.811 7.811-7.812 20.474-.001 28.284 7.813 7.812 20.476 7.809 28.284 0L256 284.284l59.303 59.302c7.808 7.81 20.473 7.811 28.284 0s7.81-20.474-.001-28.284" />
        </svg>
      ),
      badge: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
      label: s === 'CRITICAL' ? 'Critical' : s === 'HIGH' ? 'High' : 'Error',
    };
  }
  if (s === 'MEDIUM' || s === 'WARNING' || s === 'WARN') {
    return {
      bar: 'bg-amber-500',
      iconSvg: (
        <svg xmlns="http://www.w3.org/2000/svg" className="size-[18px] fill-amber-600 dark:fill-amber-400 shrink-0 mt-0.5" viewBox="0 0 486.463 486.463" aria-hidden="true">
          <path d="M243.225 333.382c-13.6 0-25 11.4-25 25s11.4 25 25 25c13.1 0 25-11.4 24.4-24.4.6-14.3-10.7-25.6-24.4-25.6" />
          <path d="M474.625 421.982c15.7-27.1 15.8-59.4.2-86.4l-156.6-271.2c-15.5-27.3-43.5-43.5-74.9-43.5s-59.4 16.3-74.9 43.4l-156.8 271.5c-15.6 27.3-15.5 59.8.3 86.9 15.6 26.8 43.5 42.9 74.7 42.9h312.8c31.3 0 59.4-16.3 75.2-43.6m-34-19.6c-8.7 15-24.1 23.9-41.3 23.9h-312.8c-17 0-32.3-8.7-40.8-23.4-8.6-14.9-8.7-32.7-.1-47.7l156.8-271.4c8.5-14.9 23.7-23.7 40.9-23.7 17.1 0 32.4 8.9 40.9 23.8l156.7 271.4c8.4 14.6 8.3 32.2-.3 47.1" />
          <path d="M237.025 157.882c-11.9 3.4-19.3 14.2-19.3 27.3.6 7.9 1.1 15.9 1.7 23.8 1.7 30.1 3.4 59.6 5.1 89.7.6 10.2 8.5 17.6 18.7 17.6s18.2-7.9 18.7-18.2c0-6.2 0-11.9.6-18.2 1.1-19.3 2.3-38.6 3.4-57.9.6-12.5 1.7-25 2.3-37.5 0-4.5-.6-8.5-2.3-12.5-5.1-11.2-17-16.9-28.9-14.1" />
        </svg>
      ),
      badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
      label: s === 'MEDIUM' ? 'Medium' : 'Warning',
    };
  }
  return {
    bar: 'bg-blue-500',
    iconSvg: (
      <svg xmlns="http://www.w3.org/2000/svg" className="size-[18px] fill-blue-600 dark:fill-blue-400 shrink-0 mt-0.5" viewBox="0 0 330 330" aria-hidden="true">
        <path d="M165 0C74.019 0 0 74.02 0 165.001S74.019 330 165 330s165-74.018 165-164.999S255.981 0 165 0m0 300c-74.44 0-135-60.56-135-134.999S90.56 30 165 30s135 60.562 135 135.001S239.439 300 165 300" />
        <path d="M164.998 70c-11.026 0-19.996 8.976-19.996 20.009 0 11.023 8.97 19.991 19.996 19.991s19.996-8.968 19.996-19.991c0-11.033-8.97-20.009-19.996-20.009m.002 70c-8.284 0-15 6.716-15 15v90c0 8.284 6.716 15 15 15s15-6.716 15-15v-90c0-8.284-6.716-15-15-15" />
      </svg>
    ),
    badge: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
    label: s === 'LOW' ? 'Low' : 'Info',
  };
}

const SingleToast: React.FC<SingleToastProps> = ({ toast, onDismiss, duration = 6000 }) => {
  const [visible, setVisible] = useState(false);
  const [exiting, setExiting] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Slide in on mount
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 20);
    return () => clearTimeout(t);
  }, []);

  // Auto-dismiss
  useEffect(() => {
    timerRef.current = setTimeout(() => startExit(), duration);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [duration]);

  const startExit = () => {
    setExiting(true);
    setTimeout(() => onDismiss(toast.id), 400);
  };

  const handleDismiss = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    startExit();
  };

  const style = severityConfig(toast.severity);

  const translateClass =
    visible && !exiting ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0';

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`
        relative bg-white dark:bg-[#0c0c0e] p-3.5 rounded-xl shadow-xl dark:shadow-[0_10px_30px_rgba(0,0,0,0.8)] border border-slate-200 dark:border-zinc-800
        w-[360px] max-w-[calc(100vw-32px)] transition-all duration-[350ms] ease-out
        ${translateClass}
      `}
    >
      <div className="flex items-start gap-2.5">
        {/* Severity SVG Icon */}
        {style.iconSvg}

        {/* Content */}
        <div className="flex-1 min-w-0 pr-1">
          <div className="flex items-center gap-2 mb-0.5">
            <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${style.badge}`}>
              {style.label}
            </span>
            <span className="text-[10px] text-slate-400 dark:text-zinc-500 ml-auto shrink-0 font-mono">
              {new Date(toast.timestamp).toLocaleTimeString('id-ID', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              })}
            </span>
          </div>

          <p className="text-sm text-slate-900 font-semibold dark:text-zinc-100 leading-snug truncate" title={toast.title}>
            {toast.title}
          </p>

          <p className="text-xs mt-0.5 text-slate-600 dark:text-zinc-400 leading-relaxed line-clamp-2">
            {toast.desc}
          </p>

          {toast.onNavigate && (
            <button
              type="button"
              onClick={() => {
                toast.onNavigate?.();
                handleDismiss();
              }}
              className="mt-1.5 inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
            >
              Lihat detail <FontAwesomeIcon icon={faArrowRight} className="text-[9px]" />
            </button>
          )}
        </div>

        {/* Dismiss button */}
        <button
          type="button"
          onClick={handleDismiss}
          aria-label="Dismiss alert"
          className="ml-auto p-1 opacity-70 hover:opacity-100 text-slate-400 hover:text-slate-600 dark:text-zinc-500 dark:hover:text-zinc-200 rounded transition cursor-pointer"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="size-2.5 fill-current"
            aria-hidden="true"
            viewBox="0 0 329.269 329"
          >
            <path d="M194.8 164.77 323.013 36.555c8.343-8.34 8.343-21.825 0-30.164-8.34-8.34-21.825-8.34-30.164 0L164.633 134.605 36.422 6.391c-8.344-8.34-21.824-8.34-30.164 0-8.344 8.34-8.344 21.824 0 30.164l128.21 128.215L6.259 292.984c-8.344 8.34-8.344 21.825 0 30.164a21.27 21.27 0 0 0 15.082 6.25c5.46 0 10.922-2.09 15.082-6.25l128.21-128.214 128.216 128.214a21.27 21.27 0 0 0 15.082 6.25c5.46 0 10.922-2.09 15.082-6.25 8.343-8.34 8.343-21.824 0-30.164zm0 0" />
          </svg>
        </button>
      </div>

      {/* Subtle bottom progress bar */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] rounded-b-xl overflow-hidden bg-slate-100 dark:bg-zinc-800/80">
        <div
          className={`h-full ${style.bar} opacity-70`}
          style={{
            animation: `toast-shrink ${duration}ms linear forwards`,
          }}
        />
      </div>
    </div>
  );
};

// ─── Container ────────────────────────────────────────────────────────────────

interface ToastContainerProps {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  // Safety cap: render at most 3 toasts even if state has more
  const visible = toasts.slice(0, 3);

  return (
    <div
      aria-label="Notifikasi keamanan"
      className="fixed top-[72px] right-4 z-[9999] flex flex-col gap-2 pointer-events-none"
    >
      {visible.map((t) => (
        <div key={t.id} className="pointer-events-auto">
          <SingleToast toast={t} onDismiss={onDismiss} duration={8000} />
        </div>
      ))}
    </div>
  );
};
