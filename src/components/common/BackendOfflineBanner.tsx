import React from 'react';
import { AlertTriangle, WifiOff, RefreshCw } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface BackendOfflineBannerProps {
  onRetry?: () => void;
  message?: string;
  isStreamOnly?: boolean;
}

export const BackendOfflineBanner: React.FC<BackendOfflineBannerProps> = ({ 
  onRetry, 
  message,
  isStreamOnly = false
}) => {
  const { isBackendOffline, toggleBackendOffline } = useAuth();

  return (
    <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-zinc-700 dark:border-rose-500/40 dark:bg-rose-950/30 dark:text-slate-200">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-rose-500/15 text-rose-600 dark:bg-rose-500/20 dark:text-rose-400">
            {isStreamOnly ? <WifiOff className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2 font-semibold text-rose-700 dark:text-rose-300 font-mono tracking-wide">
              <span>{isStreamOnly ? 'REALTIME CONNECTION LOST' : 'BACKEND OFFLINE'}</span>
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
            </div>
            <p className="text-xs text-zinc-600 dark:text-slate-400 mt-0.5">
              {message || (isStreamOnly 
                ? 'Realtime telemetry connection lost. Reconnecting to the security stream...' 
                : 'Security telemetry server is offline or unreachable. The interface only presents real data with no fabrication.')}
            </p>
          </div>
        </div>

        {onRetry && (
          <div className="flex items-center gap-2 self-end sm:self-center">
            <button
              onClick={onRetry}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-zinc-900 text-white hover:bg-zinc-800 dark:bg-white dark:text-black dark:hover:bg-gray-200 transition cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Reconnect Now
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
