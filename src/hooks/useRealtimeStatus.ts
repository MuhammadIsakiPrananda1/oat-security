import { useEffect, useState } from 'react';
import { globalRealtimeClient } from '../services/api';
import type { RealtimeStreamStatus } from '../services/api';

/**
 * Tracks the actual state of the real-time telemetry connection.
 *
 * `CONNECTED` means the dashboard is receiving live data over WebSocket or
 * the SSE fallback. Every other state means the feed is offline and the
 * client is trying to reconnect.
 */
export function useRealtimeStatus(): RealtimeStreamStatus {
  const [status, setStatus] = useState<RealtimeStreamStatus>(() => globalRealtimeClient.getStatus());

  useEffect(() => {
    const unsubscribe = globalRealtimeClient.onStatusChange(setStatus);
    return () => {
      unsubscribe();
    };
  }, []);

  return status;
}

export type LiveConnectionState = 'live' | 'connecting' | 'offline';

const INITIAL_CONNECT_GRACE_MS = 4000;

/**
 * Turns the low-level stream status into the three states shown in the UI.
 *
 * A short grace period avoids flashing "offline" while the first connection
 * is still opening. Once a connection has been established, any disconnect
 * is reported as offline immediately, including during reconnect attempts.
 */
export function useLiveConnectionState(): LiveConnectionState {
  const status = useRealtimeStatus();
  const [everConnected, setEverConnected] = useState(status === 'CONNECTED');
  const [graceElapsed, setGraceElapsed] = useState(false);

  useEffect(() => {
    if (status === 'CONNECTED') setEverConnected(true);
  }, [status]);

  useEffect(() => {
    const timer = window.setTimeout(() => setGraceElapsed(true), INITIAL_CONNECT_GRACE_MS);
    return () => window.clearTimeout(timer);
  }, []);

  if (status === 'CONNECTED') return 'live';
  if (status === 'REAL-TIME CONNECTION LOST' || everConnected || graceElapsed) return 'offline';
  return 'connecting';
}
