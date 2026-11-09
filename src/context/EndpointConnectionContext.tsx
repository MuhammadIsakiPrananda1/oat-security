import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { securityApi, globalRealtimeClient } from '../services/api';
import { useAuth } from './AuthContext';

export interface ActiveEndpoint {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  os: string;
  arch: string;
  version: string;
  status: 'ONLINE' | 'OFFLINE';
  lastSeen: string | null;
  organizationId: string;
}

export interface EndpointConnectionContextType {
  hasConnectedEndpoints: boolean;
  connectedCount: number;
  totalAgents: number;
  activeEndpoints: ActiveEndpoint[];
  isLoading: boolean;
  lastUpdate: Date | null;
  refreshEndpointStatus: () => Promise<void>;
  isRealtimeConnected: boolean;
}

const EndpointConnectionContext = createContext<EndpointConnectionContextType>({
  hasConnectedEndpoints: false,
  connectedCount: 0,
  totalAgents: 0,
  activeEndpoints: [],
  isLoading: true,
  lastUpdate: null,
  refreshEndpointStatus: async () => {},
  isRealtimeConnected: false
});

export const EndpointConnectionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, currentOrg } = useAuth();
  const [hasConnectedEndpoints, setHasConnectedEndpoints] = useState<boolean>(false);
  const [connectedCount, setConnectedCount] = useState<number>(0);
  const [totalAgents, setTotalAgents] = useState<number>(0);
  const [activeEndpoints, setActiveEndpoints] = useState<ActiveEndpoint[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [isRealtimeConnected, setIsRealtimeConnected] = useState<boolean>(
    globalRealtimeClient.getStatus() === 'CONNECTED'
  );

  const fetchStatus = useCallback(async () => {
    if (!isAuthenticated) {
      setIsLoading(false);
      return;
    }
    try {
      const orgId = currentOrg?.id || '';
      const data = await securityApi.getEndpointStatus(orgId || undefined);
      setHasConnectedEndpoints(!!data.hasConnectedEndpoints);
      setConnectedCount(Number(data.connectedCount) || 0);
      setTotalAgents(Number(data.totalAgents) || 0);
      setActiveEndpoints((data.endpoints as ActiveEndpoint[]) || []);
      setLastUpdate(new Date());
    } catch (err) {
      console.warn('[EndpointConnection] Failed to fetch endpoint status:', err);
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, currentOrg?.id]);

  // Initial fetch on mount or org change
  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Real-time WebSocket listener
  useEffect(() => {
    const unsubStatus = globalRealtimeClient.onStatusChange((status) => {
      setIsRealtimeConnected(status === 'CONNECTED');
    });

    const unsubData = globalRealtimeClient.onData((msg: any) => {
      if (!msg || typeof msg !== 'object') return;

      if (msg.type === 'endpoint.status') {
        const payload = msg.data;
        if (payload) {
          // If this event has an orgId and we are scoped to an org, ensure match
          if (payload.organizationId && currentOrg?.id && payload.organizationId !== currentOrg.id) {
            return;
          }
          setHasConnectedEndpoints(Boolean(payload.hasConnectedEndpoints));
          setConnectedCount(Number(payload.connectedCount) || 0);
          setTotalAgents(Number(payload.totalAgents) || 0);
          setActiveEndpoints((payload.endpoints as ActiveEndpoint[]) || []);
          setLastUpdate(new Date());
          setIsLoading(false);
        }
      } else if (msg.type === 'agent.heartbeat' || msg.type === 'agent.enrolled') {
        // Only refresh or flag if matching current organization
        const agentOrg = msg.data?.organizationId || msg.organizationId;
        if (agentOrg && currentOrg?.id && agentOrg !== currentOrg.id) {
          return;
        }
        fetchStatus();
      } else if (msg.type === 'agent.removed' || msg.type === 'agent.offline') {
        const agentOrg = msg.data?.organizationId || msg.organizationId;
        if (agentOrg && currentOrg?.id && agentOrg !== currentOrg.id) {
          return;
        }
        fetchStatus();
      }
    });

    return () => {
      unsubStatus();
      unsubData();
    };
  }, [currentOrg?.id, fetchStatus]);

  return (
    <EndpointConnectionContext.Provider
      value={{
        hasConnectedEndpoints,
        connectedCount,
        totalAgents,
        activeEndpoints,
        isLoading,
        lastUpdate,
        refreshEndpointStatus: fetchStatus,
        isRealtimeConnected
      }}
    >
      {children}
    </EndpointConnectionContext.Provider>
  );
};

export function useEndpointConnection() {
  return useContext(EndpointConnectionContext);
}
