import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { User, Organization } from '../types';
import { setSimulatedOffline, isSimulatedOffline, setActiveOrganization, setAuthToken, securityApi, globalRealtimeClient } from '../services/api';

export interface SetupPayload {
  name: string;
  organizationName: string;
  domain?: string;
  industry?: string;
  email: string;
  password: string;
}

interface AuthContextType {
  user: User | null;
  currentOrg: Organization | null;
  organizations: Organization[];
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (payload: { name: string; email: string; password: string; username?: string }) => Promise<User>;
  completeSetup: (payload: SetupPayload) => Promise<User>;
  updateProfile: (payload: {
    name?: string;
    avatarUrl?: string | null;
    username?: string | null;
    phone?: string | null;
    telegramBotToken?: string | null;
    bio?: string | null;
    linkedinUrl?: string | null;
    githubUrl?: string | null;
    twitterUrl?: string | null;
    instagramUrl?: string | null;
  }) => Promise<void>;
  /** `null` until the platform status has been read from the server. */
  setupRequired: boolean | null;
  logout: () => void;
  switchOrg: (orgId: string) => void;
  addOrganization: (org: Organization) => void;
  removeOrganization: (orgId: string) => void;
  hasPermission: (permission: string) => boolean;
  isBackendOffline: boolean;
  toggleBackendOffline: () => void;
  loadOrganizations: (options?: { announce?: boolean }) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const SESSION_STORAGE_KEY = 'oat-session';

interface StoredSession {
  user: User | null;
  token: string | null;
}

function loadStoredSession(): StoredSession {
  try {
    const raw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.user) {
        return { user: parsed.user as User, token: parsed.token ?? null };
      }
    }
  } catch {
    // ignore malformed session
  }
  return { user: null, token: null };
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [initialSession] = useState<StoredSession>(loadStoredSession);
  const [user, setUser] = useState<User | null>(initialSession.user);
  const [token, setToken] = useState<string | null>(initialSession.token);
  // Organizations start empty and are hydrated from the backend (data real-time).
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(null);
  const [isBackendOffline, setIsBackendOffline] = useState(isSimulatedOffline());
  const [setupRequired] = useState<boolean | null>(false);

  // Mirrors currentOrg so the async tenant hydration below can resolve the
  // active organization synchronously.
  const currentOrgRef = useRef<Organization | null>(null);
  useEffect(() => {
    currentOrgRef.current = currentOrg;
  }, [currentOrg]);

  // Keep the API client bearer token in sync with the active session.
  useEffect(() => {
    setAuthToken(token);
  }, [token]);

  // Re-hydrate the operator profile once per token so role/SOC-scope changes
  // made by an administrator apply even to an existing browser session.
  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    (async () => {
      try {
        const response = await fetch('/api/auth/me', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!response.ok) return;
        const data = await response.json().catch(() => null);
        if (!cancelled && data?.user) {
          setUser(data.user as User);
        }
      } catch {
        // Keep the cached session on transient network failures.
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  // Persist / clear the session whenever auth or role state changes.
  useEffect(() => {
    try {
      if (user) {
        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ user, token }));
      } else {
        localStorage.removeItem(SESSION_STORAGE_KEY);
      }
    } catch {
      // storage unavailable
    }
  }, [user, token]);

  const login = async (email: string, password: string) => {
    const normalizedEmail = email.trim().toLowerCase();

    let response: Response;
    try {
      response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: normalizedEmail, password })
      });
    } catch {
      throw new Error('Tidak dapat menghubungi server. Periksa koneksi backend Anda.');
    }

    if (!response.ok) {
      // An empty user table means the platform has not been provisioned yet, so
      // there is nothing to sign in to — the onboarding form handles that case.
      if (response.status === 401) {
        throw new Error('Email atau kata sandi tidak valid.');
      }
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.error || 'Gagal masuk. Coba lagi.');
    }

    const data = await response.json().catch(() => null);
    if (!data?.user) {
      throw new Error('Respons autentikasi tidak valid.');
    }

    const authenticatedUser = data.user as User;
    setUser(authenticatedUser);
    setToken(typeof data.token === 'string' ? data.token : null);
    // Scope the API client to the tenant bound to this account straight away.
    setActiveOrganization(data.user.organizationId || '');
    return authenticatedUser;
  };

  const register = async (payload: { name: string; email: string; password: string; username?: string }): Promise<User> => {
    let response: Response;
    try {
      response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch {
      throw new Error('Tidak dapat menghubungi server. Periksa koneksi backend Anda.');
    }

    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.error || 'Gagal mendaftar akun baru.');
    }

    const data = await response.json().catch(() => null);
    if (!data?.user) {
      throw new Error('Respons pendaftaran tidak valid.');
    }

    const authenticatedUser = data.user as User;
    setUser(authenticatedUser);
    setToken(typeof data.token === 'string' ? data.token : null);
    if (data.organization) {
      setOrganizations([data.organization as Organization]);
      setCurrentOrg(data.organization as Organization);
    }
    setActiveOrganization(data.user.organizationId || '');
    return authenticatedUser;
  };

  // First-run provisioning: creates the tenant and its owner account on the
  // server and signs that owner in with a real token.
  const completeSetup = async (payload: SetupPayload): Promise<User> => {
    let response: Response;
    try {
      response = await fetch('/api/auth/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch {
      throw new Error('Tidak dapat menghubungi server. Periksa koneksi backend Anda.');
    }

    const data = await response.json().catch(() => null);
    if (!response.ok || !data?.user) {
      throw new Error(data?.error || 'Setup awal gagal. Periksa kembali data yang Anda masukkan.');
    }

    const authenticatedUser = data.user as User;
    setUser(authenticatedUser);
    setToken(typeof data.token === 'string' ? data.token : null);
    if (data.organization) {
      setOrganizations([data.organization as Organization]);
      setCurrentOrg(data.organization as Organization);
    }
    setActiveOrganization(data.user.organizationId || '');
    return authenticatedUser;
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    setAuthToken(null);
  };

  /**
   * Load the tenant list from the server.
   *
   * The very first endpoint agent provisions the organization itself, so a
   * tenant can appear at any moment. The list is therefore refreshed on a
   * timer and whenever the server announces a new tenant, and the console
   * switches to it automatically when nothing was selected yet.
   */
  const loadOrganizations = useCallback(async (options: { announce?: boolean } = {}) => {
    try {
      const res = await fetch('/api/organizations');
      if (!res.ok) return;
      const data = await res.json().catch(() => null);
      const list: Organization[] = Array.isArray(data?.organizations) ? data.organizations : [];
      setOrganizations(list);
      if (list.length === 0) {
        // Nothing provisioned server-side: never keep pointing the API client
        // at a tenant that no longer exists, or every write fails on the FK.
        setCurrentOrg(null);
        setActiveOrganization('');
        return;
      }
      const previous = currentOrgRef.current;
      const next = previous ? (list.find(o => o.id === previous.id) || list[0]) : list[0];
      const changed =
        !previous ||
        previous.id !== next.id ||
        previous.name !== next.name ||
        previous.domain !== next.domain;
      if (changed) {
        setCurrentOrg(next);
        // Register the tenant with the API client right here. Doing it in an
        // effect would run *after* child dashboards fire their first fetch, so
        // those requests would be scoped to no organization and return empty.
        setActiveOrganization(next.id);
        if (options.announce && (!previous || previous.id !== next.id)) {
          window.dispatchEvent(new CustomEvent('oat:notify', {
            detail: {
              id: `org-${next.id}`,
              title: `Organization ready: ${next.name}`,
              desc: 'The endpoint agent provisioned this tenant and its monitored website.',
              severity: 'Low',
              timestamp: Date.now()
            }
          }));
        }
      }
    } catch {
      // Keep the current tenant on a transient failure.
    }
  }, []);

  // Fetch organizations from API on mount, then keep the list current.
  useEffect(() => {
    loadOrganizations();
    const timer = window.setInterval(() => loadOrganizations(), 60_000);
    return () => window.clearInterval(timer);
  }, [loadOrganizations]);

  // A tenant provisioned by an endpoint agent is announced on the real-time
  // channel, so it shows up in the switcher without reloading the browser.
  useEffect(() => {
    const unsubscribe = globalRealtimeClient.subscribe(
      (msg: any) => {
        if (!msg) return;
        if (
          msg.type === 'organization.created' ||
          msg.type === 'organization.updated' ||
          msg.type === 'organization.deleted' ||
          msg.type === 'organization.removed'
        ) {
          loadOrganizations({ announce: true });
        }
      },
      () => {}
    );
    return () => unsubscribe();
  }, [loadOrganizations]);

  // NOTE: there is intentionally no `switchRole`. A console user's role is
  // provisioned by the website owner / organization administrator and bound to
  // their account, so it cannot be self-assigned at runtime.

  useEffect(() => {
    if (currentOrg) {
      setActiveOrganization(currentOrg.id);
    }
  }, [currentOrg?.id]);

  const switchOrg = (orgId: string) => {
    const matched = organizations.find(o => o.id === orgId);
    if (matched) {
      setCurrentOrg(matched);
      setActiveOrganization(matched.id);
      if (user) {
        setUser({ ...user, organizationId: matched.id, organizationName: matched.name });
      }
    }
  };

  const addOrganization = (org: Organization) => {
    setOrganizations(prev => {
      const next = [...prev, org];
      if (!currentOrg) {
        setCurrentOrg(org);
        setActiveOrganization(org.id);
        if (user) {
          setUser({ ...user, organizationId: org.id, organizationName: org.name });
        }
      }
      return next;
    });
  };

  const removeOrganization = (orgId: string) => {
    setOrganizations(prev => {
      const next = prev.filter(o => o.id !== orgId);
      if (currentOrg?.id === orgId) {
        setCurrentOrg(next.length > 0 ? next[0] : null);
        if (user && next.length > 0) {
          setUser({ ...user, organizationId: next[0].id, organizationName: next[0].name });
        } else if (user) {
          setUser({ ...user, organizationId: '', organizationName: '' });
        }
      }
      return next;
    });
  };

  const toggleBackendOffline = () => {
    const next = !isBackendOffline;
    setIsBackendOffline(next);
    setSimulatedOffline(next);
  };

  const hasPermission = (permission: string): boolean => {
    if (!user) return false;
    if (user.role === 'Super Admin') return true;

    switch (user.role) {
      case 'Security Admin':
        return permission !== 'manage_billing_super' && permission !== 'delete_organization';
      case 'Security Analyst':
        return ['view_telemetry', 'view_waf', 'view_firewall', 'triage_incidents', 'run_ai_analysis', 'export_reports'].includes(permission);
      case 'Organization Admin':
        return ['view_telemetry', 'manage_users', 'view_reports', 'manage_integrations'].includes(permission);
      case 'Viewer':
        return ['view_telemetry', 'view_reports'].includes(permission);
      default:
        return false;
    }
  };

  const updateProfile = async (payload: {
    name?: string;
    avatarUrl?: string | null;
    username?: string | null;
    phone?: string | null;
    telegramBotToken?: string | null;
    bio?: string | null;
    linkedinUrl?: string | null;
    githubUrl?: string | null;
    twitterUrl?: string | null;
    instagramUrl?: string | null;
  }) => {
    try {
      const res = await securityApi.updateProfile(payload);
      if (res?.user) {
        setUser(res.user);
        return;
      }
    } catch (err) {
      console.warn('[AuthContext] Backend profile update fallback to local state:', err);
    }
    setUser(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        name: payload.name !== undefined ? payload.name : prev.name,
        avatarUrl: payload.avatarUrl !== undefined ? (payload.avatarUrl || undefined) : prev.avatarUrl,
        username: payload.username !== undefined ? payload.username : prev.username,
        phone: payload.phone !== undefined ? payload.phone : prev.phone,
        telegramBotToken: payload.telegramBotToken !== undefined ? payload.telegramBotToken : prev.telegramBotToken,
        bio: payload.bio !== undefined ? payload.bio : prev.bio,
        linkedinUrl: payload.linkedinUrl !== undefined ? payload.linkedinUrl : prev.linkedinUrl,
        githubUrl: payload.githubUrl !== undefined ? payload.githubUrl : prev.githubUrl,
        twitterUrl: payload.twitterUrl !== undefined ? payload.twitterUrl : prev.twitterUrl,
        instagramUrl: payload.instagramUrl !== undefined ? payload.instagramUrl : prev.instagramUrl
      };
    });
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        currentOrg,
        organizations,
        isAuthenticated: !!user,
        login,
        register,
        completeSetup,
        updateProfile,
        setupRequired,
        logout,
        switchOrg,
        addOrganization,
        removeOrganization,
        hasPermission,
        isBackendOffline,
        toggleBackendOffline,
        loadOrganizations
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
};
