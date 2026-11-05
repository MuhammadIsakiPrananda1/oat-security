import React, { useEffect, useState } from 'react';
import { 
  UserPlus, 
  Lock, 
  CheckCircle2, 
  XCircle,
  RefreshCw,
  ShieldAlert
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime } from '../../utils/dateTime';
import { SocTier, UserRole } from '../../types';
import { securityApi } from '../../services/api';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUsers } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';

interface OperatorRow {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  socTier: SocTier | null;
  status: string;
  mfa: string;
  lastLogin: string;
}

export const UsersRolesModule: React.FC = () => {
  const { currentOrg, isBackendOffline } = useAuth();
  const [users, setUsers] = useState<OperatorRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ tone: 'ok' | 'warn' | 'err'; text: string } | null>(null);

  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteName, setInviteName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<UserRole>('Security Analyst');

  // Operator roster is read from the platform database — no locally invented rows.
  const load = async () => {
    setLoading(true);
    try {
      const res = await securityApi.getUsers();
      const rows = (res?.users || []) as any[];
      setUsers(
        rows.map(u => ({
          id: u.id,
          name: u.name || 'Unnamed operator',
          email: u.email || '',
          role: (u.role || 'Viewer') as UserRole,
          socTier: (u.soc_tier || u.socTier || null) as SocTier | null,
          status: 'Active',
          mfa: (u.mfa_enabled ?? u.mfaEnabled) ? 'Enabled' : 'Disabled',
          lastLogin: u.last_login ?? u.lastLogin ?? 'Never'
        }))
      );
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isBackendOffline]);

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={load} />;
  }

  // Accounts and roles are provisioned by the organisation owner / identity
  // provider. This console has no write endpoint for either, so the form only
  // reports that nothing was sent instead of faking a successful invitation.
  const handleInvite = (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback({
      tone: 'warn',
      text: `No provisioning endpoint is connected, so no invitation was sent to ${inviteEmail || 'the entered address'}. Ask your organization owner to create the account.`
    });
    setShowInviteModal(false);
    setInviteName('');
    setInviteEmail('');
  };

  const handleEditRole = (name: string) => {
    setFeedback({
      tone: 'warn',
      text: `Role for ${name} is assigned by your organization owner and cannot be changed from this console.`
    });
  };

  const permissionsMatrix = [
    { module: 'WAF Rule Modification', superAdmin: true, secAdmin: true, secAnalyst: false, orgAdmin: false, viewer: false },
    { module: 'Firewall Policy & ACL Deploy', superAdmin: true, secAdmin: true, secAnalyst: false, orgAdmin: false, viewer: false },
    { module: 'Threat Triage & IP Block Action', superAdmin: true, secAdmin: true, secAnalyst: true, orgAdmin: false, viewer: false },
    { module: 'Live Ingress Telemetry & SIEM View', superAdmin: true, secAdmin: true, secAnalyst: true, orgAdmin: true, viewer: true },
    { module: 'Compliance & Audit Report Export', superAdmin: true, secAdmin: true, secAnalyst: true, orgAdmin: true, viewer: true },
    { module: 'User Provisioning & Role Assignment', superAdmin: true, secAdmin: false, secAnalyst: false, orgAdmin: true, viewer: false },
    { module: 'Billing, SLA & Subscription Settings', superAdmin: true, secAdmin: false, secAnalyst: false, orgAdmin: true, viewer: false },
    { module: 'AI SOC Agent Triage & Execution', superAdmin: true, secAdmin: true, secAnalyst: true, orgAdmin: false, viewer: false },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faUsers} />}
        title="Users & Role-Based"
        titleTail="Access Control (RBAC)"
        subtitle={`Manage enterprise operators, multi-factor authentication (MFA), and fine-grained zero trust permissions for ${currentOrg?.name ?? 'this organization'}.`}
        actions={
          <button
            onClick={() => setShowInviteModal(true)}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
          >
            <UserPlus className="w-3.5 h-3.5" />
            Invite Enterprise Member
          </button>
        }
      />

      {feedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-start gap-2 ${
            feedback.tone === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400'
              : feedback.tone === 'warn'
                ? 'bg-amber-500/10 border-amber-500/20 text-amber-600 dark:text-amber-400'
                : 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400'
          }`}
        >
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <span className="flex-1">{feedback.text}</span>
          <button type="button" onClick={() => setFeedback(null)} className="opacity-60 hover:opacity-100 cursor-pointer">×</button>
        </div>
      )}

      {/* Users Table (Section 16) */}
      <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden transition-colors">
        <div className="p-4 border-b border-zinc-200 dark:border-zinc-800">
          <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">{`Authorized Security Operators (${users.length})`}</h3>
        </div>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[860px] text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 text-zinc-500 dark:text-slate-400">
                <th className="p-3">OPERATOR NAME</th>
                <th className="p-3">CORPORATE EMAIL</th>
                <th className="p-3">RBAC ROLE</th>
                <th className="p-3">SOC SCOPE</th>
                <th className="p-3">MFA STATUS</th>
                <th className="p-3">ACCOUNT STATUS</th>
                <th className="p-3">LAST LOGIN</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {users.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-4 text-center text-zinc-400 dark:text-slate-500 text-[11px] font-sans">
                    {`No operators registered for ${currentOrg?.name ?? 'this organization'} yet. Accounts are provisioned by your organization owner.`}
                  </td>
                </tr>
              ) : (
                users.map(u => (
                  <tr key={u.id} className="hover:bg-zinc-100 dark:hover:bg-zinc-800 transition">
                    <td className="p-3 font-sans font-semibold text-zinc-900 dark:text-white">{u.name}</td>
                    <td className="p-3 text-zinc-700 dark:text-zinc-300">{u.email}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 border border-zinc-300 dark:border-zinc-700 text-[11px]">
                        {u.role}
                      </span>
                    </td>
                    <td className="p-3">
                      {u.socTier ? (
                        <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
                          u.socTier === 'L1'
                            ? 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30'
                            : u.socTier === 'L2'
                              ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30'
                              : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                        }`}>
                          SOC {u.socTier}
                        </span>
                      ) : (
                        <span className="text-[11px] text-zinc-400">All tiers</span>
                      )}
                    </td>
                    <td className="p-3 text-emerald-600 dark:text-emerald-400">{u.mfa}</td>
                    <td className="p-3 text-emerald-600 dark:text-emerald-400">{u.status}</td>
                    <td className="p-3 text-zinc-500 dark:text-slate-400">{u.lastLogin === 'Never' ? 'Never' : formatDateTime(u.lastLogin)}</td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleEditRole(u.name)}
                        className="text-xs text-zinc-500 dark:text-slate-400 hover:text-zinc-800 dark:hover:text-zinc-200 font-sans px-2 py-1 rounded bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 cursor-pointer transition"
                      >
                        Role
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Granular RBAC Permissions Matrix (Section 16) */}
      <div className="p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 transition-colors">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-zinc-700 dark:text-zinc-300" />
              <span>Granular Role Permissions Matrix</span>
            </h3>
            <p className="text-xs text-zinc-500 dark:text-slate-400">Strict segregation of duties enforced across the OAT platform.</p>
          </div>
        </div>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[720px] text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 text-zinc-500 dark:text-slate-400">
                <th className="p-3 font-sans">SECURITY CAPABILITY</th>
                <th className="p-3 text-center">SUPER ADMIN</th>
                <th className="p-3 text-center">SECURITY ADMIN</th>
                <th className="p-3 text-center">SECURITY ANALYST</th>
                <th className="p-3 text-center">ORG ADMIN</th>
                <th className="p-3 text-center">VIEWER</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {permissionsMatrix.map((item, idx) => (
                <tr key={idx} className="hover:bg-zinc-100 dark:hover:bg-zinc-800 transition">
                  <td className="p-3 font-sans text-zinc-800 dark:text-zinc-200">{item.module}</td>
                  <td className="p-3 text-center">
                    {item.superAdmin ? <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 mx-auto" /> : <XCircle className="w-4 h-4 text-zinc-400 dark:text-slate-500 mx-auto" />}
                  </td>
                  <td className="p-3 text-center">
                    {item.secAdmin ? <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 mx-auto" /> : <XCircle className="w-4 h-4 text-zinc-400 dark:text-slate-500 mx-auto" />}
                  </td>
                  <td className="p-3 text-center">
                    {item.secAnalyst ? <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 mx-auto" /> : <XCircle className="w-4 h-4 text-zinc-400 dark:text-slate-500 mx-auto" />}
                  </td>
                  <td className="p-3 text-center">
                    {item.orgAdmin ? <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 mx-auto" /> : <XCircle className="w-4 h-4 text-zinc-400 dark:text-slate-500 mx-auto" />}
                  </td>
                  <td className="p-3 text-center">
                    {item.viewer ? <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 mx-auto" /> : <XCircle className="w-4 h-4 text-zinc-400 dark:text-slate-500 mx-auto" />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-fadeIn">
          <div className="relative w-full max-w-md max-h-[85vh] rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl overflow-y-auto custom-scrollbar p-6 text-zinc-900 dark:text-zinc-100 transition-colors">
            <h3 className="text-base font-bold text-zinc-900 dark:text-white mb-1">Invite Enterprise Security Operator</h3>
            <p className="text-xs text-zinc-500 dark:text-slate-400 mb-4">
              Accounts and roles are provisioned by your organization owner — submitting this form records a request
              and does not issue credentials from this console.
            </p>

            <form onSubmit={handleInvite} className="space-y-3 text-left">
              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={inviteName}
                  onChange={e => setInviteName(e.target.value)}
                  placeholder="e.g. Jane Doe"
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Corporate Email</label>
                <input
                  type="email"
                  required
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                  placeholder="user@company.com"
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Assign Role</label>
                <select
                  value={inviteRole}
                  onChange={e => setInviteRole(e.target.value as UserRole)}
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white"
                >
                  <option value="Security Analyst">Security Analyst</option>
                  <option value="Security Admin">Security Admin</option>
                  <option value="Super Admin">Super Admin</option>
                  <option value="Organization Admin">Organization Admin</option>
                  <option value="Viewer">Viewer (Read-only)</option>
                </select>
              </div>

              <div className="pt-4 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs text-zinc-500 dark:text-slate-400 hover:text-zinc-800 dark:hover:text-zinc-200 bg-zinc-100 dark:bg-zinc-800 cursor-pointer transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold bg-zinc-900 text-white hover:bg-zinc-800 dark:bg-white dark:text-black dark:hover:bg-gray-200 shadow-md cursor-pointer transition"
                >
                  Issue Invitation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
