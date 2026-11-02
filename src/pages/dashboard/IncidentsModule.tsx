import React, { useEffect, useState, useMemo, useCallback } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  Plus,
  RefreshCw,
  X,
  Lock
} from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldHalved } from '@fortawesome/free-solid-svg-icons';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { ModulePageHeader, ModulePageBadge } from '../../components/common/ModulePageHeader';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import {
  Incident,
  SocTier,
  IncidentSection,
  IncidentDraft,
  IncidentAuditRow,
  AssetOption,
  SOC_TIER_META,
  getWorkspaceOptions,
  getIncidentTier,
  getMitreContext,
  getSlaInfo,
  parseStoredTime,
  hasCalendarDate,
  clockSeconds,
  exportAuditToCsv,
  WorkspaceDropdown,
  IncidentQueueList,
  IncidentDetailWorkspace,
  IncidentSopGuide,
  IncidentAuditTrail,
  DeclareIncidentModal,
  EscalateTierModal,
  ContainmentModal,
  AssignAnalystModal,
  ExportIncidentModal
} from '../../components/incidents';
import { User } from '../../types';
import { resolveUserSocScope, normalizeSocTier } from '../../utils/incidentFeed';
import { translate } from '../../i18n/translator';

/**
 * SOC Incident Management Command Center Module.
 *
 * Real-Time Architecture:
 * - 100% Real Database integration (Incidents, Agents, Applications, Users).
 * - Full L1 ➔ L2 ➔ L3 Operational Workflow Pipeline.
 * - Live WebSocket telemetry synchronization directly with the Agent Server.
 */
const TIER_ORDER: Record<SocTier, number> = { L1: 1, L2: 2, L3: 3 };

function nextTierFor(tier: SocTier): SocTier | null {
  if (tier === 'L1') return 'L2';
  if (tier === 'L2') return 'L3';
  return null;
}

export const IncidentsModule: React.FC = () => {
  const { isBackendOffline, user } = useAuth();
  const socScope = useMemo(() => resolveUserSocScope(user), [user]);
  const [loading, setLoading] = useState(true);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [analysts, setAnalysts] = useState<User[]>([]);
  const [assets, setAssets] = useState<AssetOption[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [noteText, setNoteText] = useState('');
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null);

  // Dedicated Active Section Tab (Separated & clean)
  const [activeSection, setActiveSection] = useState<IncidentSection>(socScope || 'ALL');
  const [showWorkspaceDropdown, setShowWorkspaceDropdown] = useState(false);

  // Search & Status filters within lists
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'ACTIVE' | 'RESOLVED'>('ALL');
  const [workspaceTab, setWorkspaceTab] = useState<'playbook' | 'timeline' | 'evidence'>('playbook');

  // Consolidated audit trail filters
  const [auditSearch, setAuditSearch] = useState('');
  const [auditTier, setAuditTier] = useState<'ALL' | SocTier>(socScope || 'ALL');

  // Modal Dialogs visibility
  const [showDeclare, setShowDeclare] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showContainModal, setShowContainModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showEscalateModal, setShowEscalateModal] = useState(false);

  // Escalation Form State
  const [targetEscalationTier, setTargetEscalationTier] = useState<SocTier>('L2');
  const [escalationReason, setEscalationReason] = useState<string>('');
  const [escalationAssignee, setEscalationAssignee] = useState<string>('');

  // Assign & Containment state
  const [selectedAssignee, setSelectedAssignee] = useState<string>('');
  const [containmentTarget, setContainmentTarget] = useState<string>('');
  const [containmentAction, setContainmentAction] = useState<string>('BLOCK_IP');
  const [containmentNote, setContainmentNote] = useState<string>('');

  // Declare Incident Form Draft State
  const [draft, setDraft] = useState<IncidentDraft>({
    title: '',
    severity: 'High',
    tier: 'L2',
    affectedAsset: '',
    assignedTo: '',
    notes: '',
    immediateContainment: false
  });

  // Interactive Playbook Checklist state per incident
  const [playbookChecks, setPlaybookChecks] = useState<Record<string, Record<string, boolean>>>({});

  const togglePlaybookCheck = (incidentId: string, checkKey: string) => {
    setPlaybookChecks(prev => {
      const current = prev[incidentId] || {};
      return {
        ...prev,
        [incidentId]: {
          ...current,
          [checkKey]: !current[checkKey]
        }
      };
    });
  };

  // Keep a tier-scoped operator pinned to their own SOC workspace.
  useEffect(() => {
    if (!socScope) return;
    setActiveSection(socScope);
    setAuditTier(socScope);
  }, [socScope]);

  // Primary Data Fetcher: Loads real Incidents, Users, Agents, and Applications
  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const [incRes, usersRes, agentsRes, appsRes] = await Promise.all([
        securityApi.getIncidents().catch(() => ({ incidents: [] })),
        securityApi.getUsers().catch(() => ({ users: [] })),
        securityApi.getAgents().catch(() => ({ agents: [] })),
        securityApi.getApplications().catch(() => ({ applications: [] }))
      ]);

      const loadedIncidents = incRes.incidents || [];
      setIncidents(loadedIncidents);

      const loadedUsers = usersRes.users || [];
      setAnalysts(loadedUsers);

      const agentOpts: AssetOption[] = (agentsRes.agents || []).map((ag: any) => ({
        id: ag.id,
        name: ag.hostname || ag.name,
        hostname: ag.hostname,
        type: 'agent' as const,
        ip: ag.ip,
        status: ag.status,
        os: ag.os
      }));

      const appOpts: AssetOption[] = (appsRes.applications || []).map((app: any) => ({
        id: app.id,
        name: app.name,
        domain: app.domain,
        type: 'application' as const,
        ip: app.originIp,
        status: app.status,
        environment: app.environment
      }));

      setAssets([...agentOpts, ...appOpts]);
    } catch (e) {
      console.error('[IncidentsModule] Load error:', e);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, isBackendOffline]);

  // WebSocket Live Real-Time Listener
  useEffect(() => {
    const unsubEvents = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;
      const type = msg.type || '';
      if (type === 'incident.snapshot') {
        const snapshot = msg.data || {};
        if (Array.isArray(snapshot.incidents)) setIncidents(snapshot.incidents);
        return;
      }

      if (
        type === 'incident.created' ||
        type === 'incident.updated' ||
        type === 'incident.deleted' ||
        type === 'threat.created' ||
        type === 'security.alert' ||
        type === 'agent.status' ||
        type === 'rule.updated'
      ) {
        // Quietly refresh state without flashing loading spinners
        load(true);

        if (type === 'incident.created') {
          const incTitle = msg.data?.title || 'Security Threat Correlated';
          setFeedback({
            tone: 'ok',
            text: `🔴 REAL-TIME INGESTION: New Incident detected: "${incTitle}".`
          });
        }
      }
    });

    return () => {
      unsubEvents();
    };
  }, [load]);

  // Defensive client-side scope: the REST API and WebSocket are already
  // tier-filtered, but a stale frame must never leak another tier's queue.
  const visibleIncidents = useMemo(() => {
    if (!socScope) return incidents;
    return incidents.filter(inc => getIncidentTier(inc) === socScope);
  }, [incidents, socScope]);

  // Currently focused incident
  const selectedIncident = useMemo(() => {
    return visibleIncidents.find(i => i.id === selectedId) || null;
  }, [visibleIncidents, selectedId]);

  const selectedTier = selectedIncident ? getIncidentTier(selectedIncident) : 'L1';
  const currentTierMeta = SOC_TIER_META[selectedTier];

  // Aggregate Metrics per Tier
  const metrics = useMemo(() => {
    const total = visibleIncidents.length;
    const l1Active = visibleIncidents.filter(i => getIncidentTier(i) === 'L1' && !['MITIGATED', 'CLOSED', 'RESOLVED'].includes((i.status || '').toUpperCase())).length;
    const l2Active = visibleIncidents.filter(i => getIncidentTier(i) === 'L2' && !['MITIGATED', 'CLOSED', 'RESOLVED'].includes((i.status || '').toUpperCase())).length;
    const l3Active = visibleIncidents.filter(i => getIncidentTier(i) === 'L3' && !['MITIGATED', 'CLOSED', 'RESOLVED'].includes((i.status || '').toUpperCase())).length;
    const closed = visibleIncidents.filter(i => ['MITIGATED', 'CLOSED', 'RESOLVED'].includes((i.status || '').toUpperCase())).length;
    const active = total - closed;
    return { total, l1Active, l2Active, l3Active, closed, active };
  }, [visibleIncidents]);

  // Section-filtered incidents
  const sectionIncidents = useMemo(() => {
    return incidents.filter(inc => {
      const incTier = getIncidentTier(inc);
      if (activeSection === 'L1' && incTier !== 'L1') return false;
      if (activeSection === 'L2' && incTier !== 'L2') return false;
      if (activeSection === 'L3' && incTier !== 'L3') return false;

      // Status filter
      const incStatus = (inc.status || '').toUpperCase();
      const isClosed = ['MITIGATED', 'CLOSED', 'RESOLVED'].includes(incStatus);
      if (filterStatus === 'ACTIVE' && isClosed) return false;
      if (filterStatus === 'RESOLVED' && !isClosed) return false;

      // Search query
      if (search.trim()) {
        const q = search.toLowerCase();
        const matches =
          inc.title.toLowerCase().includes(q) ||
          inc.id.toLowerCase().includes(q) ||
          (inc.affectedAsset || '').toLowerCase().includes(q) ||
          (inc.assignedAnalyst || '').toLowerCase().includes(q);
        if (!matches) return false;
      }

      return true;
    });
  }, [incidents, activeSection, filterStatus, search]);

  // Consolidated audit trail (chronological history across all incidents)
  const auditRows = useMemo<IncidentAuditRow[]>(() => {
    const rows: IncidentAuditRow[] = [];
    const DAY_MS = 24 * 60 * 60 * 1000;

    for (const inc of incidents) {
      const tier = getIncidentTier(inc);
      const createdMs = parseStoredTime(inc.created);
      const createdDate = new Date(createdMs);
      const hasCreatedDate = createdMs > 0 && !isNaN(createdDate.getTime());
      const localMidnightMs = hasCreatedDate
        ? new Date(createdDate.getFullYear(), createdDate.getMonth(), createdDate.getDate()).getTime()
        : 0;
      const declaredClock = hasCreatedDate
        ? createdDate.getHours() * 3600 + createdDate.getMinutes() * 60 + createdDate.getSeconds()
        : 0;

      let dayOffset = 0;
      let previousClock = declaredClock;

      (inc.timeline || []).forEach(entry => {
        const dated = hasCalendarDate(entry.time);
        let sortMs: number;

        if (dated) {
          sortMs = parseStoredTime(entry.time);
        } else {
          const seconds = clockSeconds(entry.time);
          if (hasCreatedDate && seconds < previousClock) dayOffset += 1;
          if (seconds > previousClock) previousClock = seconds;
          sortMs = localMidnightMs + dayOffset * DAY_MS + seconds * 1000;
        }

        rows.push({
          incidentId: inc.id,
          title: inc.title,
          severity: inc.severity,
          status: inc.status,
          tier,
          time: entry.time,
          declaredAt: inc.created,
          sortMs,
          author: entry.author || 'System',
          note: entry.note || '—'
        });
      });
    }

    return rows.sort((a, b) => b.sortMs - a.sortMs);
  }, [incidents]);

  const filteredAuditRows = useMemo(() => {
    return auditRows.filter(row => {
      if (auditTier !== 'ALL' && row.tier !== auditTier) return false;
      if (!auditSearch.trim()) return true;
      const q = auditSearch.toLowerCase();
      return [row.incidentId, row.title, row.author, row.note]
        .some(value => (value || '').toLowerCase().includes(q));
    });
  }, [auditRows, auditTier, auditSearch]);

  const auditStats = useMemo(() => {
    const incidentsCovered = new Set(auditRows.map(r => r.incidentId)).size;
    const analystCount = new Set(auditRows.map(r => r.author)).size;
    const escalations = auditRows.filter(r => /escalat|eskalasi|tier/i.test(r.note)).length;
    return { total: auditRows.length, incidentsCovered, analysts: analystCount, escalations };
  }, [auditRows]);

  const handleExportAuditCsv = () => {
    exportAuditToCsv(filteredAuditRows);
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => load()} />;
  }

  // Declare Incident Submit (Persisted to Database)
  const handleDeclare = async (e: React.FormEvent) => {
    e.preventDefault();
    const title = draft.title.trim();
    if (!title) return;

    setBusy(true);
    try {
      const res = await securityApi.createIncident({
        title,
        severity: draft.severity,
        tier: draft.tier,
        affectedAsset: draft.affectedAsset.trim() || undefined,
        assignedTo: draft.assignedTo || (user ? user.email : 'Unassigned (Triage Queue)'),
        notes: draft.notes.trim() || undefined
      });
      setShowDeclare(false);
      setDraft({
        title: '',
        severity: 'High',
        tier: 'L2',
        affectedAsset: '',
        assignedTo: '',
        notes: '',
        immediateContainment: false
      });
      await load();
      if (res?.incident?.id) {
        setSelectedId(res.incident.id);
      }
      setFeedback({ tone: 'ok', text: `Incident "${title}" declared into SOC [${draft.tier}] queue.` });
    } catch {
      setFeedback({ tone: 'err', text: 'Incident declaration failed — check the database connection.' });
    } finally {
      setBusy(false);
    }
  };

  // Status Lifecycle Update
  const handleUpdateStatus = async (newStatus: string, defaultNote?: string) => {
    if (!selectedIncident) return;
    setBusy(true);
    try {
      await securityApi.updateIncidentStatus(
        selectedIncident.id,
        newStatus,
        defaultNote || `Status updated to [${newStatus}] by ${user?.email || 'SOC Operator'}`,
        user?.email,
        selectedTier
      );
      await load(true);
      setFeedback({ tone: 'ok', text: `Incident ${selectedIncident.id} status changed to [${newStatus}].` });
    } catch {
      setFeedback({ tone: 'err', text: 'Failed to update incident status.' });
    } finally {
      setBusy(false);
    }
  };

  // Escalate SOC Tier Submit
  const handleEscalateTier = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;
    setBusy(true);
    try {
      const note = escalationReason.trim() || `Escalated to ${targetEscalationTier} for deeper analysis`;
      await securityApi.updateIncidentTier(selectedIncident.id, {
        tier: targetEscalationTier,
        note,
        assignedTo: escalationAssignee || undefined,
        analyst: user?.email || 'SOC Commander'
      });
      setShowEscalateModal(false);
      setEscalationReason('');
      await load(true);
      setFeedback({
        tone: 'ok',
        text: `Incident ${selectedIncident.id} escalated to [SOC ${targetEscalationTier}]!`
      });
    } catch {
      setFeedback({ tone: 'err', text: 'Failed to escalate incident tier.' });
    } finally {
      setBusy(false);
    }
  };

  // Quick 1-click tier promote
  const handleQuickPromoteTier = (targetTier: SocTier) => {
    setTargetEscalationTier(targetTier);
    const candidate = analysts.find(a => a.email !== user?.email) || analysts[0];
    if (candidate) setEscalationAssignee(candidate.email);
    setShowEscalateModal(true);
  };

  // Assign Analyst Submit
  const handleAssignAnalyst = async () => {
    if (!selectedIncident || !selectedAssignee) return;
    setBusy(true);
    try {
      const targetUser = analysts.find(a => a.email === selectedAssignee);
      await securityApi.assignIncident(
        selectedIncident.id,
        selectedAssignee,
        targetUser ? `Assigned to ${targetUser.name} (${targetUser.role})` : undefined
      );
      setShowAssignModal(false);
      await load(true);
      setFeedback({ tone: 'ok', text: `Incident ${selectedIncident.id} assigned to ${selectedAssignee}.` });
    } catch {
      setFeedback({ tone: 'err', text: 'Failed to assign incident analyst.' });
    } finally {
      setBusy(false);
    }
  };

  // Containment Execution Submit
  const handleExecuteContainment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;
    setBusy(true);
    try {
      const res = await securityApi.executeIncidentContainment(selectedIncident.id, {
        action: containmentAction,
        target: containmentTarget || selectedIncident.affectedAsset,
        note: containmentNote.trim() || undefined,
        blockIp: containmentAction === 'BLOCK_IP' ? containmentTarget : undefined
      });
      setShowContainModal(false);
      setContainmentNote('');
      await load(true);
      const extraMsg = res.firewallRuleCreated ? ' (Emergency perimeter firewall rule injected)' : res.agentIsolated ? ' (Host network isolation dispatched to agent)' : '';
      setFeedback({ tone: 'ok', text: `Containment action executed successfully${extraMsg}.` });
    } catch {
      setFeedback({ tone: 'err', text: 'Containment execution failed.' });
    } finally {
      setBusy(false);
    }
  };

  // Add Investigation Note Submit
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanNote = noteText.trim();
    if (!cleanNote || !selectedIncident) return;

    setBusy(true);
    try {
      await securityApi.updateIncidentStatus(
        selectedIncident.id,
        selectedIncident.status,
        cleanNote,
        user?.email,
        selectedTier
      );
      setNoteText('');
      await load(true);
      setFeedback({ tone: 'ok', text: 'Forensic audit note recorded to database timeline.' });
    } catch {
      setFeedback({ tone: 'err', text: 'Failed to save investigation note.' });
    } finally {
      setBusy(false);
    }
  };

  // Delete Incident
  const handleDeleteIncident = async () => {
    if (!selectedIncident) return;
    if (!window.confirm(translate(`Delete incident ${selectedIncident.id}? The entire audit timeline history will be permanently removed.`))) {
      return;
    }
    setBusy(true);
    try {
      await securityApi.deleteIncident(selectedIncident.id);
      setSelectedId(null);
      await load(true);
      setFeedback({ tone: 'ok', text: `Incident ${selectedIncident.id} deleted.` });
    } catch {
      setFeedback({ tone: 'err', text: 'Failed to delete incident.' });
    } finally {
      setBusy(false);
    }
  };

  const currentMitre = selectedIncident ? getMitreContext(selectedIncident.title, selectedIncident.notes) : null;
  const currentSla = selectedIncident ? getSlaInfo(selectedIncident.severity, selectedIncident.created, selectedIncident.status, selectedTier) : null;
  const workspaceOptions = useMemo(() => getWorkspaceOptions(metrics, auditRows.length), [metrics, auditRows.length]);

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Module Page Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faShieldHalved} />}
        title="Incident Management"
        titleTail="SOC Command Center"
        subtitle="Real-time SOC operations console with multi-tier response pipelines (L1 Triage, L2 Forensics, L3 Crisis Commander) synchronized live with database and Agent fleet."
        badge={
          <div className="flex items-center gap-2">
            <ModulePageBadge>
              <span>Fleet Assets: {assets.length}</span>
            </ModulePageBadge>
            <ModulePageBadge>
              <span>Active Incidents: {metrics.active}</span>
            </ModulePageBadge>
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => load()}
              disabled={loading}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-zinc-200/80 bg-white text-zinc-500 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:border-zinc-600 dark:hover:text-zinc-100 shadow-xs"
              title="Refresh database records"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>

            <button
              onClick={() => {
                setDraft({
                  title: '',
                  severity: 'High',
                  tier: 'L2',
                  affectedAsset: assets[0]?.name || '',
                  assignedTo: user?.email || '',
                  notes: '',
                  immediateContainment: false
                });
                setShowDeclare(true);
              }}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-rose-600 px-3.5 text-xs font-semibold text-white shadow-sm transition hover:bg-rose-500 cursor-pointer active:scale-95"
            >
              <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>Declare Incident</span>
            </button>
          </div>
        }
      />

      {/* Action feedback toast */}
      {feedback && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-3 animate-fadeIn shadow-sm ${feedback.tone === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400'
            }`}
        >
          <div className="flex items-center gap-2">
            {feedback.tone === 'ok' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-500" />
            )}
            <span className="font-medium">{feedback.text}</span>
          </div>
          <button type="button" onClick={() => setFeedback(null)} className="opacity-60 hover:opacity-100 cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Workspace & View Dropdown Selector + Quick Tier Filters */}
      <WorkspaceDropdown
        activeSection={activeSection}
        onSelectSection={(sec) => {
          setActiveSection(sec);
          setSelectedId(null);
        }}
        isOpen={showWorkspaceDropdown}
        onToggleOpen={() => setShowWorkspaceDropdown(open => !open)}
        onClose={() => setShowWorkspaceDropdown(false)}
        options={workspaceOptions}
        metrics={metrics}
        socScope={socScope}
      />

      {/* Conditional Content Rendering */}
      {selectedIncident ? (
        /* KONDISI 1: MEJA KERJA DETAIL INSIDEN TERFOKUS */
        <IncidentDetailWorkspace
          incident={selectedIncident}
          tier={selectedTier}
          tierMeta={currentTierMeta}
          sla={currentSla!}
          mitre={currentMitre!}
          workspaceTab={workspaceTab}
          onWorkspaceTabChange={setWorkspaceTab}
          playbookChecks={playbookChecks}
          onTogglePlaybookCheck={togglePlaybookCheck}
          noteText={noteText}
          onNoteTextChange={setNoteText}
          onAddNote={handleAddNote}
          onApplyQuickSnippet={(snippet) => {
            const localized = translate(snippet);
            setNoteText(prev => prev ? `${prev} ${localized}` : localized);
          }}
          onBack={() => setSelectedId(null)}
          onExport={() => setShowExportModal(true)}
          onDelete={handleDeleteIncident}
          onQuickPromoteTier={handleQuickPromoteTier}
          onOpenContainmentModal={(asset) => {
            setContainmentAction('BLOCK_IP');
            setContainmentTarget(asset || '');
            setShowContainModal(true);
          }}
          onUpdateStatus={handleUpdateStatus}
          onOpenAssignModal={() => {
            setSelectedAssignee(selectedIncident.assignedAnalyst || user?.email || (analysts[0]?.email ?? ''));
            setShowAssignModal(true);
          }}
          assets={assets}
          analysts={analysts}
          userEmail={user?.email}
          busy={busy}
        />
      ) : activeSection === 'GUIDE' ? (
        /* KONDISI 2: PANDUAN RUNBOOK SOP & DIREKTORI TIM SOC */
        <IncidentSopGuide analysts={analysts} />
      ) : activeSection === 'AUDIT' ? (
        /* KONDISI 3: JEJAK AUDIT TERPUSAT */
        <IncidentAuditTrail
          auditRows={filteredAuditRows}
          auditStats={auditStats}
          auditSearch={auditSearch}
          onAuditSearchChange={setAuditSearch}
          auditTier={auditTier}
          onAuditTierChange={setAuditTier}
          onExportCsv={handleExportAuditCsv}
          onSelectIncident={(id) => {
            setSelectedId(id);
            setWorkspaceTab('timeline');
          }}
        />
      ) : (
        /* KONDISI 4: DAFTAR ANTRIAN INSIDEN SESUAI WORKSPACE */
        <IncidentQueueList
          incidents={sectionIncidents}
          activeSection={activeSection}
          search={search}
          onSearchChange={setSearch}
          filterStatus={filterStatus}
          onFilterStatusChange={setFilterStatus}
          onSelectIncident={setSelectedId}
          totalSectionCount={sectionIncidents.length}
          assets={assets}
        />
      )}

      {/* MODAL 1: DEKLARASI INSIDEN BARU */}
      <DeclareIncidentModal
        isOpen={showDeclare}
        onClose={() => setShowDeclare(false)}
        draft={draft}
        onDraftChange={setDraft}
        onSubmit={handleDeclare}
        assets={assets}
        analysts={analysts}
        userEmail={user?.email}
        busy={busy}
      />

      {/* MODAL 2: ESKALASI TIER SOC */}
      <EscalateTierModal
        isOpen={showEscalateModal}
        onClose={() => setShowEscalateModal(false)}
        incident={selectedIncident}
        selectedTier={selectedTier}
        targetTier={targetEscalationTier}
        onTargetTierChange={setTargetEscalationTier}
        escalationAssignee={escalationAssignee}
        onEscalationAssigneeChange={setEscalationAssignee}
        escalationReason={escalationReason}
        onEscalationReasonChange={setEscalationReason}
        onSubmit={handleEscalateTier}
        analysts={analysts}
        userEmail={user?.email}
        busy={busy}
      />

      {/* MODAL 3: PENAHANAN PERIMETER & ISOLASI AGENT */}
      <ContainmentModal
        isOpen={showContainModal}
        onClose={() => setShowContainModal(false)}
        incident={selectedIncident}
        action={containmentAction}
        onActionChange={setContainmentAction}
        target={containmentTarget}
        onTargetChange={setContainmentTarget}
        note={containmentNote}
        onNoteChange={setContainmentNote}
        onSubmit={handleExecuteContainment}
        assets={assets}
        busy={busy}
      />

      {/* MODAL 4: PENUGASAN ANALIS REAL */}
      <AssignAnalystModal
        isOpen={showAssignModal}
        onClose={() => setShowAssignModal(false)}
        incident={selectedIncident}
        selectedAssignee={selectedAssignee}
        onAssigneeChange={setSelectedAssignee}
        onConfirm={handleAssignAnalyst}
        analysts={analysts}
        userEmail={user?.email}
        busy={busy}
      />

      {/* MODAL 5: EKSPOR FORENSIC BRIEF */}
      {showExportModal && selectedIncident && (
        <ExportIncidentModal
          isOpen={showExportModal}
          onClose={() => setShowExportModal(false)}
          incident={selectedIncident}
          tier={selectedTier}
          tierMeta={currentTierMeta}
          sla={currentSla!}
          mitre={currentMitre!}
        />
      )}
    </div>
  );
};
