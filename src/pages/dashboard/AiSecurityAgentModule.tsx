import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  Sparkles, 
  Send, 
  Bot, 
  CheckCircle2, 
  ShieldAlert, 
  ShieldCheck, 
  Server, 
  AlertTriangle, 
  Terminal, 
  Lock, 
  RefreshCw, 
  Layers, 
  Radio,
  FileCode,
  Flame,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { formatTimeShort } from '../../utils/dateTime';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faWandMagicSparkles } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';

interface PlaybookStep {
  stage: string;
  title: string;
  detail: string;
}

interface MitigationRule {
  type: 'WAF' | 'FIREWALL';
  name: string;
  category: string;
  action: 'BLOCK' | 'LOG' | 'CHALLENGE';
  pattern?: string;
  ip?: string;
  syntax: string;
  description: string;
}

interface Recommendation {
  title: string;
  action: string;
  deployable: boolean;
  rule?: MitigationRule;
}

interface Message {
  id: string;
  sender: 'user' | 'agent';
  timestamp: string;
  engineMode?: string;
  content: string;
  analysis?: {
    threatScore: number;
    owaspCategory: string;
    confidence: number;
    mitreTechnique?: string;
    threatActorProfile?: string;
    severityExplanation?: string;
  };
  playbookSteps?: PlaybookStep[];
  recommendations?: Recommendation[];
}

const CLIENT_PROMPT_INJECTION_RE = /(ignore\s+(all\s+)?(previous|prior|above|system)|you\s+are\s+now|act\s+as\s+.*unrestricted|jailbreak|dan\s+mode|<script|drop\s+table|delete\s+from|union\s+select)/i;

const OFFICIAL_SCENARIOS = [
  {
    category: 'incidents',
    label: 'Insiden & Ancaman',
    prompts: [
      {
        title: 'Triase Insiden Aktif L1–L3 & Playbook',
        prompt: 'Triage active incidents in the SOC queue. Break down L1 validation, L2 correlation, and L3 containment playbooks.'
      },
      {
        title: 'Analisis Klaster Serangan Aplikasi',
        prompt: 'Analyze attack clusters on protected applications, identify top targeted endpoints and high-volume adversaries.'
      },
      {
        title: 'Investigasi Lonjakan Serangan Kredensial',
        prompt: 'Explain the spike in credential stuffing from rotating ASNs and propose strict authentication WAF limits.'
      },
      {
        title: 'Investigasi IP Penyerang Teratas',
        prompt: 'Investigate the top malicious attacker IP sources identified in the 24-hour perimeter log telemetry.'
      }
    ]
  },
  {
    category: 'waf',
    label: 'WAF & Firewall Edge',
    prompts: [
      {
        title: 'Audit Kebijakan & Aturan WAF Edge',
        prompt: 'Audit current active WAF policies and rule effectiveness against emerging web exploit techniques.'
      },
      {
        title: 'Sintesis Aturan Virtual Patching (SQLi/XSS)',
        prompt: 'Synthesize tightened WAF virtual patch rules for injection payloads targeting API routes.'
      },
      {
        title: 'Pengetatan Rate Limiting Endpoint Login',
        prompt: 'Create tightened WAF rate limiting and bot challenge policies for payment and checkout endpoints.'
      },
      {
        title: 'Blokir Darurat IP Penyerang Teratas',
        prompt: 'Generate an emergency Firewall DENY rule for the top persistent attacker IP recorded in security events.'
      }
    ]
  },
  {
    category: 'malware',
    label: 'Malware & Sensor Host',
    prompts: [
      {
        title: 'Audit Sampel Karantina di Vault',
        prompt: 'Audit quarantined malware samples in the security vault and assess risk of webroot payload persistence.'
      },
      {
        title: 'Diagnostik Kesehatan Sensor Agen Host',
        prompt: 'Perform health check diagnostics on enrolled endpoint agents, heartbeat intervals, and rule synchronization.'
      }
    ]
  },
  {
    category: 'posture',
    label: 'Postur & Laporan',
    prompts: [
      {
        title: 'Ringkasan Postur Keamanan 24 Jam',
        prompt: 'Summarize the perimeter threat posture over the last 24 hours, including inspected requests and blocked intrusions.'
      },
      {
        title: 'Evaluasi Kesiapan OWASP Top 10',
        prompt: 'Evaluate enterprise perimeter defense alignment against OWASP Top 10 attack vectors based on current telemetry.'
      }
    ]
  }
];

export const AiSecurityAgentModule: React.FC = () => {
  const { currentOrg, isBackendOffline } = useAuth();
  const [telemetry, setTelemetry] = useState<any | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [activeCategory, setActiveCategory] = useState<string>('all');

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'agent',
      timestamp: formatTimeShort(new Date()),
      engineMode: 'OAT Autonomous SOC Copilot',
      content: `OAT Autonomous SOC Operations Copilot online for ${currentOrg?.name ?? 'your organization'}.

The copilot is directly grounded in live perimeter telemetry: inspecting edge ingress, cross-referencing active incident queues (L1–L3), monitoring endpoint agent sensors, and synthesizing real-time WAF and Firewall policies.

Select an active incident to investigate, click a quick triage scenario below, or ask any threat analysis question.`
    }
  ]);

  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [deployingRule, setDeployingRule] = useState<string | null>(null);
  const [deployedRules, setDeployedRules] = useState<Record<string, { ruleId: string; type: string }>>({});
  const [deployNotification, setDeployNotification] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null);

  const isInitialMount = useRef(true);
  const chatScrollRef = useRef<HTMLDivElement | null>(null);
  const scenarioScrollRef = useRef<HTMLDivElement | null>(null);

  const scrollScenarios = (direction: 'left' | 'right') => {
    if (scenarioScrollRef.current) {
      const scrollAmount = 320;
      scenarioScrollRef.current.scrollBy({
        left: direction === 'left' ? -scrollAmount : scrollAmount,
        behavior: 'smooth'
      });
    }
  };

  const scrollToBottom = useCallback((smooth = true) => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTo({
        top: chatScrollRef.current.scrollHeight,
        behavior: smooth ? 'smooth' : 'auto'
      });
    }
  }, []);

  // Ensure window stays at the top when entering the page (just like opening any other dashboard page)
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  }, []);

  // Only scroll inner chat container during active conversation, never on initial page load
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false;
      return;
    }
    scrollToBottom(true);
  }, [messages, loading, scrollToBottom]);

  // Load telemetry data from real database
  const loadTelemetry = useCallback(async () => {
    try {
      setTelemetryLoading(true);
      const res = await securityApi.getAiCopilotContext();
      if (res && res.telemetry) {
        setTelemetry(res.telemetry);
      }
    } catch (err) {
      console.warn('[SOC Copilot] Could not load telemetry:', err);
    } finally {
      setTelemetryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadTelemetry();
  }, [loadTelemetry]);

  // Real-time WebSocket listener for live event stream
  useEffect(() => {
    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      const type = msg?.type || '';
      if (type === 'ai.telemetry') {
        const snapshot = msg?.data?.telemetry || msg?.data;
        if (snapshot) setTelemetry(snapshot);
        return;
      }
      if (
        type === 'incident.created' ||
        type === 'incident.updated' ||
        type === 'threat.created' ||
        type === 'malware.detected' ||
        type === 'rule.updated' ||
        type === 'agent.heartbeat'
      ) {
        void loadTelemetry();
      }
    });

    return () => {
      unsubscribe();
    };
  }, [loadTelemetry]);

  const handleSendMessage = async (textToSend?: string, incidentOverrideId?: string) => {
    const rawQuery = textToSend || input || '';
    const query = rawQuery.trim();
    if (!query || loading) return;

    const userMsg: Message = {
      id: 'u-' + Date.now(),
      sender: 'user',
      timestamp: formatTimeShort(new Date()),
      content: query
    };

    setMessages(prev => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setLoading(true);

    const targetIncident = incidentOverrideId || selectedIncidentId || undefined;

    try {
      const res = await securityApi.querySocCopilot({
        query,
        incidentId: targetIncident
      });

      const analysisData = res.analysis;
      const agentMsg: Message = {
        id: 'a-' + Date.now(),
        sender: 'agent',
        timestamp: formatTimeShort(new Date()),
        engineMode: res.mode || 'OAT SOC Intelligence Engine',
        content: analysisData.summary || 'Analysis complete. The perimeter defense engine has evaluated the event telemetry.',
        analysis: {
          threatScore: analysisData.threatScore || 75,
          owaspCategory: analysisData.owaspCategory || 'OWASP Top 10 Security',
          confidence: analysisData.confidence || 90,
          mitreTechnique: analysisData.mitreTechnique,
          threatActorProfile: analysisData.threatActorProfile,
          severityExplanation: analysisData.severityExplanation
        },
        playbookSteps: analysisData.playbookSteps || [],
        recommendations: analysisData.recommendations || []
      };

      setMessages(prev => [...prev, agentMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        id: 'err-' + Date.now(),
        sender: 'agent',
        timestamp: formatTimeShort(new Date()),
        engineMode: 'Error',
        content: `Error communicating with SOC Intelligence Engine: ${err?.message || 'Server error'}. Please verify backend status.`
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const handleDeployMitigation = async (recKey: string, rule: MitigationRule) => {
    try {
      setDeployingRule(recKey);
      const res = await securityApi.deployCopilotMitigation({
        type: rule.type,
        name: rule.name,
        category: rule.category,
        action: rule.action,
        pattern: rule.pattern,
        ip: rule.ip,
        description: rule.description
      });

      setDeployedRules(prev => ({
        ...prev,
        [recKey]: { ruleId: res.ruleId, type: res.type }
      }));

      setDeployNotification({
        kind: 'ok',
        text: res.message || `${rule.type} Rule successfully provisioned to edge.`
      });

      setTimeout(() => {
        setDeployNotification(null);
      }, 7000);

      void loadTelemetry();
    } catch (err: any) {
      setDeployNotification({
        kind: 'error',
        text: `Failed to deploy rule: ${err?.message || 'Check server logs.'}`
      });
      setTimeout(() => {
        setDeployNotification(null);
      }, 7000);
    } finally {
      setDeployingRule(null);
    }
  };

  const handleIncidentSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const incId = e.target.value;
    setSelectedIncidentId(incId);
    if (incId) {
      const inc = telemetry?.activeIncidents?.find((i: any) => i.id === incId);
      const prompt = inc 
        ? `Investigate active incident [${inc.id}] "${inc.title}" on asset ${inc.affectedAsset} (${inc.severity} / ${inc.tier}). Provide immediate triage and containment steps.`
        : `Triage Incident ${incId} with playbook steps and WAF rule mitigation.`;
      void handleSendMessage(prompt, incId);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => window.location.reload()} />;
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faWandMagicSparkles} />}
        title="AI Security Operations"
        titleTail="(SOC) Copilot"
        subtitle="Autonomous heuristic correlation, MITRE ATT&CK mapping, L1–L3 incident triage, and automated edge WAF / firewall policy synthesis."
      />

      {/* Deploy Notification Banner */}
      {deployNotification && (
        <div className={`p-3.5 rounded-xl text-xs flex items-center justify-between gap-3 shadow-md border ${
          deployNotification.kind === 'ok'
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
            : 'bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300'
        }`}>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
            <span className="font-medium font-mono">{deployNotification.text}</span>
          </div>
          <button 
            onClick={() => setDeployNotification(null)}
            className="text-[10px] uppercase font-mono tracking-wider opacity-70 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Live SOC Telemetry Strip (Grounded Real DB Data) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {/* Metric 1: Active Incidents */}
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs">
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Active Incidents</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-zinc-900 dark:text-white">
              {telemetry ? telemetry.activeIncidentsCount : '—'}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono">in triage</span>
          </div>
        </div>

        {/* Metric 2: Mitigated Threats (24h) */}
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs">
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>24h Mitigated</span>
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-emerald-600 dark:text-emerald-400">
              {telemetry ? telemetry.threatsBlocked24h.toLocaleString() : '—'}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono">blocked</span>
          </div>
        </div>

        {/* Metric 3: Online Endpoint Agents */}
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs">
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Endpoint Sensors</span>
            <Server className="w-4 h-4 text-blue-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-zinc-900 dark:text-white">
              {telemetry ? `${telemetry.onlineAgents}/${telemetry.totalAgents}` : '—'}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono">active</span>
          </div>
        </div>

        {/* Metric 4: Quarantined Malware */}
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs">
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Malware Vault</span>
            <Lock className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-amber-600 dark:text-amber-400">
              {telemetry ? telemetry.malwareQuarantined : '—'}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono">isolated</span>
          </div>
        </div>

        {/* Metric 5: Edge WAF Rules */}
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>WAF Perimeter</span>
            <Layers className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-zinc-900 dark:text-white">
              {telemetry ? telemetry.activeWafRules : '—'}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono uppercase">
              {telemetry?.wafMode || 'BLOCK'}
            </span>
          </div>
        </div>
      </div>

      {/* Incident Quick-Select & Triage Bar */}
      <div className="p-3 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] flex flex-wrap items-center justify-between gap-3 shadow-2xs">
        <div className="flex items-center gap-2 text-xs flex-1 min-w-0">
          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
          <span className="font-semibold text-zinc-700 dark:text-zinc-300 font-mono text-[11px] uppercase tracking-wider shrink-0">
            Triase Insiden Aktif:
          </span>
          <select
            value={selectedIncidentId}
            onChange={handleIncidentSelect}
            className="flex-1 min-w-[200px] max-w-xl bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs text-zinc-900 dark:text-white font-mono focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-600 truncate cursor-pointer"
          >
            <option value="">-- Pilih insiden aktif dari database --</option>
            {telemetry?.activeIncidents?.map((inc: any) => (
              <option key={inc.id} value={inc.id}>
                [{inc.id}] {inc.severity} ({inc.tier}): {inc.title} — {inc.affectedAsset}
              </option>
            ))}
          </select>
          {telemetry?.activeIncidentsCount > 0 && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 font-semibold shrink-0">
              {telemetry.activeIncidentsCount} Antrean
            </span>
          )}
        </div>
      </div>

      {/* Chat Container */}
      <div className="w-full rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] flex flex-col h-[580px] min-h-[360px] overflow-hidden shadow-sm">
        {/* Chat History */}
        <div ref={chatScrollRef} className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-5 custom-scrollbar">
          {messages.map(msg => (
            <div
              key={msg.id}
              className={`flex gap-3.5 text-xs ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.sender === 'agent' && (
                <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 shadow-xs">
                  <Bot className="w-4 h-4 text-indigo-500 dark:text-indigo-400" />
                </div>
              )}

              <div className={`max-w-[88%] sm:max-w-3xl min-w-0 rounded-2xl p-4 sm:p-5 ${
                msg.sender === 'user' 
                  ? 'bg-zinc-900 text-white dark:bg-zinc-800 dark:text-zinc-100 shadow-md ml-auto' 
                  : 'bg-zinc-50/80 dark:bg-[#0f1015] border border-zinc-200/80 dark:border-zinc-800 text-zinc-900 dark:text-zinc-100 shadow-xs'
              }`}>
                {/* Meta Header */}
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3 pb-2 border-b border-zinc-200/70 dark:border-zinc-800/80 text-[10px] font-mono text-zinc-400 dark:text-zinc-500">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-zinc-700 dark:text-zinc-300">
                      {msg.sender === 'user' ? 'Security Analyst' : 'OAT AI SOC Copilot'}
                    </span>
                    {msg.engineMode && (
                      <span className="px-1.5 py-0.5 rounded bg-zinc-200/70 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 text-[9px]">
                        {msg.engineMode}
                      </span>
                    )}
                  </div>
                  <span>{msg.timestamp}</span>
                </div>

                {/* Message Body */}
                <div className="leading-relaxed whitespace-pre-line text-xs font-sans space-y-2">
                  {msg.content}
                </div>

                {/* Agent Analysis Scorecard */}
                {msg.analysis && (
                  <div className="mt-4 pt-3.5 border-t border-zinc-200/80 dark:border-zinc-800/80 space-y-3">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
                      {/* Threat Score */}
                      <div className="p-2.5 rounded-xl bg-white dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800">
                        <span className="text-zinc-400 dark:text-zinc-500 block text-[9px] uppercase">Threat Score</span>
                        <span className={`font-bold text-sm ${
                          msg.analysis.threatScore >= 80 ? 'text-rose-600 dark:text-rose-400' :
                          msg.analysis.threatScore >= 50 ? 'text-amber-600 dark:text-amber-400' :
                          'text-emerald-600 dark:text-emerald-400'
                        }`}>
                          {msg.analysis.threatScore} / 100
                        </span>
                      </div>

                      {/* OWASP Category */}
                      <div className="p-2.5 rounded-xl bg-white dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800">
                        <span className="text-zinc-400 dark:text-zinc-500 block text-[9px] uppercase">OWASP Vector</span>
                        <span className="text-zinc-800 dark:text-zinc-200 font-bold truncate block">
                          {msg.analysis.owaspCategory}
                        </span>
                      </div>

                      {/* Confidence */}
                      <div className="p-2.5 rounded-xl bg-white dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800">
                        <span className="text-zinc-400 dark:text-zinc-500 block text-[9px] uppercase">SOC Confidence</span>
                        <span className="text-emerald-600 dark:text-emerald-400 font-bold text-sm">
                          {msg.analysis.confidence}%
                        </span>
                      </div>

                      {/* MITRE Technique */}
                      <div className="p-2.5 rounded-xl bg-white dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800">
                        <span className="text-zinc-400 dark:text-zinc-500 block text-[9px] uppercase">MITRE ATT&CK</span>
                        <span className="text-indigo-600 dark:text-indigo-400 font-bold truncate block">
                          {msg.analysis.mitreTechnique || 'T1190 Exploit'}
                        </span>
                      </div>
                    </div>

                    {msg.analysis.threatActorProfile && (
                      <div className="px-3 py-2 rounded-xl bg-zinc-100/80 dark:bg-zinc-900/40 border border-zinc-200/80 dark:border-zinc-800 text-[11px] text-zinc-600 dark:text-zinc-400 flex items-center gap-2">
                        <Flame className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                        <span><strong>Attribution:</strong> {msg.analysis.threatActorProfile}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* SOC Playbook Steps (L1 - L3) */}
                {msg.playbookSteps && msg.playbookSteps.length > 0 && (
                  <div className="mt-4 pt-3.5 border-t border-zinc-200/80 dark:border-zinc-800/80 space-y-2">
                    <span className="text-[10px] font-mono text-zinc-500 dark:text-zinc-400 uppercase tracking-wider block">
                      SOC Incident Response Playbook:
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      {msg.playbookSteps.map((step, sIdx) => (
                        <div key={sIdx} className="p-3 rounded-xl bg-white dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800 space-y-1">
                          <div className="flex items-center gap-1.5 text-[10px] font-mono text-indigo-500 dark:text-indigo-400 font-bold">
                            <Terminal className="w-3 h-3" />
                            <span>{step.stage}</span>
                          </div>
                          <div className="font-semibold text-xs text-zinc-800 dark:text-zinc-200">
                            {step.title}
                          </div>
                          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
                            {step.detail}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations & Actionable Deployments */}
                {msg.recommendations && msg.recommendations.length > 0 && (
                  <div className="mt-4 pt-3.5 border-t border-zinc-200/80 dark:border-zinc-800/80 space-y-2.5">
                    <span className="text-[10px] font-mono text-zinc-500 dark:text-zinc-400 uppercase tracking-wider block">
                      Recommended Mitigation & Edge Actions:
                    </span>
                    <div className="space-y-2">
                      {msg.recommendations.map((rec, rIdx) => {
                        const recKey = `${msg.id}-${rIdx}`;
                        const deployed = deployedRules[recKey];
                        const isDeploying = deployingRule === recKey;

                        return (
                          <div key={rIdx} className="p-3.5 rounded-xl bg-white dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800 flex flex-col gap-2 shadow-2xs">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-zinc-800 dark:text-zinc-200 text-xs">
                                  {rec.title}
                                </span>
                                {rec.rule?.type && (
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                                    rec.rule.type === 'FIREWALL'
                                      ? 'bg-rose-500/10 text-rose-600 border border-rose-500/20'
                                      : 'bg-indigo-500/10 text-indigo-600 border border-indigo-500/20'
                                  }`}>
                                    {rec.rule.type}
                                  </span>
                                )}
                              </div>

                              {rec.deployable && rec.rule && (
                                <div>
                                  {deployed ? (
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-[10px] font-mono font-semibold border border-emerald-500/20">
                                      <CheckCircle2 className="w-3.5 h-3.5" />
                                      <span>Committed ({deployed.ruleId})</span>
                                    </span>
                                  ) : (
                                    <button
                                      disabled={isDeploying}
                                      onClick={() => handleDeployMitigation(recKey, rec.rule!)}
                                      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-zinc-900 text-white hover:bg-zinc-800 dark:bg-white dark:text-black dark:hover:bg-zinc-200 text-[11px] font-mono font-semibold transition shadow-xs cursor-pointer disabled:opacity-50"
                                    >
                                      {isDeploying ? (
                                        <>
                                          <RefreshCw className="w-3 h-3 animate-spin" />
                                          <span>Deploying...</span>
                                        </>
                                      ) : (
                                        <>
                                          <Radio className="w-3 h-3 text-indigo-400" />
                                          <span>Deploy to {rec.rule.type === 'FIREWALL' ? 'Firewall' : 'Edge WAF'}</span>
                                        </>
                                      )}
                                    </button>
                                  )}
                                </div>
                              )}
                            </div>

                            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-normal">
                              {rec.action}
                            </p>

                            {rec.rule?.syntax && (
                              <div className="mt-1">
                                <div className="text-[9px] font-mono text-zinc-400 mb-1 flex items-center gap-1">
                                  <FileCode className="w-3 h-3" />
                                  <span>Generated Rule Definition:</span>
                                </div>
                                <pre className="p-2.5 rounded-lg bg-zinc-100 dark:bg-black/80 border border-zinc-200 dark:border-zinc-800/80 font-mono text-[10px] text-zinc-800 dark:text-zinc-200 overflow-x-auto leading-relaxed">
                                  {rec.rule.syntax}
                                </pre>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 text-xs justify-start items-center text-zinc-500 dark:text-zinc-400 font-mono pl-2">
              <div className="w-8 h-8 rounded-xl bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center shrink-0">
                <Sparkles className="w-4 h-4 text-indigo-500 animate-spin" />
              </div>
              <span className="animate-pulse">
                SOC Copilot analyzing live database telemetry, evaluating MITRE vectors, & synthesizing mitigation...
              </span>
            </div>
          )}
        </div>

        {/* Chat Input Bar with Quick Swipeable/Scrollable Scenarios & Prompt Injection Guardrail */}
        <div className="p-3 sm:p-3.5 border-t border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/70 dark:bg-zinc-900/40 space-y-2.5">
          {/* Quick Scenario Horizontal Swipeable Toolbar */}
          <div className="space-y-1.5">
            {/* Top row: Category filter tabs + Guardrail badge */}
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 overflow-x-auto" style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}>
                <span className="text-[10px] font-mono uppercase tracking-wider font-semibold text-zinc-500 dark:text-zinc-400 shrink-0 flex items-center gap-1 mr-1">
                  <Terminal className="w-3 h-3 text-indigo-500" />
                  Skenario:
                </span>
                {[
                  { id: 'all', label: 'Semua' },
                  { id: 'incidents', label: 'Insiden' },
                  { id: 'waf', label: 'WAF Edge' },
                  { id: 'malware', label: 'Malware' },
                  { id: 'posture', label: 'Postur' }
                ].map(cat => (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => setActiveCategory(cat.id)}
                    className={`px-2 py-0.5 rounded-md text-[10px] font-mono transition cursor-pointer shrink-0 ${
                      activeCategory === cat.id
                        ? 'bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-950 font-semibold shadow-xs'
                        : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white bg-transparent'
                    }`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>

              <span className="inline-flex items-center gap-1 text-[9px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 shrink-0">
                <ShieldCheck className="w-2.5 h-2.5" />
                OWASP LLM01 Active
              </span>
            </div>

            {/* Bottom row: Horizontally scrollable text scenario chips */}
            <div className="relative flex items-center gap-1">
              <button
                type="button"
                onClick={() => scrollScenarios('left')}
                className="shrink-0 p-1 rounded-md text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 hover:bg-zinc-200/60 dark:hover:bg-zinc-800 transition cursor-pointer"
                title="Geser ke kiri"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>

              <div
                ref={scenarioScrollRef}
                className="flex-1 flex items-center gap-1.5 overflow-x-auto py-1 scroll-smooth"
                style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
              >
                {OFFICIAL_SCENARIOS
                  .filter(cat => activeCategory === 'all' || cat.category === activeCategory)
                  .flatMap(cat => cat.prompts)
                  .map((item, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => handleSendMessage(item.prompt)}
                      className="shrink-0 px-2.5 py-1 rounded-lg bg-white dark:bg-zinc-900 hover:bg-zinc-100 dark:hover:bg-zinc-800 border border-zinc-200/80 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700 text-[11px] text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-white transition shadow-2xs cursor-pointer whitespace-nowrap active:scale-[0.98]"
                    >
                      {item.title}
                    </button>
                  ))}
              </div>

              <button
                type="button"
                onClick={() => scrollScenarios('right')}
                className="shrink-0 p-1 rounded-md text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 hover:bg-zinc-200/60 dark:hover:bg-zinc-800 transition cursor-pointer"
                title="Geser ke kanan"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {CLIENT_PROMPT_INJECTION_RE.test(input) && (
            <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2 font-mono">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-500" />
              <span>
                <strong>Zero-Trust Guardrail Alert:</strong> Input teridentifikasi mengandung pola prompt injection / manipulasi instruksi AI. Silakan gunakan skenario operasional resmi pada dropdown skenario di atas.
              </span>
            </div>
          )}

          <form
            onSubmit={e => {
              e.preventDefault();
              if (!CLIENT_PROMPT_INJECTION_RE.test(input)) {
                void handleSendMessage();
              }
            }}
            className="flex items-center gap-2.5"
          >
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Ask SOC Copilot to investigate an incident, block an attacker IP, or synthesize an ingress WAF rule..."
              className={`flex-1 min-w-0 bg-white dark:bg-zinc-900 border rounded-xl px-4 py-2.5 text-xs text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none font-sans shadow-2xs ${
                CLIENT_PROMPT_INJECTION_RE.test(input)
                  ? 'border-rose-500 dark:border-rose-500'
                  : 'border-zinc-200 dark:border-zinc-700/80 focus:border-zinc-400 dark:focus:border-zinc-500'
              }`}
            />
            <button
              type="submit"
              disabled={loading || !(input || '').trim() || CLIENT_PROMPT_INJECTION_RE.test(input)}
              className="px-4 py-2.5 rounded-xl bg-zinc-900 text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-white dark:text-black dark:hover:bg-zinc-200 text-xs font-semibold flex items-center gap-2 transition shadow-sm cursor-pointer shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Analyze</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
