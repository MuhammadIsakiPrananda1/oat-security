import React, { useState, useEffect, useCallback } from 'react';
import { 
  Download, 
  Calendar, 
  RefreshCw, 
  Trash2, 
  ShieldCheck, 
  FileText, 
  CheckCircle2, 
  Copy, 
  Eye, 
  Radio, 
  X,
  FileCheck2
} from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFileLines } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { ReportItem } from '../../types';
import { formatDateTime } from '../../utils/dateTime';
import { getLanguage } from '../../i18n/translator';

const triggerDownload = (filename: string, content: string) => {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};

export const ReportsModule: React.FC = () => {
  const { currentOrg } = useAuth();
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null);
  const [selectedReport, setSelectedReport] = useState<ReportItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [lastStreamTime, setLastStreamTime] = useState<string | null>(null);

  // Form selections for report generation
  const [reportType, setReportType] = useState('Comprehensive Audit Report');
  const [reportPeriod, setReportPeriod] = useState('Last 30 Days');
  const [reportFormat, setReportFormat] = useState<'PDF' | 'CSV'>('PDF');
  const [showConfigModal, setShowConfigModal] = useState(false);

  // 1. Initial fetch from MySQL database
  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await securityApi.getReports();
      setReports(res?.reports || []);
    } catch (err) {
      console.error('[Reports] Error loading reports:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  // 2. Real-time WebSocket/SSE Subscription
  useEffect(() => {
    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;

      if (msg.type === 'report.created' && msg.data) {
        const newReport = msg.data as ReportItem;
        setReports(prev => [newReport, ...prev.filter(r => r.id !== newReport.id)]);
        setLastStreamTime(new Date().toLocaleTimeString());
        setFeedback({
          tone: 'ok',
          text: `Real-time: Report ${newReport.id} generated and verified in database.`
        });
      } else if (msg.type === 'report.deleted' && msg.data?.id) {
        setReports(prev => prev.filter(r => r.id !== msg.data.id));
        setLastStreamTime(new Date().toLocaleTimeString());
      } else if (msg.type === 'audit.created') {
        setLastStreamTime(new Date().toLocaleTimeString());
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  // 3. Generate report end-to-end
  const handleGenerate = async () => {
    setGenerating(true);
    setFeedback(null);
    try {
      const activeLang = getLanguage();
      const res = await securityApi.generateReport(reportType, reportPeriod, reportFormat, activeLang);
      if (res?.success && res.report) {
        const newReport = res.report;
        setReports(prev => [newReport, ...prev.filter(r => r.id !== newReport.id)]);
        triggerDownload(`${newReport.id}-${newReport.format.toLowerCase()}.txt`, newReport.content || '');
        setFeedback({
          tone: 'ok',
          text: `Report ${newReport.id} successfully generated, signed with SHA-256, and downloaded.`
        });
        setShowConfigModal(false);
      }
    } catch (err: any) {
      console.error('[Reports] Generate error:', err);
      setFeedback({ tone: 'err', text: 'Report generation failed. Please verify database connectivity.' });
    } finally {
      setGenerating(false);
    }
  };

  // 4. Delete report
  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete report ${id}? This action is permanent and recorded in the audit trail.`)) return;

    setDeletingId(id);
    try {
      const res = await securityApi.deleteReport(id);
      if (res?.success) {
        setReports(prev => prev.filter(r => r.id !== id));
        if (selectedReport?.id === id) {
          setSelectedReport(null);
        }
        setFeedback({ tone: 'ok', text: `Report ${id} deleted and audited.` });
      }
    } catch (err) {
      console.error('[Reports] Delete error:', err);
      setFeedback({ tone: 'err', text: `Failed to delete report ${id}.` });
    } finally {
      setDeletingId(null);
    }
  };

  const copyHash = (hash: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faFileLines} />}
        title="Executive & Compliance"
        titleTail="Security Reports"
        subtitle={`Audit-ready cryptographic documentation for ${currentOrg?.name || 'Organization'}, Board of Directors, regulators (OJK/BI), and external auditors.`}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowConfigModal(true)}
              disabled={generating}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 shadow-sm"
            >
              {generating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Calendar className="w-3.5 h-3.5" />}
              <span>{generating ? 'Generating…' : 'Generate Audit Report'}</span>
            </button>
          </div>
        }
      />

      {/* Real-Time Telemetry & Status Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800/80 bg-zinc-50/70 dark:bg-zinc-900/50 backdrop-blur-sm text-xs">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="font-mono font-semibold tracking-wide text-emerald-600 dark:text-emerald-400 text-[11px]">
            LIVE REPORTING STREAM ACTIVE
          </span>
          {lastStreamTime && (
            <span className="text-zinc-400 dark:text-zinc-500 font-mono text-[10px]">
              (Last sync: {lastStreamTime})
            </span>
          )}
        </div>
        <div className="flex items-center gap-4 text-[11px] font-mono text-zinc-500 dark:text-zinc-400">
          <div className="flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-zinc-400" />
            <span>Artifacts: <strong className="text-zinc-900 dark:text-zinc-100">{reports.length}</strong></span>
          </div>
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            <span>Integrity: <strong className="text-emerald-600 dark:text-emerald-400">SHA-256 Ground Truth</strong></span>
          </div>
          <div className="flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-sky-500" />
            <span>Audit Trail: <strong className="text-zinc-900 dark:text-zinc-100">Immutable</strong></span>
          </div>
        </div>
      </div>

      {feedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
            feedback.tone === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400'
          }`}
        >
          <span>{feedback.text}</span>
          <button 
            onClick={() => setFeedback(null)} 
            className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="md:col-span-2 p-12 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] text-center text-xs text-zinc-400 dark:text-zinc-500 flex flex-col items-center justify-center gap-2">
            <RefreshCw className="w-5 h-5 animate-spin text-zinc-400" />
            <span>Loading verified report records from database...</span>
          </div>
        ) : reports.length === 0 ? (
          <div className="md:col-span-2 p-8 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] text-center text-xs text-zinc-400 dark:text-slate-500 flex flex-col items-center justify-center gap-3">
            <FileCheck2 className="w-8 h-8 text-zinc-300 dark:text-zinc-600" />
            <div>
              <p className="font-semibold text-zinc-700 dark:text-zinc-300 mb-1">No Stored Report Artifacts Found</p>
              <p className="max-w-md mx-auto">
                Generate an audit report from live telemetry counters to establish an immutable, cryptographically signed compliance artifact.
              </p>
            </div>
            <button
              onClick={() => setShowConfigModal(true)}
              className="mt-2 inline-flex h-7 items-center gap-1.5 rounded-md bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 px-3 text-xs font-medium text-zinc-700 dark:text-zinc-200 transition cursor-pointer"
            >
              <Calendar className="w-3.5 h-3.5" />
              <span>Generate First Report</span>
            </button>
          </div>
        ) : (
          reports.map(rep => (
            <div 
              key={rep.id} 
              className="p-5 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-3.5 flex flex-col justify-between hover:border-zinc-300 dark:hover:border-zinc-700 transition shadow-sm hover:shadow"
            >
              <div>
                <div className="flex items-center justify-between mb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700 font-semibold uppercase">
                      {rep.category || 'Executive'}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800 font-bold">
                      {rep.format || 'PDF'}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-zinc-500 dark:text-slate-400">{rep.period}</span>
                </div>

                <h3 className="text-sm font-bold text-zinc-900 dark:text-white mb-1.5 leading-snug">
                  {rep.title}
                </h3>
                <p className="text-xs text-zinc-500 dark:text-slate-400 leading-relaxed mb-3">
                  {rep.summary}
                </p>

                {rep.sha256 && (
                  <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-50 dark:bg-zinc-900/80 border border-zinc-200/60 dark:border-zinc-800/80 text-[11px] font-mono text-zinc-600 dark:text-zinc-400">
                    <div className="flex items-center gap-1.5 truncate max-w-[260px]">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                      <span className="truncate text-[10px]">{rep.sha256}</span>
                    </div>
                    <button
                      onClick={(e) => copyHash(rep.sha256!, e)}
                      className="p-1 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 transition cursor-pointer"
                      title="Copy SHA-256 hash"
                    >
                      {copiedHash === rep.sha256 ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                )}
              </div>

              <div className="pt-3 border-t border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <span className="text-[11px] font-mono text-zinc-500 dark:text-slate-400">
                    {rep.fileSize || '14 KB'}
                  </span>
                  <span className="text-[11px] font-mono text-zinc-400 dark:text-slate-500">
                    {rep.createdAt ? formatDateTime(rep.createdAt) : 'Recently'}
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setSelectedReport(rep)}
                    className="inline-flex h-7 items-center gap-1 px-2.5 rounded-md border border-zinc-200 dark:border-zinc-800 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60 text-xs font-medium transition cursor-pointer"
                    title="View report details"
                  >
                    <Eye className="w-3 h-3" />
                    <span>View</span>
                  </button>
                  <button
                    onClick={() => triggerDownload(`${rep.id}-${rep.format.toLowerCase()}.txt`, rep.content || '')}
                    className="inline-flex h-7 items-center gap-1 px-2.5 rounded-md bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-white text-xs font-medium transition cursor-pointer"
                    title="Download report"
                  >
                    <Download className="w-3 h-3" />
                    <span>Export</span>
                  </button>
                  <button
                    onClick={(e) => handleDelete(rep.id, e)}
                    disabled={deletingId === rep.id}
                    className="inline-flex h-7 w-7 items-center justify-center rounded-md text-zinc-400 hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition cursor-pointer disabled:opacity-40"
                    title="Delete report"
                  >
                    {deletingId === rep.id ? (
                      <RefreshCw className="w-3 h-3 animate-spin text-rose-500" />
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Generate Report Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-[#111114] border border-zinc-200 dark:border-zinc-800 rounded-2xl w-full max-w-lg p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-zinc-100 dark:border-zinc-800 pb-4">
              <div className="flex items-center gap-2">
                <FontAwesomeIcon icon={faFileLines} className="text-zinc-700 dark:text-zinc-300" />
                <h3 className="font-semibold text-zinc-900 dark:text-white text-sm">
                  Generate Compliance & Audit Report
                </h3>
              </div>
              <button
                onClick={() => setShowConfigModal(false)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1.5">
                  Report Template & Scope
                </label>
                <select
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                  className="w-full h-9 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-1 focus:ring-zinc-400 font-medium"
                >
                  <option value="Comprehensive Audit Report">Comprehensive Audit Report (Full Platform Telemetry)</option>
                  <option value="Executive Security Summary">Executive Security Summary (C-Suite & Board Level)</option>
                  <option value="OJK / BI Regulatory Attestation">OJK / BI Regulatory Attestation (Perimeter & Edge WAF)</option>
                  <option value="ISO 27001 & SOC 2 Continuous Evidence">ISO 27001 & SOC 2 Continuous Evidence (Immutable Logs)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1.5">
                    Coverage Period
                  </label>
                  <select
                    value={reportPeriod}
                    onChange={(e) => setReportPeriod(e.target.value)}
                    className="w-full h-9 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-1 focus:ring-zinc-400"
                  >
                    <option value="Last 24 Hours">Last 24 Hours</option>
                    <option value="Last 7 Days">Last 7 Days</option>
                    <option value="Last 30 Days">Last 30 Days</option>
                    <option value="Quarter to Date">Quarter to Date</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-700 dark:text-zinc-300 font-medium mb-1.5">
                    Export Format
                  </label>
                  <select
                    value={reportFormat}
                    onChange={(e) => setReportFormat(e.target.value as 'PDF' | 'CSV')}
                    className="w-full h-9 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-1 focus:ring-zinc-400"
                  >
                    <option value="PDF">PDF (Structured Document)</option>
                    <option value="CSV">CSV (Data Export)</option>
                  </select>
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200/80 dark:border-zinc-800/80 space-y-1.5">
                <div className="flex items-center gap-1.5 text-zinc-800 dark:text-zinc-200 font-semibold text-[11px]">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Immutable Ground-Truth Verification</span>
                </div>
                <p className="text-zinc-500 dark:text-zinc-400 text-[11px] leading-relaxed">
                  Upon creation, live telemetry counts will be drawn from MySQL and hashed with SHA-256. An immutable audit record will be logged and broadcasted to all connected operators in real time.
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-zinc-100 dark:border-zinc-800">
              <button
                onClick={() => setShowConfigModal(false)}
                className="h-8 px-3.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="inline-flex h-8 items-center gap-1.5 px-4 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-white dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 text-xs font-medium transition cursor-pointer disabled:opacity-50"
              >
                {generating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Calendar className="w-3.5 h-3.5" />}
                <span>{generating ? 'Compiling & Signing…' : 'Generate & Download'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Artifact Modal */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-[#111114] border border-zinc-200 dark:border-zinc-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between p-4 border-b border-zinc-100 dark:border-zinc-800">
              <div>
                <h3 className="font-bold text-zinc-900 dark:text-white text-sm">
                  {selectedReport.title}
                </h3>
                <span className="text-xs font-mono text-zinc-400 dark:text-zinc-500">
                  ID: {selectedReport.id} • {selectedReport.period}
                </span>
              </div>
              <button
                onClick={() => setSelectedReport(null)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto font-mono text-xs text-zinc-700 dark:text-zinc-300 space-y-4">
              <div className="p-3 bg-zinc-50 dark:bg-zinc-900/80 rounded-lg border border-zinc-200/80 dark:border-zinc-800/80 space-y-1">
                <div className="text-[10px] text-zinc-400 uppercase tracking-wider font-semibold">SHA-256 Fingerprint</div>
                <div className="text-emerald-600 dark:text-emerald-400 break-all select-all font-semibold">
                  {selectedReport.sha256 || 'Calculated at generation'}
                </div>
              </div>

              <div>
                <div className="text-[10px] text-zinc-400 uppercase tracking-wider font-semibold mb-2">Artifact Ground Truth Body</div>
                <pre className="p-4 rounded-xl bg-zinc-950 text-emerald-400/90 text-[11px] leading-relaxed overflow-x-auto whitespace-pre font-mono border border-zinc-800">
                  {selectedReport.content || selectedReport.summary}
                </pre>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 border-t border-zinc-100 dark:border-zinc-800">
              <span className="text-xs font-mono text-zinc-400 dark:text-zinc-500">
                Generated: {selectedReport.createdAt ? formatDateTime(selectedReport.createdAt) : 'Live'}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => triggerDownload(`${selectedReport.id}-${selectedReport.format.toLowerCase()}.txt`, selectedReport.content || '')}
                  className="inline-flex h-8 items-center gap-1.5 px-3.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-white dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100 text-xs font-medium transition cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download File</span>
                </button>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="h-8 px-3.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
