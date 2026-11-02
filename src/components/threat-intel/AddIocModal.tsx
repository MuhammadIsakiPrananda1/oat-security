import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Globe,
  Tag,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Cpu,
  Lock
} from 'lucide-react';
interface AddIocModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (iocData: {
    indicator: string;
    type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'CVE';
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    status: 'Blocked' | 'Active' | 'Monitored';
    threatScore: number;
    confidence: number;
    targetSector: string;
    country: string;
    tags: string[];
    autoBlockFirewall: boolean;
  }) => Promise<void>;
}

export const AddIocModal: React.FC<AddIocModalProps> = ({
  isOpen,
  onClose,
  onSubmit
}) => {
  const [indicator, setIndicator] = useState('');
  const [type, setType] = useState<'IP' | 'Domain' | 'URL' | 'Hash' | 'CVE'>('IP');
  const [severity, setSeverity] = useState<'Critical' | 'High' | 'Medium' | 'Low'>('High');
  const [status, setStatus] = useState<'Blocked' | 'Active' | 'Monitored'>('Blocked');
  const [threatScore, setThreatScore] = useState(88);
  const [confidence, setConfidence] = useState(90);
  const [targetSector, setTargetSector] = useState('Enterprise Perimeter');
  const [country, setCountry] = useState('Global');
  const [tagsInput, setTagsInput] = useState('Analyst-Reported, Zero-Day-Hunting');
  const [autoBlockFirewall, setAutoBlockFirewall] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) {
      setError('Please provide an IOC indicator (IP, domain, URL, or hash).');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      const tags = tagsInput
        .split(',')
        .map(t => t.trim())
        .filter(Boolean);

      await onSubmit({
        indicator: indicator.trim(),
        type,
        severity,
        status,
        threatScore,
        confidence,
        targetSector,
        country,
        tags,
        autoBlockFirewall
      });

      // Reset
      setIndicator('');
      setTagsInput('Analyst-Reported, Zero-Day-Hunting');
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to submit IOC. Please check your network and credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-ioc-modal-title"
      className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 animate-fadeIn"
    >
      <div
        className="relative w-full max-w-xl max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-4 sm:p-6 text-zinc-900 dark:text-zinc-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-3.5 border-b border-zinc-200 dark:border-zinc-800 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 flex items-center justify-center shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 id="add-ioc-modal-title" className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white tracking-tight">
                Add Threat Indicator (IOC)
              </h3>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Register threat indicator to live feeds and enforce mitigation policies
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 transition cursor-pointer"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/50 text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Indicator Value & Type */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2 space-y-1">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                Indicator Target <span className="text-rose-500">*</span>
              </label>
              <input
                type="text"
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                placeholder="e.g. 185.220.101.45 or evil-payload.cc"
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600"
                required
              />
            </div>
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">Type</label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value as any)}
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
              >
                <option value="IP">IP Address</option>
                <option value="Domain">Domain / FQDN</option>
                <option value="URL">Full URL</option>
                <option value="Hash">File Hash (SHA256)</option>
                <option value="CVE">Vulnerability (CVE)</option>
              </select>
            </div>
          </div>

          {/* Severity & Status */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as any)}
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
              >
                <option value="Critical">Critical (Immediate Containment)</option>
                <option value="High">High (High Risk Threat)</option>
                <option value="Medium">Medium (Suspicious / Recon)</option>
                <option value="Low">Low (Informational)</option>
              </select>
            </div>
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">Default Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as any)}
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
              >
                <option value="Blocked">Blocked (Active Firewall/WAF Drop)</option>
                <option value="Active">Active (Flagged in Stream)</option>
                <option value="Monitored">Monitored (Passive Logging)</option>
              </select>
            </div>
          </div>

          {/* Sliders: Threat Score & Confidence */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-3.5 bg-zinc-50 dark:bg-zinc-900/40 rounded-xl border border-zinc-200/80 dark:border-zinc-800/80">
            <div>
              <div className="flex justify-between items-center text-xs mb-1.5">
                <span className="text-zinc-600 dark:text-zinc-400 font-medium flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5 text-amber-500" /> Threat Score
                </span>
                <span className="font-mono font-bold text-amber-600 dark:text-amber-400">{threatScore}/100</span>
              </div>
              <input
                type="range"
                min="10"
                max="100"
                value={threatScore}
                onChange={(e) => setThreatScore(Number(e.target.value))}
                className="w-full accent-amber-500 h-1.5 bg-zinc-200 dark:bg-zinc-800 rounded-lg appearance-none cursor-pointer"
              />
            </div>
            <div>
              <div className="flex justify-between items-center text-xs mb-1.5">
                <span className="text-zinc-600 dark:text-zinc-400 font-medium flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sky-500" /> Confidence
                </span>
                <span className="font-mono font-bold text-sky-600 dark:text-sky-400">{confidence}%</span>
              </div>
              <input
                type="range"
                min="20"
                max="100"
                value={confidence}
                onChange={(e) => setConfidence(Number(e.target.value))}
                className="w-full accent-sky-500 h-1.5 bg-zinc-200 dark:bg-zinc-800 rounded-lg appearance-none cursor-pointer"
              />
            </div>
          </div>

          {/* Sector & Country */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-zinc-400" /> Target Sector
              </label>
              <input
                type="text"
                value={targetSector}
                onChange={(e) => setTargetSector(e.target.value)}
                placeholder="e.g. Banking / FinTech"
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600"
              />
            </div>
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-zinc-400" /> Origin Country / Geo
              </label>
              <input
                type="text"
                value={country}
                onChange={(e) => setCountry(e.target.value)}
                placeholder="e.g. ID, RU, US, Global"
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600"
              />
            </div>
          </div>

          {/* Tags */}
          <div className="space-y-1">
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 flex items-center gap-1.5">
              <Tag className="w-3.5 h-3.5 text-zinc-400" /> Threat Tags (comma separated)
            </label>
            <input
              type="text"
              value={tagsInput}
              onChange={(e) => setTagsInput(e.target.value)}
              placeholder="e.g. C2-Server, Botnet, CobaltStrike, Phishing"
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600"
            />
          </div>

          {/* Auto Firewall Block Option */}
          <div className="p-3.5 rounded-xl bg-rose-50/50 dark:bg-rose-950/20 border border-rose-200/80 dark:border-rose-900/40 flex items-start gap-3">
            <input
              type="checkbox"
              id="autoBlock"
              checked={autoBlockFirewall}
              onChange={(e) => setAutoBlockFirewall(e.target.checked)}
              className="mt-0.5 rounded border-rose-300 dark:border-rose-800 text-rose-600 focus:ring-rose-500 cursor-pointer"
            />
            <label htmlFor="autoBlock" className="text-xs cursor-pointer select-none">
              <span className="font-semibold text-rose-700 dark:text-rose-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-rose-500" />
                Auto-contain via Perimeter Firewall
              </span>
              <p className="text-zinc-600 dark:text-zinc-400 text-[11px] mt-0.5 leading-relaxed">
                Immediately inject a high-priority DENY rule into the edge firewall engine and broadcast rule.updated via WebSocket to all connected proxies.
              </p>
            </label>
          </div>

          {/* Footer Actions */}
          <div className="pt-3 flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-end gap-2 border-t border-zinc-200 dark:border-zinc-800">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-medium text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 cursor-pointer transition text-center"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !indicator.trim()}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shadow-sm transition flex items-center justify-center gap-2 text-center"
            >
              {isSubmitting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Publishing IOC...</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4" />
                  <span>Publish Threat Indicator</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

