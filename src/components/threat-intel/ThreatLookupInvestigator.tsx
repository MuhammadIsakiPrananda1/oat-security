import React, { useState } from 'react';
import { Search, ShieldAlert, Ban, Copy, CheckCircle2 } from 'lucide-react';
import { CountryFlag } from '../common/CountryFlag';
import { ThreatLookupResponse } from './types';

interface ThreatLookupInvestigatorProps {
  onLookup: (query: string, type: 'ip' | 'domain' | 'url') => Promise<ThreatLookupResponse | null>;
  onBlockIp: (ip: string, reason?: string) => Promise<void>;
  loading: boolean;
  initialQuery?: string;
  initialType?: 'ip' | 'domain' | 'url';
}

export const ThreatLookupInvestigator: React.FC<ThreatLookupInvestigatorProps> = ({
  onLookup,
  onBlockIp,
  loading,
  initialQuery = '',
  initialType = 'ip'
}) => {
  const [query, setQuery] = useState(initialQuery);
  const [type, setType] = useState<'ip' | 'domain' | 'url'>(initialType);
  const [result, setResult] = useState<ThreatLookupResponse | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;
    setFeedback(null);
    const res = await onLookup(query.trim(), type);
    setResult(res);
  };

  const handleApplySample = (sample: string, sampleType: 'ip' | 'domain' | 'url') => {
    setQuery(sample);
    setType(sampleType);
    onLookup(sample, sampleType).then(setResult);
  };

  const handleCopyJson = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setFeedback('Intelligence telemetry JSON copied to clipboard.');
    setTimeout(() => setFeedback(null), 3000);
  };

  const handleBlock = async () => {
    if (!result?.indicator) return;
    await onBlockIp(result.indicator, `Direct Block via Threat Intel Lookup: ${result.data?.reputation || 'Malicious'}`);
    setFeedback(`IP ${result.indicator} successfully blocked on Perimeter Firewall!`);
  };

  return (
    <div className="space-y-4">
      {/* Workbench Header & Search Box */}
      <div className="p-4 sm:p-6 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xs space-y-4">
        <div>
          <h2 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white flex items-center gap-2">
            <Search className="w-4 h-4 text-indigo-500 shrink-0" />
            <span>Interactive Threat Indicator Lookup &amp; Enrichment</span>
          </h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Query any IP address, domain name, or URL against live global threat feeds, ASN reputation databases, and honeypot telemetry.
          </p>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSearch} className="space-y-3">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            {/* Type selector */}
            <div className="grid grid-cols-3 sm:flex items-center bg-zinc-100 dark:bg-zinc-900 p-0.5 rounded-xl border border-zinc-200 dark:border-zinc-800 text-xs shrink-0 text-center">
              {(['ip', 'domain', 'url'] as const).map(t => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setType(t)}
                  className={`px-3 py-1.5 rounded-lg font-semibold uppercase text-[11px] font-mono transition cursor-pointer ${
                    type === t
                      ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white shadow-xs'
                      : 'text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
                  }`}
                >
                  {t === 'ip' ? 'IP Address' : t === 'domain' ? 'Domain' : 'URL Path'}
                </button>
              ))}
            </div>

            {/* Indicator query input */}
            <div className="relative flex-1">
              <input
                type="text"
                required
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder={
                  type === 'ip'
                    ? 'Enter IP address, e.g. 185.220.101.5 or 45.154.255.88'
                    : type === 'domain'
                    ? 'Enter domain name, e.g. evil-c2-beacon.ru or update-auth.top'
                    : 'Enter URL path, e.g. http://victim.com/api/v1/auth?cmd=whoami'
                }
                className="w-full px-3.5 py-2.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl text-xs text-zinc-900 dark:text-white font-mono placeholder-zinc-400 focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading || !query.trim()}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold cursor-pointer shadow-sm transition disabled:opacity-60 shrink-0"
            >
              <Search className="w-3.5 h-3.5" />
              <span>{loading ? 'Querying Intel…' : 'Investigate Indicator'}</span>
            </button>
          </div>

          {/* Sample quick pills */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-[11px] font-mono text-zinc-400">Quick Samples:</span>
            <button
              type="button"
              onClick={() => handleApplySample('185.220.101.5', 'ip')}
              className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 font-mono text-[10px] hover:bg-zinc-200 cursor-pointer"
            >
              185.220.101.5 (Tor Exit)
            </button>
            <button
              type="button"
              onClick={() => handleApplySample('evil-c2-beacon.ru', 'domain')}
              className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 font-mono text-[10px] hover:bg-zinc-200 cursor-pointer"
            >
              evil-c2-beacon.ru (C2 Cobalt)
            </button>
            <button
              type="button"
              onClick={() => handleApplySample('45.154.255.88', 'ip')}
              className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 font-mono text-[10px] hover:bg-zinc-200 cursor-pointer"
            >
              45.154.255.88 (Scanner)
            </button>
            <button
              type="button"
              onClick={() => handleApplySample('192.168.1.1', 'ip')}
              className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 font-mono text-[10px] hover:bg-zinc-200 cursor-pointer"
            >
              192.168.1.1 (RFC1918)
            </button>
          </div>
        </form>

        {feedback && (
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-600 dark:text-emerald-400 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{feedback}</span>
          </div>
        )}
      </div>

      {/* Investigation Results Card */}
      {result && result.data && (
        <div className="p-4 sm:p-6 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-md space-y-4 animate-fadeIn">
          {/* Result Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-100 dark:border-zinc-800">
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400">
                  {result.type} INDICATOR
                </span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${
                  result.data.reputation === 'Critical'
                    ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30'
                    : result.data.reputation === 'Malicious'
                    ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20'
                    : result.data.reputation === 'Suspicious'
                    ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
                    : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'
                }`}>
                  {result.data.reputation} REPUTATION
                </span>
                <span className="text-[11px] font-mono text-zinc-400">
                  Confidence: <strong className="text-zinc-700 dark:text-zinc-300">{result.data.confidence}%</strong>
                </span>
              </div>

              <div className="flex items-center gap-2 pt-0.5">
                {result.data.countryCode && <CountryFlag countryCode={result.data.countryCode} />}
                <h3 className="text-base sm:text-lg font-bold font-mono text-zinc-900 dark:text-white select-all">
                  {result.indicator}
                </h3>
              </div>
            </div>

            {/* Risk Score Gauge */}
            <div className="flex items-center gap-3 self-start sm:self-auto">
              <div className="text-right">
                <span className="text-[10px] font-mono uppercase text-zinc-400 block">Risk Score</span>
                <div className={`text-2xl font-black font-mono leading-none ${
                  result.data.riskScore >= 90
                    ? 'text-rose-600 dark:text-rose-400'
                    : result.data.riskScore >= 75
                    ? 'text-amber-600'
                    : 'text-emerald-500'
                }`}>
                  {result.data.riskScore}<span className="text-xs font-normal text-zinc-400">/100</span>
                </div>
              </div>

              <div className="w-14 h-14 rounded-2xl border flex items-center justify-center p-2 shrink-0 bg-zinc-50 dark:bg-zinc-900/60 border-zinc-200 dark:border-zinc-800">
                <ShieldAlert className={`w-7 h-7 ${
                  result.data.riskScore >= 75 ? 'text-rose-500' : 'text-emerald-500'
                }`} />
              </div>
            </div>
          </div>

          {/* Telemetry Breakdown Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
            {/* ASN & Network */}
            <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 space-y-1">
              <span className="text-[10px] font-mono text-zinc-400 uppercase block">Autonomous System (ASN)</span>
              <div className="font-semibold text-zinc-900 dark:text-white">{result.data.asn || 'N/A'}</div>
              <div className="text-[11px] text-zinc-500 truncate">{result.data.isp || '—'}</div>
            </div>

            {/* Geolocation */}
            <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 space-y-1">
              <span className="text-[10px] font-mono text-zinc-400 uppercase block">Geolocation &amp; Jurisdiction</span>
              <div className="font-semibold text-zinc-900 dark:text-white flex items-center gap-1.5">
                {result.data.countryCode && <CountryFlag countryCode={result.data.countryCode} />}
                <span>{result.data.country || 'International'}</span>
              </div>
              <div className="text-[11px] text-zinc-500">Provider: {result.data.providerName}</div>
            </div>

            {/* Threat Attribution */}
            <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 space-y-1">
              <span className="text-[10px] font-mono text-zinc-400 uppercase block">Threat Actor / Campaign</span>
              <div className="font-semibold text-zinc-900 dark:text-white">
                {result.data.associatedThreatActor || 'Unclassified Threat Actor'}
              </div>
              <div className="text-[11px] text-zinc-500">
                Recommended Action: <strong className="text-zinc-700 dark:text-zinc-300 font-mono">{result.data.recommendedAction}</strong>
              </div>
            </div>
          </div>

          {/* Threat Categories & CVEs */}
          <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 space-y-2">
            <span className="text-[10px] font-mono text-zinc-400 uppercase block">Associated Threat Categories &amp; Signatures</span>
            <div className="flex flex-wrap gap-1.5">
              {result.data.threatCategories.map(cat => (
                <span
                  key={cat}
                  className="px-2 py-0.5 rounded-md bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 text-zinc-700 dark:text-zinc-300 text-xs font-mono"
                >
                  #{cat}
                </span>
              ))}
              {(result.data.associatedCves || []).map(cve => (
                <span
                  key={cve}
                  className="px-2 py-0.5 rounded-md bg-rose-500/10 border border-rose-500/20 text-rose-600 dark:text-rose-400 text-xs font-mono font-bold"
                >
                  {cve}
                </span>
              ))}
            </div>
          </div>

          {/* Action Footer */}
          <div className="flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-between gap-2.5 pt-3 border-t border-zinc-100 dark:border-zinc-800">
            <button
              type="button"
              onClick={handleCopyJson}
              className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs font-medium cursor-pointer shadow-xs hover:bg-zinc-50"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>Copy Intel JSON</span>
            </button>

            {result.data.recommendedAction === 'BLOCK' && (
              <button
                type="button"
                onClick={handleBlock}
                className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer shadow-sm transition"
              >
                <Ban className="w-4 h-4" />
                <span>Inject Emergency Firewall DENY Rule</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
