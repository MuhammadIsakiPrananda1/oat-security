import React from 'react';
import { BookOpen, Eye, Crosshair, Flame, Users, CheckCircle } from 'lucide-react';
import { User } from '../../types';

interface IncidentSopGuideProps {
  analysts?: User[];
}

export const IncidentSopGuide: React.FC<IncidentSopGuideProps> = ({ analysts = [] }) => {
  return (
    <div className="space-y-4 sm:space-y-6 animate-fadeIn">
      {/* Header Panduan */}
      <div className="p-4 sm:p-6 rounded-2xl border border-indigo-500/30 bg-indigo-500/5 dark:bg-indigo-950/20 space-y-2">
        <div className="flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-indigo-500 shrink-0" />
          <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white">
            SOC Standard Operating Procedures (SOP) &amp; Operational Governance
          </h3>
        </div>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
          Standard enterprise workflow governance orchestrating incidents across Tier 1 (Triage &amp; Edge Quarantine), Tier 2 (Deep Forensics &amp; Threat Hunting), and Tier 3 (Crisis Commander &amp; Executive Resolution).
        </p>
      </div>

      {/* Matriks 3 Kolom L1 vs L2 vs L3 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 sm:gap-4">
        {/* Kartu L1 */}
        <div className="p-4 sm:p-5 rounded-2xl border border-sky-500/30 bg-white dark:bg-[#0c0c0e] shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/30 flex items-center gap-1.5">
              <Eye className="w-3.5 h-3.5" />
              <span>SOC Tier 1 (L1)</span>
            </span>
            <span className="text-xs font-mono font-bold text-sky-600 dark:text-sky-400">
              SLA: &lt; 15 Min
            </span>
          </div>

          <div>
            <h4 className="text-sm font-bold text-zinc-900 dark:text-white">Frontline Triage &amp; Correlation</h4>
            <p className="text-xs text-zinc-500 mt-0.5">First Line of Defense (Ingestion &amp; Edge Block)</p>
          </div>

          <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-1.5 pt-2 border-t border-zinc-100 dark:border-zinc-800">
            <p><strong>Primary Tasks:</strong></p>
            <ul className="list-disc list-inside space-y-1 pl-1 text-[11px]">
              <li>Ingest alerts from Agent fleet &amp; WAF engine</li>
              <li>Filter false positives vs genuine attacks</li>
              <li>Inspect attacker IP, ASN, and GeoIP reputation</li>
              <li>Execute 1-click Edge Perimeter Firewall IP drops</li>
            </ul>
            <p className="pt-2 text-[11px] text-sky-600 dark:text-sky-400 font-semibold">
              ➔ Escalate to L2 if malicious payload bypasses filters or an endpoint anomaly persists.
            </p>
          </div>
        </div>

        {/* Kartu L2 */}
        <div className="p-4 sm:p-5 rounded-2xl border border-amber-500/30 bg-white dark:bg-[#0c0c0e] shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 flex items-center gap-1.5">
              <Crosshair className="w-3.5 h-3.5" />
              <span>SOC Tier 2 (L2)</span>
            </span>
            <span className="text-xs font-mono font-bold text-amber-600 dark:text-amber-400">
              SLA: &lt; 60 Min
            </span>
          </div>

          <div>
            <h4 className="text-sm font-bold text-zinc-900 dark:text-white">Deep Forensics &amp; Threat Hunting</h4>
            <p className="text-xs text-zinc-500 mt-0.5">Advanced Investigation &amp; Containment</p>
          </div>

          <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-1.5 pt-2 border-t border-zinc-100 dark:border-zinc-800">
            <p><strong>Primary Tasks:</strong></p>
            <ul className="list-disc list-inside space-y-1 pl-1 text-[11px]">
              <li>Extract raw payloads &amp; decode attack vectors</li>
              <li>Map attacks to MITRE ATT&amp;CK tactics &amp; techniques</li>
              <li>Dispatch host network isolation to Endpoint Agents</li>
              <li>Trace lateral movement across microservices</li>
              <li>Engineer custom WAF signatures &amp; virtual patches</li>
            </ul>
            <p className="pt-2 text-[11px] text-amber-600 dark:text-amber-400 font-semibold">
              ➔ Escalate to L3 if critical database impact, data breach, or ransomware is suspected.
            </p>
          </div>
        </div>

        {/* Kartu L3 */}
        <div className="p-4 sm:p-5 rounded-2xl border border-rose-500/30 bg-white dark:bg-[#0c0c0e] shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 flex items-center gap-1.5">
              <Flame className="w-4 h-4" />
              <span>SOC Tier 3 (L3)</span>
            </span>
            <span className="text-xs font-mono font-bold text-rose-600 dark:text-rose-400">
              SLA: &lt; 120 Min
            </span>
          </div>

          <div>
            <h4 className="text-sm font-bold text-zinc-900 dark:text-white">Crisis Commander &amp; Remediation</h4>
            <p className="text-xs text-zinc-500 mt-0.5">Incident Commander &amp; Executive Lead</p>
          </div>

          <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-1.5 pt-2 border-t border-zinc-100 dark:border-zinc-800">
            <p><strong>Primary Tasks:</strong></p>
            <ul className="list-disc list-inside space-y-1 pl-1 text-[11px]">
              <li>Activate Cyber Crisis War Room with CISO &amp; Leads</li>
              <li>Isolate core banking and sensitive database subnets</li>
              <li>Verify transactional data integrity &amp; exfiltration logs</li>
              <li>Draft Root Cause Analysis (RCA) &amp; systemic patches</li>
              <li>Final Incident Commander closure sign-off</li>
            </ul>
            <p className="pt-2 text-[11px] text-rose-600 dark:text-rose-400 font-semibold">
              ➔ Highest authority. Oversees post-incident hardening and regulatory compliance.
            </p>
          </div>
        </div>
      </div>

      {/* Daftar Analis Nyata dari Database */}
      <div className="p-4 sm:p-6 rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-zinc-500" />
            <h4 className="text-sm font-bold text-zinc-900 dark:text-white">
              Real SOC Analyst Directory (Database Registered)
            </h4>
          </div>
          <span className="text-xs text-zinc-400 font-mono">{analysts.length} Registered Analysts</span>
        </div>

        {analysts.length === 0 ? (
          <div className="p-6 text-center text-xs text-zinc-400">
            No analysts registered in this organization. Users added to the system will appear here automatically.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {analysts.map(analyst => {
              const isSuper = analyst.role === 'Super Admin';
              const badgeClass = isSuper
                ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30'
                : 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/30';

              return (
                <div
                  key={analyst.id}
                  className="p-3.5 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 space-y-2 hover:border-zinc-300 dark:hover:border-zinc-700 transition"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-zinc-200 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 flex items-center justify-center font-bold text-xs font-mono">
                        {(analyst.name || analyst.email)[0].toUpperCase()}
                      </div>
                      <span className="font-bold text-xs text-zinc-900 dark:text-white truncate">
                        {analyst.name || 'Analyst'}
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${badgeClass}`}>
                      {analyst.role}
                    </span>
                  </div>
                  <div className="text-[11px] text-zinc-500 font-mono truncate">{analyst.email}</div>
                  <div className="flex items-center justify-between pt-1 border-t border-zinc-200/60 dark:border-zinc-800 text-[10px] text-zinc-400">
                    <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-semibold">
                      <CheckCircle className="w-3 h-3" />
                      Active SOC Roster
                    </span>
                    <span>Org: {analyst.organizationName || 'Enterprise'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
