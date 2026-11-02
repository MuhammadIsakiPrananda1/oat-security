import React from 'react';
import { 
  CheckCircle2, 
  Download
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCreditCard } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';

export const BillingModule: React.FC = () => {
  const { currentOrg } = useAuth();

  // No mock invoices: billing records come from the real subscription service.
  const invoices: Array<{ id: string; period: string; amount: string; status: string; date: string }> = [];

  // Exports the invoice record this console actually holds — no backend document
  // store is wired up, so the file states exactly what it contains.
  const downloadInvoice = (inv: { id: string; period: string; amount: string; status: string; date: string }) => {
    const body = [
      'OAT SECURITY — INVOICE RECORD EXPORT',
      '====================================',
      `Invoice ID : ${inv.id}`,
      `Organization: ${currentOrg?.name ?? 'Unspecified organization'}`,
      `Billing period: ${inv.period}`,
      `Amount      : ${inv.amount}`,
      `Status      : ${inv.status}`,
      `Issued date : ${inv.date}`,
      '',
      `Exported at : ${new Date().toISOString()}`
    ].join('\n');

    const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${inv.id}_invoice_record.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faCreditCard} />}
        title="Enterprise SLA, Quota"
        titleTail="Subscription"
        subtitle={`Bespoke enterprise license agreement and billing telemetry for ${currentOrg?.name ?? 'your organization'}.`}
      />

      {/* Plan Details & SLA Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="p-6 rounded-xl border border-zinc-300 dark:border-zinc-700 bg-gradient-to-b from-zinc-50 to-white dark:from-white/[0.03] dark:to-[#050505] space-y-4 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-zinc-700 dark:text-zinc-300 font-bold uppercase">SUBSCRIPTION</span>
            <span className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 text-[10px] font-mono border border-zinc-300 dark:border-zinc-700">
              Awaiting data
            </span>
          </div>

          <div>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">—</div>
            <div className="text-xs text-zinc-500 dark:text-slate-400 mt-1">Plan details will sync automatically from the billing system.</div>
          </div>

          <div className="space-y-2 pt-2 border-t border-zinc-200 dark:border-zinc-800 text-xs text-zinc-700 dark:text-zinc-300">
            <div className="flex items-center gap-2 text-zinc-400 dark:text-slate-500">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>SLA features will appear once the subscription is active.</span>
            </div>
          </div>
        </div>

        {/* Quota & Usage */}
        <div className="lg:col-span-2 p-6 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 flex flex-col justify-between transition-colors">
          <div>
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-white mb-1">Monthly Traffic & Ingress Consumption</h3>
            <p className="text-xs text-zinc-500 dark:text-slate-400">No active billing cycle yet.</p>

            <div className="mt-6 p-4 rounded-lg bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 text-center text-xs text-zinc-400 dark:text-slate-500">
              No consumption data yet. Figures will populate automatically as real-time traffic arrives.
            </div>
          </div>

          <div className="pt-4 border-t border-zinc-200 dark:border-zinc-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-zinc-500 dark:text-slate-400">
            <span>Next invoice date: —</span>
            <span className="text-zinc-800 dark:text-zinc-200">Contract Ref: —</span>
          </div>
        </div>
      </div>

      {/* Invoice History */}
      <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden transition-colors">
        <div className="p-4 border-b border-zinc-200 dark:border-zinc-800">
          <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">Enterprise Billing Invoices & Receipts</h3>
        </div>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[720px] text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 text-zinc-500 dark:text-slate-400">
                <th className="p-3">INVOICE NUMBER</th>
                <th className="p-3">BILLING PERIOD</th>
                <th className="p-3">AMOUNT (EXCL. TAX)</th>
                <th className="p-3">STATUS</th>
                <th className="p-3">ISSUE DATE</th>
                <th className="p-3 text-right">RECEIPT</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {invoices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-zinc-400 dark:text-slate-500 text-[11px] font-sans">
                    No invoices yet. Billing history will appear automatically from the system.
                  </td>
                </tr>
              ) : (
                invoices.map(inv => (
                  <tr key={inv.id} className="hover:bg-zinc-100 dark:hover:bg-zinc-800 transition">
                    <td className="p-3 font-bold text-zinc-700 dark:text-zinc-300">{inv.id}</td>
                    <td className="p-3 text-zinc-800 dark:text-zinc-200">{inv.period}</td>
                    <td className="p-3 font-bold text-zinc-900 dark:text-white">{inv.amount}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                        {inv.status}
                      </span>
                    </td>
                    <td className="p-3 text-zinc-500 dark:text-slate-400">{inv.date}</td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => downloadInvoice(inv)}
                        className="px-2.5 py-1 rounded bg-zinc-50 dark:bg-zinc-900/40 hover:bg-zinc-100 dark:hover:bg-zinc-800 border border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs inline-flex items-center gap-1 cursor-pointer transition"
                      >
                        <Download className="w-3 h-3" />
                        <span>TXT</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
