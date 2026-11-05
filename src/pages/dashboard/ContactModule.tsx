import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Headset,
  Mail,
  Phone,
  MapPin,
  Clock,
  Send,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ArrowLeft,
  RefreshCw,
  Inbox,
  ShieldCheck,
  ArrowRight
} from 'lucide-react';
import { securityApi, globalRealtimeClient, ContactMessage } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { SplitContactSection } from '../../components/common/SplitContactSection';

interface ContactModuleProps {
  variant?: 'dashboard' | 'public';
  onBack?: () => void;
  onEnterDashboard?: () => void;
}

const TOPICS = [
  'General',
  'Technical Support',
  'Incident Response',
  'Billing',
  'Security Disclosure',
  'Partnership'
];

const SEVERITIES = ['Low', 'Normal', 'High', 'Critical'];

const STATUS_STYLE: Record<string, string> = {
  OPEN: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-500/10 dark:text-amber-300 dark:border-amber-500/30',
  IN_REVIEW: 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-500/10 dark:text-sky-300 dark:border-sky-500/30',
  RESOLVED: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:border-emerald-500/30'
};

const inputClass =
  'w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500';

const labelClass = 'mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400';

export const ContactModule: React.FC<ContactModuleProps> = ({
  variant = 'dashboard',
  onBack,
  onEnterDashboard
}) => {
  const { user, currentOrg, isBackendOffline } = useAuth();
  const isPublic = variant === 'public';

  const [channels, setChannels] = useState<any>(null);
  const [messages, setMessages] = useState<ContactMessage[]>([]);
  const [openCount, setOpenCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const [form, setForm] = useState({
    name: '',
    email: '',
    company: '',
    topic: 'General',
    severity: 'Normal',
    message: ''
  });

  useEffect(() => {
    if (!user) return;
    setForm(prev => ({
      ...prev,
      name: prev.name || user.name || '',
      email: prev.email || user.email || ''
    }));
  }, [user]);

  const loadChannels = useCallback(async () => {
    try {
      const result = await securityApi.getContactChannels();
      setChannels(result.channels);
    } catch {
      setChannels(null);
    }
  }, []);

  const loadMessages = useCallback(async () => {
    if (isPublic) return;
    try {
      const result = await securityApi.getContactMessages({ limit: 100 });
      setMessages(result.messages);
      setOpenCount(result.open);
    } catch (err) {
      setMessages([]);
    }
  }, [isPublic]);

  const load = useCallback(async () => {
    setLoading(true);
    await Promise.all([loadChannels(), loadMessages()]);
    setLoading(false);
  }, [loadChannels, loadMessages]);

  useEffect(() => {
    void load();
  }, [load]);

  // Live updates: a message submitted from the public site appears in the
  // console immediately, and status changes converge on every screen.
  useEffect(() => {
    if (isPublic) return;
    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      if (msg?.type === 'contact.created' || msg?.type === 'contact.updated') {
        void loadMessages();
      }
    });
    return () => unsubscribe();
  }, [isPublic, loadMessages]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setNotice(null);
    setSubmitting(true);
    try {
      await securityApi.submitContactMessage({
        name: form.name,
        email: form.email,
        company: form.company,
        topic: form.topic,
        severity: form.severity,
        message: form.message,
        source: isPublic ? 'public' : 'console'
      });
      setNotice({
        kind: 'success',
        text: 'Message received. The SOC team will reply to the email address you provided.'
      });
      setForm(prev => ({ ...prev, message: '' }));
      await loadMessages();
    } catch (err: any) {
      setNotice({ kind: 'error', text: err?.message || 'Could not send your message.' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleStatus = async (id: string, status: ContactMessage['status']) => {
    setBusyId(id);
    try {
      await securityApi.updateContactMessage(id, status);
      await loadMessages();
    } catch (err: any) {
      setNotice({ kind: 'error', text: err?.message || 'Could not update the message.' });
    } finally {
      setBusyId(null);
    }
  };

  const channelCards = useMemo(() => {
    if (!channels) return [];
    const items = [
      { icon: Mail, label: 'Email', value: channels.email, href: channels.email ? `mailto:${channels.email}` : undefined },
      { icon: Phone, label: 'Phone', value: channels.phone, href: channels.phone ? `tel:${channels.phone}` : undefined },
      { icon: MapPin, label: 'Address', value: channels.address },
      { icon: Clock, label: 'Coverage', value: channels.hours }
    ];
    return items.filter(item => Boolean(item.value));
  }, [channels]);

  if (isBackendOffline && !isPublic) {
    return <BackendOfflineBanner onRetry={load} />;
  }

  const formCard = (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e] space-y-4"
    >
      <div className="flex items-center gap-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-50 text-cyan-600 dark:bg-cyan-500/10 dark:text-cyan-300">
          <Send className="h-4 w-4" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Send a message</h2>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            Stored in the SOC queue and delivered to the on-call analysts.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className={labelClass} htmlFor="contact-name">Name</label>
          <input
            id="contact-name"
            className={inputClass}
            value={form.name}
            onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
            placeholder="Your name"
            autoComplete="name"
          />
        </div>
        <div>
          <label className={labelClass} htmlFor="contact-email">Email</label>
          <input
            id="contact-email"
            type="email"
            required
            className={inputClass}
            value={form.email}
            onChange={e => setForm(prev => ({ ...prev, email: e.target.value }))}
            placeholder="you@company.com"
            autoComplete="email"
          />
        </div>
        <div>
          <label className={labelClass} htmlFor="contact-company">Company</label>
          <input
            id="contact-company"
            className={inputClass}
            value={form.company}
            onChange={e => setForm(prev => ({ ...prev, company: e.target.value }))}
            placeholder={currentOrg?.name || 'Organization'}
            autoComplete="organization"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelClass} htmlFor="contact-topic">Topic</label>
            <select
              id="contact-topic"
              className={inputClass}
              value={form.topic}
              onChange={e => setForm(prev => ({ ...prev, topic: e.target.value }))}
            >
              {TOPICS.map(topic => <option key={topic} value={topic}>{topic}</option>)}
            </select>
          </div>
          <div>
            <label className={labelClass} htmlFor="contact-severity">Priority</label>
            <select
              id="contact-severity"
              className={inputClass}
              value={form.severity}
              onChange={e => setForm(prev => ({ ...prev, severity: e.target.value }))}
            >
              {SEVERITIES.map(severity => <option key={severity} value={severity}>{severity}</option>)}
            </select>
          </div>
        </div>
      </div>

      <div>
        <label className={labelClass} htmlFor="contact-message">Message</label>
        <textarea
          id="contact-message"
          required
          minLength={10}
          maxLength={8000}
          rows={6}
          className={`${inputClass} resize-y`}
          value={form.message}
          onChange={e => setForm(prev => ({ ...prev, message: e.target.value }))}
          placeholder="Describe the request, the affected website, and any evidence you can share."
        />
        <div className="mt-1 text-right text-[10px] font-mono text-zinc-400">
          {form.message.length}/8000
        </div>
      </div>

      {notice && (
        <div
          className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs ${
            notice.kind === 'success'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300'
              : 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300'
          }`}
        >
          {notice.kind === 'success' ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
          <span>{notice.text}</span>
        </div>
      )}

      <div className="flex justify-end">
        <button
          type="submit"
          disabled={submitting || form.message.trim().length < 10 || !form.email.trim()}
          className="inline-flex h-9 items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:from-cyan-500 hover:to-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
          {submitting ? 'Sending…' : 'Send message'}
        </button>
      </div>
    </form>
  );

  const channelPanel = (
    <div className="space-y-3">
      <div className="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e]">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-white">
          <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
          SOC contact channels
        </h2>
        {channelCards.length === 0 ? (
          <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
            Support channels are not configured for this deployment yet.
          </p>
        ) : (
          <ul className="mt-3 space-y-3">
            {channelCards.map((item, index) => (
              <li key={index} className="flex items-start gap-3">
                <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
                  <item.icon className="h-3.5 w-3.5" />
                </span>
                <div className="min-w-0">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">{item.label}</div>
                  {item.href ? (
                    <a href={item.href} className="break-all text-sm text-zinc-800 hover:text-cyan-600 dark:text-zinc-200 dark:hover:text-cyan-300">
                      {item.value}
                    </a>
                  ) : (
                    <div className="break-words text-sm text-zinc-800 dark:text-zinc-200">{item.value}</div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
        {channels?.responseSla && (
          <div className="mt-4 rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-[11px] leading-relaxed text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400">
            {channels.responseSla}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-cyan-200 bg-cyan-50/60 p-4 dark:border-cyan-500/20 dark:bg-cyan-500/5">
        <div className="flex items-center gap-2 text-xs font-semibold text-cyan-800 dark:text-cyan-200">
          <AlertCircle className="h-3.5 w-3.5" />
          Active incident?
        </div>
        <p className="mt-1 text-[11px] leading-relaxed text-cyan-800/80 dark:text-cyan-200/80">
          For an active breach, choose topic <strong>Incident Response</strong> and priority{' '}
          <strong>Critical</strong>. The request is written to the SOC queue immediately and the
          live console receives a real-time event.
        </p>
      </div>
    </div>
  );

  const ticketsPanel = !isPublic && (
    <div className="rounded-xl border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-[#0c0c0e]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-100 px-5 py-3.5 dark:border-zinc-800">
        <div className="flex items-center gap-2">
          <Inbox className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Support queue</h2>
          <span className="rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">
            {openCount} open
          </span>
        </div>
      </div>

      {messages.length === 0 ? (
        <div className="px-5 py-10 text-center">
          <Inbox className="mx-auto h-6 w-6 text-zinc-300 dark:text-zinc-600" />
          <p className="mt-2 text-xs font-medium text-zinc-600 dark:text-zinc-300">No contact requests yet</p>
          <p className="mt-1 text-[11px] text-zinc-400 dark:text-zinc-500">
            Messages from the public contact page and this console appear here in real time.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
          {messages.map(message => (
            <li key={message.id} className="px-5 py-3.5">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{message.topic}</span>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${STATUS_STYLE[message.status] || STATUS_STYLE.OPEN}`}>
                      {message.status.replace('_', ' ')}
                    </span>
                    <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-[10px] font-medium text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
                      {message.severity}
                    </span>
                    {message.source === 'public' && (
                      <span className="rounded-full bg-cyan-50 px-2 py-0.5 text-[10px] font-medium text-cyan-700 dark:bg-cyan-500/10 dark:text-cyan-300">
                        public
                      </span>
                    )}
                  </div>
                  <div className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400">
                    {message.name} · {message.email}
                    {message.company ? ` · ${message.company}` : ''} · {message.createdAt}
                  </div>
                  <p className="mt-1.5 whitespace-pre-wrap break-words text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                    {message.message}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  {message.status !== 'IN_REVIEW' && message.status !== 'RESOLVED' && (
                    <button
                      type="button"
                      disabled={busyId === message.id}
                      onClick={() => void handleStatus(message.id, 'IN_REVIEW')}
                      className="rounded-md border border-zinc-200 px-2 py-1 text-[10px] font-semibold text-zinc-600 transition hover:bg-zinc-50 disabled:opacity-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
                    >
                      Review
                    </button>
                  )}
                  {message.status !== 'RESOLVED' && (
                    <button
                      type="button"
                      disabled={busyId === message.id}
                      onClick={() => void handleStatus(message.id, 'RESOLVED')}
                      className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[10px] font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300 dark:hover:bg-emerald-500/20"
                    >
                      Resolve
                    </button>
                  )}
                  {busyId === message.id && <Loader2 className="h-3 w-3 animate-spin text-zinc-400" />}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );

  if (isPublic) {
    return (
      <div className="min-h-screen bg-white font-sans text-zinc-900 selection:bg-cyan-500/20 dark:bg-[#080d17] dark:text-slate-100">
        <header className="sticky top-0 z-40 border-b border-zinc-200 bg-white/90 px-4 py-3 backdrop-blur dark:border-slate-800/80 dark:bg-[#090f1b]/95 sm:px-6 lg:px-12">
          <div className="mx-auto flex max-w-6xl items-center justify-between gap-3">
            <button
              type="button"
              onClick={onBack}
              className="inline-flex items-center gap-2 text-sm font-medium text-zinc-600 transition hover:text-cyan-600 dark:text-slate-300 dark:hover:text-cyan-400"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to site
            </button>
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-700">
                <Headset className="h-4 w-4 text-white" />
              </div>
              <span className="text-sm font-bold tracking-wide">OAT <span className="text-cyan-600 dark:text-cyan-400">SECURITY</span></span>
            </div>
            {onEnterDashboard && (
              <button
                type="button"
                onClick={onEnterDashboard}
                className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 px-3 py-2 text-xs font-semibold text-white shadow-sm transition hover:from-cyan-500 hover:to-blue-500"
              >
                Dashboard
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </header>

        <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-12">
          <SplitContactSection
            onSendMessage={async ({ name, email, phone, message }) => {
              await securityApi.submitContactMessage({
                name,
                email,
                company: phone ? `Phone: ${phone}` : '',
                topic: 'General',
                severity: 'Normal',
                message,
                source: 'public'
              });
            }}
          />
        </main>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <ModulePageHeader
        icon={<Headset className="h-5 w-5" />}
        title="Contact &"
        titleTail="Support"
        subtitle="Message the security operations team. Requests are recorded in the platform and pushed to every open console in real time."
      />

      <SplitContactSection
        onSendMessage={async ({ name, email, phone, message }) => {
          await securityApi.submitContactMessage({
            name,
            email,
            company: phone ? `Phone: ${phone}` : currentOrg?.name || '',
            topic: 'Technical Support',
            severity: 'Normal',
            message,
            source: 'console'
          });
          await loadMessages();
        }}
      />

      {ticketsPanel}
    </div>
  );
};
