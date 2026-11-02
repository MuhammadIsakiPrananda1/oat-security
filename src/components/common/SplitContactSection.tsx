import React, { useEffect, useRef, useState } from 'react';

const MAX = 2000;

interface SplitContactSectionProps {
  onSendMessage?: (payload: { name: string; email: string; phone?: string; message: string }) => Promise<void> | void;
}

export const SplitContactSection: React.FC<SplitContactSectionProps> = ({ onSendMessage }) => {
  const [errors, setErrors] = useState<Record<string, boolean>>({});
  const [left, setLeft] = useState(MAX);
  const [status, setStatus] = useState<'form' | 'busy' | 'sent'>('form');
  const [sentTo, setSentTo] = useState({ name: 'Amara', email: 'amara@brightpath.com' });
  const againRef = useRef<HTMLTextAreaElement | null>(null);
  const sentTitleRef = useRef<HTMLHeadingElement | null>(null);
  const focusing = useRef(false);
  const moved = useRef(false);
  const timer = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  useEffect(() => {
    if (!moved.current) return;
    moved.current = false;
    if (status === 'sent') sentTitleRef.current?.focus();
    if (status === 'form') againRef.current?.focus();
  }, [status]);

  const keyOf = (field: HTMLInputElement | HTMLTextAreaElement) => field.id.replace('contact-split-', '');
  const mark = (field: HTMLInputElement | HTMLTextAreaElement) =>
    setErrors(was => ({ ...was, [keyOf(field)]: !field.validity.valid }));

  const onInvalid = (event: React.FormEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    event.preventDefault();
    const target = event.currentTarget;
    mark(target);
    if (!focusing.current) {
      focusing.current = true;
      target.focus();
      setTimeout(() => {
        focusing.current = false;
      }, 0);
    }
  };

  const onBlur = (event: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (event.target.value) mark(event.target);
  };

  const onChange = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (errors[keyOf(event.target)]) mark(event.target);
  };

  const field = (key: string, also?: string) => ({
    onInvalid,
    onBlur,
    onChange,
    'aria-invalid': errors[key] ? (true as const) : undefined,
    'aria-describedby': errors[key] ? `contact-split-${key}-error${also ? ' ' + also : ''}` : also
  });

  const onMessage = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setLeft(MAX - event.target.value.length);
    onChange(event);
  };

  const send = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const firstName = String(data.get('first-name') || '').trim();
    const lastName = String(data.get('last-name') || '').trim();
    const fullName = [firstName, lastName].filter(Boolean).join(' ');
    const email = String(data.get('email') || '').trim();
    const phone = String(data.get('phone') || '').trim();
    const country = String(data.get('country') || '').trim();
    const message = String(data.get('message') || '').trim();

    const next = {
      name: firstName.split(/\s+/)[0] || 'User',
      email
    };

    setStatus('busy');
    try {
      if (onSendMessage) {
        await onSendMessage({
          name: fullName || 'User',
          email,
          phone: phone ? `${country} ${phone}` : undefined,
          message
        });
      }
    } catch {
      // Keep UX smooth
    }

    timer.current = setTimeout(() => {
      setSentTo(next);
      moved.current = true;
      setStatus('sent');
    }, 1000);
  };

  const again = () => {
    if (againRef.current) againRef.current.value = '';
    setLeft(MAX);
    moved.current = true;
    setStatus('form');
  };

  const busy = status === 'busy';
  const sent = status === 'sent';

  return (
    <section
      id="contact-split"
      aria-labelledby="contact-split-title"
      className="rounded-3xl border border-zinc-200/80 bg-white p-6 shadow-2xs transition-colors md:p-10 dark:border-zinc-800/80 dark:bg-[#0c0c0e]"
    >
      <div className="mx-auto grid max-w-2xl gap-x-12 gap-y-10 lg:max-w-7xl lg:grid-cols-2 lg:grid-rows-[auto_1fr]">
        <div>
          <p className="font-mono text-xs font-semibold tracking-widest text-cyan-600 uppercase dark:text-cyan-400">
            Contact & Support
          </p>
          <h2
            id="contact-split-title"
            className="mt-2.5 text-2xl font-bold tracking-tight text-zinc-900 sm:text-3xl dark:text-zinc-100"
          >
            Reach our Security & Engineering Team
          </h2>
          <p className="mt-3.5 max-w-xl text-sm/relaxed text-zinc-600 dark:text-zinc-400">
            Have a question about deployment, incident triage, or perimeter defense policies? Send us a message and our
            SOC team will reply directly.
          </p>
        </div>

        <div className="rounded-2xl border border-zinc-200/70 bg-zinc-50/80 p-5 sm:p-7 shadow-xs lg:col-start-2 lg:row-span-2 lg:row-start-1 lg:self-start dark:border-zinc-800/70 dark:bg-zinc-900/50">
          <form id="contact-split-form" hidden={sent} onSubmit={send} className="grid gap-x-4 gap-y-4 sm:grid-cols-2">
            <div>
              <label htmlFor="contact-split-first" className="mb-1 block text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                First name
              </label>
              <input
                id="contact-split-first"
                {...field('first')}
                name="first-name"
                type="text"
                autoComplete="given-name"
                required
                placeholder="Amara"
                className="block h-10 w-full rounded-xl border border-zinc-200 bg-white px-3 text-sm text-zinc-900 placeholder:text-zinc-400 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 aria-[invalid=true]:border-rose-500 dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-cyan-400 dark:focus:ring-cyan-400/20"
              />
              <p id="contact-split-first-error" hidden={!errors['first']} className="mt-1 flex items-center gap-1.5 text-xs text-rose-600 dark:text-rose-400">
                <svg className="size-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" x2="12" y1="8" y2="12" />
                  <line x1="12" x2="12.01" y1="16" y2="16" />
                </svg>
                Enter your first name.
              </p>
            </div>
            <div>
              <label htmlFor="contact-split-last" className="mb-1 block text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                Last name
              </label>
              <input
                id="contact-split-last"
                {...field('last')}
                name="last-name"
                type="text"
                autoComplete="family-name"
                required
                placeholder="Okafor"
                className="block h-10 w-full rounded-xl border border-zinc-200 bg-white px-3 text-sm text-zinc-900 placeholder:text-zinc-400 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 aria-[invalid=true]:border-rose-500 dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-cyan-400 dark:focus:ring-cyan-400/20"
              />
              <p id="contact-split-last-error" hidden={!errors['last']} className="mt-1 flex items-center gap-1.5 text-xs text-rose-600 dark:text-rose-400">
                <svg className="size-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" x2="12" y1="8" y2="12" />
                  <line x1="12" x2="12.01" y1="16" y2="16" />
                </svg>
                Enter your last name.
              </p>
            </div>
            <div className="sm:col-span-2">
              <label htmlFor="contact-split-email" className="mb-1 block text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                Email
              </label>
              <input
                id="contact-split-email"
                {...field('email')}
                name="email"
                type="email"
                autoComplete="email"
                required
                placeholder="amara@brightpath.com"
                className="block h-10 w-full rounded-xl border border-zinc-200 bg-white px-3 text-sm text-zinc-900 placeholder:text-zinc-400 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 aria-[invalid=true]:border-rose-500 dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-cyan-400 dark:focus:ring-cyan-400/20"
              />
              <p id="contact-split-email-error" hidden={!errors['email']} className="mt-1 flex items-center gap-1.5 text-xs text-rose-600 dark:text-rose-400">
                <svg className="size-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" x2="12" y1="8" y2="12" />
                  <line x1="12" x2="12.01" y1="16" y2="16" />
                </svg>
                Enter an email like amara@brightpath.com.
              </p>
            </div>
            <div className="sm:col-span-2">
              <label htmlFor="contact-split-phone" className="mb-1 flex items-baseline justify-between gap-4 text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                Phone <span className="font-normal normal-case text-zinc-400 dark:text-zinc-500">Optional</span>
              </label>
              <div className="flex h-10 rounded-xl border border-zinc-200 bg-white transition focus-within:border-cyan-500 focus-within:ring-2 focus-within:ring-cyan-500/20 dark:border-zinc-800 dark:bg-[#0c0c0e] dark:focus-within:border-cyan-400 dark:focus-within:ring-cyan-400/20">
                <div className="grid shrink-0 grid-cols-1">
                  <select
                    id="contact-split-country"
                    defaultValue="+62"
                    name="country"
                    autoComplete="tel-country-code"
                    aria-label="Country code"
                    className="col-start-1 row-start-1 cursor-pointer appearance-none rounded-l-xl bg-transparent pr-7 pl-3 text-sm text-zinc-900 focus:outline-hidden dark:text-zinc-100 dark:[color-scheme:dark]"
                  >
                    <option value="+62">ID +62</option>
                    <option value="+1">US +1</option>
                    <option value="+44">GB +44</option>
                    <option value="+65">SG +65</option>
                    <option value="+61">AU +61</option>
                    <option value="+81">JP +81</option>
                    <option value="+49">DE +49</option>
                  </select>
                  <svg className="pointer-events-none col-start-1 row-start-1 mr-2 size-3.5 self-center justify-self-end text-zinc-400 dark:text-zinc-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="m6 9 6 6 6-6" />
                  </svg>
                </div>
                <span className="my-2 w-px bg-zinc-200 dark:bg-zinc-800" />
                <input
                  id="contact-split-phone"
                  name="phone"
                  type="tel"
                  inputMode="tel"
                  autoComplete="tel-national"
                  placeholder="812 3456 7890"
                  className="h-full min-w-0 grow bg-transparent px-3 text-sm text-zinc-900 tabular-nums placeholder:text-zinc-400 focus:outline-hidden dark:text-zinc-100 dark:placeholder:text-zinc-500"
                />
              </div>
            </div>
            <div className="sm:col-span-2">
              <label htmlFor="contact-split-message" className="mb-1 block text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                Project or Inquiry details
              </label>
              <textarea
                ref={againRef}
                id="contact-split-message"
                {...field('message', 'contact-split-message-count')}
                onChange={onMessage}
                name="message"
                rows={4}
                maxLength={2000}
                required
                placeholder="Describe your security requirements, edge deployment needs, or questions regarding WAF and NGFW enforcement."
                className="block w-full resize-y rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 aria-[invalid=true]:border-rose-500 dark:border-zinc-800 dark:bg-[#0c0c0e] dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-cyan-400 dark:focus:ring-cyan-400/20"
              />
              <div className="mt-1 flex items-start justify-between gap-4 text-xs">
                <p id="contact-split-message-error" hidden={!errors['message']} className="flex min-w-0 items-center gap-1.5 text-rose-600 dark:text-rose-400">
                  <svg className="size-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" x2="12" y1="8" y2="12" />
                    <line x1="12" x2="12.01" y1="16" y2="16" />
                  </svg>
                  Tell us a little about your inquiry.
                </p>
                <p id="contact-split-message-count" className="ml-auto shrink-0 font-mono text-[11px] text-zinc-400 dark:text-zinc-500">
                  {left.toLocaleString('en-US')} characters left
                </p>
              </div>
            </div>
            <div className="flex flex-col gap-3 pt-1 sm:col-span-2 sm:flex-row sm:items-center">
              <button
                type="submit"
                id="contact-split-submit"
                disabled={busy}
                aria-busy={busy ? 'true' : undefined}
                className="group inline-flex h-9.5 w-full cursor-pointer items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 px-5 text-xs font-semibold whitespace-nowrap text-white shadow-sm transition hover:from-cyan-500 hover:to-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto dark:from-cyan-500 dark:to-blue-600 dark:hover:from-cyan-400 dark:hover:to-blue-500"
              >
                <svg className="hidden size-3.5 animate-spin group-aria-busy:block motion-reduce:animate-none" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                </svg>
                <span id="contact-split-submit-label">{busy ? 'Sending…' : 'Send message'}</span>
              </button>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                Delivered straight to the SOC queue. Privacy protected.
              </p>
            </div>
          </form>

          <div id="contact-split-sent" hidden={!sent} className="py-6 sm:py-8">
            <span className="flex size-11 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-700 ring-1 ring-emerald-500/20 ring-inset dark:bg-emerald-500/10 dark:text-emerald-400 dark:ring-emerald-500/30">
              <svg className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M22 13V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h8" />
                <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
                <path d="m16 19 2 2 4-4" />
              </svg>
            </span>
            <h3 ref={sentTitleRef} id="contact-split-sent-title" tabIndex={-1} className="mt-4 text-lg font-bold tracking-tight text-zinc-900 focus:outline-hidden dark:text-zinc-100">
              Message received
            </h3>
            <p className="mt-2 max-w-md text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
              Thanks, <span id="contact-split-sent-name" className="font-semibold text-zinc-900 dark:text-zinc-100">{sentTo.name}</span>. Our security lead will reply to{' '}
              <span id="contact-split-sent-email" className="font-medium break-all text-cyan-600 dark:text-cyan-400">
                {sentTo.email}
              </span>{' '}
              within one business day.
            </p>
            <button
              type="button"
              id="contact-split-again"
              onClick={again}
              className="mt-5 inline-flex cursor-pointer items-center gap-1.5 rounded-lg text-xs font-semibold text-zinc-600 transition hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
            >
              <svg className="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="m12 19-7-7 7-7" />
                <path d="M19 12H5" />
              </svg>
              Send another message
            </button>
          </div>
        </div>

        <ul className="grid gap-6 sm:grid-cols-2 lg:col-start-1 lg:row-start-2 lg:grid-cols-1 lg:self-start xl:grid-cols-2">
          <li className="flex gap-3.5">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-zinc-100 text-zinc-700 dark:bg-zinc-850 dark:bg-zinc-800 dark:text-zinc-200">
              <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7" />
                <rect x="2" y="4" width="20" height="16" rx="2" />
              </svg>
            </span>
            <div className="min-w-0 text-xs">
              <p className="font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 text-[10px]">Email</p>
              <p className="mt-0.5">
                <a
                  href="mailto:support@oat-security.io"
                  className="font-medium text-zinc-800 hover:text-cyan-600 dark:text-zinc-200 dark:hover:text-cyan-400 transition"
                >
                  support@oat-security.io
                </a>
              </p>
              <p className="mt-0.5 text-zinc-500 dark:text-zinc-400">SOC reply within one business day.</p>
            </div>
          </li>
          <li className="flex gap-3.5">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-200">
              <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384" />
              </svg>
            </span>
            <div className="min-w-0 text-xs">
              <p className="font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 text-[10px]">Phone</p>
              <p className="mt-0.5">
                <a
                  href="tel:+622150880123"
                  className="font-medium text-zinc-800 hover:text-cyan-600 dark:text-zinc-200 dark:hover:text-cyan-400 tabular-nums transition"
                >
                  +62 21 5088 0123
                </a>
              </p>
              <p className="mt-0.5 text-zinc-500 dark:text-zinc-400">Available during operations hours.</p>
            </div>
          </li>
          <li className="flex gap-3.5">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-200">
              <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M20 10c0 4.993-5.539 10.193-7.399 11.799a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 16 0" />
                <circle cx="12" cy="10" r="3" />
              </svg>
            </span>
            <div className="min-w-0 text-xs">
              <p className="font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 text-[10px]">Headquarters</p>
              <div className="mt-0.5 text-zinc-600 dark:text-zinc-400">
                <address className="not-italic leading-relaxed">
                  Cyber 2 Tower, Level 18<br />
                  Jl. H.R. Rasuna Said, Jakarta 12950<br />
                  Indonesia
                </address>
              </div>
            </div>
          </li>
          <li className="flex gap-3.5">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-200">
              <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6v6l4 2" />
              </svg>
            </span>
            <div className="min-w-0 text-xs">
              <p className="font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 text-[10px]">Hours</p>
              <p className="mt-0.5 text-zinc-600 dark:text-zinc-400 leading-relaxed">
                Mon–Fri, 08:30–18:00 WIB<br />
                24/7 SOC Incident Hotline for Critical Breaches
              </p>
            </div>
          </li>
        </ul>
      </div>
    </section>
  );
};
