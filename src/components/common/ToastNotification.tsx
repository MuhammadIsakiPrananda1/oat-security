import React, { useEffect, useLayoutEffect, useRef, useState, useCallback } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowRight } from '@fortawesome/free-solid-svg-icons';
import { getLanguage } from '../../i18n/translator';

export interface ToastItem {
  id: string;
  title: string;
  desc: string;
  severity: string;
  timestamp: number;
  /** Callback when user clicks "Lihat detail" */
  onNavigate?: () => void;
}

interface ToastInternal extends ToastItem {
  closing: boolean;
}

interface ToastContainerProps {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
}

// Folded, up to two older toasts peek out 10px each behind the newest; open, they stand 8px apart.
const PEEK = 10;
const GAP = 8;
const FOLD = 2;
const LIFE = 6000;
const MAX = 5;

function severityConfig(severity: string) {
  const s = severity?.toUpperCase?.() || '';
  if (s === 'SUCCESS' || s === 'RESOLVED') {
    return {
      dot: 'bg-emerald-500',
      badge: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
      iconSvg: (
        <svg className="mt-0.5 size-5 shrink-0 text-emerald-600 dark:text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="10" />
          <path d="m16 9-5.5 5.5L8 12" />
        </svg>
      )
    };
  }
  if (s === 'CRITICAL' || s === 'ERROR' || s === 'HIGH') {
    return {
      dot: 'bg-rose-500',
      badge: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
      iconSvg: (
        <svg className="mt-0.5 size-5 shrink-0 text-rose-600 dark:text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      )
    };
  }
  if (s === 'MEDIUM' || s === 'WARNING' || s === 'WARN') {
    return {
      dot: 'bg-amber-500',
      badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
      iconSvg: (
        <svg className="mt-0.5 size-5 shrink-0 text-amber-500 dark:text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      )
    };
  }
  return {
    dot: 'bg-blue-500',
    badge: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
    iconSvg: (
      <svg className="mt-0.5 size-5 shrink-0 text-neutral-950 dark:text-neutral-50" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z" />
        <path d="m21.854 2.147-10.94 10.939" />
      </svg>
    )
  };
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts: incomingToasts, onDismiss }) => {
  const [itemsList, setItemsList] = useState<ToastInternal[]>([]);
  const [open, setOpen] = useState(false);

  const boxRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<HTMLOListElement | null>(null);
  const items = useRef<Record<string, HTMLElement | null>>({});
  const flags = useRef({ pointer: false, focus: false, touched: false });
  const back = useRef<Element | null>(null);
  const clocks = useRef<Map<string, { left: number; since: number; id: any }>>(new Map());
  const openRef = useRef(false);

  const reduce = () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Sync incoming props into itemsList (newest at the end for bottom-pinned layout)
  useEffect(() => {
    setItemsList(prev => {
      const existingIds = new Set(prev.map(p => p.id));
      const nextItems: ToastInternal[] = [...prev];

      incomingToasts.forEach(t => {
        if (!existingIds.has(t.id)) {
          // New toast pushes to bottom
          nextItems.push({ ...t, closing: false });
          clocks.current.set(t.id, { left: LIFE, since: 0, id: 0 });
        }
      });

      // Trim oldest if exceeding MAX
      const active = nextItems.filter(i => !i.closing);
      if (active.length > MAX) {
        const excess = active.length - MAX;
        for (let i = 0; i < excess; i++) {
          const oldest = active[i];
          if (oldest) {
            const entry = clocks.current.get(oldest.id);
            if (entry?.id) clearTimeout(entry.id);
            clocks.current.delete(oldest.id);
            oldest.closing = true;
            onDismiss(oldest.id);
          }
        }
      }

      return nextItems.filter(i => !i.closing || active.some(a => a.id === i.id));
    });
  }, [incomingToasts, onDismiss]);

  const live = itemsList.filter(t => !t.closing);

  // Places every toast: newest at the bottom; folded, the older ones behind it, smaller, with
  // their words faded; open, each above the next at its own height.
  const layout = useCallback(() => {
    if (!listRef.current) return;
    const els = [...listRef.current.querySelectorAll<HTMLElement>('[data-toast]:not([data-closing])')];
    if (els.length === 0) {
      listRef.current.style.height = '0px';
      return;
    }
    const heights = els.map(li => {
      const child = li.firstElementChild as HTMLElement;
      return child ? child.offsetHeight : 64;
    });
    const front = heights[heights.length - 1] || 0;
    let y = 0;
    for (let d = 0; d < els.length; d++) {
      const li = els[els.length - 1 - d];
      const h = heights[els.length - 1 - d];
      if (openRef.current) {
        li.style.translate = `0 ${-y}px`;
        li.style.scale = '1';
        li.style.height = `${h}px`;
        li.style.opacity = '';
        li.removeAttribute('data-folded');
        y += h + GAP;
      } else {
        li.style.translate = `0 ${-Math.min(d, FOLD) * PEEK}px`;
        li.style.scale = String(1 - Math.min(d, FOLD + 1) * 0.05);
        li.style.height = `${front}px`;
        li.style.opacity = d > FOLD ? '0' : '';
        li.toggleAttribute('data-folded', d > 0);
      }
    }
    listRef.current.style.height = `${
      openRef.current ? Math.max(0, y - GAP) : front + Math.min(els.length - 1, FOLD) * PEEK
    }px`;
  }, []);

  useLayoutEffect(() => {
    openRef.current = open;
    layout();
  });

  useEffect(() => {
    if (!listRef.current) return;
    const sizes = new ResizeObserver(() => layout());
    listRef.current.querySelectorAll('[data-toast]').forEach(li => {
      if (li.firstElementChild) sizes.observe(li.firstElementChild);
    });
    return () => sizes.disconnect();
  }, [itemsList, layout]);

  // Timers: started when a toast is raised, held while the stack is open, resumed when it folds.
  const run = (id: string) => {
    const c = clocks.current.get(id);
    if (!c || openRef.current || c.id) return;
    c.since = Date.now();
    c.id = setTimeout(() => dismiss(id), c.left);
  };

  const hold = (id: string) => {
    const c = clocks.current.get(id);
    if (!c || !c.id) return;
    clearTimeout(c.id);
    c.id = 0;
    c.left -= Date.now() - c.since;
  };

  useEffect(() => {
    clocks.current.forEach((_, id) => (open ? hold(id) : run(id)));
  }, [open]);

  useEffect(() => () => clocks.current.forEach(c => clearTimeout(c.id)), []);

  // Open while pointer is over stack, focus is inside, or after tap
  const sync = () => {
    const f = flags.current;
    openRef.current = f.pointer || f.focus || f.touched;
    setOpen(openRef.current);
  };

  useEffect(() => {
    const onDown = (event: PointerEvent) => {
      if (!flags.current.touched || !boxRef.current || boxRef.current.contains(event.target as Node)) return;
      flags.current.touched = false;
      sync();
    };
    document.addEventListener('pointerdown', onDown);
    return () => document.removeEventListener('pointerdown', onDown);
  }, []);

  const away = () => {
    const from = back.current as HTMLElement | null;
    if (from && from.isConnected && from.getClientRects().length) {
      from.focus();
    }
  };

  const drop = (ids: string[]) => {
    setTimeout(
      () => {
        setItemsList(list => list.filter(toast => !ids.includes(toast.id)));
        ids.forEach(id => onDismiss(id));
      },
      reduce() ? 0 : 200
    );
  };

  const dismiss = (id: string) => {
    const li = items.current[id];
    if (!li || li.hasAttribute('data-closing')) return;
    hold(id);
    clocks.current.delete(id);
    if (li.contains(document.activeElement)) {
      if (!listRef.current) return;
      const els = [...listRef.current.querySelectorAll<HTMLElement>('[data-toast]:not([data-closing])')];
      const at = els.indexOf(li);
      const next = els[at + 1] || els[at - 1];
      if (next) {
        next.querySelector<HTMLElement>('[data-dismiss]')?.focus();
      } else {
        away();
      }
    }
    setItemsList(list => list.map(toast => (toast.id === id ? { ...toast, closing: true } : toast)));
    drop([id]);
  };

  const clearAll = () => {
    away();
    clocks.current.forEach(c => clearTimeout(c.id));
    clocks.current.clear();
    const ids = itemsList.map(toast => toast.id);
    setItemsList(list => list.map(toast => ({ ...toast, closing: true })));
    drop(ids);
  };

  // Auto-run clocks on itemsList update
  useEffect(() => {
    itemsList.forEach(t => {
      if (!t.closing) run(t.id);
    });
  }, [itemsList]);

  if (itemsList.length === 0) return null;

  return (
    <section
      aria-label="Notifications"
      className="pointer-events-none fixed inset-x-4 bottom-[max(1rem,env(safe-area-inset-bottom))] z-50 sm:right-[max(1.5rem,env(safe-area-inset-right))] sm:bottom-[max(1.5rem,env(safe-area-inset-bottom))] sm:left-auto sm:w-96"
    >
      <div
        ref={boxRef}
        id="toast-stack-box"
        hidden={itemsList.length === 0}
        data-expanded={open ? '' : undefined}
        onPointerEnter={event => {
          if (event.pointerType !== 'mouse') return;
          flags.current.pointer = true;
          sync();
        }}
        onPointerLeave={event => {
          if (event.pointerType !== 'mouse') return;
          flags.current.pointer = false;
          sync();
        }}
        onPointerDown={event => {
          if (event.pointerType === 'mouse') return;
          flags.current.touched = true;
          sync();
        }}
        onFocus={event => {
          if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget as Node)) {
            back.current = event.relatedTarget as Element;
          }
          flags.current.focus = true;
          sync();
        }}
        onBlur={event => {
          if (event.currentTarget.contains(event.relatedTarget as Node)) return;
          flags.current.focus = false;
          sync();
        }}
        className="pointer-events-auto absolute inset-x-0 bottom-0"
      >
        <div className="mb-2 flex items-center justify-end gap-2">
          <p
            id="toast-stack-count"
            className="inline-flex h-7 items-center rounded-full bg-white px-2.5 text-xs font-medium whitespace-nowrap text-neutral-600 tabular-nums shadow-md ring-1 ring-neutral-950/10 dark:bg-neutral-900 dark:text-neutral-400 dark:ring-neutral-800"
          >
            {getLanguage() === 'id'
              ? `${live.length} notifikasi`
              : `${live.length} notification${live.length === 1 ? '' : 's'}`}
          </p>
          <button
            type="button"
            id="toast-stack-clear"
            onClick={clearAll}
            className="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-full bg-white px-2.5 text-xs font-medium whitespace-nowrap text-neutral-950 shadow-md ring-1 ring-neutral-950/10 transition-colors duration-150 hover:bg-neutral-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 motion-reduce:transition-none dark:bg-neutral-900 dark:text-neutral-50 dark:ring-neutral-800 dark:hover:bg-neutral-800 dark:focus-visible:outline-zinc-50"
          >
            <svg className="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M18 6 6 18" />
              <path d="m6 6 12 12" />
            </svg>
            {getLanguage() === 'id' ? 'Hapus semua' : 'Clear all'}
          </button>
        </div>

        <div role="status" aria-atomic="false">
          <ol
            ref={listRef}
            id="toast-stack-list"
            className="relative transition-[height] duration-300 ease-out motion-reduce:transition-none"
          >
            {itemsList.map(toast => {
              const icons = severityConfig(toast.severity);
              return (
                <li
                  key={toast.id}
                  ref={el => {
                    items.current[toast.id] = el;
                  }}
                  data-toast=""
                  data-closing={toast.closing ? '' : undefined}
                  onKeyDown={event => event.key === 'Escape' && dismiss(toast.id)}
                  className="group/toast absolute inset-x-0 bottom-0 origin-top rounded-3xl bg-white shadow-2xl ring-1 ring-neutral-950/10 transition-[translate,scale,height,opacity] duration-300 ease-out data-closing:opacity-0 data-folded:overflow-hidden motion-reduce:transition-none dark:bg-neutral-900 dark:ring-neutral-800 starting:opacity-0"
                >
                  <div className="flex items-start gap-3 p-4 transition-opacity duration-200 group-data-folded/toast:opacity-0 motion-reduce:transition-none">
                    {icons.iconSvg}
                    <div className="min-w-0 grow basis-40 text-sm break-words">
                      <p className="font-medium text-neutral-950 dark:text-neutral-50">
                        {toast.title}
                      </p>
                      <p className="mt-0.5 text-neutral-600 dark:text-neutral-400">
                        {toast.desc}
                      </p>
                      {toast.onNavigate && (
                        <button
                          type="button"
                          onClick={() => {
                            toast.onNavigate?.();
                            dismiss(toast.id);
                          }}
                          className="mt-1.5 inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                        >
                          {getLanguage() === 'id' ? 'Lihat detail' : 'View detail'} <FontAwesomeIcon icon={faArrowRight} className="text-[9px]" />
                        </button>
                      )}
                    </div>
                    <button
                      type="button"
                      data-dismiss=""
                      onClick={() => dismiss(toast.id)}
                      aria-label={getLanguage() === 'id' ? 'Tutup notifikasi' : 'Close notification'}
                      className="-mt-1 -mr-1 inline-flex size-7 shrink-0 cursor-pointer items-center justify-center rounded-xl text-neutral-600 transition-colors duration-150 hover:bg-neutral-100 hover:text-neutral-950 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 motion-reduce:transition-none dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50 dark:focus-visible:outline-zinc-50"
                    >
                      <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M18 6 6 18" />
                        <path d="m6 6 12 12" />
                      </svg>
                    </button>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      </div>
    </section>
  );
};
