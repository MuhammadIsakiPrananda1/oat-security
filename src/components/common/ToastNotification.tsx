import React, { useEffect, useLayoutEffect, useRef, useState, useCallback } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowRight } from '@fortawesome/free-solid-svg-icons';

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
        <svg className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
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
        <svg className="size-5 shrink-0 text-rose-600 dark:text-rose-400 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
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
        <svg className="size-5 shrink-0 text-amber-500 dark:text-amber-400 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
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
      <svg className="size-5 shrink-0 text-blue-500 dark:text-blue-400 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="16" x2="12" y2="12" />
        <line x1="12" y1="8" x2="12.01" y2="8" />
      </svg>
    )
  };
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts: incomingToasts, onDismiss }) => {
  const [itemsList, setItemsList] = useState<ToastInternal[]>([]);
  const [open, setOpen] = useState(false);

  const boxRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<HTMLOListElement | null>(null);
  const itemRefs = useRef<Record<string, HTMLElement | null>>({});
  const flags = useRef({ pointer: false, focus: false, touched: false });
  const clocks = useRef<Map<string, { left: number; since: number; timerId: any }>>(new Map());
  const openRef = useRef(false);

  // Sync incoming props into itemsList
  useEffect(() => {
    setItemsList(prev => {
      const existingIds = new Set(prev.map(p => p.id));
      const nextItems: ToastInternal[] = [...prev];

      incomingToasts.forEach(t => {
        if (!existingIds.has(t.id)) {
          nextItems.unshift({ ...t, closing: false });
          // Start timer
          clocks.current.set(t.id, { left: LIFE, since: Date.now(), timerId: 0 });
        }
      });

      // Trim exceeding
      const active = nextItems.filter(i => !i.closing);
      if (active.length > MAX) {
        const toDrop = active.slice(MAX);
        toDrop.forEach(d => {
          const entry = clocks.current.get(d.id);
          if (entry?.timerId) clearTimeout(entry.timerId);
          clocks.current.delete(d.id);
          onDismiss(d.id);
        });
      }

      return nextItems.filter(i => !active.slice(MAX).some(d => d.id === i.id));
    });
  }, [incomingToasts, onDismiss]);

  const live = itemsList.filter(t => !t.closing);

  // Top-anchored stack layout
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
    const front = heights[0] || 0; // Top-most item is newest

    let y = 0;
    for (let d = 0; d < els.length; d++) {
      const li = els[d];
      const h = heights[d];
      if (openRef.current) {
        // Expanded: cascade downwards with GAP
        li.style.translate = `0 ${y}px`;
        li.style.scale = '1';
        li.style.height = `${h}px`;
        li.style.opacity = '1';
        li.removeAttribute('data-folded');
        y += h + GAP;
      } else {
        // Folded: older peek out below newest (downward offset + peek)
        li.style.translate = `0 ${Math.min(d, FOLD) * PEEK}px`;
        li.style.scale = String(1 - Math.min(d, FOLD + 1) * 0.05);
        li.style.height = `${front}px`;
        li.style.opacity = d > FOLD ? '0' : '1';
        li.toggleAttribute('data-folded', d > 0);
        // z-index: top item on front, older behind
        li.style.zIndex = String(50 - d);
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

  // Timers: pause on hover/focus, resume when unhovered
  const run = (id: string) => {
    const c = clocks.current.get(id);
    if (!c || openRef.current || c.timerId) return;
    c.since = Date.now();
    c.timerId = setTimeout(() => dismiss(id), c.left);
  };

  const hold = (id: string) => {
    const c = clocks.current.get(id);
    if (!c || !c.timerId) return;
    clearTimeout(c.timerId);
    c.timerId = 0;
    c.left = Math.max(0, c.left - (Date.now() - c.since));
  };

  useEffect(() => {
    clocks.current.forEach((_, id) => (open ? hold(id) : run(id)));
  }, [open]);

  useEffect(() => {
    // Initial start for new toasts
    clocks.current.forEach((_, id) => {
      if (!openRef.current) run(id);
    });
  }, [itemsList]);

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

  const dismiss = (id: string) => {
    hold(id);
    clocks.current.delete(id);
    setItemsList(prev => prev.map(t => (t.id === id ? { ...t, closing: true } : t)));
    setTimeout(() => {
      setItemsList(prev => prev.filter(t => t.id !== id));
      onDismiss(id);
    }, 250);
  };

  const clearAll = () => {
    clocks.current.forEach(c => {
      if (c.timerId) clearTimeout(c.timerId);
    });
    clocks.current.clear();
    const ids = itemsList.map(t => t.id);
    setItemsList(prev => prev.map(t => ({ ...t, closing: true })));
    setTimeout(() => {
      setItemsList([]);
      ids.forEach(id => onDismiss(id));
    }, 250);
  };

  if (itemsList.length === 0) return null;

  return (
    <section
      aria-label="Notifikasi Keamanan"
      className="pointer-events-none fixed top-[max(1rem,env(safe-area-inset-top))] sm:top-[max(1.25rem,env(safe-area-inset-top))] inset-x-4 sm:right-[max(1.5rem,env(safe-area-inset-right))] sm:left-auto sm:w-96 z-[9999]"
    >
      <div
        ref={boxRef}
        id="toast-stack-box"
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
        onFocus={() => {
          flags.current.focus = true;
          sync();
        }}
        onBlur={event => {
          if (event.currentTarget.contains(event.relatedTarget as Node)) return;
          flags.current.focus = false;
          sync();
        }}
        className="pointer-events-auto relative w-full"
      >
        {/* Count and Clear bar displayed above the stack */}
        <div className="mb-2 flex items-center justify-end gap-2">
          <p
            id="toast-stack-count"
            className="inline-flex h-7 items-center rounded-full bg-white dark:bg-zinc-900 border border-zinc-200/80 dark:border-zinc-800 px-2.5 text-xs font-medium whitespace-nowrap text-zinc-600 dark:text-zinc-400 tabular-nums shadow-xs"
          >
            {`${live.length} notifikasi`}
          </p>
          <button
            type="button"
            onClick={clearAll}
            className="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-full bg-white dark:bg-zinc-900 border border-zinc-200/80 dark:border-zinc-800 px-2.5 text-xs font-medium whitespace-nowrap text-zinc-700 dark:text-zinc-300 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/80 transition-colors shadow-xs"
          >
            <svg className="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M18 6 6 18" />
              <path d="m6 6 12 12" />
            </svg>
            Tutup Semua
          </button>
        </div>

        {/* Stack list */}
        <div role="status" aria-atomic="false">
          <ol
            ref={listRef}
            id="toast-stack-list"
            className="relative transition-[height] duration-300 ease-out"
          >
            {itemsList.map(toast => {
              const style = severityConfig(toast.severity);
              return (
                <li
                  key={toast.id}
                  ref={el => {
                    itemRefs.current[toast.id] = el;
                  }}
                  data-toast=""
                  data-closing={toast.closing ? '' : undefined}
                  onKeyDown={event => event.key === 'Escape' && dismiss(toast.id)}
                  className="group/toast absolute inset-x-0 top-0 origin-top rounded-2xl bg-white dark:bg-[#0c0c0e] border border-zinc-200/90 dark:border-zinc-800 shadow-xl dark:shadow-[0_12px_36px_rgba(0,0,0,0.85)] transition-[translate,scale,height,opacity] duration-300 ease-out data-closing:opacity-0 data-folded:overflow-hidden select-none"
                >
                  <div className="flex items-start gap-3 p-3.5 transition-opacity duration-200 group-data-folded/toast:opacity-0">
                    {style.iconSvg}

                    <div className="min-w-0 grow basis-40 text-sm break-words">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${style.badge}`}>
                          {toast.severity}
                        </span>
                        <span className="text-[10px] text-zinc-400 dark:text-zinc-500 font-mono ml-auto">
                          {new Date(toast.timestamp).toLocaleTimeString('id-ID', {
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                          })}
                        </span>
                      </div>

                      <p className="font-semibold text-zinc-900 dark:text-zinc-100 text-[13px] leading-snug truncate">
                        {toast.title}
                      </p>
                      <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed line-clamp-2">
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
                          Lihat detail <FontAwesomeIcon icon={faArrowRight} className="text-[9px]" />
                        </button>
                      )}
                    </div>

                    <button
                      type="button"
                      data-dismiss=""
                      onClick={() => dismiss(toast.id)}
                      aria-label="Close notification"
                      className="-mt-1 -mr-1 inline-flex size-7 shrink-0 cursor-pointer items-center justify-center rounded-lg text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                    >
                      <svg className="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
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
