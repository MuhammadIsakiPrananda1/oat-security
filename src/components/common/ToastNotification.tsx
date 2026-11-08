import React, { useEffect, useLayoutEffect, useRef, useState, useCallback } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowRight, faShieldHalved, faTriangleExclamation, faCircleCheck, faCircleInfo, faXmark } from '@fortawesome/free-solid-svg-icons';
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

// Folded, up to two older toasts peek out 8px each behind the newest; open, they stand 10px apart.
const PEEK = 8;
const GAP = 10;
const FOLD = 2;
const LIFE = 6500;
const MAX = 4;

function severityConfig(severity: string) {
  const s = severity?.toUpperCase?.() || '';
  if (s === 'SUCCESS' || s === 'RESOLVED') {
    return {
      dot: 'bg-emerald-500',
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      badgeBg: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
      iconBg: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
      icon: <FontAwesomeIcon icon={faCircleCheck} className="text-xs" />
    };
  }
  if (s === 'CRITICAL' || s === 'ERROR' || s === 'HIGH') {
    return {
      dot: 'bg-rose-500',
      border: 'border-rose-500/25 hover:border-rose-500/45',
      badgeBg: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/25',
      iconBg: 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
      icon: <FontAwesomeIcon icon={faShieldHalved} className="text-xs" />
    };
  }
  if (s === 'MEDIUM' || s === 'WARNING' || s === 'WARN') {
    return {
      dot: 'bg-amber-500',
      border: 'border-amber-500/20 hover:border-amber-500/40',
      badgeBg: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
      iconBg: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
      icon: <FontAwesomeIcon icon={faTriangleExclamation} className="text-xs" />
    };
  }
  return {
    dot: 'bg-blue-500',
    border: 'border-blue-500/20 hover:border-blue-500/40',
    badgeBg: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
    iconBg: 'bg-blue-500/10 text-blue-600 dark:text-blue-400',
    icon: <FontAwesomeIcon icon={faCircleInfo} className="text-xs" />
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

  // Sync incoming props into itemsList (newest at the end for clean top stack)
  useEffect(() => {
    setItemsList(prev => {
      const existingIds = new Set(prev.map(p => p.id));
      const nextItems: ToastInternal[] = [...prev];

      incomingToasts.forEach(t => {
        if (!existingIds.has(t.id)) {
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

  // Top-anchored layout right below DashboardTopNav: stacks downwards
  const layout = useCallback(() => {
    if (!listRef.current) return;
    const els = [...listRef.current.querySelectorAll<HTMLElement>('[data-toast]:not([data-closing])')];
    if (els.length === 0) {
      listRef.current.style.height = '0px';
      return;
    }
    const heights = els.map(li => {
      const child = li.firstElementChild as HTMLElement;
      return child ? child.offsetHeight : 68;
    });
    const front = heights[heights.length - 1] || 0;
    let y = 0;
    for (let d = 0; d < els.length; d++) {
      const li = els[els.length - 1 - d];
      const h = heights[els.length - 1 - d];
      if (openRef.current) {
        li.style.translate = `0 ${y}px`;
        li.style.scale = '1';
        li.style.height = `${h}px`;
        li.style.opacity = '';
        li.removeAttribute('data-folded');
        y += h + GAP;
      } else {
        li.style.translate = `0 ${Math.min(d, FOLD) * PEEK}px`;
        li.style.scale = String(1 - Math.min(d, FOLD + 1) * 0.04);
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
    li.setAttribute('data-closing', '');
    drop([id]);
  };

  const clearAll = () => {
    const ids = itemsList.map(toast => toast.id);
    setItemsList(list => list.map(toast => ({ ...toast, closing: true })));
    drop(ids);
  };

  return (
    <aside
      aria-label="Security Notifications"
      className="pointer-events-none fixed top-[4.75rem] right-4 sm:right-6 z-[9999] w-[calc(100vw-2rem)] sm:w-[410px]"
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
        className="pointer-events-auto relative w-full flex flex-col justify-start"
      >
        {/* Header toolbar when multi-alerts are present */}
        {live.length > 1 && (
          <div className="mb-2 flex items-center justify-between px-1">
            <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
              <span className="size-1.5 rounded-full bg-emerald-500" />
              {getLanguage() === 'id' ? 'Peringatan Keamanan' : 'Security Alerts'}
            </span>
            <div className="flex items-center gap-2">
              <span className="inline-flex h-5 items-center rounded-md bg-zinc-200/70 px-2 text-[10px] font-bold tabular-nums text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                {live.length}
              </span>
              <button
                type="button"
                onClick={clearAll}
                className="text-[11px] font-medium text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 transition-colors cursor-pointer"
              >
                {getLanguage() === 'id' ? 'Hapus semua' : 'Clear all'}
              </button>
            </div>
          </div>
        )}

        <div role="status" aria-atomic="false">
          <ol
            ref={listRef}
            id="toast-stack-list"
            className="relative transition-[height] duration-300 ease-out motion-reduce:transition-none"
          >
            {itemsList.map(toast => {
              const cfg = severityConfig(toast.severity);
              return (
                <li
                  key={toast.id}
                  ref={el => {
                    items.current[toast.id] = el;
                  }}
                  data-toast=""
                  data-closing={toast.closing ? '' : undefined}
                  onKeyDown={event => event.key === 'Escape' && dismiss(toast.id)}
                  className={`group/toast absolute inset-x-0 top-0 origin-top rounded-xl border bg-white dark:bg-[#121215] shadow-lg shadow-black/10 dark:shadow-black/40 transition-[translate,scale,height,opacity] duration-300 ease-out data-closing:opacity-0 data-closing:scale-95 data-folded:overflow-hidden motion-reduce:transition-none ${cfg.border}`}
                >
                  <div className="p-3.5 flex items-start gap-3 rounded-xl">
                    <div className={`mt-0.5 shrink-0 flex items-center justify-center size-7 rounded-lg border border-black/5 dark:border-white/5 ${cfg.iconBg}`}>
                      {cfg.icon}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-mono font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border ${cfg.badgeBg}`}>
                          {toast.severity || 'ALERT'}
                        </span>
                        <h4 className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                          {toast.title}
                        </h4>
                      </div>

                      <p className="mt-1 text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed break-words line-clamp-2">
                        {toast.desc}
                      </p>

                      {toast.onNavigate && (
                        <div className="mt-2 flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              toast.onNavigate?.();
                              dismiss(toast.id);
                            }}
                            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors cursor-pointer"
                          >
                            <span>{getLanguage() === 'id' ? 'Lihat detail' : 'View detail'}</span>
                            <FontAwesomeIcon icon={faArrowRight} className="text-[10px]" />
                          </button>
                        </div>
                      )}
                    </div>

                    <button
                      type="button"
                      onClick={() => dismiss(toast.id)}
                      aria-label="Dismiss notification"
                      className="shrink-0 size-6 flex items-center justify-center rounded-md text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors cursor-pointer"
                    >
                      <FontAwesomeIcon icon={faXmark} className="text-xs" />
                    </button>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      </div>
    </aside>
  );
};
