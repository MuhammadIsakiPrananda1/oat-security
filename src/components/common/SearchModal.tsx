import React, { useState, useEffect, useRef } from 'react';
import { Search, ArrowRight } from 'lucide-react';
import { DashboardView, NAV_GROUPS } from '../layout/DashboardSidebar';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (view: DashboardView) => void;
}

function renderHighlighted(text: string, term: string) {
  const query = term.trim();
  if (!query) return text;
  const lower = text.toLowerCase();
  const needle = query.toLowerCase();
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  let idx = lower.indexOf(needle);
  let key = 0;
  while (idx !== -1) {
    if (idx > cursor) parts.push(text.slice(cursor, idx));
    parts.push(
      <span key={key++} className="bg-zinc-200 text-zinc-900 dark:bg-white/15 dark:text-white rounded px-0.5">
        {text.slice(idx, idx + needle.length)}
      </span>
    );
    cursor = idx + needle.length;
    idx = lower.indexOf(needle, cursor);
  }
  if (cursor < text.length) parts.push(text.slice(cursor));
  return parts;
}

export const SearchModal: React.FC<SearchModalProps> = ({ isOpen, onClose, onNavigate }) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset search state every time the modal opens
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setActiveIndex(0);
    }
  }, [isOpen]);

  // Close on ESC
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const term = (query || '').trim().toLowerCase();

  // Quick navigation source: every entry of the sidebar menu, grouped exactly
  // like the sidebar so the two never drift apart.
  const visibleGroups = NAV_GROUPS
    .map(group => ({
      group: group.group,
      items: group.items.filter(item =>
        !term || item.label.toLowerCase().includes(term) || group.group.toLowerCase().includes(term)
      )
    }))
    .filter(group => group.items.length > 0);

  const flatVisible = visibleGroups.flatMap(group => group.items);
  const indexById = new Map(flatVisible.map((item, index) => [item.id, index]));

  const clampedIndex = Math.min(activeIndex, Math.max(flatVisible.length - 1, 0));

  // Keep the highlighted result visible while navigating with arrow keys
  useEffect(() => {
    if (!isOpen) return;
    const el = listRef.current?.querySelector(`[data-index="${clampedIndex}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [isOpen, clampedIndex]);

  if (!isOpen) return null;

  const openItem = (index: number) => {
    const item = flatVisible[index];
    if (!item) return;
    onNavigate(item.id);
    onClose();
  };

  const handleListKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex(prev => (flatVisible.length === 0 ? 0 : (prev + 1) % flatVisible.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex(prev => (flatVisible.length === 0 ? 0 : (prev - 1 + flatVisible.length) % flatVisible.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      openItem(clampedIndex);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/40 dark:bg-black/80 backdrop-blur-sm flex items-start justify-center pt-16 sm:pt-24 p-4"
      onMouseDown={e => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-xl rounded-2xl border border-zinc-200/80 dark:border-white/10 bg-white dark:bg-[#0a0a0a] shadow-2xl overflow-hidden text-zinc-900 dark:text-zinc-100 transition-colors">
        {/* Search Input */}
        <div className="px-4 py-3.5 border-b border-zinc-100 dark:border-white/10 flex items-center gap-3">
          <Search className="w-5 h-5 text-zinc-400 dark:text-slate-500 shrink-0" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={handleListKeyDown}
            placeholder="Search menu or module..."
            className="flex-1 min-w-0 bg-transparent text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none"
          />
          {query && (
            <button
              onClick={() => {
                setQuery('');
                setActiveIndex(0);
              }}
              className="text-[11px] text-zinc-500 hover:text-zinc-900 px-2 py-0.5 rounded border border-zinc-200 hover:border-zinc-300 dark:text-slate-400 dark:hover:text-white dark:border-white/10 dark:hover:border-white/25 transition shrink-0 cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>

        {/* Navigation Results */}
        <div ref={listRef} className="max-h-[60vh] sm:max-h-80 overflow-y-auto p-2 custom-scrollbar">
          <div className="flex items-center justify-between px-3 py-1.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-slate-500">
              {term ? 'Search Results' : 'Quick Navigation'}
            </div>
            <div className="text-[11px] font-mono text-zinc-400 dark:text-slate-500">
              {flatVisible.length} items
            </div>
          </div>

          {flatVisible.length === 0 ? (
            <div className="p-6 text-center">
              <div className="text-sm text-zinc-700 dark:text-slate-300">{`No menu matches “${query}”.`}</div>
              <div className="text-[11px] text-zinc-400 dark:text-slate-500 mt-1">Try another term such as "waf", "firewall", or "reports".</div>
            </div>
          ) : (
            visibleGroups.map(group => (
              <div key={group.group} className="mb-1">
                <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-slate-500">
                  {group.group}
                </div>
                {group.items.map(item => {
                  const Icon = item.icon;
                  const idx = indexById.get(item.id) ?? -1;
                  const isActive = idx === clampedIndex;
                  return (
                    <button
                      key={item.id}
                      data-index={idx}
                      onClick={() => openItem(idx)}
                      onMouseEnter={() => setActiveIndex(idx)}
                      className={`w-full text-left p-3 rounded-xl flex items-center justify-between gap-3 transition cursor-pointer ${isActive ? 'bg-zinc-100 dark:bg-white/10' : 'hover:bg-zinc-50 dark:hover:bg-white/5'
                        }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 transition ${isActive ? 'bg-zinc-200 text-zinc-900 dark:bg-white/15 dark:text-white' : 'bg-zinc-100 text-zinc-500 dark:bg-white/5 dark:text-slate-400'
                          }`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-zinc-900 dark:text-white truncate">{renderHighlighted(item.label, term)}</span>
                            {item.live && (
                              <span className="flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-md border border-zinc-300 bg-zinc-50 text-zinc-700 dark:border-white/30 dark:bg-white/5 dark:text-white shrink-0">
                                <span className="w-1.5 h-1.5 rounded-full bg-zinc-700 dark:bg-white" />
                                LIVE
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-zinc-400 dark:text-slate-500">{group.group}</div>
                        </div>
                      </div>
                      <ArrowRight className={`w-4 h-4 shrink-0 transition ${isActive ? 'text-zinc-900 dark:text-white' : 'text-zinc-300 dark:text-slate-600'}`} />
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="px-4 py-2.5 border-t border-zinc-100 dark:border-white/10 bg-zinc-50 dark:bg-white/[0.02] flex items-center justify-between text-[11px] text-zinc-400 dark:text-slate-500">
          <span className="flex items-center gap-3">
            <span><kbd className="px-1 py-0.5 bg-zinc-100 border border-zinc-200 dark:bg-white/5 dark:border-white/10 rounded font-mono">↑↓</kbd> navigate</span>
            <span><kbd className="px-1 py-0.5 bg-zinc-100 border border-zinc-200 dark:bg-white/5 dark:border-white/10 rounded font-mono">↵</kbd> Enter to open</span>
          </span>
        </div>
      </div>
    </div>
  );
};
