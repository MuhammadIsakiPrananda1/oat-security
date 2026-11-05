import React from 'react';
import { ChevronDown, Check, SlidersHorizontal } from 'lucide-react';
import { IncidentSection, WorkspaceOption } from './types';

interface WorkspaceDropdownProps {
  activeSection: IncidentSection;
  onSelectSection: (section: IncidentSection) => void;
  isOpen: boolean;
  onToggleOpen: () => void;
  onClose: () => void;
  options: WorkspaceOption[];
  metrics: {
    total: number;
    l1Active: number;
    l2Active: number;
    l3Active: number;
  };
  socScope?: 'L1' | 'L2' | 'L3' | null;
}

export const WorkspaceDropdown: React.FC<WorkspaceDropdownProps> = ({
  activeSection,
  onSelectSection,
  isOpen,
  onToggleOpen,
  onClose,
  options,
  socScope
}) => {
  const currentWorkspace = options.find(w => w.id === activeSection) || options[0];

  // If operator is locked to a specific SOC tier, only show their relevant workspaces
  const filteredWorkspaces = options.filter(opt => {
    if (opt.group !== 'workspaces') return true;
    if (!socScope) return true;
    return opt.id === socScope;
  });

  return (
    <div className="relative w-fit">
      <button
        type="button"
        onClick={onToggleOpen}
        className="h-9 px-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold text-zinc-800 dark:text-zinc-200 inline-flex items-center gap-2.5 transition cursor-pointer shadow-xs"
      >
        <SlidersHorizontal className="w-4 h-4 text-zinc-500 dark:text-zinc-400" />
        <span className="text-[13px]">
          {currentWorkspace.label}
        </span>
        <ChevronDown className={`w-4 h-4 text-zinc-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-20 cursor-default"
            onClick={onClose}
          />
          <div className="absolute left-0 top-full mt-2 w-72 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1.5 z-30">
            {/* Workspaces Group */}
            <div className="space-y-0.5">
              {filteredWorkspaces.filter(o => o.group === 'workspaces').map(opt => {
                const isActive = activeSection === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => {
                      onSelectSection(opt.id);
                      onClose();
                    }}
                    className={`w-full px-3 py-2 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                      isActive
                        ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                        : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                    }`}
                  >
                    <span className="text-[13px]">{opt.label}</span>
                    {isActive && <Check className="w-4 h-4 text-emerald-500 shrink-0" />}
                  </button>
                );
              })}
            </div>

            {/* Governance & Reference Group */}
            {filteredWorkspaces.some(o => o.group === 'governance') && (
              <div className="space-y-0.5 pt-1 mt-1 border-t border-zinc-100 dark:border-zinc-800/80">
                {filteredWorkspaces.filter(o => o.group === 'governance').map(opt => {
                  const isActive = activeSection === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => {
                        onSelectSection(opt.id);
                        onClose();
                      }}
                      className={`w-full px-3 py-2 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        isActive
                          ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span className="text-[13px]">{opt.label}</span>
                      {isActive && <Check className="w-4 h-4 text-emerald-500 shrink-0" />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
  );
};
