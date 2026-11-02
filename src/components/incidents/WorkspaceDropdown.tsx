import React from 'react';
import { ChevronDown, Check } from 'lucide-react';
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
    <div className="flex items-center justify-between gap-3 p-2 rounded-2xl bg-zinc-100/80 dark:bg-zinc-900/80 border border-zinc-200/80 dark:border-zinc-800">
      <div className="relative w-full sm:w-auto">
        <button
          type="button"
          onClick={onToggleOpen}
          className="w-full sm:w-auto h-9 px-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] hover:bg-zinc-50 dark:hover:bg-zinc-900 text-xs font-semibold text-zinc-900 dark:text-white inline-flex items-center justify-between sm:justify-start gap-3 transition cursor-pointer shadow-xs"
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <currentWorkspace.icon className={`w-3.5 h-3.5 ${currentWorkspace.iconColor} shrink-0`} />
            <span className="font-semibold text-zinc-800 dark:text-zinc-100 truncate">
              {currentWorkspace.label}
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold shrink-0 ${currentWorkspace.badgeStyle}`}>
              {currentWorkspace.badgeText}
            </span>
            <ChevronDown className={`w-3.5 h-3.5 text-zinc-400 transition-transform duration-200 shrink-0 ${isOpen ? 'rotate-180' : ''}`} />
          </div>
        </button>

        {isOpen && (
          <>
            <div
              className="fixed inset-0 z-30 cursor-default"
              onClick={onClose}
            />
            <div className="absolute left-0 top-full mt-2 w-80 sm:w-96 max-w-[calc(100vw-2rem)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-2 z-40 animate-in fade-in zoom-in-95 duration-150 text-zinc-900 dark:text-zinc-100 space-y-1">
              {/* Header Card Profile-Style */}
              <div className="flex items-center gap-2.5 p-2 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/80 dark:bg-zinc-900/60 mb-2">
                <div className="w-8 h-8 rounded-lg bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center shrink-0">
                  <currentWorkspace.icon className={`w-4 h-4 ${currentWorkspace.iconColor}`} />
                </div>
                <div className="min-w-0 flex-1 leading-tight">
                  <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100 truncate">
                    {currentWorkspace.label}
                  </p>
                  <span className="block text-[11px] text-zinc-500 dark:text-zinc-400 truncate mt-0.5">
                    {currentWorkspace.description}
                  </span>
                </div>
              </div>

              {/* Workspaces Group */}
              <div className="space-y-0.5">
                <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 font-mono">
                  Incident Workspaces
                </div>
                {filteredWorkspaces.filter(o => o.group === 'workspaces').map(opt => {
                  const isActive = activeSection === opt.id;
                  const Icon = opt.icon;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => {
                        onSelectSection(opt.id);
                        onClose();
                      }}
                      className={`w-full p-2 flex items-center gap-2.5 rounded-lg transition-colors text-left cursor-pointer ${
                        isActive
                          ? 'bg-zinc-100 dark:bg-zinc-800/90 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 dark:hover:text-zinc-100'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 ${opt.iconColor} shrink-0`} />
                      <span className="text-xs flex-1 truncate">{opt.label}</span>
                      <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold shrink-0 ${opt.badgeStyle}`}>
                        {opt.badgeText}
                      </span>
                      {isActive && <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0 ml-1" />}
                    </button>
                  );
                })}
              </div>

              {/* Governance & Reference Group */}
              <div className="space-y-0.5 pt-1 border-t border-zinc-100 dark:border-zinc-800/80">
                <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 font-mono">
                  Governance &amp; Reference
                </div>
                {filteredWorkspaces.filter(o => o.group === 'governance').map(opt => {
                  const isActive = activeSection === opt.id;
                  const Icon = opt.icon;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => {
                        onSelectSection(opt.id);
                        onClose();
                      }}
                      className={`w-full p-2 flex items-center gap-2.5 rounded-lg transition-colors text-left cursor-pointer ${
                        isActive
                          ? 'bg-zinc-100 dark:bg-zinc-800/90 text-zinc-900 dark:text-white font-semibold'
                          : 'text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 hover:bg-zinc-100 dark:hover:bg-zinc-800/80 dark:hover:text-zinc-100'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 ${opt.iconColor} shrink-0`} />
                      <span className="text-xs flex-1 truncate">{opt.label}</span>
                      <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold shrink-0 ${opt.badgeStyle}`}>
                        {opt.badgeText}
                      </span>
                      {isActive && <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0 ml-1" />}
                    </button>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
