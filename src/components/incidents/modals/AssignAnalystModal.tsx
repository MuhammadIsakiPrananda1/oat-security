import React from 'react';
import { X, User as UserIcon, Check } from 'lucide-react';
import { Incident } from '../types';
import { User } from '../../../types';

interface AssignAnalystModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: Incident | null;
  selectedAssignee: string;
  onAssigneeChange: (email: string) => void;
  onConfirm: () => void;
  analysts?: User[];
  userEmail?: string;
  busy: boolean;
}

export const AssignAnalystModal: React.FC<AssignAnalystModalProps> = ({
  isOpen,
  onClose,
  incident,
  selectedAssignee,
  onAssigneeChange,
  onConfirm,
  analysts = [],
  userEmail,
  busy
}) => {
  if (!isOpen || !incident) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 animate-fadeIn">
      <div className="relative w-full max-w-md max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-4 sm:p-6 text-zinc-900 dark:text-zinc-100">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-200 dark:border-zinc-800 mb-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-600 flex items-center justify-center shrink-0">
              <UserIcon className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white">Assign Incident Owner</h3>
              <p className="text-xs text-zinc-500">Target Incident: {incident.id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-2">
              Select Real SOC Analyst / Operator (Database Directory)
            </label>
            <div className="space-y-1.5 max-h-56 overflow-y-auto p-1 border border-zinc-200 dark:border-zinc-800 rounded-xl bg-zinc-50/50 dark:bg-zinc-900/30">
              {/* Option to assign to currently logged in operator */}
              {userEmail && (
                <div
                  onClick={() => onAssigneeChange(userEmail)}
                  className={`p-2.5 rounded-lg flex items-center justify-between gap-2.5 transition cursor-pointer ${
                    selectedAssignee === userEmail
                      ? 'bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 text-indigo-900 dark:text-indigo-200'
                      : 'hover:bg-zinc-100 dark:hover:bg-zinc-800/60 border border-transparent text-zinc-800 dark:text-zinc-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-7 h-7 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-xs shrink-0">
                      ME
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold truncate">Myself (Current Session)</div>
                      <div className="text-[10px] text-zinc-500 dark:text-zinc-400 truncate">{userEmail}</div>
                    </div>
                  </div>
                  {selectedAssignee === userEmail && <Check className="w-4 h-4 text-indigo-600 shrink-0" />}
                </div>
              )}

              {/* All registered users in the organization */}
              {analysts.map(u => {
                const isSelected = selectedAssignee === u.email;
                return (
                  <div
                    key={u.id}
                    onClick={() => onAssigneeChange(u.email)}
                    className={`p-2.5 rounded-lg flex items-center justify-between gap-2.5 transition cursor-pointer ${
                      isSelected
                        ? 'bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 text-indigo-900 dark:text-indigo-200'
                        : 'hover:bg-zinc-100 dark:hover:bg-zinc-800/60 border border-transparent text-zinc-800 dark:text-zinc-200'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className="w-7 h-7 rounded-full bg-zinc-200 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 flex items-center justify-center font-bold text-xs font-mono shrink-0">
                        {(u.name || u.email)[0].toUpperCase()}
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-bold truncate flex items-center gap-1.5">
                          <span>{u.name || 'Analyst'}</span>
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-zinc-200/80 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">
                            {u.role}
                          </span>
                        </div>
                        <div className="text-[10px] text-zinc-500 dark:text-zinc-400 font-mono truncate">{u.email}</div>
                      </div>
                    </div>
                    {isSelected && <Check className="w-4 h-4 text-indigo-600 shrink-0" />}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-3 flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-end gap-2 border-t border-zinc-200 dark:border-zinc-800">
            <button
              type="button"
              onClick={onClose}
              className="w-full sm:w-auto px-3.5 py-2 rounded-lg text-xs text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 cursor-pointer text-center"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onConfirm}
              disabled={busy || !selectedAssignee}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 cursor-pointer shadow-xs text-center transition"
            >
              {busy ? 'Assigning…' : 'Confirm Assignment'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
