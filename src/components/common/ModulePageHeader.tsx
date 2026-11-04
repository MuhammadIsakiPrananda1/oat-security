import React from 'react';
import { translatePageTitle } from '../../i18n/translator';

interface ModulePageHeaderProps {
  /** Icon node rendered inside the 44px inverted mark; glyph styling is centralized here. */
  icon: React.ReactNode;
  /** Bold part of the title. */
  title: string;
  /** Muted light-tail part of the title, e.g. "Overview". */
  titleTail?: string;
  /** Small chip next to the title (tenant name, engine badge…). */
  badge?: React.ReactNode;
  /** Muted one-line description below the title. */
  subtitle?: React.ReactNode;
  /** Right-side action buttons / filters. */
  actions?: React.ReactNode;
}

/**
 * Canonical page header for every dashboard module — the balanced dashboard
 * identity: 44px inverted icon mark, extrabold title with light tail, small
 * chip, one-line muted subtitle.
 */
export const ModulePageHeader: React.FC<ModulePageHeaderProps> = ({
  icon,
  title,
  titleTail,
  badge,
  subtitle,
  actions
}) => {
  // Page titles are a deliberate two-tone composition ("Protected" +
  // "Applications"). Translate the pair as one phrase so Indonesian word order
  // stays natural while the bold/muted layout is preserved.
  const localizedTitle = translatePageTitle(title, titleTail);
  const displayTitle = localizedTitle?.main ?? title;
  const displayTail = localizedTitle ? localizedTitle.tail : titleTail;

  return (
    <header className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] px-5 py-4 shadow-2xs transition-colors flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div className="flex items-center gap-3.5 min-w-0">
        <span
          aria-hidden="true"
          className="w-11 h-11 shrink-0 rounded-xl bg-zinc-900 dark:bg-zinc-100 flex items-center justify-center shadow-xs [&_svg]:w-5 [&_svg]:h-5 [&_svg]:text-[20px] [&_svg]:text-white dark:[&_svg]:text-zinc-900 [&_svg]:shrink-0"
        >
          {icon}
        </span>
        <div className="min-w-0 leading-tight">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-base font-extrabold tracking-tight text-zinc-900 dark:text-white">
              {displayTitle}
              {displayTail ? <span className="font-light text-zinc-500 dark:text-zinc-400"> {displayTail}</span> : null}
            </h1>
            {badge}
          </div>
          {subtitle ? (
            <p className="text-[11px] font-medium text-zinc-400 dark:text-zinc-500 mt-1 max-w-3xl leading-normal truncate">
              {subtitle}
            </p>
          ) : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2 shrink-0">{actions}</div> : null}
    </header>
  );
};

/** Standard title chip (gray, bordered) — matches the dashboard tenant chip. */
export const ModulePageBadge: React.FC<{ children: React.ReactNode; isDimmed?: boolean }> = ({ children, isDimmed }) => (
  <span className={`inline-flex items-center gap-1.5 text-[11px] font-medium px-2 py-0.5 rounded-md border truncate max-w-[240px] transition-colors ${
    isDimmed
      ? 'bg-zinc-100/60 dark:bg-zinc-800/40 border-dashed border-zinc-300 dark:border-zinc-700/80 text-zinc-400 dark:text-zinc-500 italic'
      : 'bg-zinc-100 dark:bg-zinc-800 border-zinc-200/80 dark:border-zinc-700/80 text-zinc-700 dark:text-zinc-300'
  }`}>
    {children}
  </span>
);
