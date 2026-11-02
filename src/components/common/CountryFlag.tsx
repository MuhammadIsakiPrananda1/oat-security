import React, { useState } from 'react';
import { getCountryName } from '../../utils/ip';

interface CountryFlagProps {
  code?: string;
  name?: string;
  className?: string;
  width?: number;
  height?: number;
  title?: string;
}

/**
 * Visual Country Flag component that works 100% reliably across all operating systems,
 * including Windows where unicode emoji flags are not rendered by the OS font.
 */
export const CountryFlag: React.FC<CountryFlagProps> = ({
  code,
  name,
  className = '',
  width = 20,
  height = 14,
  title
}) => {
  let cleanCode = String(code || '').toUpperCase().trim();
  // Map local/LAN/SYS to Indonesia (host public origin)
  if (!cleanCode || cleanCode === 'LAN' || cleanCode === 'SYS') {
    cleanCode = 'ID';
  }

  const countryTitle = title || getCountryName(cleanCode, name);
  const [imgError, setImgError] = useState(false);

  // High-fidelity instant vector flags for top countries (0ms load, guaranteed offline)
  if (cleanCode === 'ID') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 3 2" className="w-full h-full block">
          <rect width="3" height="1" fill="#e70011" />
          <rect width="3" height="1" y="1" fill="#ffffff" />
        </svg>
      </span>
    );
  }

  if (cleanCode === 'DE') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 5 3" className="w-full h-full block">
          <rect width="5" height="1" fill="#000000" />
          <rect width="5" height="1" y="1" fill="#dd0000" />
          <rect width="5" height="1" y="2" fill="#ffce00" />
        </svg>
      </span>
    );
  }

  if (cleanCode === 'RU') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 3 2" className="w-full h-full block">
          <rect width="3" height="0.67" fill="#ffffff" />
          <rect width="3" height="0.67" y="0.67" fill="#0039a6" />
          <rect width="3" height="0.67" y="1.33" fill="#d52b1e" />
        </svg>
      </span>
    );
  }

  if (cleanCode === 'NL') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 3 2" className="w-full h-full block">
          <rect width="3" height="0.67" fill="#ae1c28" />
          <rect width="3" height="0.67" y="0.67" fill="#ffffff" />
          <rect width="3" height="0.67" y="1.33" fill="#21468b" />
        </svg>
      </span>
    );
  }

  if (cleanCode === 'FR') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 3 2" className="w-full h-full block">
          <rect width="1" height="2" fill="#002654" />
          <rect width="1" height="2" x="1" fill="#ffffff" />
          <rect width="1" height="2" x="2" fill="#ce1126" />
        </svg>
      </span>
    );
  }

  if (cleanCode === 'IT') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 3 2" className="w-full h-full block">
          <rect width="1" height="2" fill="#009246" />
          <rect width="1" height="2" x="1" fill="#ffffff" />
          <rect width="1" height="2" x="2" fill="#ce2b37" />
        </svg>
      </span>
    );
  }

  if (cleanCode === 'JP') {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs ${className}`}
        style={{ width, height }}
      >
        <svg viewBox="0 0 3 2" className="w-full h-full block">
          <rect width="3" height="2" fill="#ffffff" />
          <circle cx="1.5" cy="1" r="0.6" fill="#bc002d" />
        </svg>
      </span>
    );
  }

  // Fallback if country code is not a 2-letter ISO
  if (!/^[A-Z]{2}$/.test(cleanCode) || imgError) {
    return (
      <span
        title={countryTitle}
        className={`inline-flex shrink-0 items-center justify-center rounded-[2.5px] bg-zinc-200/80 dark:bg-zinc-700/80 text-[10px] text-zinc-600 dark:text-zinc-300 font-mono font-medium ${className}`}
        style={{ width, height }}
      >
        🌐
      </span>
    );
  }

  // Universal CDN flag image for any other ISO country code
  const lowerCode = cleanCode.toLowerCase();
  return (
    <span
      title={countryTitle}
      className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[2.5px] border border-black/15 dark:border-white/20 shadow-2xs bg-zinc-100 dark:bg-zinc-800 ${className}`}
      style={{ width, height }}
    >
      <img
        src={`https://flagcdn.com/w40/${lowerCode}.png`}
        srcSet={`https://flagcdn.com/w80/${lowerCode}.png 2x`}
        alt={countryTitle}
        className="w-full h-full object-cover block"
        onError={() => setImgError(true)}
        loading="lazy"
      />
    </span>
  );
};
