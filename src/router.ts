import { useEffect, useState } from 'react';

/**
 * Minimal history-based router for the SPA. The app is served by a single
 * Express entry that falls back to index.html, so real URL paths (e.g.
 * /login, /dashboard/waf) work on refresh and can be shared as deep links.
 */

export function usePathname(): string {
  const [pathname, setPathname] = useState<string>(
    () => (typeof window === 'undefined' ? '/' : window.location.pathname)
  );

  useEffect(() => {
    const handleChange = () => setPathname(window.location.pathname);
    window.addEventListener('popstate', handleChange);
    return () => window.removeEventListener('popstate', handleChange);
  }, []);

  return pathname;
}

export function navigate(to: string, options: { replace?: boolean } = {}) {
  if (typeof window === 'undefined') return;
  if (window.location.pathname === to) return;

  if (options.replace) {
    window.history.replaceState(null, '', to);
  } else {
    window.history.pushState(null, '', to);
  }
  // pushState/replaceState do not emit popstate — notify subscribers manually.
  window.dispatchEvent(new Event('popstate'));
}
