import { useEffect, type FC } from 'react';
import { getLanguage, startTranslator } from './translator';

/**
 * Mounts once at the application root so every route — public landing page,
 * login, dashboard and super-admin console — shares the same language layer.
 */
export const GlobalTranslator: FC = () => {
  useEffect(() => {
    const language = getLanguage();
    document.documentElement.lang = language;
    return startTranslator(language);
  }, []);

  return null;
};
