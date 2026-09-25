/** Tema claro/oscuro. Persiste la preferencia y la aplica a `<html>`. */
import { useEffect, useState } from 'preact/hooks';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'securekey:theme';

function readInitial(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'dark' || stored === 'light') return stored;
  } catch {
    // Modo privado o almacenamiento bloqueado: seguimos con la preferencia.
  }
  const prefersLight =
    typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches;
  return prefersLight ? 'light' : 'dark';
}

function apply(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
  const meta = document.querySelector('meta[name="color-scheme"]');
  meta?.setAttribute('content', theme === 'dark' ? 'dark light' : 'light dark');
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(readInitial);

  useEffect(() => {
    apply(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Si no se puede guardar, el tema solo dura esta pestana.
    }
  }, [theme]);

  return { theme, toggle: () => setTheme((current) => (current === 'dark' ? 'light' : 'dark')) };
}
