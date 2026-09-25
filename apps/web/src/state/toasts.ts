/**
 * Avisos efimeros (toasts).
 *
 * Store module con suscripcion en lugar de contexto: cualquier componente
 * puede notificar sin arrastrar el proveedor por todo el arbol.
 */
import { useEffect, useState } from 'preact/hooks';
import type { IconName } from '../components/Icon.js';

export type ToastTone = 'success' | 'error' | 'info' | 'warning';

export type Toast = {
  id: number;
  message: string;
  tone: ToastTone;
  icon?: IconName;
  /** ms; 0 para persistir hasta que se cierre a mano. */
  duration: number;
};

type Listener = (toasts: Toast[]) => void;

let toasts: Toast[] = [];
let nextId = 1;
const listeners = new Set<Listener>();

const ICONS: Record<ToastTone, IconName> = {
  success: 'check',
  error: 'alert',
  info: 'info',
  warning: 'alert',
};

function emit(): void {
  for (const listener of listeners) listener(toasts);
}

export function dismissToast(id: number): void {
  const next = toasts.filter((toast) => toast.id !== id);
  if (next.length === toasts.length) return;
  toasts = next;
  emit();
}

export function notify(message: string, tone: ToastTone = 'info', duration = 3200): number {
  const id = nextId++;
  toasts = [...toasts, { id, message, tone, icon: ICONS[tone], duration }];
  emit();
  if (duration > 0) {
    setTimeout(() => dismissToast(id), duration);
  }
  return id;
}

export const toast = {
  success: (message: string) => notify(message, 'success'),
  error: (message: string) => notify(message, 'error', 5000),
  info: (message: string) => notify(message, 'info'),
  warning: (message: string) => notify(message, 'warning', 4200),
};

export function useToasts(): Toast[] {
  const [snapshot, setSnapshot] = useState<Toast[]>(toasts);
  useEffect(() => {
    listeners.add(setSnapshot);
    setSnapshot(toasts);
    return () => {
      listeners.delete(setSnapshot);
    };
  }, []);
  return snapshot;
}
