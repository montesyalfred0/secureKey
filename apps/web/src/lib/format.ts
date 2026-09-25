/** Utilidades de presentacion. Sin dependencias externas. */

/** "hace 3 min", "ayer", "12 mar 2025". */
export function relativeTime(iso: string, now = Date.now()): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '-';

  const diff = Math.max(0, now - then);
  const min = Math.floor(diff / 60_000);
  if (min < 1) return 'ahora mismo';
  if (min < 60) return `hace ${min} min`;

  const hours = Math.floor(min / 60);
  if (hours < 24) return `hace ${hours} h`;

  const days = Math.floor(hours / 24);
  if (days === 1) return 'ayer';
  if (days < 7) return `hace ${days} dias`;
  if (days < 30) return `hace ${Math.floor(days / 7)} sem`;

  return new Date(then).toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

/** Iniciales para el avatar: hasta 2 caracteres, en mayusculas. */
export function initials(value: string): string {
  const words = value.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return '?';
  const first = words[0]?.[0] ?? '';
  const second = words.length > 1 ? (words[1]?.[0] ?? '') : '';
  return (first + second).toUpperCase();
}

/**
 * Color de avatar estable derivado del texto: mismo servicio -> mismo color
 * siempre, para que la lista sea visualmente reconocible de un vistazo.
 */
const AVATAR_COLORS = [
  { bg: 'rgba(99, 102, 241, 0.16)', fg: '#a5b4fc' },
  { bg: 'rgba(45, 212, 191, 0.16)', fg: '#5eead4' },
  { bg: 'rgba(244, 114, 182, 0.16)', fg: '#f9a8d4' },
  { bg: 'rgba(251, 191, 36, 0.16)', fg: '#fcd34d' },
  { bg: 'rgba(167, 139, 250, 0.16)', fg: '#c4b5fd' },
  { bg: 'rgba(56, 189, 248, 0.16)', fg: '#7dd3fc' },
];

export function avatarColor(seed: string): { bg: string; fg: string } {
  let hash = 0;
  for (let i = 0; i < seed.length; i += 1) {
    hash = (hash * 31 + seed.charCodeAt(i)) | 0;
  }
  const index = Math.abs(hash) % AVATAR_COLORS.length;
  return AVATAR_COLORS[index]!;
}

/** Dominio legible a partir de una URL introducida a mano. */
export function displayUrl(url: string): string {
  const trimmed = url.trim();
  if (trimmed.length === 0) return '';
  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    return parsed.host.replace(/^www\./, '');
  } catch {
    return trimmed.replace(/^https?:\/\//, '').replace(/\/$/, '');
  }
}

/** Construye una URL segura para el atributo href. Devuelve '' si no es válida. */
export function safeHref(url: string): string {
  const trimmed = url.trim();
  if (trimmed.length === 0) return '';
  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    // Solo http/https: javascript: y data: son vectores de XSS.
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.toString();
  } catch {
    return '';
  }
}

/** Mascara parcial: deja ver la longitud sin revelar el contenido. */
export function maskPassword(password: string, visible = 4): string {
  if (password.length === 0) return '';
  if (password.length <= visible) return '•'.repeat(password.length);
  return '•'.repeat(Math.min(18, password.length - visible)) + password.slice(-visible);
}

export function pluralize(count: number, singular: string, plural: string): string {
  return count === 1 ? singular : plural;
}
