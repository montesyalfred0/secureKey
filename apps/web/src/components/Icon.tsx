/**
 * Iconos en linea. Sin libreria externa: en un gestor de contrasenas cada
 * dependencia de JavaScript es superficie de ataque, y los iconos son SVG
 * estaticos que ni pesan ni ejecutan codigo de terceros.
 *
 * Todos usan `currentColor` y trazo de 1.75 para heredar el color del texto
 * y mantener el mismo grosor visual en toda la interfaz.
 */
import type { JSX } from 'preact';

const PATHS = {
  lock: 'M7 11V8a5 5 0 0 1 10 0v3M5 11h14a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1Zm7 4v2',
  unlock: 'M7 11V8a5 5 0 0 1 9.6-2M5 11h14a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1Zm7 4v2',
  shield: 'M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3Zm-2.5 8.5L11 13l3.5-3.5',
  // Llave de arco completo, con su ojo y dos dientes cuadrados.
  //
  // La anterior dibujaba el aro con un arco mayor (`a4 4 0 1 1`) que cerraba
  // descentrado, y luego un vástago en 45 grados que no seguia la linea de los
  // dientes. De lejos no parecia una llave: parecia un bulto con un muescon.
  // Esta es la de siempre, y se lee al instante al lado del candado y el escudo.
  key: 'M15.5 7.5a4.5 4.5 0 1 0-4.2 4.5h-.3L4 19v1h3v-2h2v-2h2l1.6-1.6A4.5 4.5 0 0 1 15.5 7.5Zm-2.2 2.2a1.1 1.1 0 1 1 0-2.2 1.1 1.1 0 0 1 0 2.2Z',
  plus: 'M12 5v14M5 12h14',
  copy: 'M9 9V6a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1h-3M6 9h8a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1Z',
  eye: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Zm9.5 2.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z',
  eyeOff: 'M4 4l16 16M9.9 5.8A9.9 9.9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-3.3 4.1M6.3 7.8A17 17 0 0 0 2.5 12S6 18.5 12 18.5c1 0 1.9-.2 2.7-.5M9.9 9.9a2.5 2.5 0 0 0 3.4 3.4',
  trash: 'M4 7h16M10 4h4M9 7v12m6-12v12M6 7l1 13h10l1-13M10 11v5m4-5v5',
  edit: 'M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17v3Zm10-13 3 3',
  check: 'M5 12.5 10 17.5 19 7',
  x: 'M6 6l12 12M18 6 6 18',
  search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Zm5 -2 4.5 4.5',
  // Engranaje con seis lobulos, simetrico por construccion.
  //
  // El anterior mezclaba `c`, `l` y `a` con radios distintos y no cerraba de
  // forma simetrica: se veia descentrado hacia la derecha y con los dientes
  // de tamanho desigual al lado de los demas iconos, que si son centrados.
  // Este es el engranaje clasico de seis lobulos, dibujado con arcos iguales.
  settings:
    'M12 9a3 3 0 0 0 0 6 3 3 0 0 0 0-6Z' +
    'M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z',
  logout: 'M14 8V6a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-2M10 12h10m0 0-3-3m3 3-3 3',
  sun: 'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0-13v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4',
  moon: 'M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5Z',
  refresh: 'M20 12a8 8 0 1 1-2.6-5.9M20 4v5h-5',
  back: 'M15 5 8 12l7 7',
  forward: 'M9 5l7 7-7 7',
  alert: 'M12 8v5m0 3h.01M10.3 3.9 2.4 17.5A1.6 1.6 0 0 0 3.8 20h16.4a1.6 1.6 0 0 0 1.4-2.5L13.7 3.9a1.6 1.6 0 0 0-2.8 0Z',
  info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-9v5m0-8h.01',
  link: 'M14 11a4 4 0 0 0-5.7 0l-2.8 2.8a4 4 0 0 0 5.7 5.7l1.4-1.4M10 13a4 4 0 0 0 5.7 0l2.8-2.8a4 4 0 0 0-5.7-5.7l-1.4 1.4',
  star: 'm12 4 2.5 5.2 5.5.8-4 3.9 1 5.6-5-2.7-5 2.7 1-5.6-4-3.9 5.5-.8L12 4Z',
  wand: 'M4 20 15 9m0 0 3 3m-3-3-1.5-1.5m4.5 1.5L15 9m-1.5-1.5 2-2a1.4 1.4 0 0 1 2 2l-2 2M5 4v3m-1.5-1.5h3M18 15v3m-1.5-1.5h3',
  chart: 'M4 20V10m5 10V4m5 16v-7m5 7V8',
  clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-14v5l3.5 2',
  menu: 'M4 7h16M4 12h16M4 17h16',
  spinner: 'M12 3a9 9 0 1 0 9 9',
  eyeCheck: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-7 8a7 7 0 0 1 14 0',
  server: 'M4 5h16v4H4V5Zm0 10h16v4H4v-4Zm2-7.5h.01M6 17.5h.01',
  download: 'M12 4v11m0 0 4-4m-4 4-4-4M5 19h14',
} as const;

export type IconName = keyof typeof PATHS;

export type IconProps = JSX.SVGAttributes<SVGSVGElement> & {
  name: IconName;
  size?: number;
};

export function Icon({ name, size = 20, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
