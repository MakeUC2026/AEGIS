// Small stroke icon set (24px grid) and the AEGIS "A" mark. Decorative: always paired with text.

const PATHS = {
  grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  pulse: "M3 12h4l3-7 4 14 3-7h4",
  chat: "M4 5h16v11H9l-5 4z",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.1-8 9-4.6-.9-8-4.5-8-9V6z",
  users: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21c0-3.9 3.1-7 7-7s7 3.1 7 7M16 3.5a4 4 0 0 1 0 7.5M18 14.5c2.4.9 4 3.2 4 6.5",
  chart: "M4 20V10M10 20V4M16 20v-7M22 20H2",
  key: "M14 10a4 4 0 1 0-1.2 2.8L21 21M17 17l2-2M15 15l2-2",
  home: "M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  check: "M9 11l3 3 8-8M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9",
  book: "M4 4.5A1.5 1.5 0 0 1 5.5 3H20v15H5.5A1.5 1.5 0 0 0 4 19.5zM4 19.5A1.5 1.5 0 0 0 5.5 21H20",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  play: "M7 4l13 8-13 8z",
  doc: "M6 3h9l5 5v13H6zM14 3v6h6",
  spark: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z",
  terminal: "M4 6l6 6-6 6M12 18h8",
  menu: "M4 6h16M4 12h16M4 18h16",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name }: { name: IconName }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  );
}

// AEGIS mark: flat-topped A whose crossbar is cut off from the right leg by a diagonal slit.
// Drawn as a mask so the cut shows whatever is behind the logo.
export function LogoMark() {
  return (
    <svg viewBox="0 0 200 176" aria-hidden="true">
      <mask id="aegis-a-cut">
        <path d="M0 175 75 0h45l80 175z" fill="#fff" />
        <path d="M97 43 73.4 103h50zM61.5 133h75l18.5 42H45z" fill="#000" />
        <path d="M116 100l46 25" stroke="#000" strokeWidth="9" />
      </mask>
      <rect width="200" height="176" fill="currentColor" mask="url(#aegis-a-cut)" />
    </svg>
  );
}
