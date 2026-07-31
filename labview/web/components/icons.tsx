/** Tiny inline icons. Status/auth cues ship as icon + label, never color alone. */
import type { JSX } from "preact";

type P = { size?: number } & JSX.SVGAttributes<SVGSVGElement>;

function base(size: number): JSX.SVGAttributes<SVGSVGElement> {
  return {
    width: size,
    height: size,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": 1.6,
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  };
}

export const IconGlobe = ({ size = 13, ...r }: P) => (
  <svg {...base(size)} {...r}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="M1.8 8h12.4M8 1.8c1.9 2 1.9 10.4 0 12.4M8 1.8c-1.9 2-1.9 10.4 0 12.4" />
  </svg>
);

export const IconLan = ({ size = 13, ...r }: P) => (
  <svg {...base(size)} {...r}>
    <rect x="6" y="1.6" width="4" height="3.2" rx="0.6" />
    <rect x="1.6" y="11.2" width="4" height="3.2" rx="0.6" />
    <rect x="10.4" y="11.2" width="4" height="3.2" rx="0.6" />
    <path d="M8 4.8v3.4M3.6 11.2V8.2h8.8v3M8 8.2v3" />
  </svg>
);

export const IconShield = ({ size = 13, ...r }: P) => (
  <svg {...base(size)} {...r}>
    <path d="M8 1.6l5 1.8v4.1c0 3-2.1 5-5 6.9-2.9-1.9-5-3.9-5-6.9V3.4z" />
    <path d="M5.8 8l1.6 1.6L10.4 6.5" />
  </svg>
);

export const IconLock = ({ size = 13, ...r }: P) => (
  <svg {...base(size)} {...r}>
    <rect x="3.2" y="7" width="9.6" height="7" rx="1.2" />
    <path d="M5.4 7V5a2.6 2.6 0 015.2 0v2" />
  </svg>
);

export const IconWarning = ({ size = 13, ...r }: P) => (
  <svg {...base(size)} {...r}>
    <path d="M8 2.2l6.2 10.8H1.8z" />
    <path d="M8 6.6v3.1M8 11.6h.01" />
  </svg>
);

export const IconServer = ({ size = 13, ...r }: P) => (
  <svg {...base(size)} {...r}>
    <rect x="2" y="2.4" width="12" height="4.4" rx="1" />
    <rect x="2" y="9.2" width="12" height="4.4" rx="1" />
    <path d="M4.4 4.6h.01M4.4 11.4h.01" />
  </svg>
);
