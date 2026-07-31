import { useEffect, useRef, useState } from "preact/hooks";
import mermaid from "mermaid";
import { resolveVar } from "../lib/palette";

let counter = 0;

function ensureInit() {
  // Re-init each render so theme variables track the live palette.
  mermaid.initialize({
    startOnLoad: false,
    securityLevel: "strict",
    theme: "base",
    fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif',
    themeVariables: {
      background: "transparent",
      primaryColor: resolveVar("--surface-2"),
      primaryTextColor: resolveVar("--ink"),
      primaryBorderColor: resolveVar("--baseline"),
      lineColor: resolveVar("--muted"),
      tertiaryColor: resolveVar("--surface"),
      fontSize: "13px",
    },
  });
}

/** Render a Mermaid definition string to inline SVG. Re-renders when `def` changes. */
export function Mermaid({ def }: { def: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    ensureInit();
    const id = `mmd-${counter++}`;
    mermaid
      .render(id, def)
      .then(({ svg }) => {
        if (!cancelled && ref.current) {
          ref.current.innerHTML = svg;
          setError(null);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [def]);

  if (error) {
    return (
      <div class="mermaid-wrap">
        <div class="center-msg">Diagram error: {error}</div>
      </div>
    );
  }
  return <div class="mermaid-wrap" ref={ref} />;
}
