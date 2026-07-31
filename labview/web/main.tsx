import { render } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import type { AppStack, IngressKind, Overview, Service } from "./model";
import { fetchOverview, rescan } from "./api";
import { AUTH_META, INGRESS_META } from "./lib/palette";
import { fmtTime, ingressSummary, serviceKey } from "./lib/format";
import { StatTile, DistributionBar, type DistSegment } from "./components/stats";
import { AppCard } from "./components/AppCard";
import { AppDetail } from "./components/AppDetail";
import { GraphView } from "./components/GraphView";

type Theme = "light" | "dark" | "auto";
const THEME_KEY = "labview-theme";

interface Flat {
  stack: AppStack;
  svc: Service;
  key: string;
}

function flatten(ov: Overview): Flat[] {
  const out: Flat[] = [];
  for (const stack of ov.stacks) {
    for (const svc of stack.services) {
      out.push({ stack, svc, key: serviceKey(stack.id, svc.name) });
    }
  }
  out.sort((a, b) => a.stack.name.localeCompare(b.stack.name) || a.svc.name.localeCompare(b.svc.name));
  return out;
}

function applyTheme(theme: Theme) {
  const el = document.documentElement;
  if (theme === "auto") el.removeAttribute("data-theme");
  else el.setAttribute("data-theme", theme);
}

function App() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<"overview" | "graph">("overview");
  const [theme, setTheme] = useState<Theme>((localStorage.getItem(THEME_KEY) as Theme) || "auto");

  // Filters
  const [search, setSearch] = useState("");
  const [ingressFilter, setIngressFilter] = useState<Set<string>>(new Set());
  const [authFilter, setAuthFilter] = useState<Set<string>>(new Set());
  const [exposedOnly, setExposedOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    fetchOverview()
      .then(setOv)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  async function doRescan() {
    setBusy(true);
    setError(null);
    try {
      setOv(await rescan());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const flat = useMemo(() => (ov ? flatten(ov) : []), [ov]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return flat.filter(({ stack, svc }) => {
      if (ingressFilter.size && !ingressFilter.has(svc.ingress)) return false;
      if (authFilter.size && !authFilter.has(svc.auth.method)) return false;
      if (exposedOnly && !svc.auth.exposedWithoutAuth) return false;
      if (q) {
        const hay = [
          svc.name,
          stack.name,
          svc.image ?? "",
          svc.containerName,
          ingressSummary(svc),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [flat, search, ingressFilter, authFilter, exposedOnly]);

  const ingressSegments = useMemo<DistSegment[]>(() => {
    const counts = new Map<IngressKind, number>();
    for (const { svc } of flat) counts.set(svc.ingress, (counts.get(svc.ingress) ?? 0) + 1);
    return INGRESS_META.map((m) => ({ key: m.key, label: m.label, cssVar: m.cssVar, count: counts.get(m.key) ?? 0 }));
  }, [flat]);

  const authSegments = useMemo<DistSegment[]>(() => {
    const counts = ov?.stats.byAuthMethod ?? {};
    return AUTH_META.map((m) => ({ key: m.key, label: m.label, cssVar: m.cssVar, count: counts[m.key] ?? 0 }));
  }, [ov]);

  function toggle(set: Set<string>, setter: (s: Set<string>) => void, key: string) {
    const next = new Set(set);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setter(next);
  }

  const selectedFlat = selected ? flat.find((f) => f.key === selected) : undefined;

  function openService(stackId: string, serviceName: string) {
    setSelected(serviceKey(stackId, serviceName));
  }

  if (error && !ov) {
    return (
      <div class="shell">
        <div class="center-msg">
          <p>Could not load overview.</p>
          <p class="mono">{error}</p>
          <button class="btn" onClick={() => location.reload()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!ov) {
    return (
      <div class="shell">
        <div class="center-msg">
          <span class="spinner" /> Loading fleet…
        </div>
      </div>
    );
  }

  const nextTheme: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
  const themeIcon: Record<Theme, string> = { auto: "◐ Auto", light: "☀ Light", dark: "☾ Dark" };

  return (
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <span class="dot">●</span>
          <h1>LabView</h1>
        </div>
        <div class="meta">
          <span class="mono">{ov.meta.appsRoot}</span>
          <span>scanned {fmtTime(ov.meta.scannedAt)}</span>
          <span>
            docker:{" "}
            {ov.meta.dockerAvailable ? (
              "connected"
            ) : (
              <span title={ov.meta.dockerError ?? ""}>config-only</span>
            )}
          </span>
        </div>
        <div class="spacer" />
        <button
          class="btn"
          onClick={() => {
            const t = nextTheme[theme];
            setTheme(t);
            localStorage.setItem(THEME_KEY, t);
          }}
          title="Toggle theme"
        >
          {themeIcon[theme]}
        </button>
        <button class="btn" onClick={doRescan} disabled={busy}>
          {busy ? <span class="spinner" /> : "↻"} Rescan
        </button>
      </header>

      {ov.meta.warnings.length > 0 && (
        <div class="banner">
          {ov.meta.warnings.length} scan warning(s): {ov.meta.warnings.slice(0, 3).join("; ")}
          {ov.meta.warnings.length > 3 ? " …" : ""}
        </div>
      )}
      {!ov.meta.dockerAvailable && (
        <div class="banner">
          Docker socket not available — showing configuration only. Live status, health and IPs are hidden.
        </div>
      )}

      <div class="kpis">
        <StatTile label="Stacks" value={ov.stats.stacks} />
        <StatTile
          label="Services"
          value={ov.stats.services}
          sub={ov.meta.dockerAvailable ? `${ov.stats.running} running` : undefined}
        />
        <StatTile label="Public" value={ov.stats.publicServices} sub="via Cloudflare" />
        <StatTile label="Local only" value={ov.stats.localOnlyServices} sub="via Traefik" />
        <StatTile label="Auth-protected" value={ov.stats.authProtected} />
        <StatTile
          label="Exposed, no auth"
          value={ov.stats.exposedWithoutAuth}
          alert={ov.stats.exposedWithoutAuth > 0}
          sub={ov.stats.exposedWithoutAuth > 0 ? "⚠ review" : "none"}
        />
      </div>

      <div class="dists">
        <DistributionBar
          title="Ingress exposure"
          segments={ingressSegments}
          active={ingressFilter}
          onToggle={(k) => toggle(ingressFilter, setIngressFilter, k)}
        />
        <DistributionBar
          title="Authentication method"
          segments={authSegments}
          active={authFilter}
          onToggle={(k) => toggle(authFilter, setAuthFilter, k)}
        />
      </div>

      <nav class="tabs">
        <button class={`tab${tab === "overview" ? " active" : ""}`} onClick={() => setTab("overview")}>
          Apps ({ov.stats.services})
        </button>
        <button class={`tab${tab === "graph" ? " active" : ""}`} onClick={() => setTab("graph")}>
          Relationship graph
        </button>
      </nav>

      {tab === "overview" && (
        <>
          <div class="filters">
            <input
              type="search"
              placeholder="Search apps, images, hostnames…"
              value={search}
              onInput={(e) => setSearch((e.target as HTMLInputElement).value)}
            />
            <button
              class="chip"
              aria-pressed={exposedOnly}
              onClick={() => setExposedOnly((v) => !v)}
            >
              ⚠ Exposed, no auth
            </button>
            {(ingressFilter.size > 0 || authFilter.size > 0 || exposedOnly || search) && (
              <button
                class="chip"
                onClick={() => {
                  setSearch("");
                  setIngressFilter(new Set());
                  setAuthFilter(new Set());
                  setExposedOnly(false);
                }}
              >
                Clear filters
              </button>
            )}
            <span class="result-count">
              {filtered.length} of {flat.length}
            </span>
          </div>

          {filtered.length === 0 ? (
            <div class="center-msg">No services match the current filters.</div>
          ) : (
            <div class="grid">
              {filtered.map(({ stack, svc, key }) => (
                <AppCard key={key} stack={stack} svc={svc} onOpen={() => setSelected(key)} />
              ))}
            </div>
          )}
        </>
      )}

      {tab === "graph" && (
        <GraphView graph={ov.graph} themeKey={theme} onOpenService={openService} />
      )}

      {selectedFlat && (
        <AppDetail stack={selectedFlat.stack} svc={selectedFlat.svc} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

const root = document.getElementById("app");
if (root) render(<App />, root);
