import type { Overview } from "./model";

/** Fetch the current overview payload. */
export async function fetchOverview(): Promise<Overview> {
  const res = await fetch("api/overview", { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`GET /api/overview failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as Overview;
}

/** Trigger a fresh scan on the server, returning the rebuilt overview. */
export async function rescan(): Promise<Overview> {
  const res = await fetch("api/rescan", { method: "POST", headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`POST /api/rescan failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as Overview;
}
