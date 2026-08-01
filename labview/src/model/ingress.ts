import type { IngressKind } from "./types.js";

/**
 * The ingress vocabulary and every pure operation on it.
 *
 * A service carries a *set* of kinds, not one: a container behind the tunnel, behind
 * the proxy, with a published port and a listening container port is all four things
 * at once, and each of them is separately true. The five kinds are independent by
 * construction, so nothing here combines them and nothing picks a winner except
 * `primaryIngress`, which exists only because a graph node has one fill colour.
 *
 * Here rather than in the analyzer because five places need the same answers and must
 * not drift: the classifier builds the set, the analyzer asks whether it is reachable,
 * the sidecar validates a declared expectation against it, the CLI and the UI word it.
 * Every list is typed by the union in `types.ts`, so renaming a kind is a compile
 * error rather than a silent mismatch.
 */

/**
 * Every kind, ordered most → least exposed. The order is load-bearing three times
 * over: it is the canonical order of a normalized set, the priority
 * `primaryIngress` resolves by, and the row order of the dashboard's ingress bars.
 */
export const INGRESS_KINDS: readonly IngressKind[] = [
  "public",
  "traefik",
  "lan",
  "internal",
  "none",
];

export function isIngressKind(value: string): value is IngressKind {
  return (INGRESS_KINDS as readonly string[]).includes(value);
}

/**
 * The kinds that mean someone outside the container network can answer: through the
 * tunnel, through the proxy, or straight at a published host port.
 *
 * `internal` is deliberately absent. It says another *container* can reach the
 * service, which is not exposure — and `none` says nothing can.
 */
const EXTERNAL_KINDS: readonly IngressKind[] = ["public", "traefik", "lan"];

/**
 * The only constructor for a kind set: deduped, in canonical order, and **never
 * empty** — nothing applying yields `["none"]` rather than `[]`.
 *
 * Non-empty on purpose. An empty array would render as no badge at all, sort into no
 * bar segment, and match no filter, so a service with no ingress whatsoever would
 * quietly disappear from the one view that should show it. `none` is a real answer
 * and is stored as one.
 */
export function normalizeIngress(kinds: Iterable<IngressKind>): IngressKind[] {
  const set = new Set(kinds);
  const out = INGRESS_KINDS.filter((k) => k !== "none" && set.has(k));
  return out.length ? out : ["none"];
}

/**
 * The most exposed kind in the set, for the two views that can only show one: a
 * cytoscape node's background and a mermaid `classDef`. Never used to *decide*
 * anything — a fill colour is the whole of its job, and the badges beside it list
 * the full set.
 */
export function primaryIngress(kinds: readonly IngressKind[]): IngressKind {
  return INGRESS_KINDS.find((k) => kinds.includes(k)) ?? "none";
}

/** The externally-reachable subset, in canonical order. */
export function externalIngress(kinds: readonly IngressKind[]): IngressKind[] {
  return EXTERNAL_KINDS.filter((k) => kinds.includes(k));
}

/**
 * Whether anyone outside the container network can reach this service.
 *
 * Shared so the two questions that turn on it — `exposedWithoutAuth`, and whether a
 * declared acceptance still applies — can never disagree about the same service.
 */
export function isExternallyReachable(kinds: readonly IngressKind[]): boolean {
  return EXTERNAL_KINDS.some((k) => kinds.includes(k));
}

/** `"public, lan"` — the keys, for notes, drift text and the CLI. */
export function formatIngress(kinds: readonly IngressKind[]): string {
  return kinds.join(", ");
}

/**
 * How two kind sets differ, for the sidecar drift check. Named in both directions
 * because "expected public, traefik; found public, lan" is a diff a reader should not
 * have to do by eye.
 */
export function diffIngress(
  expected: readonly IngressKind[],
  actual: readonly IngressKind[],
): { missing: IngressKind[]; unexpected: IngressKind[] } {
  return {
    missing: expected.filter((k) => !actual.includes(k)),
    unexpected: actual.filter((k) => !expected.includes(k)),
  };
}
