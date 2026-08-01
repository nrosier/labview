import type { IngressKind } from "./types.js";

/**
 * The ingress vocabulary and every pure operation on it.
 *
 * A service carries a *set* of kinds, not one: a container behind the tunnel, behind
 * the proxy and publishing a host port is all three things at once, and each of them is
 * separately true. Nothing here combines two kinds into a third and nothing picks a
 * winner except `primaryIngress`, which exists only because a graph node has one fill
 * colour.
 *
 * The three external kinds are independent of each other. `internal` is the exception
 * and the one rule in this module: it is reported only when it is the whole answer, for
 * the reason given on `normalizeIngress`.
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
 * The only constructor for a kind set: deduped, in canonical order, **never empty**, and
 * carrying `internal` only when nothing external does.
 *
 * Non-empty on purpose. An empty array would render as no badge at all, sort into no
 * bar segment, and match no filter, so a service with no ingress whatsoever would
 * quietly disappear from the one view that should show it. `none` is a real answer
 * and is stored as one.
 *
 * `internal` is withheld beside any external kind because in a real fleet nearly every
 * service shares a network with a neighbour, so a tag that is true of almost everything
 * says nothing about any of it. What a reader is looking for is the service reachable
 * *only* from the container network — the database behind a frontend — and that is
 * precisely the set this leaves it on. Nothing is invented: `internal` is still the same
 * positive evidence (`expose:`, or a shared real network), and this only decides when it
 * is worth reporting. What it costs is the ability to tell, from the tags of a public
 * service, whether a sibling can also reach it; the drawer's networks and the graph's
 * network edges still say so.
 *
 * Applied here rather than in the classifier so the one other source of a kind set — a
 * `.labview` `expected: ingress:` list — is collapsed the same way. That is what makes a
 * sidecar written as `[public, lan, internal]` agree with a scan of `[public, lan]`
 * instead of drifting against a rule it has no way of knowing about.
 */
export function normalizeIngress(kinds: Iterable<IngressKind>): IngressKind[] {
  const set = new Set(kinds);
  if (EXTERNAL_KINDS.some((k) => set.has(k))) set.delete("internal");
  const out = INGRESS_KINDS.filter((k) => k !== "none" && set.has(k));
  return out.length ? out : ["none"];
}

/**
 * A stack's kinds: every kind at least one of its services carries, in canonical order.
 *
 * Deliberately **not** put through `normalizeIngress`, and this is the one place that
 * distinction matters. A stack is not a service: the whole point of rolling up rather
 * than reducing is that a public frontend and a database only its neighbour can reach
 * make the stack *both*, so the row says `Public` `Internal` and the reader can see
 * there is something inside worth expanding for. Normalizing here would withhold
 * `internal` on the union — the frontend's exposure would erase the database from the
 * collapsed view, which is exactly backwards.
 *
 * Here rather than inline in the card so the rule is something a test can call: the
 * badge is now the only stack-level place `internal` appears at all.
 */
export function rollUpIngress(services: readonly (readonly IngressKind[])[]): IngressKind[] {
  return INGRESS_KINDS.filter((k) => services.some((kinds) => kinds.includes(k)));
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

/**
 * Whether a declared expectation and the classification agree.
 *
 * Read off {@link diffIngress} rather than compared separately, so the analyzer's drift
 * note and the UI row that renders only on disagreement cannot reach opposite
 * conclusions about one service. Sets, not sequences: the same kinds in any order are
 * the same expectation.
 *
 * Here rather than in the component for the same reason `matchesTagFilter` is — a render
 * decision in a `.tsx` file is unassertable, and "agreement is silent" is precisely the
 * kind of rule that regresses invisibly.
 */
export function ingressMatchesExpectation(
  expected: readonly IngressKind[],
  actual: readonly IngressKind[],
): boolean {
  const { missing, unexpected } = diffIngress(expected, actual);
  return missing.length === 0 && unexpected.length === 0;
}
