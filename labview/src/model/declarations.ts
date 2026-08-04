import type {
  AppStack,
  AuthFamily,
  AuthMethod,
  DeclaredAuth,
  DeclaredAuthAgreement,
  DeclaredAuthMechanism,
} from "./types.js";

/**
 * The runtime side of the declaration vocabulary: the values a `.labview` file may
 * use, and how they are worded for a reader.
 *
 * Here rather than in the parser because three places need the same list and must
 * not drift — the parser validates against it, the UI labels from it, and the
 * documentation is generated from the same wording. Both arrays are typed by their
 * union, so renaming a member is a compile error rather than a silent mismatch.
 */

/** Every declarable mechanism, in the order the UI lists them. */
export const DECLARED_AUTH_MECHANISMS: readonly DeclaredAuthMechanism[] = [
  "app-local-accounts",
  "app-ldap",
  "app-oidc",
  "app-saml",
  "app-token",
  "mtls",
  "network-restricted",
  "external-proxy",
  "other",
];

/**
 * Short wording for one mechanism. Every label says *who* enforces it, because that
 * is the whole point of the distinction: LabView could not see it, so a reader needs
 * to know where to go and look.
 */
const MECHANISM_LABELS: Record<DeclaredAuthMechanism, string> = {
  "app-local-accounts": "Local accounts in the app",
  "app-ldap": "LDAP bind by the app",
  "app-oidc": "OIDC login by the app",
  "app-saml": "SAML login by the app",
  "app-token": "API token required",
  mtls: "Client certificates (mTLS)",
  "network-restricted": "Network-restricted",
  "external-proxy": "Authenticating proxy outside the fleet",
  other: "Other mechanism",
};

export function declaredAuthLabel(mechanism: DeclaredAuthMechanism): string {
  return MECHANISM_LABELS[mechanism];
}

export function isDeclaredAuthMechanism(value: string): value is DeclaredAuthMechanism {
  return (DECLARED_AUTH_MECHANISMS as readonly string[]).includes(value);
}

/**
 * One line summarising declared mechanisms, e.g.
 * `Local accounts in the app (built-in user database); LDAP bind by the app`.
 *
 * Shared by the analyzer's note and the UI so the two can never word the same
 * declaration differently.
 */
export function declaredAuthSummary(auth: readonly DeclaredAuth[]): string {
  return auth
    .map((a) => (a.detail ? `${declaredAuthLabel(a.mechanism)} (${a.detail})` : declaredAuthLabel(a.mechanism)))
    .join("; ");
}

/**
 * The exposure figure as `23/28` — findings needing attention over findings found.
 *
 * Here, beside the declaration vocabulary, because the two numbers only differ on
 * account of a declaration; and one implementation rather than two because the
 * dashboard tile and the CLI line must not be able to describe the same scan
 * differently.
 *
 * A plain total when nothing was accepted: `28/28` reads as though five are missing.
 * `accepted` can never exceed `exposed` — a service is only counted as accepted if it
 * is counted as exposed — so no clamp, which would hide that being untrue.
 */
export function formatExposureCount(exposed: number, accepted: number): string {
  return accepted > 0 ? `${exposed - accepted}/${exposed}` : String(exposed);
}

/* -------------------------------------------------------------------------- */
/* Comparing a declaration against what the scan detected                     */
/* -------------------------------------------------------------------------- */

/**
 * The three mechanisms both vocabularies can name.
 *
 * `DeclaredAuthMechanism` and `AuthMethod` describe *different things* — the first
 * what an application does for itself, the second what LabView could see in front of
 * it — and they overlap in only three places. Comparing them anywhere else produces a
 * disagreement out of two statements that are both true, which is why the two maps
 * below are deliberately partial: an absent entry means "not comparable", and that is
 * the common case.
 */
const DECLARED_FAMILY: Partial<Record<DeclaredAuthMechanism, AuthFamily>> = {
  "app-oidc": "oidc",
  "app-ldap": "ldap",
  "external-proxy": "proxy",
};

/** The same three families as the scan names them. Providers are irrelevant here. */
const DETECTED_FAMILY: Partial<Record<AuthMethod, AuthFamily>> = {
  "authentik-oauth": "oidc",
  "other-oauth": "oidc",
  "authentik-ldap": "ldap",
  ldap: "ldap",
  "authentik-forward-auth": "proxy",
  "forward-auth": "proxy",
};

/**
 * Which tier of the request path each family sits in.
 *
 * Two mechanisms only contradict each other when they answer the same question. "How
 * does the app log a user in" (`oidc`, `ldap`) and "what stands in front of the app"
 * (`proxy`) are different questions, so a declared OIDC login behind a detected
 * forward-auth gate is defence in depth rather than drift — the single rule that keeps
 * every layered setup out of the warning path.
 */
const FAMILY_LAYER: Record<AuthFamily, "app" | "proxy"> = {
  oidc: "app",
  ldap: "app",
  proxy: "proxy",
};

/**
 * How a declaration stands relative to the scan.
 *
 * `wouldBeExposed` is the exposure verdict *without* the declaration — reachable from
 * outside with nothing observable in front. It is passed in rather than re-derived
 * because the caller has already established it and the two must not be able to
 * disagree: whenever this returns `supplies`, that is exactly the service the
 * declaration took out of the exposed count.
 *
 * Returns `undefined` when nothing was declared, which is not an outcome but the
 * absence of one — there is nothing to compare and nothing to show.
 */
export function compareDeclaredAuth(
  declared: readonly DeclaredAuth[],
  detected: AuthMethod,
  wouldBeExposed: boolean,
): DeclaredAuthAgreement | undefined {
  if (!declared.length) return undefined;

  // Load-bearing: the declaration is the only reason this service is not flagged.
  // Necessarily means the scan detected nothing (`wouldBeExposed` already accounts for
  // gates that carry no `AuthMethod`), so this can never coincide with a family
  // comparison below — a declaration changes the verdict only in this one case.
  if (wouldBeExposed) return "supplies";

  const detectedFamily = DETECTED_FAMILY[detected];
  // `basic-auth`, `none`, or a gate with no method: nothing to compare against.
  if (!detectedFamily) return "supplements";

  // The scan already says all of this, so there is nothing left to tell the reader.
  if (declared.every((a) => DECLARED_FAMILY[a.mechanism] === detectedFamily)) return "redundant";

  const families = declared
    .map((a) => DECLARED_FAMILY[a.mechanism])
    .filter((f): f is AuthFamily => f !== undefined);
  const layer = FAMILY_LAYER[detectedFamily];
  // Both sides name a mechanism at the same tier and they name different ones: one of
  // the two is out of date. If either side also names the detected family, they agree
  // about that tier and whatever else is declared is additional, not contradictory.
  if (families.some((f) => FAMILY_LAYER[f] === layer) && !families.includes(detectedFamily)) {
    return "conflicts";
  }
  return "supplements";
}

/**
 * Whether a declared mechanism is worth putting in front of a reader at all.
 *
 * `redundant` is the one outcome that renders nowhere: the scan detected the same
 * family, so a second statement of it sends the reader to check two sources that agree
 * and buries the declarations that do add something. Every other outcome — including
 * `conflicts`, which is a disagreement worth reading — is shown.
 *
 * In the model rather than in the components because three call sites share it (the
 * badge on the stack row, the badge in the drawer, the declared `Authentication` row)
 * and because a rule that only exists inside a `.tsx` file cannot be asserted.
 */
export function showsDeclaredAuth(agreement: DeclaredAuthAgreement | undefined): boolean {
  return agreement !== "redundant";
}

/**
 * Which family each side names, or `undefined` where that side's vocabulary has no
 * counterpart. Exported so the tests can enumerate the incomparable mechanisms from
 * the maps themselves rather than from a hand-written list that could fall behind them.
 */
export function declaredAuthFamily(mechanism: DeclaredAuthMechanism): AuthFamily | undefined {
  return DECLARED_FAMILY[mechanism];
}

export function detectedAuthFamily(detected: AuthMethod): AuthFamily | undefined {
  return DETECTED_FAMILY[detected];
}

/** What a family is about, for the sentence that reports a conflict. */
const FAMILY_SUBJECT: Record<AuthFamily, string> = {
  oidc: "the app's own login",
  ldap: "the app's own login",
  proxy: "the gate in front of the app",
};

/**
 * How to refer to the tier a detected method sits in, in a sentence.
 *
 * Only ever called for a method that has a family — a conflict cannot arise without
 * one — so the fallback exists to keep the caller branchless, not because it describes
 * a real case.
 */
export function detectedAuthSubject(detected: AuthMethod): string {
  const family = DETECTED_FAMILY[detected];
  return family ? FAMILY_SUBJECT[family] : "the same mechanism";
}

/* -------------------------------------------------------------------------- */
/* Every disagreement in the fleet, collected for the reader                   */
/* -------------------------------------------------------------------------- */

/**
 * Which of the two analyzer-written note fields a report is about.
 *
 * The pair exists because they must never be merged: `drift` is *the file and the scan
 * contradict each other*, `unconfirmed` is *the scan asked and could not tell*. One is a
 * warning and the other is an open question, and the only thing they share is their shape.
 */
export type DeclarationNoteField = "drift" | "unconfirmed";

/** One service's entries, in the words the analyzer wrote them. */
export interface ServiceDrift {
  service: string;
  /** The file the declaration was read from, e.g. `.labview`. Never a full path. */
  file: string;
  /** The chosen field of `ServiceDeclaration`, carried through unchanged. */
  entries: readonly string[];
}

/** The drifting services of one stack, and how many disagreements they hold between them. */
export interface StackDrift {
  stackId: string;
  stackName: string;
  services: ServiceDrift[];
  entries: number;
}

/**
 * Every `.labview` disagreement in the fleet, grouped the way the fleet is organised.
 *
 * Two counts, because there are two questions and one number cannot answer both.
 * `services` is how many services disagree with their sidecar — the figure
 * `OverviewStats.declarationDrift` counts and the dashboard tile shows. `entries` is how
 * many disagreements there are, which is the larger of the two: one service can have a
 * stale acceptance *and* an expectation the scan contradicts, and a stack card's badge
 * already counts that way. Naming both here is what keeps the tile and the panel behind
 * it from looking like they disagree about the same fleet.
 */
export interface DeclarationNoteReport {
  stacks: StackDrift[];
  services: number;
  entries: number;
}

/**
 * The drift report's name, kept because drift is what this shape was built for and what
 * most of its callers mean. An alias rather than a second interface so the two reports
 * cannot acquire different fields.
 */
export type DeclarationDriftReport = DeclarationNoteReport;

/**
 * Collect one of the note fields, for a reader who has a count and wants the cases behind it.
 *
 * Derived from `stacks` rather than carried in the payload, for the reason every roll-up in
 * the UI is: the entries are already on `svc.declared`, and a second copy in `ScanMeta` would
 * be a second thing to keep in step with the first. Nothing here is re-worded or re-derived
 * either — the analyzer owns what an entry says, and a panel that paraphrased it would give
 * one fact two voices.
 *
 * Grouped by stack because both fields are *service* facts with no stack-level counterpart —
 * `ServiceDeclaration` has them, `Declaration` does not — so the stack is a heading the
 * services imply, not a source of its own.
 *
 * In `src/model/` rather than in the component that renders it so it can be asserted:
 * smoke never mounts a DOM, and "the panel lists exactly the services the tile counted" is
 * precisely the claim worth pinning.
 */
function collectDeclarationNotes(
  stacks: readonly AppStack[],
  field: DeclarationNoteField,
): DeclarationNoteReport {
  const out: StackDrift[] = [];
  let services = 0;
  let entries = 0;
  // Sorted rather than taken in scan order, and by name rather than by count: the fleet
  // list is alphabetical, so a reader arriving from it finds the stack where they left it,
  // and the same scan produces the same panel twice (I7).
  for (const stack of [...stacks].sort((a, b) => a.name.localeCompare(b.name))) {
    const drifting: ServiceDrift[] = [];
    for (const svc of [...stack.services].sort((a, b) => a.name.localeCompare(b.name))) {
      const declared = svc.declared;
      if (!declared?.[field].length) continue;
      drifting.push({ service: svc.name, file: declared.file, entries: declared[field] });
    }
    if (!drifting.length) continue;
    const stackEntries = drifting.reduce((n, s) => n + s.entries.length, 0);
    out.push({ stackId: stack.id, stackName: stack.name, services: drifting, entries: stackEntries });
    services += drifting.length;
    entries += stackEntries;
  }
  return { stacks: out, services, entries };
}

/** Every `.labview` disagreement in the fleet — the warning half of the pair. */
export function collectDeclarationDrift(stacks: readonly AppStack[]): DeclarationDriftReport {
  return collectDeclarationNotes(stacks, "drift");
}

/**
 * Every declaration this scan asked about and could not settle, grouped the same way.
 *
 * The other half of `collectDeclarationDrift`, and a wrapper over the same walker rather
 * than a second one: two panels that grouped or sorted the same fleet differently would be
 * two accounts of one scan, and the sort is what makes either of them reproducible (I7).
 *
 * The distinction this exists to hold is the whole point of the pair — a service listed here
 * is **not** a service with a problem. Its declaration is intact, its verdict is unchanged,
 * and all that has happened is that a single request to `/` came back without a login page,
 * which is exactly what a client-rendered login, a deeper route or a token-guarded API also
 * looks like. It is a list of places worth checking by hand, not a list of things that are
 * wrong.
 */
export function collectUnconfirmedDeclarations(stacks: readonly AppStack[]): DeclarationNoteReport {
  return collectDeclarationNotes(stacks, "unconfirmed");
}

const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;

/**
 * The report as one line — `3 services in 2 stacks · 4 disagreements`.
 *
 * Shared by the panel's subtitle and the tile's tooltip so the two cannot count the same
 * fleet differently, and worded with both figures because the tile shows only the first:
 * a reader who sees `3` and then a panel listing four warnings needs the sentence that
 * says why those are the same thing.
 */
export function driftSummaryText(report: DeclarationDriftReport): string {
  if (report.services === 0) return "no declaration disagrees with this scan";
  return [
    `${plural(report.services, "service")} in ${plural(report.stacks.length, "stack")}`,
    plural(report.entries, "disagreement"),
  ].join(" · ");
}

/**
 * The same line for the other field — `1 service in 1 stack · 1 unconfirmed declaration`.
 *
 * A separate function rather than a noun parameter on the one above, because the empty
 * sentence differs in more than a noun: "no declaration disagrees with this scan" would be
 * actively wrong here, where nothing being listed means every declaration the probe asked
 * about was either confirmed or never asked — not that none of them disagree.
 */
export function unconfirmedSummaryText(report: DeclarationNoteReport): string {
  if (report.services === 0) return "every declaration this scan asked about was answered";
  return [
    `${plural(report.services, "service")} in ${plural(report.stacks.length, "stack")}`,
    plural(report.entries, "unconfirmed declaration"),
  ].join(" · ");
}
