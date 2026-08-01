import type { DeclaredAuth, DeclaredAuthMechanism, IngressKind } from "./types.js";

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
 * The ingress kinds as a runtime list, for validating a declared expectation and for
 * the palette check. The union in `types.ts` stays the source of truth; this exists
 * because a YAML string has to be compared against something.
 */
export const INGRESS_KINDS: readonly IngressKind[] = [
  "public",
  "public+lan",
  "public+traefik",
  "traefik",
  "lan",
  "internal",
];

export function isIngressKind(value: string): value is IngressKind {
  return (INGRESS_KINDS as readonly string[]).includes(value);
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
