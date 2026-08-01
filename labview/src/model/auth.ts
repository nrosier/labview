import type { AuthMethod, Service } from "./types.js";
import { isExternallyReachable } from "./ingress.js";

/**
 * What may be said about a service the scan found no authentication mechanism on.
 *
 * Nothing here concerns LabView's own login — that vocabulary is `model/access.ts`.
 * This file is about the posture of a *scanned* service, and specifically about the one
 * sentence that is easy to get wrong: "no proxy auth".
 *
 * A gate is only expected in front of something that can be answered from outside the
 * container network. A database its own stack's frontend reaches over an internal
 * network has no proxy in front of it because it needs none, and a dashboard that
 * labels it "No proxy auth" has turned a correct topology into a page of warnings a
 * reader learns to ignore — which is how the one real finding gets missed. So the
 * absence of a mechanism is reported only where its presence was expected.
 *
 * Here rather than in the components because four call sites ask the same question (the
 * badge on a stack roll-up, the badge on a service row, the drawer header, the drawer's
 * `Method` row) and because a rule that only exists inside a `.tsx` file cannot be
 * asserted.
 */

/**
 * Why a service has no authentication mechanism. Exactly one of the four is a finding.
 */
export type NoAuthReason =
  /**
   * Reachable from outside, nothing detected in front of it, nothing declared — the
   * only one of these a reader has to act on, and the only place the words "no proxy
   * auth" belong.
   */
  | "gap"
  /** Nothing outside the container network can reach it, so no gate is expected. */
  | "not-reachable"
  /**
   * The operator's `.labview` file says the service authenticates itself. Taken at
   * face value: a declared mechanism is assumed to be configured and working, so this
   * is not reported as a missing gate. Unverifiable by construction, which is why it
   * stays a separate reason rather than becoming an `AuthMethod`.
   */
  | "declared"
  /**
   * A gate was confirmed, but one this model has no mechanism name for — a SAML
   * application the identity provider's API reported, or an access policy on the
   * tunnel route. Protected, and calling it a gap would be a plain falsehood.
   */
  | "unnamed-gate";

/** Every reason, so a consumer can enumerate them rather than restate the union. */
export const NO_AUTH_REASONS: readonly NoAuthReason[] = [
  "gap",
  "not-reachable",
  "declared",
  "unnamed-gate",
];

/**
 * Why `svc` has no mechanism, or `undefined` when it has one.
 *
 * Decided from the analyzer's own verdict rather than re-derived, so the two can never
 * disagree: `exposedWithoutAuth` already means "reachable from outside, no gate of any
 * kind detected, and nothing declared", which is precisely the finding. Everything
 * after it is therefore *not* a finding, and only needs telling apart to be worded.
 *
 * The last branch is a derivation, not a guess. Reaching it means the method is `none`,
 * something outside can reach the service, nothing was declared, and the analyzer still
 * did not count it as exposed — which happens only where `finalizeAuth` found a gate it
 * had no `AuthMethod` to report.
 */
export function noAuthReason(
  svc: Pick<Service, "auth" | "ingress" | "declared">,
): NoAuthReason | undefined {
  if (svc.auth.method !== "none") return undefined;
  if (svc.auth.exposedWithoutAuth) return "gap";
  if (!isExternallyReachable(svc.ingress)) return "not-reachable";
  if (svc.declared?.auth.length) return "declared";
  return "unnamed-gate";
}

/**
 * Whether a method is worth a badge of its own.
 *
 * `none` is not a mechanism, it is the absence of one — and a badge row lists what was
 * found. Where that absence matters, the exposure badge beside it says so in the words
 * a reader can act on, so a "No proxy auth" badge would either duplicate that or, far
 * more often, contradict it.
 */
export function showsAuthMethod(method: AuthMethod): boolean {
  return method !== "none";
}

/** A short answer and the sentence behind it, for a `title` attribute. */
export interface NoAuthText {
  label: string;
  title: string;
}

const NO_AUTH_TEXT: Record<NoAuthReason, NoAuthText> = {
  gap: {
    label: "No proxy auth",
    title: "Reachable from outside the container network with no detected proxy/SSO authentication.",
  },
  "not-reachable": {
    label: "None expected",
    title:
      "Reachable only from inside the container network, so no proxy or SSO gate is expected in front of it.",
  },
  declared: {
    label: "Declared, not detected",
    title:
      "No gate was detected. The stack's .labview file declares that the service authenticates itself, which this scan takes at face value and cannot verify.",
  },
  "unnamed-gate": {
    label: "None named — gate confirmed",
    title:
      "A gate in front of this service was confirmed, but it has no mechanism name in this model. The evidence states what it is.",
  },
};

/** The wording for a reason. One place, so the badge and the drawer cannot drift. */
export function noAuthText(reason: NoAuthReason): NoAuthText {
  return NO_AUTH_TEXT[reason];
}
