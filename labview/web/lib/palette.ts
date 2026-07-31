import type { AuthMethod, IngressKind } from "../model";

/**
 * Color roles for the two categorical dimensions the UI encodes: ingress kind
 * and auth method. Each maps to a CSS custom property defined in styles.css
 * (the validated dataviz palette). DOM elements reference `cssVar` directly via
 * `var(--…)`; canvas views resolve it to a hex string with `resolveVar()` so
 * there is a single source of truth that also follows the light/dark toggle.
 */

export interface RoleMeta<K extends string> {
  key: K;
  label: string;
  cssVar: string;
}

/** Ingress kinds in a fixed, meaningful order (most→least exposed). */
export const INGRESS_META: RoleMeta<IngressKind>[] = [
  { key: "public", label: "Public", cssVar: "--ing-public" },
  { key: "public+local", label: "Public + Local", cssVar: "--ing-publiclocal" },
  { key: "local", label: "Local", cssVar: "--ing-local" },
  { key: "internal", label: "Internal", cssVar: "--ing-internal" },
];

/** Auth methods in a fixed order (grouped: Authentik variants, then others). */
export const AUTH_META: RoleMeta<AuthMethod>[] = [
  { key: "authentik-forward-auth", label: "Authentik (forward-auth)", cssVar: "--auth-forward" },
  { key: "authentik-oauth", label: "Authentik (OAuth/OIDC)", cssVar: "--auth-oauth" },
  { key: "authentik-ldap", label: "Authentik (LDAP)", cssVar: "--auth-ldap" },
  { key: "other-oauth", label: "Other OAuth / Access", cssVar: "--auth-otheroauth" },
  { key: "basic-auth", label: "Basic auth", cssVar: "--auth-basic" },
  { key: "none", label: "No proxy auth", cssVar: "--auth-none" },
];

const INGRESS_BY_KEY = new Map(INGRESS_META.map((m) => [m.key, m]));
const AUTH_BY_KEY = new Map(AUTH_META.map((m) => [m.key, m]));

export function ingressVar(kind: IngressKind): string {
  return INGRESS_BY_KEY.get(kind)?.cssVar ?? "--muted";
}
export function ingressLabel(kind: IngressKind): string {
  return INGRESS_BY_KEY.get(kind)?.label ?? kind;
}
export function authVar(method: AuthMethod): string {
  return AUTH_BY_KEY.get(method)?.cssVar ?? "--muted";
}
export function authLabel(method: AuthMethod): string {
  return AUTH_BY_KEY.get(method)?.label ?? method;
}

/** Resolve a CSS custom property to its computed value (for canvas libs). */
export function resolveVar(name: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || "#888888";
}

/** True when the effective theme is dark (toggle wins over OS preference). */
export function isDarkTheme(): boolean {
  const attr = document.documentElement.getAttribute("data-theme");
  if (attr === "dark") return true;
  if (attr === "light") return false;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}
