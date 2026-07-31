import type { AppStack } from "../model/types.js";

export interface MiddlewareDef {
  name: string;
  /** Traefik middleware type: forwardauth, basicauth, headers, redirectscheme, ... */
  type: string;
  /** forwardauth.address, when type is forwardauth. */
  address?: string;
  /** Stack the middleware was defined in. */
  definedIn: string;
}

export type MiddlewareRegistry = Map<string, MiddlewareDef>;

// Types that actually gate access (used to break name collisions in favor of auth).
const AUTH_TYPES = new Set(["forwardauth", "basicauth", "digestauth"]);

/**
 * Build a registry of every Traefik middleware DEFINED anywhere (across all
 * stacks), keyed by bare name. Services elsewhere reference these as
 * `<name>@docker`, so a global view lets us classify a reference accurately
 * (forward-auth vs a headers/redirect middleware) instead of guessing by name.
 */
export function buildMiddlewareRegistry(stacks: AppStack[], traefikPrefix: string): MiddlewareRegistry {
  const p = traefikPrefix.endsWith(".") ? traefikPrefix : `${traefikPrefix}.`;
  const defRe = new RegExp(`^${escape(p)}http\\.middlewares\\.([^.]+)\\.([^.]+)`);
  const addrRe = new RegExp(`^${escape(p)}http\\.middlewares\\.([^.]+)\\.forwardauth\\.address$`, "i");

  const reg: MiddlewareRegistry = new Map();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      for (const [key, value] of Object.entries(svc.labels)) {
        const m = key.match(defRe);
        if (!m) continue;
        const [, name, type] = m;
        const existing = reg.get(name!);
        if (!existing || (AUTH_TYPES.has(type!) && !AUTH_TYPES.has(existing.type))) {
          reg.set(name!, { name: name!, type: type!, definedIn: stack.id, address: existing?.address });
        }
        const am = key.match(addrRe);
        if (am) {
          const entry = reg.get(name!);
          if (entry) entry.address = value;
        }
      }
    }
  }
  return reg;
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
