import type { EnvVar } from "./model/types.js";
import type { FleetViewConfig } from "./config.js";

/** Decide whether an env key's value should be masked. */
export function shouldMask(key: string, cfg: FleetViewConfig): boolean {
  if (!cfg.secrets.maskValues) return false;
  const K = key.toUpperCase();
  if (cfg.secrets.keysNever.some((n) => n.toUpperCase() === K)) return false;
  if (cfg.secrets.keysAlways.some((n) => n.toUpperCase() === K)) return true;
  return cfg.secrets.keyPatterns.some((p) => K.includes(p.toUpperCase()));
}

/** Return a copy of the env with secret values masked per config. */
export function maskEnv(env: EnvVar[], cfg: FleetViewConfig): EnvVar[] {
  return env.map((e) => {
    if (shouldMask(e.key, cfg)) {
      return { ...e, value: null, masked: true };
    }
    return e;
  });
}
