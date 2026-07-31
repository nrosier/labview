import type { EnvVar } from "./model/types.js";
import type { LabViewConfig } from "./config.js";

/**
 * Matches the credential portion of a URI that carries an inline password:
 * `scheme://user:password@host`. The `user` group may be empty (`redis://:pw@h`)
 * but the password must be non-empty, so `http://user@host` and a plain
 * `ldap://host:389` (no `@`) are left alone. Excluding `/` from both groups
 * stops the pattern reaching across into a path or query string.
 */
const URI_CREDENTIAL = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^\s:@/]*):([^\s@/]+)@/g;

/** Placeholder substituted for a redacted password inside a URI. */
const REDACTED = "***";

/** Decide whether an env key's value should be masked outright. */
export function shouldMask(key: string, cfg: LabViewConfig): boolean {
  if (!cfg.secrets.maskValues) return false;
  const K = key.toUpperCase();
  if (cfg.secrets.keysNever.some((n) => n.toUpperCase() === K)) return false;
  if (cfg.secrets.keysAlways.some((n) => n.toUpperCase() === K)) return true;
  return cfg.secrets.keyPatterns.some((p) => K.includes(p.toUpperCase()));
}

/**
 * Redact inline passwords from any URIs in `value`, or return `null` when there
 * is nothing to redact. Connection strings such as `DATABASE_URL` and
 * `REDIS_URL` carry a password but have a key matching no secret pattern, so
 * key-based masking alone leaks them. Only the password is removed — the
 * scheme, user and host stay visible, which is the part worth reading.
 */
export function redactUriCredentials(value: string): string | null {
  URI_CREDENTIAL.lastIndex = 0;
  if (!URI_CREDENTIAL.test(value)) return null;
  URI_CREDENTIAL.lastIndex = 0;
  return value.replace(URI_CREDENTIAL, (_full, scheme: string, user: string) => `${scheme}${user}:${REDACTED}@`);
}

/**
 * Return a copy of the env with secret values masked per config. A masked entry
 * either drops its value entirely (the key matched a secret pattern) or keeps a
 * partially redacted string (an inline URI password was removed).
 */
export function maskEnv(env: EnvVar[], cfg: LabViewConfig): EnvVar[] {
  return env.map((e) => {
    if (shouldMask(e.key, cfg)) {
      return { ...e, value: null, masked: true };
    }
    if (cfg.secrets.maskValues && cfg.secrets.redactUriCredentials && e.value !== null) {
      const redacted = redactUriCredentials(e.value);
      if (redacted !== null) return { ...e, value: redacted, masked: true };
    }
    return e;
  });
}
