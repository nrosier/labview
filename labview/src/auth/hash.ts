/**
 * Password hashes, in modular crypt format.
 *
 * The passwd file stores `user:hash` and the hash names its own algorithm through
 * its `$id$` prefix, exactly as `/etc/shadow` and `htpasswd` do. That is the whole
 * reason the format was chosen: an operator can produce an entry with
 * `htpasswd -nbB`, with `npm run hashpw`, or with anything else that emits MCF, and
 * LabView reads the algorithm off the value rather than out of a config key that
 * could disagree with it.
 *
 * **Only bcrypt is verified.** `$2a$`, `$2b$` and `$2y$` — which is precisely what
 * `htpasswd -nbB` writes and what the reverse proxy's own basicauth middleware
 * accepts, so a fleet that already has such a file can reuse it. Every other `$id$`
 * is recognised well enough to *name* in a warning and then refused: silently
 * ignoring a `$6$` entry would leave an operator convinced they had configured a
 * user who cannot sign in, and accepting one would mean shipping an
 * implementation of a second hash function.
 *
 * Nothing here throws. A malformed hash is a `false`, and the reason is reported by
 * the caller that parsed the file.
 */
import { randomBytes } from "node:crypto";
import { compare, getRounds, hash as bcryptHash, truncates } from "bcryptjs";

/** The cost `hashpw` uses. Roughly 250ms per verify in pure JS on a modern host. */
export const DEFAULT_COST = 12;

/**
 * A well-formed bcrypt hash: `$2<a|b|y>$<cost>$<22-char salt><31-char digest>`, 60
 * characters exactly.
 *
 * Shape-checked rather than handed straight to `compare`, so a hash that was
 * truncated by a copy-paste is a named warning at parse time instead of a user who
 * silently can never sign in.
 */
const BCRYPT_RE = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/;

/**
 * The MCF algorithm ids LabView can verify.
 *
 * `2a` and `2y` are accepted alongside `2b` because they identify the same
 * function — the letters distinguish implementations that once differed over a
 * sign-extension bug and a null-byte edge case, and every current tool emits one of
 * the three. Refusing two of them would reject files that work everywhere else.
 */
export const SUPPORTED_HASH_IDS: readonly string[] = ["2a", "2b", "2y"];

/**
 * Names for the algorithms LabView does *not* verify, so a refusal can say what it
 * refused.
 *
 * Not a capability list — nothing here can be checked. It exists so the warning
 * reads "sha512-crypt, which LabView cannot verify" instead of "unsupported hash",
 * which leaves the operator guessing whether the file or the tool was wrong.
 */
const KNOWN_FOREIGN: Record<string, string> = {
  "1": "md5-crypt",
  "2": "bcrypt (pre-2a, unversioned)",
  "5": "sha256-crypt",
  "6": "sha512-crypt",
  y: "yescrypt",
  gy: "gost-yescrypt",
  "7": "scrypt",
  apr1: "Apache md5",
  sha1: "Apache sha1",
  argon2i: "Argon2i",
  argon2d: "Argon2d",
  argon2id: "Argon2id",
  pbkdf2: "PBKDF2",
  "pbkdf2-sha256": "PBKDF2-SHA256",
  "pbkdf2-sha512": "PBKDF2-SHA512",
};

/**
 * The algorithm id a hash claims, or `undefined` when the value is not in modular
 * crypt format at all — which in a passwd file means a plaintext password.
 */
export function hashAlgorithmId(value: string): string | undefined {
  if (!value.startsWith("$")) return undefined;
  const id = value.slice(1).split("$", 1)[0];
  return id ? id : undefined;
}

/** How to describe an id in a warning: its common name, or the id itself. */
export function hashAlgorithmName(id: string): string {
  if (SUPPORTED_HASH_IDS.includes(id)) return "bcrypt";
  return KNOWN_FOREIGN[id] ?? "$" + id + "$";
}

/** Whether this exact value can be verified: bcrypt, and well-formed. */
export function isSupportedHash(value: string): boolean {
  return BCRYPT_RE.test(value);
}

/** The bcrypt cost baked into a hash, or `undefined` if it is not a bcrypt hash. */
export function hashCost(value: string): number | undefined {
  const m = BCRYPT_RE.exec(value);
  if (!m) return undefined;
  try {
    return getRounds(value);
  } catch {
    return Number(m[1]);
  }
}

/**
 * Whether `password` matches `hash`.
 *
 * Never throws and never distinguishes "wrong password" from "unusable hash": both
 * are `false`, because a caller that could tell them apart would have a second way
 * to probe the file's contents. The shape check runs first so a malformed value
 * cannot reach `compare` at all.
 *
 * bcrypt considers only the first 72 bytes of a password. That is inherent to the
 * function rather than a choice made here; `hashPassword` warns about it at the one
 * point where it can still be acted on.
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (!isSupportedHash(hash)) return false;
  try {
    return await compare(password, hash);
  } catch {
    return false;
  }
}

/** Hash a password for a passwd entry. `$2b$`, at `cost`. */
export async function hashPassword(password: string, cost = DEFAULT_COST): Promise<string> {
  const rounds = Math.min(31, Math.max(4, Math.floor(cost)));
  return bcryptHash(password, rounds);
}

/** Whether bcrypt will ignore part of this password (over 72 bytes in UTF-8). */
export function passwordTruncates(password: string): boolean {
  return truncates(password);
}

/**
 * A hash no password matches, for the unknown-user path.
 *
 * Signing in as a name that is not in the file has to cost the same as signing in
 * as one that is, or the response time is an oracle for which accounts exist. So
 * the login route verifies against this instead of returning early, and the caller
 * discards the result.
 *
 * Generated from `randomBytes` on first use rather than committed as a constant:
 * a bcrypt hash in the source tree is a thing every future reader has to satisfy
 * themselves is not a real credential, and there is no reason to make them. Cached
 * per cost, and the cost comes from the file's own entries, so the decoy verify is
 * as expensive as the real one it is imitating.
 *
 * The first unknown-user attempt after startup pays for one extra hash while this
 * is built. Everything after it is indistinguishable.
 */
const decoys = new Map<number, Promise<string>>();

export function decoyHash(cost = DEFAULT_COST): Promise<string> {
  const rounds = Math.min(31, Math.max(4, Math.floor(cost)));
  let pending = decoys.get(rounds);
  if (!pending) {
    pending = hashPassword(randomBytes(32).toString("base64"), rounds);
    decoys.set(rounds, pending);
  }
  return pending;
}
