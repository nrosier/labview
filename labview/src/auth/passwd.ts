/**
 * The passwd file: `user:hash`, one per line, `#` comments and blank lines ignored.
 *
 * Deliberately the shape `/etc/shadow` and `htpasswd` already use, so an operator
 * can produce it with tools they have and read it without learning anything new. The
 * algorithm is named by the hash itself rather than by a config key — see
 * `auth/hash.ts` — which is what lets a file written by `htpasswd -nbB` work
 * unchanged.
 *
 * Split into a pure {@link parsePasswd} and an I/O {@link readPasswd} for the reason
 * `scan/sidecar.ts` gives: every validation rule below can then be asserted without
 * committing a fixture for it, and the file's own size and error handling are
 * asserted separately.
 *
 * Two rules shape the whole module.
 *
 * **A warning never contains a hash.** It names the line, the user, and the
 * algorithm — never the value, because warnings reach the log and the log is copied
 * into issues and pastebins.
 *
 * **A bad line is skipped, never fatal.** A file with one mistyped entry still signs
 * in every other user (**I4**). The only thing that turns enforcement off is a file
 * with *no* usable entry at all, which is reported as such.
 */
import { readFileSync, statSync } from "node:fs";
import { isValidUsername } from "../model/access.js";
import {
  DEFAULT_COST,
  decoyHash,
  hashAlgorithmId,
  hashAlgorithmName,
  hashCost,
  isSupportedHash,
  verifyPassword,
  SUPPORTED_HASH_IDS,
} from "./hash.js";

/** Refuse anything larger. A thousand bcrypt entries is about 62 KiB. */
export const MAX_PASSWD_BYTES = 64 * 1024;
/** Cap on usable entries, so a mistakenly-mounted file cannot fill the map. */
export const MAX_PASSWD_ENTRIES = 1000;
/**
 * Longest password accepted at the login route.
 *
 * bcrypt only reads the first 72 bytes, so this rejects nothing anyone could be
 * using — it exists so a large body cannot be turned into hashing work.
 */
export const MAX_PASSWORD_CHARS = 1024;

export interface PasswdEntry {
  user: string;
  hash: string;
  /** The bcrypt cost from the hash, used to make the decoy verify cost the same. */
  cost: number;
}

/**
 * How the file itself read, separately from what was in it.
 *
 *  - `missing` — no file. The normal state of an unconfigured LabView, and silent.
 *  - `unreadable` — it exists and could not be used: a directory, a permission
 *    problem, too large. Always warned about, because the operator meant to
 *    configure something.
 *  - `ok` — it was read, whatever the contents turned out to be.
 */
export type PasswdState = "ok" | "missing" | "unreadable";

export interface PasswdFile {
  state: PasswdState;
  /** Usable entries only, by username. */
  entries: Map<string, PasswdEntry>;
  warnings: string[];
}

/**
 * Parse passwd text. Pure — no I/O and no clock.
 *
 * Line numbers are 1-based and counted over every line including comments, so a
 * warning points at what the operator sees in their editor.
 */
export function parsePasswd(text: string): { entries: Map<string, PasswdEntry>; warnings: string[] } {
  const entries = new Map<string, PasswdEntry>();
  const warnings: string[] = [];
  let capped = false;

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const line = raw.trim();
    const n = i + 1;
    if (!line || line.startsWith("#")) continue;

    const colon = line.indexOf(":");
    if (colon <= 0) {
      // The line is not echoed: it is either a username LabView has not validated
      // yet or, if the separator was simply missed, a password in clear.
      warnings.push(`passwd line ${n}: no "user:hash" separator — entries look like alice:$2b$12$…`);
      continue;
    }
    const user = line.slice(0, colon).trim();
    const hash = line.slice(colon + 1).trim();

    if (!isValidUsername(user)) {
      // Also not echoed. An invalid username is by definition a string that may
      // contain a newline or a control character, which is how a log gets forged.
      warnings.push(
        `passwd line ${n}: username is not usable — letters, digits and . _ @ - only, up to 64 characters`,
      );
      continue;
    }
    if (!hash) {
      warnings.push(`passwd line ${n}: user "${user}" has no hash`);
      continue;
    }

    const id = hashAlgorithmId(hash);
    if (!id) {
      warnings.push(
        `passwd line ${n}: user "${user}" has a plaintext password, not a hash — LabView never accepts one; run \`npm run hashpw\``,
      );
      continue;
    }
    if (!SUPPORTED_HASH_IDS.includes(id)) {
      warnings.push(
        `passwd line ${n}: user "${user}" uses ${hashAlgorithmName(id)}, which LabView cannot verify — rehash with bcrypt (\`npm run hashpw\` or \`htpasswd -nbB\`)`,
      );
      continue;
    }
    if (!isSupportedHash(hash)) {
      warnings.push(
        `passwd line ${n}: user "${user}" has a malformed bcrypt hash — a complete one is 60 characters`,
      );
      continue;
    }
    if (entries.has(user)) {
      warnings.push(`passwd line ${n}: user "${user}" is already defined above — the first entry wins`);
      continue;
    }
    if (entries.size >= MAX_PASSWD_ENTRIES) {
      if (!capped) {
        warnings.push(`passwd: stopped at ${MAX_PASSWD_ENTRIES} users; later lines were ignored`);
        capped = true;
      }
      continue;
    }
    entries.set(user, { user, hash, cost: hashCost(hash) ?? DEFAULT_COST });
  }

  return { entries, warnings };
}

/**
 * The last successful read of each path, so the file is re-parsed only when it
 * changes.
 *
 * Re-reading rather than loading once at startup means adding a user does not need a
 * restart — the same treatment the Authentik `tokenFile` gets, and the same reason: a
 * credential an operator can rotate without downtime is a credential they will
 * actually rotate. The identity is size + mtime + inode, so an editor that replaces
 * the file is picked up as well as one that writes in place.
 */
const cache = new Map<string, { key: string; file: PasswdFile }>();

/**
 * Read and parse the passwd file at `path`.
 *
 * Never throws. Each failure the operator can actually cause is distinguished,
 * because "could not read the file" is the least useful thing to be told:
 *
 *  - a **directory** at the path is what Docker creates when a bind-mounted host
 *    file does not exist yet, which is the single most common way this goes wrong;
 *  - a **permission** failure is expected, since the container runs unprivileged;
 *  - **too large** means something other than a passwd file got mounted.
 */
export function readPasswd(path: string): PasswdFile {
  let key: string;
  try {
    const st = statSync(path);
    if (st.isDirectory()) {
      return {
        state: "unreadable",
        entries: new Map(),
        warnings: [
          `${path} is a directory, not a file — Docker creates one at a bind-mount path when the host file is missing. Create the file on the host, then recreate the container.`,
        ],
      };
    }
    if (st.size > MAX_PASSWD_BYTES) {
      return {
        state: "unreadable",
        entries: new Map(),
        warnings: [
          `${path} is ${st.size} bytes, over the ${MAX_PASSWD_BYTES}-byte limit for a passwd file — check what is mounted there`,
        ],
      };
    }
    key = `${st.size}:${st.mtimeMs}:${st.ino}`;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      cache.delete(path);
      return { state: "missing", entries: new Map(), warnings: [] };
    }
    return { state: "unreadable", entries: new Map(), warnings: [unreadable(path, code)] };
  }

  const hit = cache.get(path);
  if (hit && hit.key === key) return hit.file;

  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    // The same wording as the stat failure above, and reached far more often than it
    // looks: a mode-600 file owned by root in a world-readable directory stats fine and
    // fails here, which is precisely what a bind-mounted `/config/passwd` is when the
    // container runs unprivileged.
    return {
      state: "unreadable",
      entries: new Map(),
      warnings: [unreadable(path, (err as NodeJS.ErrnoException).code)],
    };
  }

  const { entries, warnings } = parsePasswd(text);
  const file: PasswdFile = { state: "ok", entries, warnings };
  cache.set(path, { key, file });
  return file;
}

/**
 * Why a file could not be read, in the operator's terms.
 *
 * `EACCES` gets its own sentence because it is both the most likely failure and the one
 * whose cause is least obvious from the outside: the image runs as a non-root user by
 * design, so a passwd file the host created as root is unreadable however correct its
 * contents are.
 */
function unreadable(path: string, code: string | undefined): string {
  return code === "EACCES"
    ? `${path} cannot be read by this process — LabView runs unprivileged, so the file has to be readable by its user`
    : `${path} could not be read (${code ?? "unknown error"})`;
}

/** Forget the cached read of every path. Only for tests. */
export function clearPasswdCache(): void {
  cache.clear();
}

/**
 * Whether `password` is `user`'s.
 *
 * Takes the same time whether or not the user exists: an unknown name is verified
 * against {@link decoyHash} at the same cost as a real entry and the result thrown
 * away. Returning early would make the response time a list of valid usernames.
 *
 * The cost for the decoy comes from the file's own entries rather than the default,
 * so an operator who rehashed at cost 14 does not reintroduce the difference.
 */
export async function verifyLogin(
  file: PasswdFile,
  rawUser: string,
  password: string,
): Promise<boolean> {
  const user = rawUser.trim();
  const entry = isValidUsername(user) ? file.entries.get(user) : undefined;
  if (password.length > MAX_PASSWORD_CHARS) return false;

  const hash = entry?.hash ?? (await decoyHash(prevailingCost(file)));
  const ok = await verifyPassword(password, hash);
  return entry ? ok : false;
}

/** The cost of the first usable entry, or the default when there is none. */
function prevailingCost(file: PasswdFile): number {
  for (const e of file.entries.values()) return e.cost;
  return DEFAULT_COST;
}
