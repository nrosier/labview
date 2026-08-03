/**
 * Which build is running: the version, and the commit it came from.
 *
 * While LabView is pre-release the semver is not the useful identifier — it sits at
 * `0.1.0` across hundreds of commits, so it cannot answer the one question a version is
 * asked ("is the fix in the thing I am running?"). The short commit can, so that is what
 * gets stamped, and the version rides along behind it.
 *
 * There are two ways to learn a commit and they are not interchangeable, which is why
 * {@link BuildStamp} records which one answered:
 *
 *  - **The image** cannot read git at all. `.git` is at the repository root, the Docker
 *    build context is `./labview`, and `.dockerignore` excludes `.git` in any case — so an
 *    image only knows its commit if the build told it, via `LABVIEW_BUILD_SHA`. When it
 *    did, the claim is strong: these bytes were compiled from that commit.
 *  - **A checkout** reads `.git` directly, because a dev stamp that needs an export step
 *    is a dev stamp nobody has. The claim is weaker and the wording in `model/build.ts`
 *    says so: the working tree *was at* that commit, which is silent about uncommitted
 *    edits, since no file read can see them.
 *
 * Split into a pure {@link resolveBuildStamp} over injected sources and an I/O
 * {@link buildStamp}, for `auth/passwd.ts`'s reason: every rule below — the precedence,
 * the shortening, the four ways `HEAD` can read — is then assertable without committing a
 * `.git` directory to a fixture, which git would not let us do anyway.
 *
 * Everything here degrades (**I4**). No unset variable, missing file, junk `HEAD` or
 * checkout-shaped-but-not-a-checkout directory is an error; each one is the next source
 * getting its turn, and running out of sources is `source: "unknown"` rather than a throw.
 * Nothing on this path may prevent a scan.
 */
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { BuildStamp } from "./model/types.js";

/**
 * The package version.
 *
 * A hand-kept copy of `package.json`'s, which is why the commit is the part the UI leads
 * with. Reading the manifest at runtime is a separate change from stamping the build, and
 * this is not it.
 */
export const VERSION = "0.1.0";

/** Characters of a full object id kept for display — git's own default. */
export const SHORT_SHA_CHARS = 7;
/** Longest stamp accepted from the environment. A full object id is 40. */
export const MAX_SHA_CHARS = 40;
/**
 * How far up from this module to look for a checkout.
 *
 * Three is enough for every layout that exists — `dist/`, `src/` under `tsx`, and
 * `scripts/` — and the fourth is slack. Bounded rather than open-ended because walking to
 * `/` would let a LabView installed anywhere under an unrelated repository report that
 * repository's commit as its own.
 */
export const MAX_WALK_LEVELS = 4;
/**
 * Refuse to read a git file larger than this. `packed-refs` is the big one, and it is a
 * line per ref — tens of KiB in a repository with thousands.
 */
export const MAX_GIT_FILE_BYTES = 256 * 1024;

/** A full object id, as `HEAD`, a loose ref and `packed-refs` all write it. */
const FULL_SHA_RE = /^[0-9a-f]{40}$/i;
/**
 * What a stamp from the environment may contain.
 *
 * Narrow because the value arrives from outside the process and is rendered in the topbar,
 * put in a tooltip and written to a log line: a newline or a control character here is how
 * a log entry gets forged. Anything failing this is treated as absent (the checkout gets
 * its turn) rather than trimmed into a different string, on `sanitizeUsername`'s reasoning
 * — a rejected value is not worth salvaging.
 */
const SAFE_STAMP_RE = /^[A-Za-z0-9._-]+$/;
/**
 * What a `HEAD` symref may point at. `refs/…`, no traversal.
 *
 * `HEAD` is a file, so its contents are input, and this one is turned into a path we then
 * read. Constraining it to a `refs/` subpath with no `..` segment is **I8** in the small:
 * the only thing a checkout may make us open is one of its own refs.
 */
const REF_NAME_RE = /^refs\/[A-Za-z0-9._\-/]+$/;

/** Where {@link resolveBuildStamp} gets its answers. All of them, so it stays pure. */
export interface StampSources {
  env: Record<string, string | undefined>;
  /**
   * File contents, or `undefined` for anything unreadable — absent, a directory, too
   * large, unpermitted. The distinction between those does not matter here the way it
   * does for a passwd file: nobody configured this, so there is nothing to warn about.
   */
  readText: (path: string) => string | undefined;
  /** Directory to start walking up from. Defaults to this module's own. */
  from?: string;
}

/**
 * Resolve the stamp from `sources`. Pure — no fs, no clock, no environment of its own.
 *
 * Precedence is the environment first, and deliberately so: an image built from a
 * checkout that happens to be mounted into it is still the image's commit that matters,
 * and the argument is the only thing that knows it.
 */
export function resolveBuildStamp(sources: StampSources): BuildStamp {
  const fromEnv = readEnvStamp(sources.env.LABVIEW_BUILD_SHA);
  if (fromEnv) return { version: VERSION, commit: fromEnv, source: "image" };

  const fromCheckout = readCheckout(sources.readText, sources.from ?? moduleDir());
  if (fromCheckout) return { version: VERSION, commit: fromCheckout, source: "checkout" };

  // No `commit` key at all rather than an empty string: `source` already names this
  // outcome, and a blank commit would render as one.
  return { version: VERSION, source: "unknown" };
}

/**
 * The stamp of the running build, resolved once.
 *
 * Memoized because it is read on every rebuild and the answer cannot change while the
 * process lives — the environment is fixed at exec, and a checkout moving under a running
 * server is not a state worth chasing.
 */
export function buildStamp(): BuildStamp {
  cached ??= resolveBuildStamp({ env: process.env, readText: readTextSync });
  return cached;
}

let cached: BuildStamp | undefined;

/**
 * `LABVIEW_BUILD_SHA`, validated and shortened.
 *
 * A full object id is cut to {@link SHORT_SHA_CHARS} so the CI-supplied `github.sha` and a
 * human's `git rev-parse --short HEAD` render identically. Anything else is used as given,
 * because a tag or a version string is a deliberate answer to "which build" and truncating
 * it would destroy the answer.
 */
function readEnvStamp(raw: string | undefined): string | undefined {
  const value = (raw ?? "").trim();
  if (!value || !SAFE_STAMP_RE.test(value)) return undefined;
  const capped = value.slice(0, MAX_SHA_CHARS);
  return FULL_SHA_RE.test(capped) ? capped.slice(0, SHORT_SHA_CHARS) : capped;
}

/**
 * Walk up from `from` for a checkout, and return its `HEAD` commit.
 *
 * A `.git` **file** — what a linked worktree or a submodule has — ends the walk without an
 * answer instead of following its `gitdir:` line into another repository's layout. That
 * indirection can chain, and the object id is not in the file it points at either, so the
 * bounded thing to do is stop and let `LABVIEW_BUILD_SHA` be the answer for those trees.
 * Ending the walk rather than continuing up matters: a submodule's parent repository is
 * *not* the commit this build came from.
 */
function readCheckout(readText: StampSources["readText"], from: string): string | undefined {
  let dir = from;
  for (let level = 0; level <= MAX_WALK_LEVELS; level++) {
    const gitDir = join(dir, ".git");
    const head = readText(join(gitDir, "HEAD"));
    if (head !== undefined) return readHead(readText, gitDir, head);
    // `.git` reading as text is a worktree or submodule pointer, not a missing marker.
    if (readText(gitDir) !== undefined) return undefined;

    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
  return undefined;
}

/**
 * The commit `HEAD` names: detached, loose ref, or packed ref.
 *
 * All three are shortened here rather than by the caller, so the stamp is one length
 * whatever path produced it.
 */
function readHead(
  readText: StampSources["readText"],
  gitDir: string,
  head: string,
): string | undefined {
  const text = head.trim();
  if (FULL_SHA_RE.test(text)) return text.slice(0, SHORT_SHA_CHARS);
  if (!text.startsWith("ref:")) return undefined;

  const ref = text.slice(4).trim();
  if (!REF_NAME_RE.test(ref) || ref.includes("..")) return undefined;

  const loose = (readText(join(gitDir, ...ref.split("/"))) ?? "").trim();
  if (FULL_SHA_RE.test(loose)) return loose.slice(0, SHORT_SHA_CHARS);

  // `git gc` or a fresh clone leaves the branch in `packed-refs` with no loose file, which
  // is the normal state of a CI checkout rather than an edge case.
  return readPackedRef(readText(join(gitDir, "packed-refs")), ref);
}

/** The object id `packed-refs` lists for `ref`, ignoring peeled (`^`) and comment lines. */
function readPackedRef(packed: string | undefined, ref: string): string | undefined {
  if (!packed) return undefined;
  for (const line of packed.split(/\r?\n/)) {
    if (!line || line.startsWith("#") || line.startsWith("^")) continue;
    const sp = line.indexOf(" ");
    if (sp <= 0) continue;
    const sha = line.slice(0, sp);
    if (line.slice(sp + 1).trim() !== ref || !FULL_SHA_RE.test(sha)) continue;
    return sha.slice(0, SHORT_SHA_CHARS);
  }
  return undefined;
}

/** This module's directory — `dist/` in an image, `src/` under `tsx`. */
function moduleDir(): string {
  return dirname(fileURLToPath(import.meta.url));
}

/** {@link StampSources.readText} over the real filesystem. Never throws. */
function readTextSync(path: string): string | undefined {
  try {
    if (statSync(path).size > MAX_GIT_FILE_BYTES) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    // Absent, a directory, unreadable — all the same answer, see `StampSources.readText`.
    return undefined;
  }
}
