import { realpathSync } from "node:fs";
import { resolve, sep } from "node:path";

/**
 * Path containment for every file LabView reads out of a stack directory.
 *
 * Shared rather than duplicated because both readers need exactly the same rule and
 * for the same reason. A compose document is untrusted input — `env_file:
 * ../../../../etc/shadow` must not pull a host file into the API response — and a
 * `.labview` sidecar is untrusted in a quieter way: LabView picks its path itself, so
 * only a symlink can escape, and the contents of whatever it points at would be
 * echoed back as a service `description`.
 */

/**
 * Resolve `ref` relative to `dir` and return it only if it stays inside `root`.
 * Returns null when the reference escapes the boundary, either lexically
 * (`../../etc/passwd`) or through a symlink pointing out of the tree.
 *
 * Both the literal and the fully-resolved form of the root are accepted, because
 * an apps root is often reached through a symlink (a TrueNAS dataset under
 * `/mnt/.ix-apps`, a bind mount) and a real path must not be rejected just
 * because it does not textually match the configured one.
 */
export function resolveContained(dir: string, root: string, ref: string): string | null {
  const lexicalRoot = resolve(root);
  const roots = [lexicalRoot, realpathOrNull(lexicalRoot) ?? lexicalRoot];
  const within = (p: string): boolean => roots.some((r) => p === r || p.startsWith(r + sep));

  const target = resolve(dir, ref);
  // Lexical escape: `../..` climbing out of the tree.
  if (!within(target)) return null;
  // Symlink escape: a link inside the tree pointing outside it. Only checkable
  // when the file exists; if it does not there is nothing to read either way.
  const real = realpathOrNull(target);
  if (real !== null && !within(real)) return null;
  return target;
}

export function realpathOrNull(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}
