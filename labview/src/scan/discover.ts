import { readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import type { LabViewConfig } from "../config.js";

export interface DiscoveredStack {
  id: string;
  dir: string;
  composeFile: string;
  envFile?: string;
}

/**
 * Find every immediate subdirectory of `appsRoot` that contains a compose file.
 * Layout expected: `<appsRoot>/<container>/compose.yml` (+ optional `.env`).
 */
export function discoverStacks(cfg: LabViewConfig): DiscoveredStack[] {
  const root = cfg.appsRoot;
  if (!existsSync(root)) return [];

  const entries = safeReaddir(root);
  const stacks: DiscoveredStack[] = [];

  for (const name of entries) {
    if (name.startsWith(".")) continue;
    const dir = join(root, name);
    let isDir = false;
    try {
      isDir = statSync(dir).isDirectory();
    } catch {
      continue;
    }
    if (!isDir) continue;

    const composeFile = cfg.composeFilenames.map((f) => join(dir, f)).find((p) => existsSync(p));
    if (!composeFile) continue;

    const envCandidate = join(dir, ".env");
    stacks.push({
      id: name,
      dir,
      composeFile,
      envFile: existsSync(envCandidate) ? envCandidate : undefined,
    });
  }

  stacks.sort((a, b) => a.id.localeCompare(b.id));
  return stacks;
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}
