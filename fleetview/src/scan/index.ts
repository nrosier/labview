import type { FleetViewConfig } from "../config.js";
import type { AppStack } from "../model/types.js";
import { discoverStacks } from "./discover.js";
import { parseStack } from "./compose.js";

/** Discover and parse every stack under the configured apps root. */
export function scanStacks(cfg: FleetViewConfig): { stacks: AppStack[]; warnings: string[] } {
  const warnings: string[] = [];
  const discovered = discoverStacks(cfg);
  if (discovered.length === 0) {
    warnings.push(`No compose files found under ${cfg.appsRoot}. Is it mounted?`);
  }
  const stacks: AppStack[] = [];
  for (const disc of discovered) {
    try {
      stacks.push(parseStack(disc));
    } catch (err) {
      warnings.push(`Failed to parse ${disc.dir}: ${(err as Error).message}`);
    }
  }
  return { stacks, warnings };
}

export { discoverStacks } from "./discover.js";
export { parseStack } from "./compose.js";
