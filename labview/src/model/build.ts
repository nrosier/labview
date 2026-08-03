/**
 * What the page says about the build it is drawing: the label in the topbar, and the
 * sentence behind it.
 *
 * Pure and free of any Node import, for `model/access.ts`'s reason — the topbar imports
 * this file, `tsconfig.web.json` compiles `web/` with `types: []`, and everything that
 * needs the filesystem or the environment to *find* the build lives in `src/build.ts`
 * instead, which the web bundle cannot reach.
 *
 * Here rather than inside the component because the sentence is the load-bearing part.
 * `image` and `checkout` are different claims about the same seven characters, and the
 * whole reason `BuildStamp.source` exists is so the UI can say which one it has. A tooltip
 * written in a `.tsx` could not be asserted — smoke never mounts a DOM — and an
 * unassertable sentence about provenance is exactly the sentence that drifts into
 * over-claiming (**I1**).
 */
import type { BuildStamp, BuildStampSource } from "./types.js";

/**
 * What the topbar shows beside the wordmark.
 *
 * The commit alone when there is one: every build of a pre-release is `0.1.0`, so the
 * version distinguishes nothing and the sha distinguishes everything. The version is the
 * fallback rather than an addition, so something always renders — a stamp that can be
 * blank is a stamp an operator learns to ignore.
 */
export function buildLabel(build: BuildStamp): string {
  return build.commit ?? build.version;
}

/**
 * The sentence behind the label, one per source.
 *
 * Exhaustive over {@link BuildStampSource} on purpose: a fifth way to learn a commit is a
 * compile error here until somebody has decided what it lets LabView claim.
 */
const BUILD_TITLE: Record<BuildStampSource, (build: BuildStamp) => string> = {
  // The strong claim, and the only one entitled to "built from": the commit was passed in
  // at image build time, so it describes the bytes that are running.
  image: (b) => `LabView ${b.version} — image built from commit ${b.commit}.`,
  // The weak claim, stated as such. A file read sees `HEAD`, never the working tree, so an
  // edited-but-uncommitted checkout reports the commit it diverged from. Saying so is the
  // difference between a useful stamp and a misleading one.
  checkout: (b) =>
    `LabView ${b.version} — running from a checkout at commit ${b.commit}. Uncommitted changes are not reflected.`,
  // Names the absence and stops. No sha, no "built from", nothing to mistake for
  // provenance: an image built without `LABVIEW_BUILD_SHA`, or a copy of the tree with no
  // git in it, genuinely does not know which commit it came from.
  unknown: (b) => `LabView ${b.version}. This build does not record which revision it came from.`,
};

export function buildTitle(build: BuildStamp): string {
  return BUILD_TITLE[build.source](build);
}

/**
 * The one line the log says at startup about which build is running.
 *
 * `LabView 0.1.0 (d0e2030, image)`. Shaped after `accessModeSummary` and the
 * `LabView scanning <root>` line so the startup block reads as one story, and it names the
 * source for the same reason the tooltip does: a log copied into an issue has to be honest
 * about whether that sha describes the bytes or just the tree they were started in.
 */
export function buildSummary(build: BuildStamp): string {
  return build.commit
    ? `LabView ${build.version} (${build.commit}, ${build.source})`
    : `LabView ${build.version} (no revision recorded)`;
}
