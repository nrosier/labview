#!/usr/bin/env node
import { build, context } from "esbuild";
import { cpSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outdir = resolve(root, "web/dist");
const watch = process.argv.includes("--watch");

mkdirSync(outdir, { recursive: true });
// Copy the static shell + styles verbatim.
cpSync(resolve(root, "web/index.html"), resolve(outdir, "index.html"));
cpSync(resolve(root, "web/styles.css"), resolve(outdir, "styles.css"));

/** @type {import('esbuild').BuildOptions} */
const options = {
  entryPoints: [resolve(root, "web/main.tsx")],
  bundle: true,
  format: "esm",
  splitting: false,
  sourcemap: true,
  minify: !watch,
  target: ["es2020"],
  jsx: "automatic",
  jsxImportSource: "preact",
  outfile: resolve(outdir, "app.js"),
  logLevel: "info",
  loader: { ".css": "empty" },
  define: { "process.env.NODE_ENV": watch ? '"development"' : '"production"' },
};

if (watch) {
  const ctx = await context(options);
  await ctx.watch();
  console.log("[build-web] watching…");
} else {
  await build(options);
  console.log("[build-web] done ->", outdir);
}
