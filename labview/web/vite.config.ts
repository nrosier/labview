import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import { fileURLToPath } from "node:url";

// `--config web/vite.config.ts` is run from the package root, and Vite resolves
// `root` against the *working directory*, not against this file. So it is derived
// from `import.meta.url` instead: the web project's root is the directory this
// config lives in, whichever directory npm happened to be invoked from.
const webRoot = fileURLToPath(new URL(".", import.meta.url));

// Dev-only, and loopback only. This is the port LabView's own server defaults to
// (`server.port` in config.ts), not a guess about anyone's host — and `server.*` is
// never inlined into a bundle, so I2 is untouched by it. See §9.
const apiTarget = `http://127.0.0.1:${process.env.LABVIEW_PORT ?? "8080"}`;

export default defineConfig({
  root: webRoot,
  // Relative asset URLs — `./app.js`, not `/app.js`. Vite's default is absolute,
  // which would break the one thing api.ts goes out of its way to preserve: a
  // LabView served under a path prefix. The shell and the API have to agree about
  // this, and both are relative.
  base: "./",
  plugins: [preact()],
  build: {
    // Relative to `root`, so: web/dist — the directory server.ts mounts (§3.8).
    outDir: "dist",
    emptyOutDir: true,
    target: "es2020",
    // Not shipped. The map is ~13 MB, it lands in the runtime image, and
    // @fastify/static serves whatever is in web/dist to anyone who asks (§7).
    // The dev server keeps its own maps regardless of this.
    sourcemap: false,
    // One stylesheet rather than a per-chunk split, so the built name below is
    // unambiguous and the shell needs exactly one <link>.
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        // mermaid reaches for its diagram types through ~38 dynamic imports. Left
        // alone, Rollup turns each into its own chunk; inlining keeps the promise
        // §3.9 makes — one self-contained app.js, no second request to load a
        // diagram — and keeps the public artifact list in §3.13/§7/§12 exactly
        // three files. Valid because there is a single entry (index.html).
        inlineDynamicImports: true,
        entryFileNames: "app.js",
        // styles.css is the only asset: the stylesheet references no url(), so
        // there is nothing else this pattern could collide with.
        assetFileNames: "styles.css",
      },
    },
    // One deliberately large bundle, so Rollup's advice to code-split is noise here.
    // Set just above the known size rather than switched off: a jump past this still
    // says so, which is the part of the warning worth keeping.
    chunkSizeWarningLimit: 4000,
  },
  server: {
    // The API and the OIDC round-trip are the two things the dev server cannot
    // answer itself. Everything else — the shell, the modules, HMR — is Vite's.
    // `/auth` is here because it sits outside `/api` on purpose (§3.13) and the
    // login flow could not complete without it.
    proxy: {
      "/api": { target: apiTarget, changeOrigin: false },
      "/auth": { target: apiTarget, changeOrigin: false },
    },
  },
});
