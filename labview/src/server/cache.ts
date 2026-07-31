/**
 * The scan cache, and the one rule that makes an explicit rescan trustworthy.
 *
 * A scan of a real fleet takes seconds — one Engine sweep plus two API exchanges — and
 * several callers can want a result inside that window: the warm scan at boot, a page
 * load, a timer expiring, an operator pressing Rescan. Sharing one build between them is
 * the point of this module, and it is also where a rescan can quietly lie.
 *
 * A build reads the compose files once, at its start. So a build that began *before* the
 * operator edited a file cannot contain that edit, and handing it to a rescan that
 * arrived *after* the edit answers with the pre-edit fleet — which looks exactly like
 * "LabView did not re-read the files". Hence the rule: a forced request may only be
 * answered by a build that started after the request arrived. Everything else here is
 * ordinary coalescing.
 *
 * Separated from `startServer` because the race is the behaviour: with `build` and `now`
 * injected, every ordering is assertable without a listening socket or a real clock.
 */

export interface ScanCacheDeps<T> {
  /** Produce a fresh value. Called at most once per concurrent wave of requests. */
  build: () => Promise<T>;
  /** How long a value may be served without rebuilding. `0` disables reuse. */
  ttlMs: number;
  /** Injected for determinism in tests. Defaults to `Date.now`. */
  now?: () => number;
  /**
   * Called once per completed build — not once per caller waiting on it.
   *
   * `prev` is the value this build replaced, or `undefined` for the first build, which is
   * what lets a caller report what changed. `forced` distinguishes an explicit rescan
   * from a timer expiry, because the two deserve different noise levels.
   */
  onBuilt?: (next: T, prev: T | undefined, info: { forced: boolean }) => void;
}

export interface ScanCache<T> {
  /**
   * The current value, rebuilding when it is stale or when `force` is set.
   *
   * Rejects when the build rejects; the previously cached value is left intact, so the
   * next caller reads the old value or triggers a fresh attempt rather than inheriting
   * the failure.
   */
  get(force: boolean): Promise<T>;
  /** The cached value without ever building. For callers that only want what is already known. */
  peek(): T | undefined;
}

export function createScanCache<T>(deps: ScanCacheDeps<T>): ScanCache<T> {
  const now = deps.now ?? Date.now;
  let value: T | undefined;
  let builtAt = 0;
  let inflight: Promise<T> | null = null;
  let inflightStartedAt = 0;

  async function get(force: boolean): Promise<T> {
    const requestedAt = now();
    if (!force && value !== undefined && now() - builtAt < deps.ttlMs) return value;

    // A loop, not an `if`: after awaiting one build another caller may have started the
    // next, and this request has to re-ask the same question of it.
    for (;;) {
      const current = inflight;
      if (!current) break;
      // A passive request takes whatever is being built. A forced one only accepts a
      // build that began after it asked — otherwise it would return a scan of the files
      // as they were before the edit that prompted the click.
      if (!force || inflightStartedAt >= requestedAt) return current;
      // Wait it out rather than starting a second build alongside it: two concurrent
      // sweeps would double the load on the socket proxy to produce one answer. The
      // failure is swallowed here only so this request goes on to build for itself —
      // the original caller still sees the rejection.
      await current.catch(() => undefined);
    }

    inflightStartedAt = now();
    const build = deps
      .build()
      .then((next) => {
        const prev = value;
        value = next;
        builtAt = now();
        deps.onBuilt?.(next, prev, { forced: force });
        return next;
      })
      .finally(() => {
        if (inflight === build) inflight = null;
      });
    inflight = build;
    return build;
  }

  return { get, peek: () => value };
}
