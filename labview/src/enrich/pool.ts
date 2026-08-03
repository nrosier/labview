/**
 * Running many independent round-trips without opening all of them at once.
 *
 * Two stages of a scan need this and need it identically. The Docker client inspects one
 * container at a time and a fleet has hundreds; the probe asks one service at a time and
 * a fleet has as many. Both are latency-bound rather than CPU-bound, so serializing them
 * makes a scan take minutes — and both talk to something that will drop connections if
 * given hundreds at once, whether that is a socket proxy or a reverse proxy fronting the
 * whole fleet.
 *
 * Here rather than beside either caller because the second one arriving is exactly when a
 * copy would have been made, and a copy that later diverged on ordering would make one
 * stage's output non-deterministic while the other stayed fine (invariant I7).
 */

/**
 * Map `items` through `fn` with at most `limit` calls in flight, preserving
 * input order in the result.
 *
 * Order-preserving by writing into a pre-sized array by index rather than by pushing as
 * results land, which is what lets a caller walk the fleet in scan order and get the same
 * output twice from the same input however the network behaved in between (**I7**).
 *
 * `fn` must not reject — a rejection escapes and abandons the remaining work. Both
 * callers pass a function that cannot: `getResponse` and the Docker inspect wrapper each
 * return their failure rather than throwing it.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
