/**
 * Failed-attempt throttling for the login route.
 *
 * **Keyed by username, not by source address.** LabView is meant to sit behind a
 * tunnel and a reverse proxy, where every request arrives from the same handful of
 * addresses — the proxy's. Keying on the peer would put the whole fleet in one bucket,
 * so six wrong passwords from one browser would lock everybody out, and keying on
 * `X-Forwarded-For` would key on a header anyone can set. The username is the thing
 * being guessed, so it is the thing counted.
 *
 * The consequence is deliberate and worth stating: an attacker who knows a username
 * can keep that one account locked out. For a read-only dashboard with a handful of
 * operators that is a far better failure than either alternative, and the operator can
 * still reach `/api/healthz`, the logs and the container.
 *
 * `now` is a parameter, never read from the clock, because every rule here is a
 * comparison against it.
 */

/** What the login route should do about an attempt. */
export interface ThrottleDecision {
  allowed: boolean;
  /** Seconds to wait, for the `Retry-After` header. `0` when allowed. */
  retryAfterSeconds: number;
}

interface Bucket {
  failures: number;
  /** Epoch ms of the most recent failure — both the window anchor and the eviction key. */
  last: number;
}

export class LoginThrottle {
  private readonly buckets = new Map<string, Bucket>();

  /**
   * @param maxFailures attempts allowed within the window before locking.
   * @param lockoutSeconds how long a lock lasts, and how much quiet resets the count.
   * @param max distinct usernames tracked at once.
   */
  constructor(
    private readonly maxFailures: number,
    private readonly lockoutSeconds: number,
    private readonly max = 4096,
  ) {}

  /**
   * The key a username counts against.
   *
   * Lower-cased, so `Alice` and `alice` share a budget — otherwise case alone
   * multiplies the allowance by every capitalisation of the name. Callers pass the
   * output of `sanitizeUsername`, which collapses every unusable name to `"?"`: all
   * junk usernames then share one bucket, which is the right answer, since a script
   * spraying random names is one attacker.
   */
  static key(sanitizedUser: string): string {
    return sanitizedUser.toLowerCase();
  }

  /**
   * Whether an attempt on `key` may proceed.
   *
   * Read-only — asking does not consume an attempt, so this can be called before the
   * password is verified without a correct password ever being charged for one.
   */
  check(key: string, now: Date): ThrottleDecision {
    const b = this.buckets.get(key);
    if (!b || b.failures < this.maxFailures) return { allowed: true, retryAfterSeconds: 0 };
    const elapsed = (now.getTime() - b.last) / 1000;
    const remaining = this.lockoutSeconds - elapsed;
    if (remaining <= 0) {
      // The window closed. Drop the bucket rather than zeroing it, so an abandoned
      // name stops occupying a slot.
      this.buckets.delete(key);
      return { allowed: true, retryAfterSeconds: 0 };
    }
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(remaining)) };
  }

  /**
   * Charge a failure.
   *
   * The window is anchored to the *latest* failure, not the first, so the count only
   * resets after `lockoutSeconds` of quiet. Anchoring to the first would let an
   * attacker pace their guesses to the window boundary and never be locked out.
   */
  fail(key: string, now: Date): ThrottleDecision {
    const t = now.getTime();
    const existing = this.buckets.get(key);
    const stale = existing !== undefined && (t - existing.last) / 1000 > this.lockoutSeconds;
    if (existing && !stale) {
      existing.failures += 1;
      existing.last = t;
    } else {
      this.evictIfFull();
      this.buckets.set(key, { failures: 1, last: t });
    }
    return this.check(key, now);
  }

  /** Clear the count for `key`. A correct password ends the lockout. */
  succeed(key: string): void {
    this.buckets.delete(key);
  }

  /** Drop every bucket whose window has closed. */
  prune(now: Date): void {
    const cutoff = now.getTime() - this.lockoutSeconds * 1000;
    for (const [k, b] of this.buckets) if (b.last <= cutoff) this.buckets.delete(k);
  }

  get size(): number {
    return this.buckets.size;
  }

  /**
   * Make room at the cap by dropping the least recently failed bucket.
   *
   * Bounded because the key comes from a request body: without a cap, a script posting
   * a million distinct usernames would be a memory leak rather than a lockout. The
   * oldest entry is the one closest to expiring anyway, so evicting it is the smallest
   * loss — and losing a bucket loses a lockout, not a credential.
   */
  private evictIfFull(): void {
    if (this.buckets.size < this.max) return;
    let oldest: string | undefined;
    let oldestAt = Infinity;
    for (const [k, b] of this.buckets) {
      if (b.last < oldestAt) {
        oldest = k;
        oldestAt = b.last;
      }
    }
    if (oldest !== undefined) this.buckets.delete(oldest);
  }
}
