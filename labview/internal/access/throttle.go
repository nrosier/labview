package access

import (
	"sync"
	"time"
)

// The login throttle (§19).
//
// **A locked-out name is refused regardless of whether the password was right.** That is the point of
// the whole mechanism: a lock that opens for the correct password is not a lock, it is a slightly
// slower guessing game. It also means the throttle's answer is computed before any hash is compared,
// which is why the check comes first and the verification second.
//
// The counter is per name and not per address. An attacker guessing one account moves between
// addresses freely, and a lab behind a tunnel presents every request from the same address — so a
// per-address counter would both miss the attack and lock out the whole household when one person
// mistyped.

// MaxThrottleKeys is the number of usernames tracked at once (§19).
//
// A bound is needed because the key comes off the wire: without one, a script posting a fresh name per
// request would grow the table until the process died — a memory exhaustion delivered through the
// login form. 4096 is far more names than a homelab has and small enough to be free.
const MaxThrottleKeys = 4096

// Throttle counts recent failures per username.
//
// Safe for concurrent use. Every method takes the current time as a parameter so the expiry and the
// eviction are testable without waiting (I7).
type Throttle struct {
	// Max is the failures allowed inside Window before a name is locked. Zero or negative disables
	// the throttle, which is a configuration and not an error.
	Max int

	// Window is how long failures are remembered, and therefore how long a lock lasts.
	Window time.Duration

	mu sync.Mutex

	// entries is keyed on the case-folded sanitised name (ThrottleKey), so `Admin` and `admin` are
	// one account as far as a lock is concerned and the table cannot be filled with arbitrary bytes.
	entries map[string]*attempts

	// order is insertion order, for the eviction §19 requires. A slice rather than a heap: 4096
	// entries evicted one at a time is a memmove of a few kilobytes, and a heap here would be more
	// code than the thing it saves.
	order []string
}

// attempts is one name's recent failures.
type attempts struct {
	// count is failures inside the window, and first is when the window opened. Storing the window's
	// start rather than each failure's time keeps this to two words — and it is what makes the lock
	// last exactly Window from the failure that triggered it rather than sliding forward with every
	// further attempt.
	count int
	first time.Time

	// last is when the most recent failure landed, used only for eviction ordering when the table is
	// full.
	last time.Time
}

// Verdict is what a throttle says about one attempt.
type Verdict struct {
	// Locked is whether this attempt must be refused without checking the password.
	Locked bool

	// RetryAfter is how long until the lock lifts, rounded up to a whole second because that is what
	// a Retry-After header carries. Always at least 1 second when locked: a header saying `0` invites
	// an immediate retry, which is the opposite of what was meant.
	RetryAfter time.Duration
}

// Allow reports whether an attempt for user may proceed.
//
// It counts nothing. A check that incremented would lock a name out for reading the login form, and
// would make the count depend on how many times the gate happened to consult it.
func (t *Throttle) Allow(user string, now time.Time) Verdict {
	if t.Max <= 0 {
		return Verdict{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	e := t.entries[ThrottleKey(user)]
	if e == nil || t.expired(e, now) {
		return Verdict{}
	}
	if e.count < t.Max {
		return Verdict{}
	}

	remaining := t.Window - now.Sub(e.first)
	if remaining < time.Second {
		remaining = time.Second
	}
	return Verdict{Locked: true, RetryAfter: remaining.Round(time.Second)}
}

// Failed records a failed attempt and returns the verdict that now applies.
//
// Returning the new verdict, rather than requiring a second Allow, is what lets the gate answer the
// attempt that *reached* the limit with a 429 rather than telling that one caller their password was
// wrong and the next one that they are locked.
func (t *Throttle) Failed(user string, now time.Time) Verdict {
	if t.Max <= 0 {
		return Verdict{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := ThrottleKey(user)
	e := t.entries[key]
	switch {
	case e == nil:
		if t.entries == nil {
			t.entries = map[string]*attempts{}
		}
		t.evict()
		e = &attempts{first: now}
		t.entries[key], t.order = e, append(t.order, key)
	case t.expired(e, now):
		// A window that closed starts a new one rather than continuing the old count. Otherwise two
		// mistyped passwords a month apart would combine into a lock-out.
		e.count, e.first = 0, now
	}

	e.count, e.last = e.count+1, now

	if e.count < t.Max {
		return Verdict{}
	}
	remaining := t.Window - now.Sub(e.first)
	if remaining < time.Second {
		remaining = time.Second
	}
	return Verdict{Locked: true, RetryAfter: remaining.Round(time.Second)}
}

// Succeeded clears a name's count (§19).
//
// **The reset is on success only.** A name whose owner has just proved who they are is not a name
// under attack, so continuing to count against it would lock out the person who got in — and the
// count that was accumulating was, by construction, somebody failing to be them.
func (t *Throttle) Succeeded(user string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := ThrottleKey(user)
	if _, ok := t.entries[key]; !ok {
		return
	}
	delete(t.entries, key)
	for i, have := range t.order {
		if have == key {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
}

// expired reports whether an entry's window has closed. The caller holds the lock.
func (t *Throttle) expired(e *attempts, now time.Time) bool {
	return t.Window <= 0 || now.Sub(e.first) >= t.Window
}

// evict makes room for one new entry, dropping the oldest (§19). The caller holds the lock.
//
// Oldest by insertion, which is also oldest by when its window opened. The alternative — dropping the
// least recently failed — would let an attacker cycling through names evict the very entry that is
// locking them out, since their own attempts keep the decoy names fresh.
func (t *Throttle) evict() {
	for len(t.entries) >= MaxThrottleKeys && len(t.order) > 0 {
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.entries, oldest)
	}
}

// Tracked is how many names are counted against, for a test and for a diagnostic. It is a count and
// never the names (§19).
func (t *Throttle) Tracked() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
