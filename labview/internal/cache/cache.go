// Package cache is §17's build cache: one scan shared by every reader, and the rule that decides
// when a new one has to be run.
//
// **A forced request may only be answered by a build that started after it arrived.** That is the
// whole contract, and every line below exists to keep it. A caller who pressed Rescan is asking
// about the fleet as it is now; handing them a build that began before they asked would answer a
// question they did not put. The TTL, the coalescing and the once-per-build callback all follow from
// that one sentence.
//
// There are at most two builds at any moment: the one running, and the one queued behind it. A
// forced request that the running build cannot answer does not start a second build alongside it —
// it queues, and every later request that also cannot use the running build queues with it. That is
// what makes two forced requests arriving together share one build rather than run two scans of the
// same fleet.
//
// The clock and the build function are injected, so all five of §17's consequences are testable
// without waiting.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/changes"
	"github.com/nrosier/labview/internal/payload"
)

// Build is one scan. It is handed the probe override this build was asked for, and it never fails —
// a scan that could not read anything still produces a payload saying so (I4).
type Build func(ctx context.Context, probe *bool) payload.Overview

// Built is called once for each completed build, with the note describing what moved since the
// previous one and whether this build was forced.
//
// **Once per build, not once per waiter** (§17): ten browsers sharing one build produce one line in
// the log, because the log records what LabView did and it did one scan.
//
// It runs after the result is published, so a listener that reads the cache sees this build rather
// than the one before it. It must not call back into the cache. It is the one place in this package
// that may log — I7 keeps the analysis silent, not the server.
type Built func(note changes.Note, forced bool)

// Cache holds the current build and coordinates the next one.
type Cache struct {
	build Build
	now   func() time.Time
	ttl   time.Duration
	built Built

	mu sync.Mutex

	// current is the newest finished build, at is when the build that produced it *started*, and
	// probe is the override it was asked with.
	//
	// Started, not finished: the freshness a reader cares about is when LabView looked, and §17's
	// rule is stated in terms of when a build began. It also means a slow build does not get to
	// claim the whole TTL for a fleet it read minutes ago.
	current *payload.Overview
	at      time.Time
	probe   *bool

	// running is the build in progress and queued are the builds waiting to start, oldest first. A
	// waiter takes a pointer, releases the lock and blocks on that build's done channel, so the
	// lock is never held across a scan.
	//
	// The queue holds more than one only when two waiting requests disagree about the probe: every
	// request that can share a queued build does, so the ordinary case is a queue of one.
	running *build
	queued  []*build
}

// build is one run and everything a waiter needs in order to decide whether it may be answered by
// it.
type build struct {
	// startedAt is the whole of the forced-request rule: a forced request that arrived at T may
	// only be answered by a build whose startedAt is at or after T. Zero until the build starts,
	// which is why a queued build is joinable by anyone — it has not started yet, so it cannot
	// have started too early.
	startedAt time.Time

	// forced is whether *any* of this build's waiters forced it. A timer rebuild that a Rescan
	// joined did happen because somebody asked, and §17's cadence turns on whether anybody did.
	forced bool

	// probe is the override this build runs with (§13.7). The request that created the build owns
	// it; see probeSuits for who may join.
	probe *bool

	done   chan struct{}
	result payload.Overview
}

// Options configures a cache.
type Options struct {
	// Build is required.
	Build Build

	// TTL is how long a build stays fresh. Zero or negative means every request rebuilds, which is
	// a setting and not an error — somebody actively editing a fleet may want exactly that.
	TTL time.Duration

	// Now is the injected clock (§17, I7). Nil is time.Now.
	Now func() time.Time

	// Built is optional; nil means nobody is listening.
	Built Built
}

// New makes a cache. It runs nothing: the first build happens on the first Get, or on Warm.
func New(o Options) *Cache {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{build: o.Build, now: now, ttl: o.TTL, built: o.Built}
}

// Get returns a build, running one if this request may not be answered by what is held.
func (c *Cache) Get(ctx context.Context, forced bool, probe *bool) payload.Overview {
	// The arrival time is read first, before the mutex, because it is what the whole rule is stated
	// against. Reading it after acquiring the lock would let a build that started while this call
	// was queued for the lock count as having started after the request arrived.
	arrived := c.now()

	c.mu.Lock()

	// A queued build has not started, so it necessarily starts after this request arrived — which is
	// what lets two forced requests arriving together share one build. Checked before the running
	// build so a forced request joins the pending scan rather than being measured against the stale
	// one.
	for _, b := range c.queued {
		if !probeSuits(probe, b.probe) {
			continue
		}
		if forced {
			b.forced = true
		}
		c.mu.Unlock()
		return c.wait(ctx, b)
	}

	if b := c.running; b != nil && probeSuits(probe, b.probe) {
		// A non-forced request joins whatever is running. A forced one may join only if that build
		// started at or after it arrived.
		if !forced || !b.startedAt.Before(arrived) {
			if forced {
				b.forced = true
			}
			c.mu.Unlock()
			return c.wait(ctx, b)
		}
	}

	if !forced && c.fresh(arrived) && probeSuits(probe, c.probe) {
		out := *c.current
		c.mu.Unlock()
		return out
	}

	b := &build{forced: forced, probe: probe, done: make(chan struct{})}

	// Queue behind the running build rather than beside it. The running build's waiters asked
	// earlier and are entitled to it, and two scans of one fleet at once would read the same Docker
	// socket twice for no gain.
	if c.running != nil {
		c.queued = append(c.queued, b)
		c.mu.Unlock()
		return c.wait(ctx, b)
	}

	b.startedAt = arrived
	c.running = b
	c.mu.Unlock()

	// The build runs on its own goroutine, with a context that cannot be cancelled by the request
	// that happened to start it: other waiters are owed the result, and a browser closing a tab is
	// not a reason to abandon a scan (I4). It is also what lets *this* caller be cancelled — a
	// caller that ran the build inline could not return until it finished, whatever its context
	// said. That goroutine also runs whatever queues behind this build, so a queued build has a
	// runner without the cache keeping one of its own.
	go c.drain(context.WithoutCancel(ctx), b)
	return c.wait(ctx, b)
}

// Warm runs a build in the background, for §18's *the cache MUST be warmed in the background at
// startup*. It returns immediately; a request arriving during the warm build joins it.
func (c *Cache) Warm(ctx context.Context) {
	go c.Get(ctx, false, nil)
}

// Peek returns the held build without running one, or nil. It is for a caller that wants to render
// what is already known — never for one that wants a scan.
func (c *Cache) Peek() *payload.Overview {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		return nil
	}
	out := *c.current
	return &out
}

// fresh reports whether the held build may answer a non-forced request. The caller holds the lock.
func (c *Cache) fresh(at time.Time) bool {
	return c.current != nil && c.ttl > 0 && at.Sub(c.at) < c.ttl
}

// probeSuits reports whether a request asking for want may be answered by a build running with has
// (§13.7).
//
// A nil override is the caller saying *whatever configuration says* — no requirement of their own,
// so any build answers it, and the ordinary overview stays cheap after somebody has forced one
// probing rescan. An explicit override is a requirement about this build, so it is only answered by
// a build that ran with it: a caller who asked for the probe and got a payload without one would
// have been told nothing about the thing they asked about.
func probeSuits(want, has *bool) bool {
	return want == nil || (has != nil && *want == *has)
}

// drain runs b, then whatever queued behind it, until nothing is waiting. The context is already
// detached from the request that started it; cancellation reaches waiters through wait, never
// through the build.
func (c *Cache) drain(ctx context.Context, b *build) {
	for b != nil {
		out := c.build(ctx, b.probe)

		c.mu.Lock()
		previous := c.current
		b.result = out
		// The TTL is stamped from this build's own start, by the same arithmetic every build uses —
		// which is how a forced build resets the TTL (§17) without a rule of its own.
		c.current, c.at, c.probe = &out, b.startedAt, b.probe
		forced := b.forced

		// Take the oldest queued build, in arrival order: a request that waited longer is not made
		// to wait again behind one that arrived after it.
		var next *build
		if len(c.queued) > 0 {
			next, c.queued = c.queued[0], c.queued[1:]
			next.startedAt = c.now()
		}
		c.running = next
		c.mu.Unlock()

		close(b.done)

		if c.built != nil {
			c.built(changes.Describe(previous, out), forced)
		}

		b = next
	}
}

// wait blocks until the build finishes, or until the caller's context is done.
//
// A cancelled caller gets the previous build if there is one and an empty payload if there is not.
// The build itself carries on for the waiters that are still owed it.
func (c *Cache) wait(ctx context.Context, b *build) payload.Overview {
	select {
	case <-b.done:
		return b.result
	case <-ctx.Done():
		if held := c.Peek(); held != nil {
			return *held
		}
		return payload.Overview{}
	}
}
