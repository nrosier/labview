package cache

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/changes"
	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

// clock is the injected clock §17 requires. It does not sleep: a test moves it by hand, so every
// assertion about the TTL and about arrival order is exact rather than raced.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock {
	return &clock{at: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// builder is the injected build function. It counts its runs, records the probe override each was
// asked with, and can be held open so a test controls exactly when a build finishes.
type builder struct {
	mu      sync.Mutex
	runs    int
	probes  []*bool
	entered chan struct{} // one send per build started
	release chan struct{} // a build waits here when hold is set
	hold    bool

	// stacks lets a test make consecutive builds differ, so the change note has something to say.
	stacks func(run int) []payload.AppStack
}

func newBuilder() *builder {
	return &builder{entered: make(chan struct{}, 64), release: make(chan struct{})}
}

func (b *builder) fn(ctx context.Context, probe *bool) payload.Overview {
	b.mu.Lock()
	b.runs++
	run := b.runs
	b.probes = append(b.probes, probe)
	hold := b.hold
	stacks := b.stacks
	b.mu.Unlock()

	select {
	case b.entered <- struct{}{}:
	default:
	}

	if hold {
		<-b.release
	}

	out := payload.Overview{Meta: payload.ScanMeta{AppsRoot: "/data/apps",
		ScannedAt: strconv.Itoa(run)}}
	if stacks != nil {
		out.Stacks = stacks(run)
		out.Stats.Stacks = len(out.Stacks)
		for _, s := range out.Stacks {
			out.Stats.Services += len(s.Services)
		}
	}
	return out
}

func (b *builder) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.runs
}

func (b *builder) asked() []*bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*bool(nil), b.probes...)
}

// holding makes every build block until releaseAll is called.
func (b *builder) holding() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hold = true
}

func (b *builder) releaseAll() {
	b.mu.Lock()
	b.hold = false
	b.mu.Unlock()
	close(b.release)
}

// awaitEntered blocks until n builds have started, and fails rather than hanging if they do not.
func (b *builder) awaitEntered(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-b.entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("waited for build %d of %d to start; %d ran", i+1, n, b.count())
		}
	}
}

// notes records what the built callback was told, so a test can assert it fired once per build.
type notes struct {
	mu   sync.Mutex
	got  []changes.Note
	made []bool
}

func (n *notes) fn(note changes.Note, forced bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, note)
	n.made = append(n.made, forced)
}

func (n *notes) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.got)
}

func (n *notes) at(i int) (changes.Note, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.got[i], n.made[i]
}

// await blocks until want callbacks have fired. The callback runs after the result is published, so
// a Get returning does not on its own mean the listener has been told — waiters are not made to wait
// on a listener.
func (n *notes) await(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n.count() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waited for %d callbacks; %d fired", want, n.count())
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

// fixture is a cache with everything injected.
func fixture(t *testing.T, ttl time.Duration) (*Cache, *builder, *clock, *notes) {
	t.Helper()
	b, ck, n := newBuilder(), newClock(), &notes{}
	return New(Options{Build: b.fn, TTL: ttl, Now: ck.now, Built: n.fn}), b, ck, n
}

// ---------------------------------------------------------------------------
// §17's five consequences
// ---------------------------------------------------------------------------

func TestAForcedRequestNeverReceivesAnInFlightBuildsResult(t *testing.T) {
	// The first of the five, and the sentence the whole package is built around: *a forced request
	// may only be answered by a build that started after it arrived*. A caller who pressed Rescan is
	// asking about the fleet as it is now.
	c, b, ck, _ := fixture(t, time.Minute)
	b.holding()

	// A build is running, started before the forced request arrives.
	go c.Get(context.Background(), false, nil)
	b.awaitEntered(t, 1)
	ck.advance(time.Second)

	answered := make(chan payload.Overview, 1)
	go func() { answered <- c.Get(context.Background(), true, nil) }()

	// The forced request is still waiting: nothing it may be answered by has finished.
	select {
	case out := <-answered:
		t.Fatalf("the forced request took the in-flight build's result: %q", out.Meta.ScannedAt)
	case <-time.After(100 * time.Millisecond):
	}

	b.releaseAll()
	out := <-answered
	if out.Meta.ScannedAt != "2" {
		t.Fatalf("the forced request must be answered by the second build; got build %q",
			out.Meta.ScannedAt)
	}
	if b.count() != 2 {
		t.Fatalf("one build was running and one had to be run for the forced request; got %d",
			b.count())
	}
}

func TestTwoForcedRequestsArrivingTogetherShareOneBuild(t *testing.T) {
	// The second. Both arrive while an older build is running, so neither may take it — and the one
	// they get is the same one, because two scans of one fleet at the same moment read the same
	// socket twice for no gain.
	c, b, ck, _ := fixture(t, time.Minute)
	b.holding()

	go c.Get(context.Background(), false, nil)
	b.awaitEntered(t, 1)
	ck.advance(time.Second)

	first := make(chan payload.Overview, 1)
	second := make(chan payload.Overview, 1)
	go func() { first <- c.Get(context.Background(), true, nil) }()
	go func() { second <- c.Get(context.Background(), true, nil) }()

	// Give both forced requests time to queue before anything finishes.
	time.Sleep(100 * time.Millisecond)
	b.releaseAll()

	a, z := <-first, <-second
	if a.Meta.ScannedAt != z.Meta.ScannedAt {
		t.Fatalf("the two forced requests were answered by different builds: %q and %q",
			a.Meta.ScannedAt, z.Meta.ScannedAt)
	}
	if b.count() != 2 {
		t.Fatalf("the stale build plus one shared build is two; got %d", b.count())
	}
}

func TestTwoForcedRequestsAtOneInstantWithNothingRunningShareOneBuild(t *testing.T) {
	// The same consequence from the other side: no build is in flight, and the clock does not move
	// between the two arrivals. The second request arrives at the instant the first build started,
	// which is *at or after* its arrival, so it is entitled to it.
	c, b, _, _ := fixture(t, time.Minute)
	b.holding()

	first := make(chan payload.Overview, 1)
	go func() { first <- c.Get(context.Background(), true, nil) }()
	b.awaitEntered(t, 1)

	second := make(chan payload.Overview, 1)
	go func() { second <- c.Get(context.Background(), true, nil) }()
	time.Sleep(100 * time.Millisecond)

	b.releaseAll()
	a, z := <-first, <-second
	if a.Meta.ScannedAt != z.Meta.ScannedAt {
		t.Fatalf("both arrived at the build's own start instant, so both share it; got %q and %q",
			a.Meta.ScannedAt, z.Meta.ScannedAt)
	}
	if b.count() != 1 {
		t.Fatalf("one build; got %d", b.count())
	}
}

func TestAForcedBuildResetsTheTTL(t *testing.T) {
	// The third. The forced scan is the newest reading of the fleet, so the next ordinary request is
	// answered from it rather than rebuilding because the *previous* build had aged out.
	c, b, ck, _ := fixture(t, 60*time.Second)

	c.Get(context.Background(), false, nil) // build 1 at t+0
	ck.advance(50 * time.Second)
	c.Get(context.Background(), true, nil) // build 2 at t+50, forced

	ck.advance(30 * time.Second) // t+80: 80s after build 1, 30s after build 2
	out := c.Get(context.Background(), false, nil)

	if b.count() != 2 {
		t.Fatalf("the forced build reset the TTL, so no third build was needed; got %d builds",
			b.count())
	}
	if out.Meta.ScannedAt != "2" {
		t.Fatalf("answered from the forced build; got build %q", out.Meta.ScannedAt)
	}
}

func TestANonForcedRequestDuringAForcedBuildJoinsIt(t *testing.T) {
	// The fourth. A reader with no requirement of their own takes whatever is being read now.
	c, b, ck, _ := fixture(t, time.Minute)
	b.holding()

	go c.Get(context.Background(), true, nil)
	b.awaitEntered(t, 1)
	ck.advance(time.Second)

	joined := make(chan payload.Overview, 1)
	go func() { joined <- c.Get(context.Background(), false, nil) }()
	time.Sleep(100 * time.Millisecond)

	b.releaseAll()
	if out := <-joined; out.Meta.ScannedAt != "1" {
		t.Fatalf("the ordinary request joins the forced build; got build %q", out.Meta.ScannedAt)
	}
	if b.count() != 1 {
		t.Fatalf("joining is not building; got %d builds", b.count())
	}
}

func TestTheBuiltCallbackFiresOncePerBuildAndNotOncePerWaiter(t *testing.T) {
	// The fifth. Ten browsers sharing one build produce one line in the log, because the log records
	// what LabView did and it did one scan.
	c, b, _, n := fixture(t, time.Minute)
	b.holding()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Get(context.Background(), false, nil) }()
	}
	b.awaitEntered(t, 1)
	time.Sleep(100 * time.Millisecond)
	b.releaseAll()
	wg.Wait()
	n.await(t, 1)

	if b.count() != 1 {
		t.Fatalf("ten waiters, one build; got %d", b.count())
	}
	if n.count() != 1 {
		t.Fatalf("the callback fires once per build, not once per waiter; fired %d times", n.count())
	}
}

// ---------------------------------------------------------------------------
// The TTL and the ordinary path
// ---------------------------------------------------------------------------

func TestTheFirstRequestBuilds(t *testing.T) {
	c, b, _, _ := fixture(t, time.Minute)

	if out := c.Get(context.Background(), false, nil); out.Meta.AppsRoot != "/data/apps" {
		t.Fatalf("the first request is answered by a build; got %#v", out.Meta)
	}
	if b.count() != 1 {
		t.Fatalf("one build; got %d", b.count())
	}
}

func TestAFreshBuildAnswersWithoutRebuilding(t *testing.T) {
	c, b, ck, _ := fixture(t, 60*time.Second)

	c.Get(context.Background(), false, nil)
	ck.advance(59 * time.Second)
	c.Get(context.Background(), false, nil)

	if b.count() != 1 {
		t.Fatalf("still inside the TTL; got %d builds", b.count())
	}
}

func TestABuildOlderThanTheTTLIsRebuilt(t *testing.T) {
	c, b, ck, _ := fixture(t, 60*time.Second)

	c.Get(context.Background(), false, nil)
	ck.advance(60 * time.Second)
	c.Get(context.Background(), false, nil)

	if b.count() != 2 {
		t.Fatalf("the TTL had elapsed; got %d builds", b.count())
	}
}

func TestTheTTLIsMeasuredFromWhenTheBuildStarted(t *testing.T) {
	// Not from when it finished. The freshness a reader cares about is when LabView looked, and a
	// slow build does not get to claim the whole TTL for a fleet it read minutes ago.
	c, b, ck, _ := fixture(t, 60*time.Second)
	b.holding()

	slow := make(chan struct{})
	go func() { defer close(slow); c.Get(context.Background(), false, nil) }()
	b.awaitEntered(t, 1)
	ck.advance(90 * time.Second) // the build takes a minute and a half
	b.releaseAll()
	<-slow // and it has published before the next request arrives

	// It is now t+90 and the build started at t+0, so it is already stale.
	c.Get(context.Background(), false, nil)
	if b.count() != 2 {
		t.Fatalf("a build that started 90s ago is stale under a 60s TTL; got %d builds", b.count())
	}
}

func TestAZeroTTLRebuildsEveryTime(t *testing.T) {
	// A setting, not an error: somebody actively editing a fleet may want exactly this.
	c, b, _, _ := fixture(t, 0)

	c.Get(context.Background(), false, nil)
	c.Get(context.Background(), false, nil)
	c.Get(context.Background(), false, nil)

	if b.count() != 3 {
		t.Fatalf("no TTL means no cache; got %d builds", b.count())
	}
}

// ---------------------------------------------------------------------------
// Coalescing and the probe override
// ---------------------------------------------------------------------------

func TestConcurrentRequestsShareOneBuild(t *testing.T) {
	// §18: *Concurrent requests share one in-flight build unless one is forced.*
	c, b, _, _ := fixture(t, time.Minute)
	b.holding()

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Get(context.Background(), false, nil) }()
	}
	b.awaitEntered(t, 1)
	time.Sleep(100 * time.Millisecond)
	b.releaseAll()
	wg.Wait()

	if b.count() != 1 {
		t.Fatalf("25 concurrent readers, one build; got %d", b.count())
	}
}

func TestTheProbeOverrideOfTheRequestThatStartedTheBuildIsWhatTheBuildRunsWith(t *testing.T) {
	// §13.7: an override is *for this build*. The caller who asked for it is the one whose request
	// created the build, and the build function is told so.
	c, b, _, _ := fixture(t, time.Minute)

	c.Get(context.Background(), true, yes())

	asked := b.asked()
	if len(asked) != 1 || asked[0] == nil || !*asked[0] {
		t.Fatalf("the build must be told the override it was asked with; got %v", asked)
	}
}

func TestARequestWithNoOverrideIsAnsweredByAnyBuild(t *testing.T) {
	// A nil override is the caller saying *whatever configuration says* — no requirement of their
	// own — so the ordinary overview stays cheap after somebody has forced one probing rescan.
	c, b, _, _ := fixture(t, time.Minute)

	c.Get(context.Background(), true, yes())
	c.Get(context.Background(), false, nil)

	if b.count() != 1 {
		t.Fatalf("a request with no requirement takes what is held; got %d builds", b.count())
	}
}

func TestARequestWhoseExplicitOverrideDisagreesIsNotAnsweredFromTheCache(t *testing.T) {
	// The other side of it: a caller who asked for the probe and got a payload without one would have
	// been told nothing about the thing they asked about.
	c, b, _, _ := fixture(t, time.Minute)

	c.Get(context.Background(), false, no())
	c.Get(context.Background(), false, yes())

	if b.count() != 2 {
		t.Fatalf("the second request asked a different question; got %d builds", b.count())
	}
	asked := b.asked()
	if asked[0] == nil || *asked[0] || asked[1] == nil || !*asked[1] {
		t.Fatalf("each build ran with its own request's override; got %v", asked)
	}
}

func TestARequestWhoseExplicitOverrideMatchesIsAnsweredFromTheCache(t *testing.T) {
	c, b, _, _ := fixture(t, time.Minute)

	c.Get(context.Background(), false, yes())
	c.Get(context.Background(), false, yes())

	if b.count() != 1 {
		t.Fatalf("the same question is answered from the same build; got %d builds", b.count())
	}
}

func TestARequestWithADifferentOverrideDoesNotJoinAnInFlightBuild(t *testing.T) {
	c, b, _, _ := fixture(t, time.Minute)
	b.holding()

	go c.Get(context.Background(), false, no())
	b.awaitEntered(t, 1)

	wanted := make(chan payload.Overview, 1)
	go func() { wanted <- c.Get(context.Background(), false, yes()) }()
	time.Sleep(100 * time.Millisecond)

	b.releaseAll()
	<-wanted

	if b.count() != 2 {
		t.Fatalf("a different question needs its own build; got %d", b.count())
	}
}

func TestTwoQueuedBuildsThatDisagreeAreBothRunAndNeitherWaiterIsStranded(t *testing.T) {
	// The queue holds more than one only when waiting requests disagree about the probe. Overwriting
	// a queued build with a second one would leave its waiter blocked for ever, so the queue is a
	// queue rather than a slot.
	c, b, ck, _ := fixture(t, time.Minute)
	b.holding()

	go c.Get(context.Background(), false, nil) // the stale build
	b.awaitEntered(t, 1)
	ck.advance(time.Second)

	first := make(chan payload.Overview, 1)
	second := make(chan payload.Overview, 1)
	go func() { first <- c.Get(context.Background(), true, yes()) }()
	go func() { second <- c.Get(context.Background(), true, no()) }()
	time.Sleep(150 * time.Millisecond)

	b.releaseAll()

	for name, ch := range map[string]chan payload.Overview{"probe on": first, "probe off": second} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("the %s waiter was stranded", name)
		}
	}
	if b.count() != 3 {
		t.Fatalf("the stale build plus one for each disagreeing request; got %d", b.count())
	}
}

// ---------------------------------------------------------------------------
// The cadence the callback reports
// ---------------------------------------------------------------------------

func TestTheFirstBuildsCallbackCarriesTheBaseline(t *testing.T) {
	c, b, _, n := fixture(t, time.Minute)
	b.stacks = func(int) []payload.AppStack {
		return []payload.AppStack{{ID: "media", Services: []payload.Service{{Name: "jellyfin"}}}}
	}

	c.Get(context.Background(), false, nil)
	n.await(t, 1)

	note, forced := n.at(0)
	if note.Baseline == "" {
		t.Fatalf("the first build states the baseline; got %#v", note)
	}
	if forced {
		t.Fatal("a first build nobody asked for is not forced")
	}
}

func TestAQuietTimerRebuildIsQuietAndAQuietForcedOneIsStillMarkedForced(t *testing.T) {
	// §17's cadence: *a **forced** rescan answers even when nothing moved (somebody asked); only a
	// quiet **timer** rebuild stays silent*. The cache does not decide what to print — it hands the
	// listener both facts, so the listener can apply that rule.
	c, b, ck, n := fixture(t, time.Second)
	b.stacks = func(int) []payload.AppStack {
		return []payload.AppStack{{ID: "media", Services: []payload.Service{{Name: "jellyfin"}}}}
	}

	c.Get(context.Background(), false, nil) // the baseline
	ck.advance(2 * time.Second)
	c.Get(context.Background(), false, nil) // a timer rebuild of an unchanged fleet
	c.Get(context.Background(), true, nil)  // and a forced one
	n.await(t, 3)

	if n.count() != 3 {
		t.Fatalf("three builds, three callbacks; got %d", n.count())
	}

	timer, timerForced := n.at(1)
	if !timer.Quiet() || timerForced {
		t.Fatalf("an unforced rebuild of an unchanged fleet is quiet and unforced; got %#v %v",
			timer, timerForced)
	}

	rescan, rescanForced := n.at(2)
	if !rescan.Quiet() {
		t.Fatalf("nothing moved, so the note itself is still quiet; got %#v", rescan)
	}
	if !rescanForced {
		t.Fatal("somebody asked, which is what lets the listener answer anyway")
	}
}

func TestABuildAnyWaiterForcedReportsAsForced(t *testing.T) {
	// A timer rebuild that a Rescan joined did happen because somebody asked.
	c, b, ck, n := fixture(t, time.Minute)
	b.holding()

	go c.Get(context.Background(), false, nil)
	b.awaitEntered(t, 1)

	// Forced, and arriving at the instant the build started, so it joins rather than queues.
	done := make(chan struct{})
	go func() { defer close(done); c.Get(context.Background(), true, nil) }()
	time.Sleep(100 * time.Millisecond)
	ck.advance(time.Second)

	b.releaseAll()
	<-done
	n.await(t, 1)

	if b.count() != 1 {
		t.Fatalf("the forced request joined; got %d builds", b.count())
	}
	if _, forced := n.at(0); !forced {
		t.Fatal("a build one of whose waiters forced it is a forced build")
	}
}

func TestTheCallbackSeesEachBuildAgainstTheOneBefore(t *testing.T) {
	c, b, ck, n := fixture(t, time.Second)
	b.stacks = func(run int) []payload.AppStack {
		out := []payload.AppStack{{ID: "media", Services: []payload.Service{{Name: "jellyfin"}}}}
		if run > 1 {
			out = append(out, payload.AppStack{ID: "edge",
				Services: []payload.Service{{Name: "traefik"}}})
		}
		return out
	}

	c.Get(context.Background(), false, nil)
	ck.advance(2 * time.Second)
	c.Get(context.Background(), false, nil)
	n.await(t, 2)

	note, _ := n.at(1)
	if len(note.Config) == 0 {
		t.Fatalf("a stack appeared between the two builds; got %#v", note)
	}
}

func TestTheCallbackRunsAfterTheResultIsPublished(t *testing.T) {
	// So a listener that reads the cache sees this build rather than the one before it.
	b, ck := newBuilder(), newClock()
	seen := make(chan string, 4)
	var c *Cache
	c = New(Options{Build: b.fn, TTL: time.Minute, Now: ck.now,
		Built: func(changes.Note, bool) {
			if held := c.Peek(); held != nil {
				seen <- held.Meta.ScannedAt
			} else {
				seen <- "nothing"
			}
		}})

	c.Get(context.Background(), false, nil)

	if got := <-seen; got != "1" {
		t.Fatalf("the callback must see its own build published; saw %q", got)
	}
}

// ---------------------------------------------------------------------------
// Peek, Warm and cancellation
// ---------------------------------------------------------------------------

func TestPeekRunsNoBuild(t *testing.T) {
	c, b, _, _ := fixture(t, time.Minute)

	if got := c.Peek(); got != nil {
		t.Fatalf("nothing has been built; got %#v", got)
	}
	if b.count() != 0 {
		t.Fatalf("Peek is not a request for a scan; ran %d builds", b.count())
	}

	c.Get(context.Background(), false, nil)
	if got := c.Peek(); got == nil || got.Meta.ScannedAt != "1" {
		t.Fatalf("Peek returns what is held; got %#v", got)
	}
}

func TestWarmBuildsInTheBackgroundAndARequestJoinsIt(t *testing.T) {
	// §18: *The cache MUST be warmed in the background at startup.*
	c, b, _, _ := fixture(t, time.Minute)
	b.holding()

	c.Warm(context.Background())
	b.awaitEntered(t, 1)

	joined := make(chan payload.Overview, 1)
	go func() { joined <- c.Get(context.Background(), false, nil) }()
	time.Sleep(100 * time.Millisecond)
	b.releaseAll()

	if out := <-joined; out.Meta.ScannedAt != "1" {
		t.Fatalf("the request joins the warm build; got %q", out.Meta.ScannedAt)
	}
	if b.count() != 1 {
		t.Fatalf("warming and joining is one build; got %d", b.count())
	}
}

func TestACancelledCallerGetsWhatIsHeldAndTheBuildCarriesOn(t *testing.T) {
	// I4: a browser closing a tab is not a reason to abandon a scan other waiters are owed.
	c, b, ck, _ := fixture(t, time.Second)

	c.Get(context.Background(), false, nil) // build 1, so something is held
	ck.advance(2 * time.Second)
	b.holding()

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan payload.Overview, 1)
	go func() { got <- c.Get(ctx, false, nil) }()
	b.awaitEntered(t, 2)

	cancel()
	if out := <-got; out.Meta.ScannedAt != "1" {
		t.Fatalf("a cancelled caller gets what was held; got %q", out.Meta.ScannedAt)
	}

	// The build itself was not cancelled, and publishes.
	b.releaseAll()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if held := c.Peek(); held != nil && held.Meta.ScannedAt == "2" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the build was abandoned with the caller who happened to start it")
}

func TestACancelledCallerWithNothingHeldGetsAnEmptyPayloadRatherThanBlocking(t *testing.T) {
	c, b, _, _ := fixture(t, time.Minute)
	b.holding()

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan payload.Overview, 1)
	go func() { got <- c.Get(ctx, false, nil) }()
	b.awaitEntered(t, 1)
	cancel()

	select {
	case out := <-got:
		if out.Meta.AppsRoot != "" {
			t.Fatalf("nothing was held, so nothing is returned; got %#v", out.Meta)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled caller with nothing held blocked")
	}
	b.releaseAll()
}

func TestABuildIsNotCancelledByTheContextOfTheRequestThatStartedIt(t *testing.T) {
	// The build function is handed a context that outlives its first caller, which is what makes the
	// claim in wait's comment true rather than merely intended.
	b, ck := newBuilder(), newClock()
	live := make(chan error, 1)
	c := New(Options{TTL: time.Minute, Now: ck.now,
		Build: func(ctx context.Context, _ *bool) payload.Overview {
			<-b.release
			live <- ctx.Err()
			return payload.Overview{}
		}})

	ctx, cancel := context.WithCancel(context.Background())
	go c.Get(ctx, false, nil)
	time.Sleep(100 * time.Millisecond)
	cancel()
	close(b.release)

	if err := <-live; err != nil {
		t.Fatalf("the build's context was cancelled with its caller: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestManyMixedRequestsAllGetAnAnswer(t *testing.T) {
	// The whole thing under -race: forced and unforced, with and without an override, all at once.
	// Every caller gets a payload and nobody is stranded.
	c, b, ck, _ := fixture(t, 50*time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var probe *bool
			switch i % 3 {
			case 1:
				probe = yes()
			case 2:
				probe = no()
			}
			if out := c.Get(context.Background(), i%4 == 0, probe); out.Meta.AppsRoot != "/data/apps" {
				t.Errorf("request %d got no payload", i)
			}
		}(i)
		if i%10 == 0 {
			ck.advance(20 * time.Millisecond)
		}
	}
	wg.Wait()

	if b.count() == 0 {
		t.Fatal("no build ran at all")
	}
}
