package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/payload"
)

// get is the overview request every test in this file starts from.
func get(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}

// post is a rescan with a body, or with none when body is empty and unset is true.
func post(path, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Origin", "http://"+r.Host)
	return r
}

// overviewOf reads a reply as the payload it is meant to be. It decodes rather than matching text,
// because the assertion is about the document a client parses (Appendix A).
func overviewOf(t *testing.T, rec *httptest.ResponseRecorder) payload.Overview {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != ContentTypeJSON {
		t.Fatalf("answered as %q, want %q", got, ContentTypeJSON)
	}
	var out payload.Overview
	decode(t, rec, &out)
	return out
}

// ---------------------------------------------------------------------------
// GET /api/overview
// ---------------------------------------------------------------------------

// The route answers with the cache's payload and asks for no scan of its own: a second reader inside the
// TTL is answered by the build the first one caused (§17, §18).
func TestTheOverviewIsTheCachedPayloadAndASecondReaderDoesNotRebuild(t *testing.T) {
	l := newLab(t, labOptions{})

	first := overviewOf(t, l.do(get("/api/overview")))
	second := overviewOf(t, l.do(get("/api/overview")))

	if first.Stats.Stacks != 1 || second.Stats.Stacks != 1 {
		t.Fatalf("the two readers saw builds %d and %d, want both 1", first.Stats.Stacks, second.Stats.Stacks)
	}
	if l.built() != 1 {
		t.Fatalf("%d builds ran for two readers inside the TTL", l.built())
	}
}

// §18: *concurrent requests share one in-flight build unless one is forced.* Eight readers arrive while
// the build is held open; each is either joined to it or answered from what it produced, and either way
// the fleet is scanned once. A route that scanned per request would scan it eight times.
func TestConcurrentReadersAreAnsweredByOneBuild(t *testing.T) {
	block := make(chan struct{})
	l := newLab(t, labOptions{block: block})

	var wg sync.WaitGroup
	seen := make([]int, 8)
	for i := range seen {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := l.do(get("/api/overview"))
			var out payload.Overview
			if err := decodeQuiet(rec, &out); err == nil {
				seen[i] = out.Stats.Stacks
			}
		}(i)
	}

	// Released only once a build is under way, so the readers are provably concurrent with a scan rather
	// than merely with each other.
	waitForBuild(t, l)
	close(block)
	wg.Wait()

	if l.built() != 1 {
		t.Fatalf("%d builds ran for eight concurrent readers", l.built())
	}
	for i, stacks := range seen {
		if stacks != 1 {
			t.Fatalf("reader %d saw build %d, want the single build 1", i, stacks)
		}
	}
}

// A reader who has gone away is told nothing. The cache answers a cancelled caller with an empty payload
// when it holds nothing, and writing that as a 200 would be this server stating the fleet is empty.
func TestACancelledReaderIsNotAnsweredWithAnEmptyFleet(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	l := newLab(t, labOptions{block: block})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := l.do(get("/api/overview").WithContext(ctx))

	if rec.Body.Len() != 0 {
		t.Fatalf("a cancelled reader was answered with %q", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// POST /api/rescan
// ---------------------------------------------------------------------------

// §17: a forced request may only be answered by a build that started after it arrived. The cache holds a
// perfectly fresh payload — the clock is frozen, so it can never expire — and the rescan is still answered
// by a new one.
func TestARescanIsAnsweredByABuildThatStartedAfterItArrived(t *testing.T) {
	l := newLab(t, labOptions{})

	if first := overviewOf(t, l.do(get("/api/overview"))); first.Stats.Stacks != 1 {
		t.Fatalf("the first reader saw build %d", first.Stats.Stacks)
	}

	out := overviewOf(t, l.do(post("/api/rescan", "{}")))

	if out.Stats.Stacks != 2 {
		t.Fatalf("the rescan was answered by build %d; the held build 1 was already there when it arrived", out.Stats.Stacks)
	}
	if l.built() != 2 {
		t.Fatalf("%d builds ran", l.built())
	}
}

// The same rule under concurrency: three rescans arrive together against a held build, and not one of
// them may be answered by it. They are allowed to share a build with each other — that is the *unless one
// is forced* clause, and two operators pressing Rescan together do not need two scans.
func TestNoConcurrentRescanIsAnsweredByTheBuildItAskedToReplace(t *testing.T) {
	l := newLab(t, labOptions{})

	overviewOf(t, l.do(get("/api/overview")))

	var wg sync.WaitGroup
	seen := make([]int, 3)
	for i := range seen {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := l.do(post("/api/rescan", "{}"))
			var out payload.Overview
			if err := decodeQuiet(rec, &out); err == nil {
				seen[i] = out.Stats.Stacks
			}
		}(i)
	}
	wg.Wait()

	for i, stacks := range seen {
		if stacks <= 1 {
			t.Fatalf("rescan %d was answered by build %d, which existed before it arrived", i, stacks)
		}
	}
	if l.built() > 1+len(seen) {
		t.Fatalf("%d builds ran for %d rescans", l.built(), len(seen))
	}
}

// §13.7: the override is threaded as a parameter of the build, and `meta.probe` reports what the build
// ran with — so the payload says `request` only when the value reached the build that answered.
func TestARescanThreadsTheProbeOverrideIntoTheBuild(t *testing.T) {
	l := newLab(t, labOptions{probeDefault: false})

	out := overviewOf(t, l.do(post("/api/rescan", `{"probe":true}`)))

	if !out.Meta.Probe.Enabled || out.Meta.Probe.Source != payload.ProbeSourceRequest {
		t.Fatalf("meta.probe is %+v, want enabled from the request", out.Meta.Probe)
	}

	ran := l.probes()
	if len(ran) != 1 || ran[0] == nil || !*ran[0] {
		t.Fatalf("the build ran with %v, want the override true", ran)
	}
}

// §13.7's whole point: **validated, not coerced**. One known key, one known type, and everything else
// means *use configuration*. The default is deliberately `true` here, so a case that wrongly decoded to
// `false` shows up as the probe having been switched off by a request that said nothing usable — and the
// reverse, a truthy `"yes"` or `1` starting fleet-wide outbound requests, is the mistake this table exists
// to prevent.
func TestTheProbeSwitchIsValidatedRatherThanCoerced(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *bool // the override the build must run with
	}{
		{"no body", "", nil},
		{"an empty object", `{}`, nil},
		{"a bare null", `null`, nil},
		{"an array", `[true]`, nil},
		{"a bare true", `true`, nil},
		{"malformed", `{"probe":`, nil},
		{"a null value", `{"probe":null}`, nil},
		{"the string yes", `{"probe":"yes"}`, nil},
		{"the string true", `{"probe":"true"}`, nil},
		{"the number one", `{"probe":1}`, nil},
		{"the number zero", `{"probe":0}`, nil},
		{"an object", `{"probe":{"enabled":true}}`, nil},
		{"another key", `{"probes":true}`, nil},
		{"a capitalised key", `{"Probe":false}`, nil},
		{"unknown fields alongside", `{"probe":false,"depth":3}`, ptr(false)},
		{"true", `{"probe":true}`, ptr(true)},
		{"false", `{"probe":false}`, ptr(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t, labOptions{probeDefault: true})

			var r *http.Request
			if tc.body == "" {
				r = httptest.NewRequest(http.MethodPost, "/api/rescan", nil)
			} else {
				r = post("/api/rescan", tc.body)
			}
			out := overviewOf(t, l.do(r))

			ran := l.probes()
			if len(ran) != 1 {
				t.Fatalf("%d builds ran", len(ran))
			}
			if !samePtr(ran[0], tc.want) {
				t.Fatalf("the build ran with %s, want %s — §13.7 validates the switch rather than coercing it",
					show(ran[0]), show(tc.want))
			}

			// The payload's own account of it, which is what a client reads and what the log line quotes.
			wantSource := payload.ProbeSourceConfig
			wantEnabled := true
			if tc.want != nil {
				wantSource, wantEnabled = payload.ProbeSourceRequest, *tc.want
			}
			if out.Meta.Probe.Source != wantSource || out.Meta.Probe.Enabled != wantEnabled {
				t.Fatalf("meta.probe is %+v, want {enabled:%v source:%s}", out.Meta.Probe, wantEnabled, wantSource)
			}
		})
	}
}

// A body over the cap is not a reason to refuse the rescan (I4). It is a reason to believe nothing it
// claimed about the probe, which is what *use configuration* means.
func TestAnOversizedRescanBodyStillRescansWithConfiguration(t *testing.T) {
	l := newLab(t, labOptions{probeDefault: false})

	body := `{"probe":true,"pad":"` + strings.Repeat("x", MaxBodyBytes) + `"}`
	out := overviewOf(t, l.do(post("/api/rescan", body)))

	if out.Meta.Probe.Source != payload.ProbeSourceConfig {
		t.Fatalf("meta.probe is %+v; an unread body must not be believed about the probe", out.Meta.Probe)
	}
	if l.built() != 1 {
		t.Fatalf("%d builds ran; the rescan itself must still happen", l.built())
	}
}

// The log line states what the build did, not what the request asked for — read from `meta.probe`, so a
// coalesced rescan whose override was discarded says so rather than agreeing with the request.
func TestTheRescanLogLineStatesWhatTheBuildDidAboutTheProbe(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{`{"probe":true}`, "probe on (request)"},
		{`{"probe":false}`, "probe off (request)"},
		{`{}`, "probe off (config)"},
	} {
		l := newLab(t, labOptions{probeDefault: false})
		l.do(post("/api/rescan", tc.body))

		if got := l.last(t, EventRescan).Detail; !strings.Contains(got, tc.want) {
			t.Fatalf("%s logged %q, want it to state %q", tc.body, got, tc.want)
		}
	}
}

// A rescan is an outbound-request-causing action, so the log line names whoever caused it (§19). While
// enforcing that is the session's subject; with nothing enforced there is nobody to name and the line says
// so rather than inventing a name.
func TestTheRescanLogLineNamesWhoeverCausedIt(t *testing.T) {
	enforcing := newLab(t, labOptions{enforce: true})
	r := post("/api/rescan", "{}")
	enforcing.signIn(t, r, "ada")
	if rec := enforcing.do(r); rec.Code != http.StatusOK {
		t.Fatalf("a signed-in rescan answered %d: %s", rec.Code, rec.Body.String())
	}
	if got := enforcing.last(t, EventRescan).Username; got != "ada" {
		t.Fatalf("the rescan was logged as %q, want the session's subject", got)
	}

	open := newLab(t, labOptions{})
	open.do(post("/api/rescan", "{}"))
	if got := open.last(t, EventRescan).Username; got != access.UnknownUsername {
		t.Fatalf("an unauthenticated rescan was logged as %q, want %q", got, access.UnknownUsername)
	}
}

// ---------------------------------------------------------------------------
// GET /api/healthz
// ---------------------------------------------------------------------------

// §18: the health check runs no scan. Asserted while enforcing, because the other half of the requirement
// is that it needs no session: a container probe cannot sign in, and a health check that waited on a fleet
// scan would let an orchestrator restart LabView for being busy.
func TestHealthzNeedsNoSessionAndRunsNoScan(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	rec := l.do(get("/api/healthz"))

	if rec.Code != http.StatusOK {
		t.Fatalf("healthz answered %d while enforcing: %s", rec.Code, rec.Body.String())
	}
	var health payload.Health
	decode(t, rec, &health)
	if !health.OK {
		t.Fatalf("healthz answered %+v", health)
	}
	if l.built() != 0 {
		t.Fatalf("healthz ran %d builds", l.built())
	}
}

// ---------------------------------------------------------------------------
// Warming
// ---------------------------------------------------------------------------

// §18: the cache MUST be warmed in the background at startup so the first reader does not wait. The build
// therefore happens with no request having arrived, and the reader that follows is answered by it rather
// than causing a second one.
func TestWarmBuildsBeforeAnyReaderArrives(t *testing.T) {
	l := newLab(t, labOptions{})

	l.Warm(context.Background())
	waitForBuild(t, l)

	out := overviewOf(t, l.do(get("/api/overview")))
	if out.Stats.Stacks != 1 {
		t.Fatalf("the first reader saw build %d, want the warm build 1", out.Stats.Stacks)
	}
	if l.built() != 1 {
		t.Fatalf("%d builds ran; the first reader after a warm one must not cause another", l.built())
	}
}

// Warm returns before the build does — the point of warming at startup is that binding the port is not
// blocked on scanning the fleet.
func TestWarmDoesNotWaitForTheBuild(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	l := newLab(t, labOptions{block: block})

	l.Warm(context.Background())

	// Returning at all is the assertion: the build is held open and cannot finish until this test's
	// deferred close, so a Warm that waited would never reach here.
	waitForBuild(t, l)
	if l.built() != 1 {
		t.Fatalf("%d builds are under way after warming", l.built())
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// waitForBuild blocks until a build has started, which is how a test synchronises with a background scan
// without sleeping for one.
func waitForBuild(t *testing.T, l *lab) {
	t.Helper()
	select {
	case <-l.starts:
	case <-time.After(5 * time.Second):
		t.Fatal("no build started")
	}
}

// decodeQuiet is decode for a goroutine, which may not call t.Fatalf.
func decodeQuiet(rec *httptest.ResponseRecorder, into any) error {
	return json.Unmarshal(rec.Body.Bytes(), into)
}

func ptr(b bool) *bool { return &b }

func samePtr(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func show(b *bool) string {
	if b == nil {
		return "no override"
	}
	if *b {
		return "the override true"
	}
	return "the override false"
}
