package httpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/cache"
	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
)

// at is the suite's clock: a fixed instant plus seconds, so every assertion about a cookie, a TTL or a
// throttle window is arithmetic rather than a wait.
func at(seconds int) time.Time {
	return time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC).Add(time.Duration(seconds) * time.Second)
}

// password is the one bcrypt hash this suite needs, memoised.
//
// Cost 12 is a quarter of a second (§19), so hashing per test would dominate the run — and hashing it
// once is safe because every test signs in as the same person with the same password.
var password = sync.OnceValue(func() string {
	hash, err := access.Mint("one")
	if err != nil {
		panic("hashing the test password: " + err.Error())
	}
	return hash
})

// lab is the whole registered surface plus the levers a test pulls: what the build returns, when it
// returns, and what reached the log.
type lab struct {
	*Server

	gate  *access.Gate
	cache *cache.Cache
	now   func() time.Time

	probeDefault bool
	block        chan struct{}

	// starts receives the number of every build as it begins, so a test waits for a background build
	// rather than sleeping for one. Buffered well past any test's build count, so a build never blocks
	// on a test that is not listening.
	starts chan int

	mu        sync.Mutex
	events    []Event
	builds    int
	overrides []*bool
}

type labOptions struct {
	// enforce enables the passwd method, which is what makes the posture enforce (§19).
	enforce bool

	assets fs.FS
	oidc   *access.Provider

	// oidcConfig makes the `oidc` method live in the posture. The provider runs the handshake; this is
	// what makes the gate willing to hand a completed one a session (§19).
	oidcConfig config.OIDCConfig

	// ttl is the cache TTL; zero means a minute, which with a frozen clock means *never stale*.
	ttl time.Duration

	// probeDefault is what a build with no override reports in meta.probe.
	probeDefault bool

	// block, when non-nil, holds every build until the test closes it.
	block chan struct{}

	now func() time.Time
}

func newLab(t *testing.T, o labOptions) *lab {
	t.Helper()

	l := &lab{probeDefault: o.probeDefault, block: o.block, starts: make(chan int, 128)}

	now := o.now
	if now == nil {
		now = func() time.Time { return at(0) }
	}
	l.now = now

	cfg := config.AuthConfig{}
	if o.enforce {
		// A real file, because the caps and the four unreadable cases are §19's tests and this suite only
		// needs one usable entry.
		file := filepath.Join(t.TempDir(), "passwd")
		if err := os.WriteFile(file, []byte("ada:"+password()+"\n"), 0o600); err != nil {
			t.Fatalf("writing the passwd file: %v", err)
		}
		cfg.Passwd = config.PasswdConfig{Enabled: true, File: file}
	}
	cfg.OIDC = o.oidcConfig

	l.gate = &access.Gate{
		Postures: &access.Postures{Config: func() config.AuthConfig { return cfg }, Now: now},
		Signer:   access.NewSigner("a test signing secret that is long enough", time.Hour),
		Throttle: &access.Throttle{Max: 3, Window: 60 * time.Second},
		Now:      now,
	}

	ttl := o.ttl
	if ttl == 0 {
		ttl = time.Minute
	}
	l.cache = cache.New(cache.Options{Build: l.build, TTL: ttl, Now: now})

	srv, err := New(Options{
		Cache:  l.cache,
		Gate:   l.gate,
		OIDC:   o.oidc,
		Assets: o.assets,
		Now:    now,
		Logged: l.record,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Server = srv
	return l
}

// build is the scan every route reaches through the cache. It counts, records the override it ran with,
// and reports the build number as the stack count so two payloads are distinguishable.
func (l *lab) build(_ context.Context, probe *bool) payload.Overview {
	l.mu.Lock()
	l.builds++
	n := l.builds
	l.overrides = append(l.overrides, probe)
	block := l.block
	l.mu.Unlock()

	select {
	case l.starts <- n:
	default:
	}

	if block != nil {
		<-block
	}

	enabled, source := l.probeDefault, payload.ProbeSourceConfig
	if probe != nil {
		enabled, source = *probe, payload.ProbeSourceRequest
	}

	return payload.Overview{
		Meta: payload.ScanMeta{
			ScannedAt: at(0).Format(time.RFC3339),
			Probe:     payload.ProbeRun{Enabled: enabled, Source: source},
		},
		Stats: payload.OverviewStats{Stacks: n},
	}
}

func (l *lab) record(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *lab) built() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.builds
}

func (l *lab) probes() []*bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.overrides)
}

// last is the most recent event of a kind, which is what a test asserts about: the log carries the half
// of every outcome the client is not told (§19).
func (l *lab) last(t *testing.T, what string) Event {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.events) - 1; i >= 0; i-- {
		if l.events[i].What == what {
			return l.events[i]
		}
	}
	t.Fatalf("no %q event reached the log; the log holds %+v", what, l.events)
	return Event{}
}

// do issues one request against the whole composed surface — gate, router, handler — which is the only
// way this suite reaches a handler. A test that called a handler directly would be testing a route
// nobody registered (§18).
func (l *lab) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	l.ServeHTTP(rec, r)
	return rec
}

// signIn adds a valid session cookie for user, minted by the same signer the gate verifies with.
func (l *lab) signIn(t *testing.T, r *http.Request, user string) {
	t.Helper()
	token, _, err := l.gate.Signer.Mint(user, payload.MethodPasswd, l.now())
	if err != nil {
		t.Fatalf("minting a test session: %v", err)
	}
	r.AddCookie(&http.Cookie{Name: access.DefaultCookieName, Value: token})
}

// decode reads a JSON reply, failing with the body when it is not JSON — which is how a plain-text
// answer from the router shows up as the assertion it violates rather than as a parse error.
func decode(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		t.Fatalf("the reply is not JSON (%v): %q", err, rec.Body.String())
	}
}

// cookieNamed finds one Set-Cookie by name, or nil.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

// §18: everything the server registers MUST be registered in one place. The test of that is that the
// documented table and the answering surface agree — every row is answered by something other than the
// *no such endpoint* this package produces for a path no route claimed.
func TestEveryRouteInTheTableIsRegistered(t *testing.T) {
	l := newLab(t, labOptions{})

	for _, route := range Routes() {
		r := httptest.NewRequest(route.Method, route.Path, strings.NewReader("{}"))
		rec := l.do(r)

		if rec.Code == http.StatusNotFound {
			var reply errorReply
			decode(t, rec, &reply)
			if reply.Error == "no such endpoint" {
				t.Fatalf("%s %s is in the table and is not registered", route.Method, route.Path)
			}
		}
		if rec.Code == http.StatusMethodNotAllowed {
			t.Fatalf("%s %s is in the table and answered 405", route.Method, route.Path)
		}
	}
}

// The other direction: §18's *needs a session* column and §19's allowlist are two statements of one
// fact, so they are cross-checked. A route that stopped needing a session without being allowlisted
// would 401 forever; one that gained a session requirement while staying allowlisted would serve fleet
// data to anybody.
func TestTheSessionColumnAndTheAllowlistAgree(t *testing.T) {
	public := map[string]bool{}
	for _, path := range access.PublicPaths() {
		public[path] = true
	}

	registered := map[string]bool{}
	for _, route := range Routes() {
		registered[route.Path] = true

		switch {
		case !strings.HasPrefix(route.Path, APIPrefix):
			// Outside the API, so §19 does not gate it at all and it must not be in an allowlist that is
			// about the API.
			if public[route.Path] {
				t.Fatalf("%s is outside the API and is in §19's allowlist", route.Path)
			}
		case route.Session && public[route.Path]:
			t.Fatalf("%s needs a session and is in §19's public allowlist, so it needs none", route.Path)
		case !route.Session && !public[route.Path]:
			t.Fatalf("%s needs no session and is not in §19's public allowlist, so it would be refused while enforcing", route.Path)
		}
	}

	for _, path := range access.PublicPaths() {
		if !registered[path] {
			t.Fatalf("§19 allowlists %s and §18 registers no route for it", path)
		}
	}
}

// §18: the routes are the table plus the asset catch-all, and nothing else answers under `/api`. Asserted
// by asking for paths that look like routes and are not.
func TestAnAPIPathNoRouteClaimsIs404JSON(t *testing.T) {
	l := newLab(t, labOptions{})

	for _, path := range []string{
		"/api",
		"/api/",
		"/api/nope",
		"/api/overview/extra",
		"/api/OVERVIEW",
		"/api/v3/core/applications",
	} {
		rec := l.do(httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d, want 404", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != ContentTypeJSON {
			t.Fatalf("%s answered with %q; §18 requires a 404 under /api/ to stay JSON", path, got)
		}
		var reply errorReply
		decode(t, rec, &reply)
		if reply.Error != "no such endpoint" {
			t.Fatalf("%s answered %q", path, reply.Error)
		}
	}
}

// A known path under an unregistered method is 405, not 404: the two say different things and one for
// both would send a client with a method bug looking for a route that exists.
func TestAWrongMethodOnAKnownAPIPathIs405WithTheMethodsThatWork(t *testing.T) {
	l := newLab(t, labOptions{})

	for _, tc := range []struct {
		method, path, allow string
	}{
		{http.MethodPost, "/api/overview", http.MethodGet},
		{http.MethodGet, "/api/rescan", http.MethodPost},
		{http.MethodGet, "/api/login", http.MethodPost},
		{http.MethodPost, "/api/healthz", http.MethodGet},
		{http.MethodDelete, "/api/session", http.MethodGet},
		{http.MethodPut, "/api/logout", http.MethodPost},
	} {
		rec := l.do(httptest.NewRequest(tc.method, tc.path, nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s answered %d, want 405", tc.method, tc.path, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != tc.allow {
			t.Fatalf("%s %s allows %q, want %q", tc.method, tc.path, got, tc.allow)
		}
		if got := rec.Header().Get("Content-Type"); got != ContentTypeJSON {
			t.Fatalf("%s %s answered 405 as %q, not JSON", tc.method, tc.path, got)
		}
	}
}

// A POST to a route outside the API reaches the asset handler, which refuses it rather than answering a
// POST with the index document.
func TestAPostToTheUIOrTheOIDCRoutesIsRefusedRatherThanServedTheShell(t *testing.T) {
	l := newLab(t, labOptions{assets: nil})

	for _, path := range []string{"/", "/auth/oidc/start", "/auth/oidc/callback", "/anything"} {
		rec := l.do(httptest.NewRequest(http.MethodPost, path, nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s answered %d, want 405", path, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Fatalf("POST %s allows %q", path, got)
		}
	}
}

// §19's three headers are on every answer, including the ones this package writes itself. The gate owns
// the rule; this asserts the gate is actually wrapped around the router.
func TestTheGateIsWrappedAroundTheWholeRouter(t *testing.T) {
	l := newLab(t, labOptions{})

	for _, path := range []string{"/api/overview", "/api/healthz", "/api/nope", "/", "/auth/oidc/start"} {
		rec := l.do(httptest.NewRequest(http.MethodGet, path, nil))

		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "same-origin",
			"X-Frame-Options":        "DENY",
		} {
			if got := rec.Header().Get(header); got != want {
				t.Fatalf("%s: %s is %q, want %q", path, header, got, want)
			}
		}
	}
}

// The gate decides on the **normalised** path, before the router gets a chance to canonicalise one. A
// duplicate-slash API path is refused while enforcing rather than redirected to the path that would have
// been refused — a 301 first would answer an unauthenticated caller with the shape of the API.
func TestTheGateDecidesBeforeTheRouterCanonicalises(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	for _, path := range []string{"/api//overview", "/api/overview/", "//api/overview"} {
		rec := l.do(httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s answered %d while enforcing, want 401", path, rec.Code)
		}
	}
}

// §19: any `..` is refused rather than resolved, and the refusal happens before the router — so a
// traversal cannot be answered by whatever the cleaned path would have reached.
func TestATraversalIsRefusedAndNeverRouted(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	for _, path := range []string{"/api/healthz/../overview", "/api/healthz/%2e%2e/overview"} {
		rec := l.do(httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d, want 400", path, rec.Code)
		}
		if l.built() != 0 {
			t.Fatalf("%s reached a build", path)
		}
	}
}

// §18: while enforcing, the two data routes need a session and the four public ones do not. Asserted
// through the composed surface, because a route is only gated if it was registered inside the gate.
func TestWhileEnforcingTheDataRoutesNeedASessionAndThePublicOnesDoNot(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	for _, route := range Routes() {
		r := httptest.NewRequest(route.Method, route.Path, strings.NewReader("{}"))
		if route.Method == http.MethodPost {
			// §19 checks the origin on a POST before the session, so a same-origin one is what isolates
			// the session decision.
			r.Header.Set("Origin", "http://"+r.Host)
		}
		rec := l.do(r)

		// The gate's own refusal, by its body rather than by its status: `POST /api/login` with no
		// credentials also answers 401, and a test that read the status alone would call a rejected
		// password a gated route.
		gated := rec.Code == http.StatusUnauthorized &&
			strings.TrimSpace(rec.Body.String()) == `{"error":"authentication required"}`
		if gated != route.Session {
			t.Fatalf("%s %s: 401=%v, table says it needs a session=%v (answered %d)",
				route.Method, route.Path, gated, route.Session, rec.Code)
		}
	}
}

func TestWithNothingEnforcedEveryRouteIsOpen(t *testing.T) {
	l := newLab(t, labOptions{})

	for _, route := range Routes() {
		r := httptest.NewRequest(route.Method, route.Path, strings.NewReader("{}"))
		rec := l.do(r)

		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("%s %s answered 401 with nothing enforced; §19 is open unless configured", route.Method, route.Path)
		}
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// The two dependencies that are not allowed to be missing. Everywhere else a missing input degrades
// (I4); a missing gate would serve a fleet with no authentication and a missing cache would serve an
// empty one, and both would look like they were working.
func TestASurfaceWithNoGateOrNoCacheIsRefusedRatherThanBuilt(t *testing.T) {
	built := cache.New(cache.Options{Build: func(context.Context, *bool) payload.Overview {
		return payload.Overview{}
	}})

	if _, err := New(Options{Cache: built}); err == nil {
		t.Fatal("a server with no gate was built")
	}
	if _, err := New(Options{Gate: &access.Gate{Postures: &access.Postures{}, Signer: access.NewSigner("x", time.Hour)}}); err == nil {
		t.Fatal("a server with no cache was built")
	}
}

// §18: the surface is constructible without opening a listening socket, and constructing it runs no
// scan — a constructor that started work would mean no test could build the surface without one.
func TestConstructingTheSurfaceRunsNoScan(t *testing.T) {
	l := newLab(t, labOptions{})

	if l.built() != 0 {
		t.Fatalf("%d builds ran before any request arrived", l.built())
	}
	if l.Handler() == nil {
		t.Fatal("the composed handler is nil")
	}
}
