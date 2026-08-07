// Package httpapi is LabView's whole HTTP surface (§18).
//
// **One place registers everything.** §18 requires it, and it requires it for a reason worth
// restating: a route registered on the path that binds the port is invisible to every test, and the
// routes are where authentication, caching and content type are decided. So `New` returns a
// `*Server` that *is* an `http.Handler`, the table below is the only place a route comes from, and
// nothing in this package opens a socket. The listener lives in `cmd/labview` and does one thing —
// hand this handler to `http.Server`.
//
// Three properties follow from that shape and are asserted rather than assumed:
//
//   - **The API does not depend on the UI.** Assets arrive as an `fs.FS` that may be nil. Every API
//     route answers identically either way (§18), because a dashboard whose asset bundle failed to
//     embed should still be able to tell an operator what it can see.
//   - **A 404 under `/api/` stays JSON** (§18). The router's own plain-text 404 is never reachable:
//     `/api` and `/api/` are registered, so an unknown API path is answered by this package.
//   - **The gate wraps the router, not the routes.** One hook pair around the whole mux, so a route
//     added later cannot be added un-gated (§19).
package httpapi

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/cache"
	"github.com/nrosier/labview/internal/payload"
)

// Options is everything the server needs. Nothing is read from ambient state (I7): the clock, the
// build cache, the gate and the assets all arrive here, which is what lets a test construct the whole
// surface with no filesystem, no network and no listener.
type Options struct {
	// Cache is §17's build cache. Required — it is the only path from a request to a scan, and the
	// coalescing §18 requires is its property rather than this package's.
	Cache *cache.Cache

	// Gate is §19's access control. Required. It is wrapped around the router, so a route cannot
	// opt out of it.
	Gate *access.Gate

	// OIDC is the provider handshake, nil when no provider is configured. Nil is not an error: the
	// two routes stay registered and redirect with `method-unavailable`, because a route that
	// disappeared when the method was switched off would answer a stale browser with the UI shell
	// instead of a failure it can render.
	OIDC *access.Provider

	// Assets is the embedded UI, nil when this build carries none. Nil is not an error either
	// (§18: the API MUST NOT depend on the presence of UI assets).
	Assets fs.FS

	// Now is the injected clock. Nil is time.Now.
	Now func() time.Time

	// Logged receives what the log wants and the client is never told (§19). Nil means nobody is
	// listening, which is what a test that does not care about the log passes.
	Logged func(Event)
}

// Server is the registered surface. It is an http.Handler and holds no listener.
type Server struct {
	cache  *cache.Cache
	gate   *access.Gate
	oidc   *access.Provider
	assets fs.FS

	// files serves the assets, built once so every request shares one file handler.
	files http.Handler

	now    func() time.Time
	logged func(Event)

	// handler is the composed surface: the gate's two hooks around the router.
	handler http.Handler

	// methods is path → the methods registered on it, derived from the same table the router is built
	// from. It is what turns an unknown method on a known API path into a 405 with an accurate
	// `Allow` header rather than into a 404 that says the path does not exist.
	methods map[string][]string
}

// New registers the whole surface and returns it.
//
// It returns an error rather than substituting a default for a missing cache or gate. Everywhere else
// in this program a missing input degrades (I4), because a missing input is a fact about the fleet or
// its configuration and the reader needs to be told. These two are neither: a server with no gate
// would serve a fleet with no authentication and a server with no cache would serve an empty one, and
// both would look like they were working.
func New(o Options) (*Server, error) {
	if o.Cache == nil {
		return nil, errors.New("httpapi: no build cache, so no route could answer with a scan")
	}
	if o.Gate == nil {
		return nil, errors.New("httpapi: no gate, so every route would be unauthenticated")
	}

	s := &Server{
		cache:   o.Cache,
		gate:    o.Gate,
		oidc:    o.OIDC,
		assets:  o.Assets,
		now:     o.Now,
		logged:  o.Logged,
		methods: map[string][]string{},
	}
	if s.assets != nil {
		s.files = http.FileServerFS(s.assets)
	}
	s.handler = s.register()
	return s, nil
}

// ServeHTTP answers one request. This is the only entry point, so anything the routes do — the gate,
// the headers, the JSON 404 — cannot be bypassed by reaching a handler directly.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Handler is the same surface as an http.Handler, for a caller that wants to compose it.
func (s *Server) Handler() http.Handler { return s.handler }

// Warm starts the first build in the background (§18), so the first reader does not wait for a scan.
//
// It is a method on the server rather than something New does, because a constructor that started
// work would mean a test could not build the surface without running a scan — and §18's whole
// requirement is that the surface be constructible.
func (s *Server) Warm(ctx context.Context) { s.cache.Warm(ctx) }

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

// Route is one row of §18's table.
type Route struct {
	// Method is the one method this route answers. No route answers two: a handler that switched on
	// the method would be two routes sharing a name, and the table is the documentation.
	Method string

	// Path is the exact path, already in the form access.Normalise produces.
	Path string

	// Session is §18's *needs a session* column — **conditional on enforcement** (§19). It is
	// documentation and a test: a route that needs a session is a route that must not be in §19's
	// public allowlist, and one that does not must be in it or be outside `/api` entirely.
	Session bool
}

// AssetsPath is the catch-all §18 writes as `GET /*`. It is not in the table because it is not a
// route: it is what answers everything no route claimed.
const AssetsPath = "/"

// APIPrefix is the subtree whose 404s stay JSON (§18).
const APIPrefix = "/api/"

// binding is a row of the table together with what answers it.
type binding struct {
	Route
	handler http.HandlerFunc
}

// table is §18's table, in §18's order. **This is the one place a route is declared.**
func (s *Server) table() []binding {
	return []binding{
		{Route{http.MethodGet, "/api/overview", true}, s.overview},
		{Route{http.MethodPost, "/api/rescan", true}, s.rescan},
		{Route{http.MethodGet, "/api/healthz", false}, s.healthz},
		{Route{http.MethodGet, "/api/session", false}, s.session},
		{Route{http.MethodPost, "/api/login", false}, s.login},
		{Route{http.MethodPost, "/api/logout", false}, s.logout},
		{Route{http.MethodGet, "/auth/oidc/start", false}, s.oidcStart},
		{Route{http.MethodGet, "/auth/oidc/callback", false}, s.oidcCallback},
	}
}

// Routes is the table without its handlers, for documentation and for a test.
//
// Derived from the same slice the router is built from rather than written out a second time, so the
// documented surface and the registered surface cannot disagree — which is the same reason §19 derives
// PublicPaths from its allowlist.
func Routes() []Route {
	bindings := (&Server{}).table()
	out := make([]Route, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, b.Route)
	}
	return out
}

// register builds the router and wraps it. Called once, from New.
func (s *Server) register() http.Handler {
	mux := http.NewServeMux()

	for _, b := range s.table() {
		// The method is part of the pattern, so a POST to a GET route does not reach the handler. It
		// falls to the subtree below, which answers 405 with the methods this loop recorded.
		mux.Handle(b.Method+" "+b.Path, b.handler)
		s.methods[b.Path] = append(s.methods[b.Path], b.Method)
	}

	// **A 404 under `/api/` MUST stay JSON** (§18). Both spellings, because `/api` alone would
	// otherwise be answered by the router's redirect to `/api/` — a 301 to a path that 404s, where a
	// 404 was the honest answer. Registering them here also means the router's plain-text
	// `404 page not found` is unreachable for the API.
	mux.Handle(APIPrefix, http.HandlerFunc(s.apiMissing))
	mux.Handle("/api", http.HandlerFunc(s.apiMissing))

	// Everything else is the UI, with the single-page fallback (§18).
	mux.Handle(AssetsPath, http.HandlerFunc(s.assetFile))

	// The gate goes around the whole router: its response hook has to be able to set headers on the
	// 401 its own request hook writes, and a route registered inside the mux cannot opt out of a hook
	// that wraps the mux (§19).
	return s.gate.Wrap(mux)
}

// apiMissing answers an API path no route claimed.
//
// 405 when the path exists under another method and 404 when it does not, both as JSON. The
// distinction is worth making: a client that posted to `GET /api/overview` has a bug in its method and
// a client that asked for `/api/overvieww` has a bug in its URL, and one 404 for both would send the
// first one looking for a route that is registered.
func (s *Server) apiMissing(w http.ResponseWriter, r *http.Request) {
	normalised, ok := access.Normalise(r.URL.Path)
	if !ok {
		// Unreachable through the gate, which refuses an unnormalisable path first. Written anyway,
		// because this handler is registered on the router and a caller composing the router without
		// the gate should not get an answer derived from a path this program will not interpret.
		writeError(w, http.StatusBadRequest, "the request path could not be normalised")
		return
	}

	if allow := s.methods[normalised]; len(allow) > 0 {
		w.Header().Set("Allow", strings.Join(allow, ", "))
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeError(w, http.StatusNotFound, "no such endpoint")
}

// ---------------------------------------------------------------------------
// The log
// ---------------------------------------------------------------------------

// The kinds of event this package reports. Strings rather than an enum, because they are log fields
// and a reader greps for them.
const (
	EventLogin        = "login"
	EventLogout       = "logout"
	EventRescan       = "rescan"
	EventOIDCStart    = "oidc-start"
	EventOIDCCallback = "oidc-callback"
)

// Event is one thing the server did, for the log and never for a client (§19: *a reply says less than
// the log*).
//
// It carries no request, no cookie and no password. A struct rather than a formatted string, so the
// caller decides the wording and a test can assert on the fields — and so there is no way to log a
// credential by interpolating one into a message.
type Event struct {
	// What is one of the constants above.
	What string

	// Username is already sanitised (§16): `?` unless it satisfied the pattern.
	Username string

	// Via is the method a sign-in used, empty when the event is not a sign-in.
	Via payload.LoginMethod

	// OK is whether it succeeded.
	OK bool

	// Status is what the client was told, or 302 for a redirect.
	Status int

	// Reason is the served code, one of §4.7's eight, empty on success.
	Reason payload.LoginFailureReason

	// Detail is the sentence for the operator. It is the half of the outcome the client never sees.
	Detail string

	// Report is the connection report when the event involved reading from a provider (§15), nil
	// otherwise.
	Report *payload.ConnectionReport
}

func (s *Server) log(e Event) {
	if s.logged != nil {
		s.logged(e)
	}
}

// clock is the injected time, defaulted here so no handler has to.
func (s *Server) clock() func() time.Time {
	if s.now == nil {
		return time.Now
	}
	return s.now
}

// viewer is the sanitised name of whoever is calling, for a log line.
//
// It reads the viewer the gate resolved rather than the cookie, so an open dashboard and a gated one
// log the same thing, and a handler reached without the gate reports `?` rather than a name it has not
// verified.
func viewerName(r *http.Request) string {
	if name := access.From(r.Context()).Name; name != "" {
		return name
	}
	return access.UnknownUsername
}
