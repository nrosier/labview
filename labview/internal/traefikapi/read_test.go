package traefikapi

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// noFleet is a scan that found nothing, which is what a read test wants: the matching rules have
// their own tables and here every live router must come back reported rather than attributed.
func noFleet() *fleet.Index { return fleet.NewIndex(nil) }

// ---------------------------------------------------------------------------
// The injected proxy
// ---------------------------------------------------------------------------

// call is one request the read issued, recorded in the only two terms §12 constrains: where it went,
// and what it carried. The header is recorded by *presence*, because the test asserts that no
// credential was sent and a test that stored the value would itself be the leak (I6).
type call struct {
	method        string
	url           string
	authorization bool
	cookies       []string
}

// stub is a Traefik API held as code. It replaces the transport rather than the client, so the
// bounds, the phase classification and the body cap are all still the real package's and only the
// bytes are the test's — the same arrangement §23 requires of the corpus.
type stub struct {
	answer func(*http.Request) (int, http.Header, string)

	mu    sync.Mutex
	calls []call
}

func (s *stub) RoundTrip(r *http.Request) (*http.Response, error) {
	var names []string
	for _, c := range r.Cookies() {
		names = append(names, c.Name)
	}
	sort.Strings(names)

	s.mu.Lock()
	s.calls = append(s.calls, call{
		method:        r.Method,
		url:           r.URL.String(),
		authorization: r.Header.Get("Authorization") != "",
		cookies:       names,
	})
	s.mu.Unlock()

	status, header, body := s.answer(r)
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

func (s *stub) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	for _, c := range s.calls {
		out = append(out, c.url)
	}
	return out
}

func (s *stub) sentACredential() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range s.calls {
		if c.authorization {
			return true
		}
	}
	return false
}

// The three documents a working proxy answers. `rawdata` is the `docs` fixture's shape: a chain in a
// file provider, a gate two levels inside it, and a backend the proxy last saw DOWN.
const (
	versionBody = `{"Version":"3.1.2","Codename":"mimolette"}`

	rawDataBody = `{
	  "routers": {
	    "docs@docker": {"entryPoints":["websecure"],"middlewares":["secured@file"],
	      "service":"docs","rule":"Host(` + "`docs.example.com`" + `)","status":"enabled","tls":{}},
	    "dashboard@docker": {"entryPoints":["websecure"],"middlewares":["dashboard-auth@file"],
	      "service":"api@internal","rule":"Host(` + "`edge.example.com`" + `)","status":"enabled"}
	  },
	  "middlewares": {
	    "secured@file": {"chain":{"middlewares":["authentik@file"]},"status":"enabled"},
	    "authentik@file": {"forwardAuth":{"address":"` + outpostAddress + `"},"status":"enabled"},
	    "dashboard-auth@file": {"basicAuth":{"users":["admin:$apr1$x"]},"status":"enabled"}
	  },
	  "services": {
	    "docs@docker": {"loadBalancer":{"servers":[{"url":"http://docs:80"}]},
	      "serverStatus":{"http://docs:80":"DOWN"},"status":"enabled"}
	  }
	}`

	entrypointsBody = `[{"name":"web","address":":80"},
	  {"name":"websecure","address":":443","http":{"middlewares":["compress@file"]}}]`
)

// proxy answers the three documents, and nothing else exists.
func proxy(r *http.Request) (int, http.Header, string) {
	switch r.URL.Path {
	case pathVersion:
		return http.StatusOK, nil, versionBody
	case pathRawData:
		return http.StatusOK, nil, rawDataBody
	case pathEntrypoints:
		return http.StatusOK, nil, entrypointsBody
	default:
		return http.StatusNotFound, nil, `{"error":"no such path"}`
	}
}

func read(t *testing.T, s *stub, cfg config.TraefikConfig, candidates []Candidate) Read {
	t.Helper()
	return Do(context.Background(), Options{
		Cfg:        cfg,
		Client:     transport.New(transport.Options{RoundTripper: s}),
		Candidates: candidates,
	})
}

// enabled is the configuration an operator who switched nothing on has: the integration is on by
// default and names no address.
func enabled() config.TraefikConfig {
	return config.TraefikConfig{Enabled: true, TimeoutMs: 5000}
}

// owned is the discovered candidate a credential may follow, and unowned is one that merely looks
// like a proxy.
func owned() []Candidate {
	return []Candidate{{
		URL: "http://traefik:8080", Internal: true, Key: "apps/edge", Owned: true,
		Why: "`apps/edge` declares a router whose service is `api@internal`",
	}}
}

func unowned() []Candidate {
	return []Candidate{{
		URL: "http://gateway:8080", Internal: true, Key: "apps/gateway", Owned: false,
		Why: "`apps/gateway` is where another service's tunnel origin resolved",
	}}
}

// ---------------------------------------------------------------------------
// The three reads, and nothing else
// ---------------------------------------------------------------------------

// TestAWorkingReadIssuesTheThreeRequestsSection12NamesAndNoOthers is the read's whole surface.
//
// The claim that these are the only three endpoints LabView touches on somebody's proxy has to be
// checkable rather than trusted, and a fourth request — a probe of the dashboard, a retry of a path
// that 404ed — would be this program reaching further into a proxy than §12 permits.
func TestAWorkingReadIssuesTheThreeRequestsSection12NamesAndNoOthers(t *testing.T) {
	s := &stub{answer: proxy}
	got := read(t, s, enabled(), owned())

	want := []string{
		"http://traefik:8080" + pathVersion,
		"http://traefik:8080" + pathRawData,
		"http://traefik:8080" + pathEntrypoints,
	}
	if paths := s.paths(); !reflect.DeepEqual(paths, want) {
		t.Fatalf("requests =\n  %#v\nwant\n  %#v", paths, want)
	}

	if !got.Report.OK || got.Report.Phase != payload.PhaseConnected {
		t.Fatalf("report = %+v, want a connected read", got.Report)
	}
	if !got.ChainComplete() {
		t.Fatal("ChainComplete() = false on a read that obtained the entrypoints")
	}
	if got.Source != payload.SourceDiscovered || got.Endpoint != "http://traefik:8080" {
		t.Fatalf("endpoint = %q from %q, want the candidate that answered", got.Endpoint, got.Source)
	}
	if got.EndpointKey != "apps/edge" {
		t.Fatalf("EndpointKey = %q — without it the endpoint that answered is attributable to no "+
			"service, and `role: \"proxy\"` has only one half", got.EndpointKey)
	}
	if got.Snapshot.Version != "3.1.2" {
		t.Fatalf("version = %q, want 3.1.2", got.Snapshot.Version)
	}
	if n := len(got.Snapshot.Routers); n != 2 {
		t.Fatalf("routers = %d, want 2", n)
	}
	// Two entrypoints were returned and only one carries middlewares. The other must still be
	// absent rather than present-and-empty: `EntrypointsRead` is the fact, per entrypoint there is
	// nothing to record.
	if got := got.Snapshot.Entrypoints["websecure"]; !reflect.DeepEqual(got, []string{"compress@file"}) {
		t.Fatalf("entrypoint middlewares = %#v", got)
	}
}

// TestACandidateThatAnswersUnauthenticatedIsUsedWithNothingSent is §12's credential rule read
// literally.
//
// The configuration here *has* a username and password and the candidate *is* owned, so a credential
// was available and permitted at every one of the three requests. It still may not be sent: the API
// answered without one, and `none` is the finding.
func TestACandidateThatAnswersUnauthenticatedIsUsedWithNothingSent(t *testing.T) {
	cfg := enabled()
	cfg.Username, cfg.Password = "admin", "hunter2"

	s := &stub{answer: proxy}
	got := read(t, s, cfg, owned())

	if s.sentACredential() {
		t.Fatal("a credential was sent to an API that had already answered without one (§12)")
	}
	if got.Credential != payload.CredentialNone {
		t.Fatalf("Credential = %q, want %q", got.Credential, payload.CredentialNone)
	}
	if note := CredentialNote(got); note == "" {
		t.Fatal("an API that answered unauthenticated must be reported as a note on the proxy service")
	}
}

// ---------------------------------------------------------------------------
// The challenge
// ---------------------------------------------------------------------------

// gated is a proxy behind an Authentik outpost: it challenges anonymous callers, issues a flow cookie
// with the challenge and a session cookie with the authenticated answer, and thereafter expects both
// echoed.
func gated(challenge int) func(*http.Request) (int, http.Header, string) {
	return func(r *http.Request) (int, http.Header, string) {
		var flow, session bool
		for _, c := range r.Cookies() {
			switch c.Name {
			case "authentik_flow":
				flow = true
			case "authentik_session":
				session = true
			}
		}

		if r.Header.Get("Authorization") == "" {
			h := http.Header{"Set-Cookie": []string{"authentik_flow=abc; Path=/"}}
			if challenge >= 300 && challenge < 400 {
				h.Set("Location", "https://sso.example.com/if/flow/default/")
			}
			return challenge, h, `<!DOCTYPE html><html><body>sign in</body></html>`
		}
		if r.URL.Path == pathVersion {
			return http.StatusOK,
				http.Header{"Set-Cookie": []string{"authentik_session=xyz; Path=/"}},
				versionBody
		}
		if !flow || !session {
			// The cookie was not echoed, so the outpost challenges again — which is what makes the
			// replay a requirement rather than a courtesy.
			return http.StatusFound, nil, ""
		}
		return proxy(r)
	}
}

// TestAnOwnedCandidateIsRetriedWithACredentialAndItsCookiesAreReplayed is the outpost case §12 names.
//
// The session an outpost issues on the authenticated response is what the reads that follow need; a
// retry that authenticated and then dropped the cookie would be challenged again on the very next
// request, and the read would report a proxy that is answering perfectly well as unreachable.
func TestAnOwnedCandidateIsRetriedWithACredentialAndItsCookiesAreReplayed(t *testing.T) {
	cfg := enabled()
	cfg.Username, cfg.Password = "admin", "hunter2"

	s := &stub{answer: gated(http.StatusUnauthorized)}
	got := read(t, s, cfg, owned())

	if !got.Report.OK {
		t.Fatalf("report = %+v, want the authenticated read to have succeeded", got.Report)
	}
	if got.Credential != payload.CredentialBasic {
		t.Fatalf("Credential = %q, want %q", got.Credential, payload.CredentialBasic)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) != 4 {
		t.Fatalf("requests = %#v, want four: the anonymous probe, the retry, and the two reads", s.paths())
	}
	if s.calls[0].authorization {
		t.Fatal("the first request carried a credential; §12 requires the anonymous probe first")
	}
	for _, c := range s.calls[2:] {
		want := []string{"authentik_flow", "authentik_session"}
		if !reflect.DeepEqual(c.cookies, want) {
			t.Fatalf("%s carried cookies %#v, want %#v", c.url, c.cookies, want)
		}
	}
}

// TestARedirectIsAChallenge is why the challenge test is not the two authentication statuses.
//
// A dashboard behind an Authentik outpost answers an anonymous request with a 302 to the login flow,
// and the transport follows no redirect. Reading only 401 and 403 would classify a gated API as
// merely `status`, never retry, and report a proxy the operator gave working credentials for as
// unreadable.
func TestARedirectIsAChallenge(t *testing.T) {
	cfg := enabled()
	cfg.Username, cfg.Password = "admin", "hunter2"

	s := &stub{answer: gated(http.StatusFound)}
	got := read(t, s, cfg, owned())

	if !got.Report.OK || got.Credential != payload.CredentialBasic {
		t.Fatalf("report = %+v, credential = %q — a 302 must trigger the authenticated retry",
			got.Report, got.Credential)
	}

	for _, status := range []int{401, 403, 407, 301, 302, 303, 307, 308} {
		if !challenged(status) {
			t.Fatalf("challenged(%d) = false", status)
		}
	}
	for _, status := range []int{200, 204, 400, 404, 500, 502} {
		if challenged(status) {
			t.Fatalf("challenged(%d) = true — that is not the proxy asking for a credential", status)
		}
	}
}

// TestAnUnownedCandidateIsNeverOfferedACredential is the constraint that makes discovery safe to run
// at all.
//
// A candidate discovered by tunnel origin or by image is an inference about somebody else's
// container. Sending the operator's proxy password there would hand it to whatever is actually
// listening — so the challenge is recorded, the candidate is rejected, and the attempt says why.
func TestAnUnownedCandidateIsNeverOfferedACredential(t *testing.T) {
	cfg := enabled()
	cfg.Username, cfg.Password = "admin", "hunter2"

	s := &stub{answer: gated(http.StatusUnauthorized)}
	got := read(t, s, cfg, unowned())

	if s.sentACredential() {
		t.Fatal("a credential was sent to an address the scan did not prove is the proxy's own API (§12)")
	}
	if got.Report.OK {
		t.Fatalf("report = %+v, want a failed read", got.Report)
	}
	if len(got.Attempts) != 1 {
		t.Fatalf("attempts = %#v, want the one candidate that was tried", got.Attempts)
	}
	attempt := got.Attempts[0]
	if !strings.Contains(attempt.Detail, "did not prove is the proxy's own API") {
		t.Fatalf("detail = %q, want the refusal explained", attempt.Detail)
	}
	if !strings.Contains(attempt.Why, "tunnel origin resolved") {
		t.Fatalf("why = %q — an attempt list without the evidence says only that a scan tried some "+
			"addresses (§15)", attempt.Why)
	}
	if attempt.Endpoint != "http://gateway:8080"+pathVersion && attempt.Endpoint != "http://gateway:8080" {
		t.Fatalf("endpoint = %q, want the address that was tried", attempt.Endpoint)
	}
}

// TestOnlyTwoCredentialsExistHere is §12's flat statement that an Authentik API token is not a valid
// credential for a proxy.
//
// The guarantee is structural: nothing in this read's inputs can carry one. `Options` holds the
// proxy's own configuration, and the whole vocabulary of what was needed is two members.
func TestOnlyTwoCredentialsExistHere(t *testing.T) {
	cfg := enabled()
	cfg.Username, cfg.Password = "admin", "hunter2"

	s := &stub{answer: proxy}
	got := read(t, s, cfg, owned())

	switch got.Credential {
	case payload.CredentialNone, payload.CredentialBasic:
	default:
		t.Fatalf("Credential = %q, which is not a member of the closed set", got.Credential)
	}

	if h := basic("admin", "hunter2"); len(h) != 1 || !strings.HasPrefix(h["Authorization"], "Basic ") {
		t.Fatalf("basic() = %#v, want exactly one Basic authorization header", h)
	}
	if h := basic("", ""); h != nil {
		t.Fatalf("basic() with nothing configured = %#v, want no header at all rather than an empty one", h)
	}
}

// ---------------------------------------------------------------------------
// Partial and failed reads
// ---------------------------------------------------------------------------

// TestAnUnreadEntrypointListIsAPartialReadAndNotAFailure is the phase that carries §12's
// `chainComplete`.
//
// Every router and every chain was obtained; what is missing is the one thing that licenses a live
// chain to supersede a label. Failing the read would throw away a routing table that is correct, and
// succeeding silently would let the downgrade fire on a gate this program had not looked for.
func TestAnUnreadEntrypointListIsAPartialReadAndNotAFailure(t *testing.T) {
	s := &stub{answer: func(r *http.Request) (int, http.Header, string) {
		if r.URL.Path == pathEntrypoints {
			return http.StatusInternalServerError, nil, `{"error":"internal"}`
		}
		return proxy(r)
	}}
	got := read(t, s, enabled(), owned())

	if got.Report.Phase != payload.PhasePartial {
		t.Fatalf("phase = %q, want %q", got.Report.Phase, payload.PhasePartial)
	}
	if !got.Reachable() {
		t.Fatal("Reachable() = false on a partial read: `partial` is conn's definition of worked (§15)")
	}
	if got.ChainComplete() {
		t.Fatal("ChainComplete() = true with no entrypoint list")
	}
	if len(got.Snapshot.Routers) != 2 {
		t.Fatalf("routers = %d, want the table that was read to be kept", len(got.Snapshot.Routers))
	}
	if !strings.Contains(got.Report.Detail, "no live chain may supersede a label") {
		t.Fatalf("detail = %q, want the consequence of the gap stated", got.Report.Detail)
	}

	sum := Summarize(got, Apply(got.Snapshot, noFleet()))
	if !sum.Reachable || sum.EntrypointsRead {
		t.Fatalf("summary = %+v, want reachable with the entrypoints unread", sum)
	}
	if sum.Error == "" {
		t.Fatal("a partial read is reachable *and* has something to say, and the summary must say it")
	}
}

// TestAnUnreadableRoutingTableIsTheReadsFailure pins which of the three documents the read depends
// on.
//
// The version alone says a proxy is there and says nothing about this fleet. With no routing table
// there is nothing to match, and the snapshot has to stay walkable rather than become a nil a caller
// must check for (I4).
func TestAnUnreadableRoutingTableIsTheReadsFailure(t *testing.T) {
	s := &stub{answer: func(r *http.Request) (int, http.Header, string) {
		if r.URL.Path == pathRawData {
			return http.StatusOK, nil, `<!DOCTYPE html><html><body>login</body></html>`
		}
		return proxy(r)
	}}
	got := read(t, s, enabled(), owned())

	if got.Report.OK {
		t.Fatalf("report = %+v, want a failed read", got.Report)
	}
	if got.Report.Phase != payload.PhaseProtocol {
		t.Fatalf("phase = %q, want %q — something answered, and it was not this API",
			got.Report.Phase, payload.PhaseProtocol)
	}
	if len(got.Snapshot.Live()) != 0 || got.Snapshot.Middlewares == nil || got.Snapshot.Services == nil {
		t.Fatal("the snapshot of a failed read must be empty and safe to walk")
	}
	if len(s.paths()) != 2 {
		t.Fatalf("requests = %#v, want the read to stop at the document it needs", s.paths())
	}
}

// TestSomethingThatAnswersJSONIsNotYetAProxy is what turns a guessed address into an endpoint.
//
// A discovered candidate is a guess. An array, a bare string or a login page is a well-formed answer
// from something that is not this API, and accepting one would name an unrelated service as the
// fleet's reverse proxy — and, where the candidate is owned, would offer it a credential.
func TestSomethingThatAnswersJSONIsNotYetAProxy(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"an array", `[]`},
		{"a bare string", `"traefik"`},
		{"a number", `7`},
		{"a login page", `<!DOCTYPE html><html><body>sign in</body></html>`},
		{"nothing at all", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &stub{answer: func(r *http.Request) (int, http.Header, string) {
				return http.StatusOK, nil, tc.body
			}}
			got := read(t, s, enabled(), owned())

			if got.Report.OK {
				t.Fatalf("report = %+v, want the candidate rejected", got.Report)
			}
			if got.Endpoint != "" {
				t.Fatalf("Endpoint = %q, want none: nothing earned it", got.Endpoint)
			}
			if len(s.paths()) != 1 {
				t.Fatalf("requests = %#v, want the read to stop at the probe", s.paths())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Endpoint selection
// ---------------------------------------------------------------------------

// TestAConfiguredAddressIsUsedVerbatimAndNothingElseIsTried is the operator's own statement being
// taken at its word.
//
// A failure against a configured address is a fact about their configuration. Quietly trying a
// discovered address instead would hide it, and would report a working scan against a proxy the
// operator was not asking about.
func TestAConfiguredAddressIsUsedVerbatimAndNothingElseIsTried(t *testing.T) {
	cfg := enabled()
	cfg.URL = "http://edge.internal:8080/"

	s := &stub{answer: func(r *http.Request) (int, http.Header, string) {
		if r.URL.Host != "edge.internal:8080" {
			t.Fatalf("the read went to %q, which the operator did not configure", r.URL)
		}
		return http.StatusInternalServerError, nil, `{"error":"internal"}`
	}}
	got := read(t, s, cfg, owned())

	if !got.Configured || got.Source != payload.SourceConfig {
		t.Fatalf("configured = %v from %q, want the configured source", got.Configured, got.Source)
	}
	if got.Endpoint != "http://edge.internal:8080" {
		t.Fatalf("Endpoint = %q, want the configured address with its trailing slash trimmed and "+
			"nothing else changed", got.Endpoint)
	}
	if got.Report.OK {
		t.Fatalf("report = %+v, want the failure reported against the configured address", got.Report)
	}
	if len(got.Attempts) != 0 {
		t.Fatalf("attempts = %#v, want none: nothing was guessed", got.Attempts)
	}
}

// TestAConfiguredAddressThatWantsACredentialNobodyGaveSaysSo keeps two unlike hints apart.
//
// `credential` asks the operator for a password; `authenticate` tells them the one they gave was
// refused. A configured endpoint that challenges with nothing configured to send is the first.
func TestAConfiguredAddressThatWantsACredentialNobodyGaveSaysSo(t *testing.T) {
	cfg := enabled()
	cfg.URL = "http://edge.internal:8080"

	s := &stub{answer: func(r *http.Request) (int, http.Header, string) {
		return http.StatusUnauthorized, nil, `{"error":"unauthorized"}`
	}}
	got := read(t, s, cfg, nil)

	if got.Report.Phase != payload.PhaseCredential {
		t.Fatalf("phase = %q, want %q", got.Report.Phase, payload.PhaseCredential)
	}
	if !strings.Contains(got.Report.Detail, "traefik.username") {
		t.Fatalf("detail = %q, want the missing configuration named", got.Report.Detail)
	}
}

// TestNothingToTryIsNotConfiguredRatherThanUnreachable is the phase a fleet with no proxy gets.
//
// There is no built-in proxy address to fall back to, so there is nothing to fail against. A
// `connect` failure against a guessed address would report a fleet with no reverse proxy as one whose
// reverse proxy is down.
func TestNothingToTryIsNotConfiguredRatherThanUnreachable(t *testing.T) {
	s := &stub{answer: proxy}
	got := read(t, s, enabled(), nil)

	if got.Report.Phase != payload.PhaseNotConfigured {
		t.Fatalf("phase = %q, want %q", got.Report.Phase, payload.PhaseNotConfigured)
	}
	if len(s.paths()) != 0 {
		t.Fatalf("requests = %#v, want none", s.paths())
	}
	if got.Report.Endpoint != "" || got.Report.Source != "" {
		t.Fatalf("report = %+v, want no endpoint on a phase that happened before the network",
			got.Report)
	}
}

// TestADisabledIntegrationTouchesNothing is the switch meaning what it says.
func TestADisabledIntegrationTouchesNothing(t *testing.T) {
	s := &stub{answer: proxy}
	got := read(t, s, config.TraefikConfig{Enabled: false, TimeoutMs: 5000}, owned())

	if got.Report.Phase != payload.PhaseDisabled {
		t.Fatalf("phase = %q, want %q", got.Report.Phase, payload.PhaseDisabled)
	}
	if len(s.paths()) != 0 {
		t.Fatalf("requests = %#v, want none", s.paths())
	}
	if got.Enabled {
		t.Fatal("Enabled = true on a disabled read")
	}
	if len(got.Snapshot.Routers) != 0 || got.Snapshot.EntrypointsRead {
		t.Fatal("a disabled read must produce an empty snapshot")
	}
}

// ---------------------------------------------------------------------------
// The summary
// ---------------------------------------------------------------------------

// TestTheSummaryReportsTheReadsOwnNumbers is what makes it a projection.
//
// Every number it carries is already on the read or derived by the read's own method, so the count a
// card shows and the count the connection report's phase was decided from cannot come apart.
func TestTheSummaryReportsTheReadsOwnNumbers(t *testing.T) {
	s := &stub{answer: proxy}
	got := read(t, s, enabled(), owned())
	m := Apply(got.Snapshot, noFleet())

	sum := Summarize(got, m)
	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"routers", sum.Routers, len(got.Snapshot.Routers)},
		{"middlewares", sum.Middlewares, 3},
		{"services", sum.Services, len(got.Snapshot.Services)},
		{"matched services", sum.MatchedServices, m.MatchedServices()},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	if !sum.Enabled || sum.Configured || !sum.Reachable || !sum.EntrypointsRead {
		t.Fatalf("summary = %+v, want an enabled, discovered, complete read", sum)
	}
	if sum.Endpoint != got.Endpoint || sum.EndpointSource != got.Source || sum.Version != "3.1.2" {
		t.Fatalf("summary = %+v, want the read's own endpoint and version", sum)
	}
	if sum.Error != "" {
		t.Fatalf("Error = %q on a complete read", sum.Error)
	}
	// With no fleet index nothing can be matched, and the two routers have to be *reported* as
	// unmatched rather than silently absent from both lists.
	if len(sum.UnmatchedRouters) != 2 {
		t.Fatalf("unmatched = %#v, want both routers", sum.UnmatchedRouters)
	}
}

// TestAMiddlewareFiledUnderTwoNamesIsCountedOnce is the count a reader compares against the list.
//
// A router refers to a middleware by its key or by the name its definition carries, and the snapshot
// indexes both so neither lookup misses. The count is of middlewares, not of index entries.
func TestAMiddlewareFiledUnderTwoNamesIsCountedOnce(t *testing.T) {
	s := &stub{answer: func(r *http.Request) (int, http.Header, string) {
		if r.URL.Path == pathRawData {
			return http.StatusOK, nil, `{"routers":{},"services":{},"middlewares":{
			  "authentik": {"forwardAuth":{"address":"http://a:9000/x"},"name":"authentik@file"}
			}}`
		}
		return proxy(r)
	}}
	got := read(t, s, enabled(), owned())

	if n := len(got.Snapshot.Middlewares); n != 2 {
		t.Fatalf("index entries = %d, want the definition filed under both names it is referred to by", n)
	}
	if n := Summarize(got, Apply(got.Snapshot, noFleet())).Middlewares; n != 1 {
		t.Fatalf("Middlewares = %d, want 1: one definition is one middleware", n)
	}
}
