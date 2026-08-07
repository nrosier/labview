package corpus

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// This file is the corpus's whole model of the outside world. Three stubs, one recorder, and one
// transport that answers nothing.
//
// What they record is worth as much as what they serve. The containment rules of I8 and §13.6 are all
// statements about requests that must *not* happen — a credential to a guessed address, a request to a
// service whose authentication was already detected, a second request to a page that carried a form —
// and an absence can only be asserted against a list of what was asked.

// ---------------------------------------------------------------------------
// What a stub records
// ---------------------------------------------------------------------------

// call is one request a stub answered.
type call struct {
	URL string
	// Credential is whether the request carried one, in any of the three forms this program sends:
	// a bearer token, basic auth, or a cookie. It is deliberately not *which* — a test that needed
	// the value to make its point would be a test that logged a credential.
	Credential bool
	// Cookie is the one exception, because the gated proxy exchange is *about* echoing a session
	// back and there is no way to assert that without comparing it. The value is a fixture string.
	Cookie string
}

// recorder is the shared call log. Guarded because the pipeline reads two APIs concurrently and probes
// a fleet in parallel, so several goroutines reach one stub at once (§5, §13.6).
type recorder struct {
	mu    sync.Mutex
	calls []call
}

func (r *recorder) add(c call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

// all is a copy, so a caller can walk it while a straggler is still finishing.
func (r *recorder) all() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]call(nil), r.calls...)
}

// count is how many requests reached this address exactly.
func (r *recorder) count(url string) int {
	n := 0
	for _, c := range r.all() {
		if c.URL == url {
			n++
		}
	}
	return n
}

// asked is whether this address was requested at all — the shape every containment assertion takes.
func (r *recorder) asked(url string) bool { return r.count(url) > 0 }

// authenticated is every address that received a credential. The list rather than a boolean, because
// the failure message wants to name the address a token reached.
func (r *recorder) authenticated() []string {
	var out []string
	for _, c := range r.all() {
		if c.Credential {
			out = append(out, c.URL)
		}
	}
	return out
}

// hosts is the distinct hosts that were reached, for the discovery walk's own assertions.
func (r *recorder) hosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range r.all() {
		host := hostOf(c.URL)
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

func hostOf(rawURL string) string {
	rest := rawURL
	if _, after, ok := strings.Cut(rawURL, "://"); ok {
		rest = after
	}
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// credentialOf reads the request's own headers for any of the three forms.
func credentialOf(r *http.Request) (bool, string) {
	cookie := r.Header.Get("Cookie")
	return r.Header.Get("Authorization") != "" || cookie != "", cookie
}

// ---------------------------------------------------------------------------
// Answering
// ---------------------------------------------------------------------------

// answer is one canned response. Every field optional: a header being absent is itself evidence, and
// the probe's whole subject is what a response did *not* say.
type answer struct {
	status    int
	location  string
	challenge string // WWW-Authenticate
	cookie    string // Set-Cookie
	mediaType string
	body      string
}

// respond turns one canned answer into the http.Response a RoundTripper returns.
func respond(r *http.Request, a answer) (*http.Response, error) {
	head := http.Header{}
	if a.mediaType != "" {
		head.Set("Content-Type", a.mediaType)
	}
	if a.location != "" {
		head.Set("Location", a.location)
	}
	if a.challenge != "" {
		head.Set("WWW-Authenticate", a.challenge)
	}
	if a.cookie != "" {
		head.Set("Set-Cookie", a.cookie)
	}
	return &http.Response{
		StatusCode: a.status,
		Header:     head,
		Body:       io.NopCloser(strings.NewReader(a.body)),
		Request:    r,
	}, nil
}

// jsonAnswer is the shape both API stubs return: a status and a marshalled body.
func jsonAnswer(status int, body any) answer {
	raw, err := json.Marshal(body)
	if err != nil {
		// A fixture that will not marshal is a broken fixture, and there is no test to fail here —
		// this runs inside a RoundTripper. Serving the error as a 500 body puts it where the failing
		// assertion can print it.
		return answer{status: 500, mediaType: "application/json", body: `{"detail":"` + err.Error() + `"}`}
	}
	return answer{status: status, mediaType: "application/json", body: string(raw)}
}

// unresolved is the error a name that does not resolve produces, and it is a *net.DNSError so that
// conn.FromError classifies it as `resolve` from the error's type rather than from its text (§10).
//
// This is the ordinary state of a fleet's public hostnames seen from inside the fleet, and the
// probe's fall-through to the next vantage exists for exactly it (§13.2).
func unresolved(host string) error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true},
	}
}

// refusing is the transport a root with no integrations gets: every request fails to resolve.
//
// Not a nil RoundTripper and not one that returns a 404, because both would be softer than the truth.
// A root that switched nothing on and still issued a request has a bug, and the assertion that finds
// it is a connection report saying `resolve` for a target that should have said `disabled`.
type refusing struct{}

func (refusing) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, unresolved(r.URL.Hostname())
}

// ---------------------------------------------------------------------------
// The identity provider
// ---------------------------------------------------------------------------

// The origin in `fixtures/authentik` that actually serves the API — the `server` service's container
// name and the *target* side of its port mapping. Discovery has to arrive here from the compose file
// alone: the published host port is 9443 and the public hostname is `sso.example.com`, so a walk that
// reached for either does not match this and the read fails.
const akOrigin = "http://authentik-server:9000"

// Where the API answers in `fixtures/traefik` — the outpost, because that root's fleet puts it there.
// Two different origins across two roots is the point: nothing in the reader may assume one.
const akOutpostOrigin = "http://authentik-outpost:9000"

// Not a credential. An arbitrary string the stub demands verbatim, so that a request arriving without
// it is answered the way the real API answers one — 403 with a sentence about credentials, which is
// what §11's reporting has to turn into a hint an operator can act on.
const akToken = "corpus-fixture-token-0000000000"

// akMode is how much of its own list the instance will serve.
type akMode struct {
	// superuser is whether this instance honours `superuser_full_list=true`. The default — false — is
	// the least-privilege token most fleets will use, and the one the shortfall reporting has to be
	// honest under. Sending the parameter to an ordinary token proves nothing, which is why the stub
	// requires both.
	superuser bool

	// hides narrows which applications the policy filter removes. Nil means *the whole `:withheld`
	// set*, which is the fixture's default. Naming a subset is how a run in which recovery closes the
	// entire gap becomes reachable — and that run is where §23's required conclusion comes from.
	hides []string
}

// akFixture is `fixtures/authentik-api.json`, read once per process.
//
// A document rather than Go, unlike the probe answers, because an API response *is* a document: the
// two pagination envelopes, the policy filter's interaction with `count`, and the fifteen records the
// matcher walks are all shapes with a wire format, and inventing a second one in Go would mean the
// fixture no longer looked like what the reader will meet.
func akFixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return apiFixture(t, "authentik-api.json")
}

func apiFixture(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatalf("the API fixture could not be read: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s is not JSON: %v", name, err)
	}
	return out
}

// authentikAnswer answers one request from a fixture payload, or reports that the request was not for
// this origin so a caller can try something else.
//
// Shared by both API stubs: the proxy root's runs need the same identity payload served, because the
// three-way cross-check of §12 reads all three sources in one scan and a stub that served only two
// could not exercise it. Duplicating the pagination envelopes would mean two places for the assumed
// shape to drift.
//
// It behaves like the real thing in the four ways the reader depends on:
//
//  1. `/api/v3/root/config/` answers without a credential — it is `AllowAny` upstream, and it is what
//     the reader uses to tell *this is Authentik* from *this is something else on port 9000*.
//  2. Every other endpoint demands the exact bearer token, and answers 403 rather than 401 without
//     it, which is what DRF does and is the case §11's hint is written for.
//  3. Any other origin is simply not an API. The outpost, the worker and the database are all
//     candidates discovery generates, and none of them may answer.
//  4. `/core/applications/` paginates and *then* policy-filters the page as the token's own user, so
//     withheld applications are missing from `results` while still counted in `pagination.count` —
//     upstream computes the count before the filter runs. That gap is the entire subject of §11's
//     shortfall reporting, and it is only reachable because the count stays honest.
func authentikAnswer(fixture map[string]json.RawMessage, origin string, mode akMode, r *http.Request) (answer, bool) {
	if originOf(r.URL) != origin {
		return answer{}, false
	}

	endpoint := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v3/"), "/")
	if endpoint == "root/config" {
		return jsonAnswer(200, rawOr(fixture["root/config"], `{}`)), true
	}
	if r.Header.Get("Authorization") != "Bearer "+akToken {
		return jsonAnswer(403, map[string]string{"detail": "Authentication credentials were not provided."}), true
	}

	pages, ok := recordPages(fixture[endpoint])
	if !ok {
		return jsonAnswer(404, map[string]string{"detail": "Not found."}), true
	}

	// The withheld set is a key of its own in the fixture rather than a flag on a record, because it
	// is not a property of the application — it is what *this token's* policies removed.
	withheld, hasWithheld := recordPages(fixture[endpoint+":withheld"])
	all := pages
	if hasWithheld {
		all = append(append([][]record(nil), pages...), withheld...)
	}

	// `count` is the full total in every mode. It is the field the shortfall rests on.
	count := 0
	for _, page := range all {
		count += len(page)
	}

	served := all
	if !mode.superuser || r.URL.Query().Get("superuser_full_list") != "true" {
		filter := map[string]bool{}
		switch {
		case mode.hides != nil:
			for _, slug := range mode.hides {
				filter[slug] = true
			}
		case hasWithheld:
			for _, page := range withheld {
				for _, rec := range page {
					filter[rec.Slug] = true
				}
			}
		}
		served = nil
		for _, page := range all {
			var kept []record
			for _, rec := range page {
				if !filter[rec.Slug] {
					kept = append(kept, rec)
				}
			}
			if len(kept) > 0 {
				served = append(served, kept)
			}
		}
	}

	page := 1
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n > 0 {
		page = n
	}
	results := []json.RawMessage{}
	if page <= len(served) {
		for _, rec := range served[page-1] {
			results = append(results, rec.Raw)
		}
	}

	// Outposts answer in the DRF envelope and everything else in Authentik's own, so one fixture
	// exercises both branches of the pagination reader.
	if endpoint == "outposts/instances" {
		return jsonAnswer(200, map[string]any{
			"count": count, "next": nil, "previous": nil, "results": results,
		}), true
	}
	next := 0
	if page < len(served) {
		next = page + 1
	}
	previous := 0
	if page > 1 {
		previous = page - 1
	}
	return jsonAnswer(200, map[string]any{
		"pagination": map[string]any{
			"next": next, "previous": previous, "count": count,
			"current": page, "total_pages": len(served),
		},
		"results": results,
	}), true
}

// record is one fixture record: its slug, for the policy filter, and the bytes, so everything else
// about it reaches the reader exactly as written.
type record struct {
	Slug string
	Raw  json.RawMessage
}

// recordPages reads a fixture value as pages of records.
//
// A fixture states one page as a flat array and several as an array of arrays, which is how
// `core/applications` carries two pages without a second key. The distinction is made by looking at
// the first element rather than by a marker, because a marker would be a fixture format and this is
// meant to look like the wire.
func recordPages(raw json.RawMessage) ([][]record, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var flat []json.RawMessage
	if err := json.Unmarshal(raw, &flat); err != nil {
		return nil, false
	}
	if len(flat) == 0 {
		return [][]record{{}}, true
	}

	var nested [][]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err == nil {
		out := make([][]record, 0, len(nested))
		for _, page := range nested {
			out = append(out, records(page))
		}
		return out, true
	}
	return [][]record{records(flat)}, true
}

func records(page []json.RawMessage) []record {
	out := make([]record, 0, len(page))
	for _, raw := range page {
		var head struct{ Slug string }
		_ = json.Unmarshal(raw, &head)
		out = append(out, record{Slug: head.Slug, Raw: raw})
	}
	return out
}

func rawOr(raw json.RawMessage, fallback string) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(fallback)
	}
	return raw
}

// originOf is scheme://host[:port], which is what both API stubs dispatch on.
func originOf(u *url.URL) string { return u.Scheme + "://" + u.Host }

// authentikStub stands in for `fixtures/authentik`'s instance.
//
// Every request is recorded, which is what lets a test assert the *absence* of one: the token must
// never be sent to a candidate that failed the probe (§11), and there is no other way to check it.
func authentikStub(t *testing.T, mode akMode) (*recorder, http.RoundTripper) {
	t.Helper()
	fixture := akFixture(t)
	rec := &recorder{}

	return rec, roundTripper(func(r *http.Request) (*http.Response, error) {
		credential, cookie := credentialOf(r)
		rec.add(call{URL: r.URL.String(), Credential: credential, Cookie: cookie})

		if a, ok := authentikAnswer(fixture, akOrigin, mode, r); ok {
			return respond(r, a)
		}
		// Not this origin. The worker, the database and the published host port all land here, and
		// each is a candidate discovery generated — so this is the answer that makes discovery's walk
		// visible in the attempt list rather than a fixture that quietly resolves nowhere.
		return respond(r, jsonAnswer(404, map[string]string{"detail": "Not found."}))
	})
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

// The container address discovery tries first, and the only one listening: `edge-proxy` is the
// container name and 8080 is the port `api.insecure` serves on. `fixtures/traefik/edge` publishes 80
// and 443 and nothing else, so 8080 is tried on the strength of Traefik's own default rather than of
// a declared port.
const tfOrigin = "http://edge-proxy:8080"

// The public hostname the proxy's own `api@internal` router serves — the one address a credential may
// be sent to, because that router's rule proves the hostname is the API's own address rather than
// merely some address of the container (§12).
const tfGatedOrigin = "https://edge.example.com"

// Not credentials. Arbitrary strings the stub demands verbatim.
const (
	tfUser     = "labview"
	tfPassword = "corpus-fixture-app-password-0000"
	tfSession  = "authentik_proxy_session=corpus-fixture-session"
)

func tfBasic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(tfUser+":"+tfPassword))
}

// tfMode is how the proxy behaves for one run.
type tfMode struct {
	// gated serves the API on the public hostname behind the outpost instead of on the container
	// address: no credential, no answer, and the session cookie it sets on the way in must come back
	// on the follow-up requests — which is what Authentik's documentation says to expect and what
	// §12's exchange is written against.
	gated bool

	// entrypointsFail fails `/api/entrypoints`, leaving the read partial. The routing table arrived
	// and the entrypoint list did not, which is a real Traefik configuration (the API can be exposed
	// with the endpoint disabled) and is the case §15's `partial` phase exists for.
	entrypointsFail bool

	// dropRoute serves the runtime config without one route — its router and its like-named service
	// together, because that is how a route leaves: the Docker provider derives both from one
	// container. It is the one thing a stub option can produce that no fixture edit can, namely two
	// *successful* reads of the same files that differ in what the proxy returned (§17).
	dropRoute string
}

// tfStub stands in for `fixtures/traefik`'s proxy, and on the outpost's own origin for the identity
// provider — because the cross-check is only meaningful when all three sources answer in one run.
func tfStub(t *testing.T, mode tfMode) (*recorder, http.RoundTripper) {
	t.Helper()
	fixture := apiFixture(t, "traefik-api.json")
	var akPayload map[string]json.RawMessage
	if err := json.Unmarshal(rawOr(fixture["authentik"], `{}`), &akPayload); err != nil {
		t.Fatalf("the proxy fixture's identity payload is not an object: %v", err)
	}

	origin := tfOrigin
	if mode.gated {
		origin = tfGatedOrigin
	}
	rec := &recorder{}

	return rec, roundTripper(func(r *http.Request) (*http.Response, error) {
		credential, cookie := credentialOf(r)
		rec.add(call{URL: r.URL.String(), Credential: credential, Cookie: cookie})

		if a, ok := authentikAnswer(akPayload, akOutpostOrigin, akMode{}, r); ok {
			return respond(r, a)
		}
		if originOf(r.URL) != origin {
			return respond(r, jsonAnswer(404, map[string]string{"detail": "no such host"}))
		}

		// The handshake is `/api/version`, which needs no credential upstream. It is what turns a
		// guessed address into a proved one (§12), so it is answered before the gate below decides
		// what may be sent — a handshake that demanded a credential would make discovery
		// indistinguishable from authorization.
		probing := r.URL.Path == "/api/version"
		if mode.gated {
			if r.Header.Get("Authorization") != tfBasic() {
				return respond(r, jsonAnswer(401, map[string]string{"detail": "authentication required"}))
			}
			if !probing && cookie != tfSession {
				return respond(r, jsonAnswer(401, map[string]string{"detail": "session not echoed"}))
			}
		}

		switch {
		case probing:
			a := jsonAnswer(200, rawOr(fixture["version"], `{}`))
			if mode.gated {
				a.cookie = tfSession
			}
			return respond(r, a)
		case r.URL.Path == "/api/rawdata":
			return respond(r, jsonAnswer(200, rawdata(t, fixture, mode.dropRoute)))
		case r.URL.Path == "/api/entrypoints":
			if mode.entrypointsFail {
				return respond(r, jsonAnswer(500, map[string]string{"error": "internal server error"}))
			}
			return respond(r, jsonAnswer(200, rawOr(fixture["entrypoints"], `[]`)))
		}
		return respond(r, jsonAnswer(404, map[string]string{"detail": "not found"}))
	})
}

// rawdata is the runtime config as the stub serves it, minus a dropped route.
func rawdata(t *testing.T, fixture map[string]json.RawMessage, drop string) any {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rawOr(fixture["rawdata"], `{}`), &raw); err != nil {
		t.Fatalf("the proxy fixture's runtime config is not an object: %v", err)
	}
	if drop == "" {
		return raw
	}

	// A provider-qualified name: `docs@docker` is dropped by the name before the `@`, which is how an
	// operator names a route and how the fixture's comments refer to them.
	without := func(key string) {
		var section map[string]json.RawMessage
		if err := json.Unmarshal(rawOr(raw[key], `{}`), &section); err != nil {
			return
		}
		for name := range section {
			if base, _, _ := strings.Cut(name, "@"); base == drop {
				delete(section, name)
			}
		}
		encoded, err := json.Marshal(section)
		if err != nil {
			return
		}
		raw[key] = encoded
	}
	without("routers")
	without("services")
	return raw
}

// ---------------------------------------------------------------------------
// The fleet's own services
// ---------------------------------------------------------------------------

// probeLanHost is §23's LAN address, and I2's reason for it being configured rather than found: the
// container cannot see its host's address, so an operator supplies one or there is no LAN vantage.
//
// A documentation-range address rather than a plausible one. If it ever escapes a stub and reaches a
// real socket it must not be able to arrive anywhere.
const probeLanHost = "192.0.2.10"

// probeStub answers as the fixture fleet's own services.
//
// Unlike the two API stubs, this one impersonates *scanned* services rather than an API LabView was
// given the address of — so what it records is worth as much as what it serves. That no request
// carried a credential, that nothing was asked at a database port, that a `tcp://` tunnel hostname was
// never resolved, and that each address was asked exactly once are all assertions about the call log
// and cannot be made any other way.
//
// An address at an origin the table does not have fails to resolve, because that is the ordinary state
// of a fleet's public names seen from inside it. An unlisted *path* at an origin that does answer gets
// a 404 instead: the state walk of §13.4 asks up to four more paths per shell, and a host that
// resolves at `/` cannot plausibly fail DNS at `/api/me`. Keeping the resolve failure for an unknown
// *origin* is what leaves `fixtures/probe/lan-fallback` meaningful — its tunnel hostname is absent
// from the table entirely, and the fall-through to a LAN port exists for exactly that.
func probeStub() (*recorder, http.RoundTripper) {
	rec := &recorder{}
	origins := map[string]bool{}
	for address := range probeAnswers {
		origins[hostOf(address)] = true
	}

	return rec, roundTripper(func(r *http.Request) (*http.Response, error) {
		address := r.URL.String()
		credential, cookie := credentialOf(r)
		rec.add(call{URL: address, Credential: credential, Cookie: cookie})

		if a, ok := probeAnswers[address]; ok {
			return respond(r, a)
		}
		if origins[r.URL.Host] {
			return respond(r, answer{status: 404, mediaType: "text/plain", body: "not found"})
		}
		return nil, unresolved(r.URL.Hostname())
	})
}

// roundTripper adapts a function, so each stub above reads as one function rather than as a type with
// one method.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
