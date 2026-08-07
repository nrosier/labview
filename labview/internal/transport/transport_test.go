package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/payload"
)

// roundTrip is an injected transport. Every test here runs the real client — its bounds, its
// classification and its body cap — over bytes a test supplies, which is the same arrangement the
// corpus uses to run the whole pipeline with no network (§23).
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// respond builds a response the way a real transport hands one over: a status, headers, and a body
// that must be closed.
func respond(status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// ---------------------------------------------------------------------------
// The bounds of I8
// ---------------------------------------------------------------------------

// TestTheBodyCapIsSharedAndIsSixtyFourKiB is I8's size bound at the one place it is applied. The cap
// is a single constant because two of them drift, and a payload whose probe truncated at 64 KiB
// while its API truncated at 128 would make the truncation note mean two different things.
func TestTheBodyCapIsSharedAndIsSixtyFourKiB(t *testing.T) {
	if BodyCap != 64*1024 {
		t.Fatalf("BodyCap = %d, want 65536 — §13.6 and I8 both name 64 KiB", BodyCap)
	}

	for _, tc := range []struct {
		name      string
		size      int
		want      int
		truncated bool
	}{
		{"well under the cap", 10, 10, false},
		{"one byte under", BodyCap - 1, BodyCap - 1, false},
		{"exactly the cap", BodyCap, BodyCap, false},
		{"one byte over", BodyCap + 1, BodyCap, true},
		{"far over", BodyCap * 4, BodyCap, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Options{RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
				return respond(200, nil, strings.Repeat("x", tc.size)), nil
			})})

			res := c.Do(context.Background(), Request{URL: "http://example.invalid/api"})
			if len(res.Body) != tc.want {
				t.Errorf("read %d bytes, want %d", len(res.Body), tc.want)
			}
			if res.Truncated != tc.truncated {
				t.Errorf("truncated = %v, want %v", res.Truncated, tc.truncated)
			}
			// A truncated read is still a read: the phase is whatever the status said, because the
			// first 64 KiB of a login page still contains its login form (§13.6).
			if res.Phase != payload.PhaseConnected {
				t.Errorf("phase = %q, want %q", res.Phase, payload.PhaseConnected)
			}
		})
	}
}

// TestExactlyTheCapIsNotReportedAsTruncated states the boundary on its own, because getting it wrong
// is invisible: a cap implemented with a bare LimitReader cannot tell a body of exactly 64 KiB from
// a body of a megabyte, and would either invent a truncation on the first or miss it on the second.
func TestExactlyTheCapIsNotReportedAsTruncated(t *testing.T) {
	body, truncated, err := readCapped(strings.NewReader(strings.Repeat("y", BodyCap)))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if truncated {
		t.Error("a body of exactly the cap was reported as truncated")
	}
	if len(body) != BodyCap {
		t.Errorf("read %d bytes, want %d", len(body), BodyCap)
	}

	body, truncated, err = readCapped(strings.NewReader(strings.Repeat("y", BodyCap+1)))
	if err != nil || !truncated || len(body) != BodyCap {
		t.Errorf("one byte over: %d bytes, truncated = %v, err = %v", len(body), truncated, err)
	}
}

// TestRequestsInFlightAreBounded is I8's concurrency bound. A scan of a large fleet asks about every
// service, and without a bound it opens one connection per service at once — which is a fleet-wide
// outbound burst from a program whose entire job is to be safe to point at a homelab.
func TestRequestsInFlightAreBounded(t *testing.T) {
	var mu sync.Mutex
	var inFlight, peak int

	c := New(Options{
		MaxConcurrency: 2,
		RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()

			time.Sleep(20 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			return respond(200, nil, "{}"), nil
		}),
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Do(context.Background(), Request{URL: "http://example.invalid/api"})
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if peak > 2 {
		t.Errorf("%d requests were in flight at once, want at most 2", peak)
	}
	if peak < 2 {
		t.Errorf("peak concurrency was %d; the bound is not a bound, it is a serialisation", peak)
	}
}

// TestWaitingForASlotIsNotChargedToTheBudget is why the semaphore is taken before the clock starts.
// A loaded scan queues requests, and charging the wait to the per-request budget would report a
// healthy fleet as a fleet of timeouts — a diagnosis about LabView's own scheduling, dressed up as a
// diagnosis about the fleet.
func TestWaitingForASlotIsNotChargedToTheBudget(t *testing.T) {
	var mu sync.Mutex
	var elapsedSeen []time.Duration

	// The clock advances by 100ms per reading, so one request's measured elapsed is always 100ms
	// however long it waited for its slot.
	var ticks int
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		ticks++
		return time.Unix(0, 0).Add(time.Duration(ticks) * 100 * time.Millisecond)
	}

	c := New(Options{
		MaxConcurrency: 1,
		Timeout:        150 * time.Millisecond,
		Now:            now,
		RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
			return respond(200, nil, "{}"), nil
		}),
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := c.Do(context.Background(), Request{URL: "http://example.invalid/api"})
			mu.Lock()
			elapsedSeen = append(elapsedSeen, res.Elapsed)
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, d := range elapsedSeen {
		if d != 100*time.Millisecond {
			t.Errorf("elapsed = %v, want 100ms — the queue wait was charged to the request", d)
		}
	}
}

// TestNoRedirectIsEverFollowed is the rule two sections need for opposite reasons: the probe needs
// the 3xx itself, because where it points is the evidence (§13.3); an API read needs it *not*
// followed, because a followed redirect is how a request for JSON arrives at a login page carrying a
// 200 (§15).
func TestNoRedirectIsEverFollowed(t *testing.T) {
	var asked []string
	c := New(Options{RoundTripper: roundTrip(func(r *http.Request) (*http.Response, error) {
		asked = append(asked, r.URL.String())
		return respond(302, http.Header{"Location": {"https://sso.example.com/if/flow/login/"}}, ""), nil
	})})

	res := c.Do(context.Background(), Request{URL: "http://app.example.com/"})

	if len(asked) != 1 {
		t.Errorf("issued %d requests, want 1: %v", len(asked), asked)
	}
	if res.Status != 302 {
		t.Errorf("status = %d, want the 302 itself", res.Status)
	}
	if got := res.Header.Get("Location"); got != "https://sso.example.com/if/flow/login/" {
		t.Errorf("Location = %q, want it intact — it is the evidence", got)
	}
	// And a 3xx is not a read: the phase says so, so no reader has to remember that a 302 body is
	// not the document it asked for.
	if res.OK() {
		t.Errorf("phase = %q reads as ok; a redirect is not a read", res.Phase)
	}
}

// ---------------------------------------------------------------------------
// The structural refusals
// ---------------------------------------------------------------------------

// TestCertificateVerificationCannotBeSwitchedOff is §21 checked as a property of the code rather
// than as a claim in a comment. The strong form of the invariant is not that a flag is false — it is
// that no field exists to set, so there is nothing for a future change to plumb through.
func TestCertificateVerificationCannotBeSwitchedOff(t *testing.T) {
	fields := reflect.TypeOf(Options{})
	for i := 0; i < fields.NumField(); i++ {
		name := strings.ToLower(fields.Field(i).Name)
		for _, forbidden := range []string{"insecure", "skipverify", "verify", "tls", "notls", "trust"} {
			if strings.Contains(name, forbidden) {
				t.Errorf("Options has a field %q; §21 allows no option that weakens TLS",
					fields.Field(i).Name)
			}
		}
	}

	rt, ok := realTransport("").(*http.Transport)
	if !ok {
		t.Fatal("the real transport is no longer an *http.Transport")
	}
	if rt.TLSClientConfig.InsecureSkipVerify {
		t.Error("verification is disabled in the built transport")
	}
	if rt.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", rt.TLSClientConfig.MinVersion)
	}
	// And no proxy is taken from the environment: a homelab's HTTP_PROXY is for reaching the
	// internet, and routing an internal read through it would send the fleet's own addresses to
	// whatever the proxy is (I2).
	if rt.Proxy != nil {
		t.Error("the transport takes a proxy from the environment")
	}
}

// TestAnonymousCarriesNoCredential is §13's requirement that the probe send none *and not by
// omission*. The signature is the guarantee — Anonymous has no parameter for a header, a cookie or a
// body — and this asserts the consequence on the wire, which is what a reviewer can check.
func TestAnonymousCarriesNoCredential(t *testing.T) {
	var seen *http.Request
	c := New(Options{RoundTripper: roundTrip(func(r *http.Request) (*http.Response, error) {
		seen = r.Clone(r.Context())
		return respond(200, nil, "<html></html>"), nil
	})})

	c.Anonymous(context.Background(), "http://app.example.com/?token=Nz9Kq3vExample#frag")

	if seen == nil {
		t.Fatal("no request was issued")
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Authentik-Token",
	} {
		if got := seen.Header.Get(name); got != "" {
			t.Errorf("the anonymous request carried %s: %q", name, got)
		}
	}
	// Exactly one header, and it identifies the reader rather than authenticating it.
	if len(seen.Header) != 1 || seen.Header.Get("User-Agent") != UserAgent {
		t.Errorf("headers = %v, want only User-Agent: %s", seen.Header, UserAgent)
	}
	// GET with no query string (§13.6). The token in the URL above is exactly the accident this
	// drops: a redirect URI read out of a compose file can carry one.
	if seen.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", seen.Method)
	}
	if seen.URL.RawQuery != "" || seen.URL.Fragment != "" {
		t.Errorf("url = %q, want no query and no fragment", seen.URL)
	}
	if strings.Contains(seen.URL.String(), "Nz9Kq3vExample") {
		t.Errorf("url = %q, which carries the credential it was assembled from", seen.URL)
	}
	if seen.Body != nil && seen.Body != http.NoBody {
		t.Error("the anonymous request carried a body")
	}
}

// TestAnonymousHasNowhereToPutACredential is the guarantee itself rather than its consequence. If a
// later change gave Anonymous a header parameter, every test above would still pass — the probe
// would simply be able to pass one.
func TestAnonymousHasNowhereToPutACredential(t *testing.T) {
	fn := reflect.TypeOf((*Client).Anonymous)
	// receiver, context, url — and nothing else.
	if fn.NumIn() != 3 {
		t.Fatalf("Anonymous takes %d arguments, want (client, context, url) and nothing more", fn.NumIn())
	}
	if got := fn.In(2).Kind(); got != reflect.String {
		t.Errorf("Anonymous's second argument is a %s; a struct or a map is somewhere to put a "+
			"credential", got)
	}
}

// TestOnlyGETAndPOSTAreIssued is I5 as a refusal rather than as a convention. Every fleet read is a
// GET; POST exists solely for the OIDC token exchange, which is a conversation with an identity
// provider and not a write to anything scanned. A method with no caller is refused rather than left
// available for a future one.
func TestOnlyGETAndPOSTAreIssued(t *testing.T) {
	var issued int
	c := New(Options{RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
		issued++
		return respond(200, nil, "{}"), nil
	})})

	for _, method := range []string{"PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"} {
		res := c.Do(context.Background(), Request{Method: method, URL: "http://example.invalid/x"})
		if !errors.Is(res.Err, ErrMethod) {
			t.Errorf("%s was not refused: err = %v", method, res.Err)
		}
		if res.OK() {
			t.Errorf("%s produced an ok result", method)
		}
	}
	if issued != 0 {
		t.Errorf("%d refused requests reached the transport anyway", issued)
	}

	for _, method := range []string{"", "GET", "POST"} {
		if res := c.Do(context.Background(), Request{Method: method, URL: "http://example.invalid/x"}); res.Err != nil {
			t.Errorf("method %q was refused: %v", method, res.Err)
		}
	}
	if issued != 3 {
		t.Errorf("%d permitted requests reached the transport, want 3", issued)
	}
}

// TestNoCookieSurvivesAResponse is why the client holds no jar. Traefik's authenticated retry
// replays the cookies from its own challenge within one exchange (§12); a jar would carry them into
// every subsequent read, so a session obtained from one service would be presented to the next —
// and the probe's anonymous reading would stop being anonymous.
func TestNoCookieSurvivesAResponse(t *testing.T) {
	var second *http.Request
	var n int
	c := New(Options{RoundTripper: roundTrip(func(r *http.Request) (*http.Response, error) {
		n++
		if n == 2 {
			second = r.Clone(r.Context())
		}
		return respond(200, http.Header{"Set-Cookie": {"session=abc; Path=/"}}, "{}"), nil
	})})

	first := c.Do(context.Background(), Request{URL: "http://app.example.com/api"})
	if len(first.Cookies) != 1 || first.Cookies[0].Name != "session" {
		t.Fatalf("the response's own cookies were not returned: %v", first.Cookies)
	}
	c.Anonymous(context.Background(), "http://app.example.com/")

	if second == nil {
		t.Fatal("the second request was not issued")
	}
	if got := second.Header.Get("Cookie"); got != "" {
		t.Errorf("the second request carried %q from the first response", got)
	}
}

// TestCookiesAreReplayedWhenAskedFor is the other half: a caller that has a cookie in hand for one
// exchange can send it, which is what Traefik's retry needs (§12). It travels as a parameter of the
// one request rather than as state on the client.
func TestCookiesAreReplayedWhenAskedFor(t *testing.T) {
	var seen *http.Request
	c := New(Options{RoundTripper: roundTrip(func(r *http.Request) (*http.Response, error) {
		seen = r.Clone(r.Context())
		return respond(200, nil, "{}"), nil
	})})

	c.Do(context.Background(), Request{
		URL:     "http://traefik.example.com/api/http/routers",
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
	})

	if got := seen.Header.Get("Cookie"); !strings.Contains(got, "session=abc") {
		t.Errorf("Cookie = %q, want the replayed cookie", got)
	}
}

// ---------------------------------------------------------------------------
// Classification belongs to the transport
// ---------------------------------------------------------------------------

// TestThePhaseComesBackAlreadyClassified is §15's single-classification requirement made structural.
// This package owns the elapsed time and the budget, so it is the only thing that *can* decide
// whether a teardown was a timeout — and a caller therefore receives a phase it had no way to
// derive itself.
func TestThePhaseComesBackAlreadyClassified(t *testing.T) {
	// A reset that arrives exactly at the budget is a timeout; the identical reset arriving early is
	// a connect failure. The message is the same in both cases.
	for _, tc := range []struct {
		name    string
		advance time.Duration
		want    payload.ConnectionPhase
	}{
		{"at the budget", 2 * time.Second, payload.PhaseTimeout},
		{"well inside it", 20 * time.Millisecond, payload.PhaseConnect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			c := New(Options{
				Timeout: 2 * time.Second,
				Now: func() time.Time {
					calls++
					if calls == 1 {
						return time.Unix(100, 0)
					}
					return time.Unix(100, 0).Add(tc.advance)
				},
				RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
					return nil, &os2SyscallError{syscall.ECONNRESET}
				}),
			})

			res := c.Do(context.Background(), Request{URL: "http://example.invalid/api"})
			if res.Phase != tc.want {
				t.Errorf("phase = %q, want %q", res.Phase, tc.want)
			}
			if res.Elapsed != tc.advance {
				t.Errorf("elapsed = %v, want %v", res.Elapsed, tc.advance)
			}
		})
	}
}

// os2SyscallError is a transport-level errno without importing os for one line.
type os2SyscallError struct{ errno syscall.Errno }

func (e *os2SyscallError) Error() string { return "read tcp: " + e.errno.Error() }
func (e *os2SyscallError) Unwrap() error { return e.errno }

// TestTheStatusIsClassifiedAndTheBodyIsStillRead is why a reader gets both. A 401's body says which
// realm and a 403's says which permission, and a transport that only read 2xx bodies would leave the
// failures that most need a detail with nothing to put in one.
func TestTheStatusIsClassifiedAndTheBodyIsStillRead(t *testing.T) {
	for _, tc := range []struct {
		status int
		phase  payload.ConnectionPhase
	}{
		{200, payload.PhaseConnected},
		{401, payload.PhaseAuthenticate},
		{403, payload.PhaseAuthorize},
		{404, payload.PhasePath},
		{500, payload.PhaseStatus},
	} {
		c := New(Options{RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
			return respond(tc.status, nil, `{"detail":"why"}`), nil
		})})

		res := c.Do(context.Background(), Request{URL: "http://example.invalid/api"})
		if res.Phase != tc.phase {
			t.Errorf("status %d: phase = %q, want %q", tc.status, res.Phase, tc.phase)
		}
		if string(res.Body) != `{"detail":"why"}` {
			t.Errorf("status %d: body = %q, want it read", tc.status, res.Body)
		}
		if res.Code != http.StatusText(tc.status) && res.Code == "" {
			t.Errorf("status %d: no code reported", tc.status)
		}
	}
}

// TestAnUnassemblableURLIsNotANetworkFailure is I1 applied to the program's own faults. A URL this
// program built and cannot parse is a configuration problem; reporting it as `connect` would send an
// operator to check a firewall for a mistake in a variable.
func TestAnUnassemblableURLIsNotANetworkFailure(t *testing.T) {
	var issued int
	c := New(Options{RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
		issued++
		return respond(200, nil, "{}"), nil
	})})

	res := c.Do(context.Background(), Request{URL: "http://exa mple.invalid/\x7f"})
	if res.Phase != payload.PhaseNotConfigured {
		t.Errorf("phase = %q, want %q", res.Phase, payload.PhaseNotConfigured)
	}
	if issued != 0 {
		t.Error("a URL that would not parse was nonetheless dialled")
	}
}

// TestACancelledContextIsNotAFleetFailure is the shutdown case. A scan interrupted by a stopping
// process must not report the fleet as unreachable, and the phase says so: the cancellation is the
// caller's, and the classification comes from the same mapping as everything else.
func TestACancelledContextIsNotAFleetFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := New(Options{MaxConcurrency: 1, RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("a cancelled scan issued a request")
		return respond(200, nil, "{}"), nil
	})})
	// The slot is free, so this reaches the request; either way nothing is dialled and a phase comes
	// back rather than a nil result.
	res := c.Do(ctx, Request{URL: "http://example.invalid/api"})
	if res.Phase == "" || !payload.ValidConnectionPhase(string(res.Phase)) {
		t.Errorf("phase = %q, want a member of the closed set", res.Phase)
	}
	if res.OK() {
		t.Error("a cancelled request reported ok")
	}
}

// ---------------------------------------------------------------------------
// Endpoints and headers
// ---------------------------------------------------------------------------

// TestEndpointIsTheOneCredentialFreeFormatter is §20's requirement that one formatter produce every
// endpoint field in the payload. It removes the three places a credential hides — userinfo, the
// query string, the fragment — and keeps the path, because which path answered is often the whole
// diagnosis.
func TestEndpointIsTheOneCredentialFreeFormatter(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"http://authentik:9000/api/v3/root/config/", "http://authentik:9000/api/v3/root/config"},
		{"https://sso.example.com", "https://sso.example.com"},
		{"http://admin:hunter2@traefik:8080/api/overview", "http://traefik:8080/api/overview"},
		{"http://traefik:8080/api?token=Nz9Kq3vExample", "http://traefik:8080/api"},
		{"http://traefik:8080/api#section", "http://traefik:8080/api"},
		{"http://user@authentik:9000/api", "http://authentik:9000/api"},
		{"unix:///var/run/docker.sock", "unix:///var/run/docker.sock"},
		{"/var/run/docker.sock", "/var/run/docker.sock"},
		{"", ""},
	} {
		if got := Endpoint(tc.in); got != tc.want {
			t.Errorf("Endpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// A bare username with no password is dropped too, which is where this formatter deliberately
	// parts company with secrets.RedactURIs. There, a username is evidence about how a service is
	// configured and is worth keeping. Here it is not part of the address that answered — and
	// `http://<apikey>@host` with no password is a real way to pass a token, so the shape that
	// looks least like a credential is the one that most often is one.
	for _, in := range []string{
		"http://user@authentik:9000/api",
		"http://Nz9Kq3vExample@authentik:9000/api",
	} {
		if got := Endpoint(in); strings.Contains(got, "@") {
			t.Errorf("Endpoint(%q) = %q, want no userinfo at all", in, got)
		}
	}
}

// TestAnUnparseableEndpointIsWithheldRatherThanPassedThrough is where a formatter that gave up would
// do the most damage. A string that will not parse is exactly the shape a credential survives in, so
// the fallback is a replacement and never the input.
func TestAnUnparseableEndpointIsWithheldRatherThanPassedThrough(t *testing.T) {
	for _, in := range []string{
		"http://admin:hunter2@exa mple.com/\x7f",
		"::::",
		"http://",
		"not a url at all",
	} {
		got := Endpoint(in)
		if got == in {
			t.Errorf("Endpoint(%q) passed its input through", in)
		}
		if strings.Contains(got, "hunter2") {
			t.Errorf("Endpoint(%q) = %q, which carries a credential", in, got)
		}
	}
}

// TestSameOriginIsOneComparison is the rule §13.6 requires the redirect signal, the meta refresh and
// the media-type reading to share. Scheme and authority as written: a service reached over http and
// redirecting to https has sent the reader somewhere else, and calling that the same origin would
// lose the strongest gate signal there is.
func TestSameOriginIsOneComparison(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"http://app.example.com/", "http://app.example.com/login", true},
		{"http://app.example.com:80/", "http://app.example.com/", false},
		{"http://app.example.com/", "https://app.example.com/", false},
		{"http://app.example.com/", "http://sso.example.com/", false},
		{"http://app.example.com/", "", false},
		{"", "", false},
	} {
		if got := SameOrigin(tc.a, tc.b); got != tc.same {
			t.Errorf("SameOrigin(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
	// An explicit port and a default port are different origins here, deliberately. This comparison
	// decides whether a redirect left the service, and a scan that normalised ports would have to
	// know every scheme's default to do it — which is knowledge about the far side that I1 does not
	// let it invent.
	if SameOrigin("http://x/", "http://x:80/") {
		t.Error("an explicit port was normalised away")
	}
}

// TestASocketClientReportsTheSocket is why Options carries an endpoint at all. Every Docker request
// goes to one socket that appears in no URL — the URL's host names nothing — so a result that
// derived its endpoint from the request would report `http://docker`, an address that does not exist.
func TestASocketClientReportsTheSocket(t *testing.T) {
	c := New(Options{
		Endpoint: "unix:///var/run/docker.sock",
		RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
			return respond(200, nil, "OK"), nil
		}),
	})

	res := c.Do(context.Background(), Request{URL: "http://docker/_ping"})
	if res.Endpoint != "unix:///var/run/docker.sock" {
		t.Errorf("endpoint = %q, want the socket", res.Endpoint)
	}

	// And without one, the endpoint is derived from the URL — which is right for the probe, where
	// every request goes somewhere else.
	free := New(Options{RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
		return respond(200, nil, "OK"), nil
	})})
	if got := free.Do(context.Background(), Request{URL: "http://app.example.com/x?t=1"}).Endpoint; got != "http://app.example.com/x" {
		t.Errorf("endpoint = %q, want it derived from the URL with the query dropped", got)
	}
}

// TestWhatWasSentIsNamesAndNeverValues is I6 at the diagnostic that reports a credentialed read. The
// names are what an operator needs — *the token header was sent and refused* — and the value is the
// one thing that must never travel with them.
func TestWhatWasSentIsNamesAndNeverValues(t *testing.T) {
	c := New(Options{RoundTripper: roundTrip(func(*http.Request) (*http.Response, error) {
		return respond(401, nil, "{}"), nil
	})})

	res := c.Do(context.Background(), Request{
		URL: "http://authentik:9000/api/v3/root/config/",
		Header: map[string]string{
			"authorization": "Bearer Nz9Kq3vExample",
			"Accept":        "application/json",
		},
	})

	want := []string{"Accept", "Authorization"}
	if len(res.Sent) != len(want) {
		t.Fatalf("sent = %v, want %v", res.Sent, want)
	}
	for i := range want {
		if res.Sent[i] != want[i] {
			t.Errorf("sent = %v, want %v in canonical sorted order", res.Sent, want)
			break
		}
	}
	for _, name := range res.Sent {
		if strings.Contains(name, "Nz9Kq3vExample") || strings.Contains(name, "Bearer") {
			t.Errorf("sent carries a value: %q", name)
		}
	}
	if res.Sent == nil && len(want) > 0 {
		t.Error("sent is nil")
	}
	// A request with no headers of its own reports none, rather than reporting the User-Agent this
	// package adds: the diagnostic is about what the *reader* sent, and the reader sent nothing.
	if got := c.Do(context.Background(), Request{URL: "http://x.invalid/"}).Sent; got != nil {
		t.Errorf("sent = %v, want nil for a request that set no headers", got)
	}
}

// TestDefaultsAreTheOnesTheSpecStates keeps the two numbers honest. A caller that names neither gets
// §3.1's budget and a bounded number in flight — never an unbounded one, which is what a zero value
// would mean if the constructor took it literally.
func TestDefaultsAreTheOnesTheSpecStates(t *testing.T) {
	c := New(Options{})
	if c.budget != DefaultTimeout {
		t.Errorf("budget = %v, want %v", c.budget, DefaultTimeout)
	}
	if c.limit == nil {
		t.Fatal("a client built with no options is unbounded")
	}
	if cap(c.limit) != DefaultConcurrency {
		t.Errorf("concurrency = %d, want %d", cap(c.limit), DefaultConcurrency)
	}
	if c.now == nil {
		t.Error("no clock")
	}
	// A negative value is the explicit opt-out, so a caller that genuinely wants no bound does not
	// have to guess whether zero means one or none.
	if New(Options{MaxConcurrency: -1}).limit != nil {
		t.Error("a negative concurrency was still bounded")
	}
}
