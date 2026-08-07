package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// A fleet in a table
// ---------------------------------------------------------------------------

// answer is one canned HTTP response, keyed by the address it belongs to.
type reply struct {
	status int
	header map[string]string
	body   string
	fail   bool // the address does not answer at all
}

var errRefused = errors.New("connection refused")

// fleet is the stub transport: §13's whole I/O layer exercised without a socket, through the one
// injection point transport.Options names.
type fleet struct {
	replies map[string]reply

	mu   sync.Mutex
	sent []*http.Request
}

func (f *fleet) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.sent = append(f.sent, req)
	f.mu.Unlock()

	got, ok := f.replies[req.URL.String()]
	if !ok || got.fail {
		// Nothing answers here. An address absent from the table is the same fact as one marked failing:
		// the fleet was asked something the fixture never offered.
		return nil, errRefused
	}

	head := http.Header{}
	for name, value := range got.header {
		head.Set(name, value)
	}
	if head.Get("Content-Type") == "" && got.body != "" {
		head.Set("Content-Type", "text/html; charset=utf-8")
	}
	return &http.Response{
		StatusCode: got.status,
		Header:     head,
		Body:       io.NopCloser(bytes.NewReader([]byte(got.body))),
		Request:    req,
	}, nil
}

// requested is every address the fleet was asked for, sorted (the run is concurrent).
func (f *fleet) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]string, 0, len(f.sent))
	for _, req := range f.sent {
		out = append(out, req.URL.String())
	}
	sort.Strings(out)
	return out
}

func (f *fleet) client(t *testing.T) *transport.Client {
	t.Helper()
	return transport.New(transport.Options{RoundTripper: f})
}

// subject wraps one service under a key.
func subject(key string, s payload.Service) Subject { return Subject{Key: key, Service: s} }

// tunnelled is a service reachable at one public hostname and nowhere else.
func tunnelled(host string) payload.Service {
	return payload.Service{Cloudflare: []payload.CloudflareRoute{tunnel(host, "http://app:8080")}}
}

func run(t *testing.T, f *fleet, subjects ...Subject) Read {
	t.Helper()
	return Do(context.Background(), Options{
		Enabled:  true,
		Source:   payload.ProbeSourceRequest,
		Client:   f.client(t),
		Subjects: subjects,
	})
}

// ---------------------------------------------------------------------------
// The one meta.connections entry
// ---------------------------------------------------------------------------

func TestADisabledRunSaysDisabledAndAsksNothing(t *testing.T) {
	f := &fleet{replies: map[string]reply{}}

	got := Do(context.Background(), Options{
		Enabled:  false,
		Source:   payload.ProbeSourceConfig,
		Client:   f.client(t),
		Subjects: []Subject{subject("app", tunnelled("app.example.com"))},
	})

	if got.Report.Phase != payload.PhaseDisabled {
		t.Fatalf("want phase disabled, got %q", got.Report.Phase)
	}
	if len(f.sent) != 0 {
		t.Fatalf("a disabled probe issues no request; got %v", f.requested())
	}
	if got.Run.Enabled {
		t.Fatal("and the payload says the mode it ran in")
	}
	if len(got.Results) != 0 {
		t.Fatalf("with no results; got %+v", got.Results)
	}
}

func TestAFleetWithNoAddressToAskIsNotFound(t *testing.T) {
	f := &fleet{replies: map[string]reply{}}
	database := payload.Service{Ports: []payload.PortMapping{port("5432:5432", "5432")}}

	got := run(t, f, subject("db", database))

	if got.Report.Phase != payload.PhaseNotFound {
		t.Fatalf("want not-found, got %q", got.Report.Phase)
	}
	if !strings.Contains(got.Report.Detail, "no address to ask") {
		t.Fatalf("the detail says why; got %q", got.Report.Detail)
	}
	if len(f.sent) != 0 {
		t.Fatalf("and nothing was asked; got %v", f.requested())
	}
}

func TestAFleetWhoseCandidatesWereAllWithheldIsASuccessNotNotFound(t *testing.T) {
	// §13.1 says so in as many words: every question that could have been asked had already been
	// answered by configuration, and `not-found` would read as a broken integration.
	f := &fleet{replies: map[string]reply{}}
	s := tunnelled("app.example.com")
	s.Auth.Method = payload.AuthAuthentikForwardAuth

	got := run(t, f, subject("app", s))

	if got.Report.Phase != payload.PhaseConnected {
		t.Fatalf("want connected, got %q", got.Report.Phase)
	}
	if got.Skipped != 1 || got.Probed() != 0 {
		t.Fatalf("one withheld candidate and nothing probed; got %+v", got)
	}
	if !strings.Contains(got.Report.Detail, "1 service not asked (authentication already detected)") {
		t.Fatalf("the sentence names the withheld service; got %q", got.Report.Detail)
	}
	if len(f.sent) != 0 {
		t.Fatalf("and no request was issued; got %v", f.requested())
	}
}

func TestPartOfTheFleetNotAnsweringIsPartialAndStillOK(t *testing.T) {
	f := &fleet{replies: map[string]reply{
		"https://gated.example.com/":           {status: 302, header: map[string]string{"Location": "/users/sign_in"}},
		"https://open.example.com/":            {status: 200, body: `<div id="root"></div>`},
		"https://open.example.com/api/":        {status: 200, body: `{}`},
		"https://open.example.com/api/me":      {status: 200, body: `{}`},
		"https://open.example.com/api/v1/me":   {status: 200, body: `{}`},
		"https://open.example.com/api/v1/user": {status: 200, body: `{}`},
		"https://silent.example.com/":          {fail: true},
	}}

	got := run(t, f,
		subject("gated", tunnelled("gated.example.com")),
		subject("open", tunnelled("open.example.com")),
		subject("silent", tunnelled("silent.example.com")),
	)

	if got.Report.Phase != payload.PhasePartial {
		t.Fatalf("want partial, got %q", got.Report.Phase)
	}
	if !got.Report.OK {
		t.Fatal("partial is still ok — everything that answered was read (I4)")
	}
	if got.Gated != 1 || got.Open != 1 || got.Silent != 1 {
		t.Fatalf("one of each; got gated %d open %d silent %d", got.Gated, got.Open, got.Silent)
	}
	if got.ExtraRequests != 4 {
		t.Fatalf("the open service's four second questions are counted; got %d", got.ExtraRequests)
	}

	want := "3 services probed — 1 gated, 1 open, 1 did not answer — 4 extra requests at current-user addresses"
	if got.Report.Detail != want {
		t.Fatalf("the summary sentence is §13.6's\n got %q\nwant %q", got.Report.Detail, want)
	}
}

func TestARunThatAskedNoSecondQuestionsDoesNotSayZero(t *testing.T) {
	// "0 extra requests" reads as a bound having been hit rather than as a shape that never came up.
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/": {status: 401, header: map[string]string{"WWW-Authenticate": `Basic realm="app"`}},
	}}

	got := run(t, f, subject("app", tunnelled("app.example.com")))

	if strings.Contains(got.Report.Detail, "extra request") {
		t.Fatalf("no second question was asked, so the segment is absent; got %q", got.Report.Detail)
	}
	if got.Report.Detail != "1 service probed — 1 gated, 0 open, 0 did not answer" {
		t.Fatalf("got %q", got.Report.Detail)
	}
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

func TestAnHTTPAnswerOfAnyStatusIsAConnectedProbe(t *testing.T) {
	// conn.FromStatus would read a 401 as `authenticate` and a 404 as `not-found` — the right readings
	// for an API being consumed and the wrong ones for an address being asked a question.
	for _, status := range []int{200, 302, 401, 403, 404, 500} {
		f := &fleet{replies: map[string]reply{
			"https://app.example.com/":            {status: status, body: `<p>hi</p>`},
			"https://app.example.com/api/":        {status: 404},
			"https://app.example.com/api/me":      {status: 404},
			"https://app.example.com/api/v1/me":   {status: 404},
			"https://app.example.com/api/v1/user": {status: 404},
		}}

		got := run(t, f, subject("app", tunnelled("app.example.com"))).Results["app"]
		if got.Phase != payload.PhaseConnected {
			t.Fatalf("a %d answer is a connected probe; got %q", status, got.Phase)
		}
		if got.Status == nil || *got.Status != status {
			t.Fatalf("and the status is recorded; got %v", got.Status)
		}
	}
}

func TestAServiceThatAnsweredNowhereIsNoAnswerWithItsAttempts(t *testing.T) {
	f := &fleet{replies: map[string]reply{}}
	s := payload.Service{
		Cloudflare: []payload.CloudflareRoute{tunnel("app.example.com", "http://app:8080")},
		Traefik:    []payload.TraefikRoute{router("app", "app.lan", false)},
	}

	read := run(t, f, subject("app", s))
	got := read.Results["app"]

	if VerdictOf(got) != VerdictNoAnswer {
		t.Fatalf("want no-answer, got %q", VerdictOf(got))
	}
	if len(got.Attempts) != 2 {
		t.Fatalf("both addresses are recorded as attempts; got %+v", got.Attempts)
	}
	if read.Silent != 1 || read.Gated != 0 || read.Open != 0 {
		t.Fatal("and it is counted in neither statistic, claiming no measurement")
	}
	if !strings.HasPrefix(got.Detail, "No answer from ") {
		t.Fatalf("the sentence says so; got %q", got.Detail)
	}
}

func TestTheWalkStopsAtTheFirstAddressThatAnswers(t *testing.T) {
	// Answering means an HTTP response arrived whatever its status. Only a transport failure falls
	// through.
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/": {status: 404},
		"http://app.lan/":          {status: 200, body: `<p>hi</p>`},
	}}
	s := payload.Service{
		Cloudflare: []payload.CloudflareRoute{tunnel("app.example.com", "http://app:8080")},
		Traefik:    []payload.TraefikRoute{router("app", "app.lan", false)},
	}

	got := run(t, f, subject("app", s)).Results["app"]

	if got.Vantage != payload.VantagePublic {
		t.Fatalf("the 404 answered, so the walk stopped there; got vantage %q", got.Vantage)
	}
	if requested := f.requested(); len(requested) != 1 || requested[0] != "https://app.example.com/" {
		t.Fatalf("and the router address was never asked; got %v", requested)
	}
}

func TestATransportFailureFallsThroughToTheNextVantage(t *testing.T) {
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/": {fail: true},
		"http://app.lan/":          {status: 302, header: map[string]string{"Location": "/login"}},
	}}
	s := payload.Service{
		Cloudflare: []payload.CloudflareRoute{tunnel("app.example.com", "http://app:8080")},
		Traefik:    []payload.TraefikRoute{router("app", "app.lan", false)},
	}

	got := run(t, f, subject("app", s)).Results["app"]

	if got.Vantage != payload.VantageTraefik {
		t.Fatalf("the second address answered; got vantage %q", got.Vantage)
	}
	if got.Gate != payload.GateRedirectLogin {
		t.Fatalf("and it was read; got gate %q", got.Gate)
	}
	if len(got.Attempts) != 1 {
		t.Fatalf("the failure it walked past is kept as an attempt; got %+v", got.Attempts)
	}
}

func TestAtMostFourAddressesPerServiceAreEverAsked(t *testing.T) {
	// §13.6's containment bound, at the layer that spends the requests.
	f := &fleet{replies: map[string]reply{}}
	s := payload.Service{Cloudflare: []payload.CloudflareRoute{
		tunnel("a.example.com", "http://app:80"),
		tunnel("b.example.com", "http://app:80"),
		tunnel("c.example.com", "http://app:80"),
		tunnel("d.example.com", "http://app:80"),
		tunnel("e.example.com", "http://app:80"),
		tunnel("f.example.com", "http://app:80"),
	}}

	run(t, f, subject("app", s))

	if got := len(f.requested()); got != AddressCap {
		t.Fatalf("want at most %d requests for one service, got %d: %v", AddressCap, got, f.requested())
	}
}

func TestTheSecondQuestionGoesToTheOriginThatAnsweredAndStaysOutOfTheAttempts(t *testing.T) {
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/":     {status: 200, body: `<div id="root"></div>`},
		"https://app.example.com/api/": {status: 401, header: map[string]string{"WWW-Authenticate": "Bearer"}},
	}}

	read := run(t, f, subject("app", tunnelled("app.example.com")))
	got := read.Results["app"]

	if got.Gate != payload.GateStateChallenge {
		t.Fatalf("want state-challenge, got %q", got.Gate)
	}
	if got.State == nil || got.State.Asked != 1 {
		t.Fatalf("one address was asked; got %+v", got.State)
	}
	if len(got.Attempts) != 0 {
		t.Fatalf("§13.4's addresses stay out of the attempt list; got %+v", got.Attempts)
	}
	if read.ExtraRequests != 1 {
		t.Fatalf("they are counted separately instead; got %d", read.ExtraRequests)
	}
}

func TestTheSecondQuestionIsOnlyAskedWhenTheShortfallCallsForIt(t *testing.T) {
	cases := []struct {
		name string
		page reply
		want bool
	}{
		{"a page with no form", reply{status: 200, body: `<div id="root"></div>`}, true},
		{"a page with a form", reply{status: 200, body: `<form action="/x"><input name="q"></form>`}, false},
		{"a page with a gate", reply{status: 200, body: `<form><input type="password"></form>`}, false},
		{"a redirect", reply{status: 302, header: map[string]string{"Location": "/dashboard"}}, false},
		{"a 401", reply{status: 401}, false},
		{"a JSON 200", reply{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: `{}`}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fleet{replies: map[string]reply{
				"https://app.example.com/":            c.page,
				"https://app.example.com/api/":        {status: 200, body: `{}`},
				"https://app.example.com/api/me":      {status: 200, body: `{}`},
				"https://app.example.com/api/v1/me":   {status: 200, body: `{}`},
				"https://app.example.com/api/v1/user": {status: 200, body: `{}`},
			}}

			read := run(t, f, subject("app", tunnelled("app.example.com")))
			asked := read.ExtraRequests > 0
			if asked != c.want {
				t.Fatalf("%s: second question asked = %v, want %v (requests %v)",
					c.name, asked, c.want, f.requested())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

func TestNoRequestEverCarriesACredential(t *testing.T) {
	// The signature of Anonymous is the guarantee; this is the observation of it. A cookie, an
	// Authorization header or a bearer token in a query string would each make the probe a mechanism
	// (I3).
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/":     {status: 200, body: `<div id="root"></div>`},
		"https://app.example.com/api/": {status: 401, header: map[string]string{"WWW-Authenticate": "Bearer"}},
	}}

	run(t, f, subject("app", tunnelled("app.example.com")))

	for _, req := range f.sent {
		if req.Method != http.MethodGet {
			t.Fatalf("GET only; got %s", req.Method)
		}
		for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key"} {
			if req.Header.Get(name) != "" {
				t.Fatalf("%s carried %s", req.URL, name)
			}
		}
		if len(req.Cookies()) != 0 {
			t.Fatalf("%s carried a cookie", req.URL)
		}
		if req.URL.RawQuery != "" {
			t.Fatalf("no query string (§13.6); got %q", req.URL.RawQuery)
		}
		if req.Body != nil && req.Body != http.NoBody {
			t.Fatalf("%s carried a body", req.URL)
		}
	}
}

func TestARedirectIsNeverFollowedBecauseWhereItPointsIsTheEvidence(t *testing.T) {
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/": {status: 302,
			header: map[string]string{"Location": "https://auth.example.com/outpost/start"}},
		"https://auth.example.com/outpost/start": {status: 200, body: `<form><input type="password"></form>`},
	}}

	got := run(t, f, subject("app", tunnelled("app.example.com"))).Results["app"]

	if got.Gate != payload.GateRedirectOrigin {
		t.Fatalf("the redirect itself is the gate; got %q", got.Gate)
	}
	for _, address := range f.requested() {
		if strings.HasPrefix(address, "https://auth.example.com") {
			t.Fatalf("the redirect was followed to %s", address)
		}
	}
}

func TestABodyIsKeptOnlyWhenTheContentTypeNamesAPage(t *testing.T) {
	// A JSON document that happens to contain the word `password` is not a login form, and a 60 KiB
	// bundle is not a page. §13.6 puts the condition here, once, before any rule sees a body.
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/": {status: 200,
			header: map[string]string{"Content-Type": "application/json"},
			body:   `{"login":{"password":"required"},"form":"<input type=\"password\">"}`},
	}}

	got := run(t, f, subject("app", tunnelled("app.example.com"))).Results["app"]

	if got.Gate != "" {
		t.Fatalf("no body was read as a page, so no signal fired; got %q", got.Gate)
	}
	if got.Form != nil || got.Anon != nil {
		t.Fatalf("and nothing was read out of it; got form %+v anon %+v", got.Form, got.Anon)
	}
	if !strings.Contains(got.Detail, "application/json") {
		t.Fatalf("the sentence names the type; got %q", got.Detail)
	}
}

func TestATruncatedPageIsStillReadAndSaysItWasCut(t *testing.T) {
	// A truncated HTML page carries its login form in the first 64 KiB or the page is not a login page.
	// The fact that it was cut is reported rather than assumed away.
	padding := strings.Repeat("<p>filler filler filler</p>", 4000) // comfortably past the cap
	f := &fleet{replies: map[string]reply{
		"https://app.example.com/": {status: 200, body: `<html><body>` + padding},
	}}

	got := run(t, f, subject("app", tunnelled("app.example.com"))).Results["app"]

	if got.Truncated == nil || !*got.Truncated {
		t.Fatal("the body reached the read cap and the record says so")
	}
	if got.Anon == nil || got.Anon.TextChars == 0 {
		t.Fatalf("and what did arrive was still read; got %+v", got.Anon)
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

func TestTheTallyIsWalkedInSubjectOrderAndNotInCompletionOrder(t *testing.T) {
	// I7. The same fleet gives the same numbers and the same report however the goroutines interleave.
	f := &fleet{replies: map[string]reply{
		"https://one.example.com/":   {status: 401, header: map[string]string{"WWW-Authenticate": "Basic"}},
		"https://two.example.com/":   {status: 200, body: `<form action="/x"><input name="q"></form>`},
		"https://three.example.com/": {fail: true},
	}}
	subjects := []Subject{
		subject("one", tunnelled("one.example.com")),
		subject("two", tunnelled("two.example.com")),
		subject("three", tunnelled("three.example.com")),
	}

	first := run(t, f, subjects...)
	for i := 0; i < 12; i++ {
		again := run(t, &fleet{replies: f.replies}, subjects...)
		if again.Report.Detail != first.Report.Detail {
			t.Fatalf("the same fleet gave\n%q\nthen\n%q", first.Report.Detail, again.Report.Detail)
		}
		for _, key := range first.Keys() {
			if again.Results[key].Detail != first.Results[key].Detail {
				t.Fatalf("%s gave\n%q\nthen\n%q", key, first.Results[key].Detail, again.Results[key].Detail)
			}
		}
	}
}

func TestKeysAreSorted(t *testing.T) {
	f := &fleet{replies: map[string]reply{
		"https://b.example.com/": {status: 404},
		"https://a.example.com/": {status: 404},
		"https://c.example.com/": {status: 404},
	}}

	got := run(t, f,
		subject("charlie", tunnelled("c.example.com")),
		subject("alpha", tunnelled("a.example.com")),
		subject("bravo", tunnelled("b.example.com")),
	).Keys()

	if !equal(got, []string{"alpha", "bravo", "charlie"}) {
		t.Fatalf("want sorted keys, got %v", got)
	}
}

func TestAServiceWithNoAddressGetsNoResultEntryAtAll(t *testing.T) {
	// The counts carry those facts instead; a record with nothing in it would read as a measurement.
	f := &fleet{replies: map[string]reply{}}
	database := payload.Service{Ports: []payload.PortMapping{port("5432:5432", "5432")}}
	withheld := tunnelled("app.example.com")
	withheld.Auth.Method = payload.AuthAuthentikForwardAuth

	got := run(t, f, subject("db", database), subject("app", withheld))

	if len(got.Results) != 0 {
		t.Fatalf("neither is a result; got %v", got.Keys())
	}
	if got.Skipped != 1 {
		t.Fatalf("only the withheld candidate is skipped; got %d", got.Skipped)
	}
}

func TestTheClientIsBuiltFromTheConfigWhenNoneWasGiven(t *testing.T) {
	// Not a network test: the point is that Do never dereferences a nil client, so a caller that passes
	// only configuration gets a run rather than a panic (I4).
	got := Do(context.Background(), Options{
		Enabled: true,
		Source:  payload.ProbeSourceConfig,
		Cfg:     config.ProbeConfig{TimeoutMs: 1, MaxConcurrency: 1},
	})

	if got.Report.Phase != payload.PhaseNotFound {
		t.Fatalf("no subjects means nothing to ask; got %q", got.Report.Phase)
	}
}
