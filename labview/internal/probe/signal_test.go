package probe

import (
	"net/http"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// html builds an Answer carrying a page. Every body-reading signal needs a 200 and an HTML content
// type, which is the only condition under which a body is kept at all (§13.3).
func html(body string) Answer {
	return Answer{
		URL:    base,
		Status: 200,
		Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:   []byte(body),
	}
}

func answer(status int, header map[string]string) Answer {
	h := http.Header{}
	for name, value := range header {
		h.Set(name, value)
	}
	return Answer{URL: base, Status: status, Header: h}
}

func TestTheEightSignalsFireOnWhatSection13SaysTheyFireOn(t *testing.T) {
	cases := []struct {
		name string
		in   Answer
		want payload.ProbeGate
	}{
		{
			"a 401 with a challenge header",
			answer(401, map[string]string{"WWW-Authenticate": `Basic realm="ops"`}),
			payload.GateChallenge,
		},
		{
			"a 407 with a challenge header",
			answer(407, map[string]string{"Proxy-Authenticate": "Basic", "WWW-Authenticate": "Basic"}),
			payload.GateChallenge,
		},
		{
			"a 302 off the origin",
			answer(302, map[string]string{"Location": "https://sso.example.com/if/flow/x/"}),
			payload.GateRedirectOrigin,
		},
		{
			"a 302 that stayed put and landed on a login path",
			answer(302, map[string]string{"Location": "/users/sign_in?next=/"}),
			payload.GateRedirectLogin,
		},
		{
			"a meta refresh onto a login path",
			html(`<meta http-equiv="refresh" content="0; url=/login">`),
			payload.GateMetaRefreshLogin,
		},
		{
			"a meta refresh off the origin",
			html(`<meta http-equiv="REFRESH" content="0;URL='https://sso.example.com/'">`),
			payload.GateMetaRefreshLogin,
		},
		{
			"a hidden SAML request",
			html(`<form method="post"><input type="hidden" name="SAMLRequest" value="PHNhbWw"></form>`),
			payload.GateSSOForm,
		},
		{
			"a password input",
			html(`<form><input name="user"><input type="password" name="pass"><button>Go</button></form>`),
			payload.GatePasswordForm,
		},
		{
			"an autocomplete current-password input",
			html(`<form><input name="user" autocomplete="username"><input autocomplete="current-password"></form>`),
			payload.GatePasswordForm,
		},
		{
			"a magic-link form posting to a login path",
			html(`<form action="/login"><input type="email" name="email"><button>Email me a link</button></form>`),
			payload.GateCredentialForm,
		},
		{
			"a one-time-code form",
			html(`<form action="/verify"><input name="username"><input autocomplete="one-time-code"><input type="submit"></form>`),
			payload.GateCredentialForm,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Signals(c.in).Gate; got != c.want {
				t.Fatalf("%s must read as %q, got %q", c.name, c.want, got)
			}
		})
	}
}

func TestTheThingsThatMustNotBeReadAsAGate(t *testing.T) {
	// Every one of these would buy false comfort: a service reported as protected that anyone can
	// reach. §13.3 names them, and the asymmetry it demands is that they all read as *answered, no gate
	// observed*.
	cases := []struct {
		name string
		in   Answer
		why  string
	}{
		{
			"a bare 401 with no challenge header",
			answer(401, nil),
			"an anonymous-enabled Grafana answers one while serving everybody",
		},
		{
			"a 403",
			answer(403, nil),
			"nginx 403s a directory with no index",
		},
		{
			"a same-origin redirect to /dashboard",
			answer(302, map[string]string{"Location": "/dashboard"}),
			"a landing page is not a login page",
		},
		{
			"a meta refresh with no url=",
			html(`<meta http-equiv="refresh" content="30">`),
			"a timed reload of the same page",
		},
		{
			"a meta refresh that stayed on the origin and off a login path",
			html(`<meta http-equiv="refresh" content="0; url=/home">`),
			"same rule as the redirect one layer up",
		},
		{
			"a homepage with the words Sign in and no form",
			html(`<h1>Welcome</h1><p>Please <b>Sign in</b> to continue.</p><a href="/x">x</a>`),
			"body-text matching is the first thing §13.3 forbids",
		},
		{
			"a title claiming to be a login page",
			html(`<title>Login — Acme</title><p>public content</p>`),
			"<title> matching is forbidden",
		},
		{
			"a link to a product whose name implies a gate",
			html(`<p>hi</p><a href="https://goauthentik.io">Powered by authentik</a>`),
			"a product-name marker matched by a link is explicitly excluded",
		},
		{
			"a Set-Cookie on a 200",
			Answer{URL: base, Status: 200, Header: http.Header{
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"session=abc; Path=/"},
			}, Body: []byte(`<p>hello</p>`)},
			"a session cookie on a 200 is how every application tracks anonymous visitors",
		},
		{
			"a cross-origin form action with no SAML field",
			html(`<form action="https://hosted.example.net/subscribe"><input type="email" name="email"><button>Subscribe</button></form>`),
			"a hosted newsletter signup has the identical shape and the opposite meaning",
		},
		{
			"a 401 that serves a login form",
			Answer{URL: base, Status: 401, Header: http.Header{"Content-Type": []string{"text/html"}},
				Body: []byte(`<form><input type="password"></form>`)},
			"the body is read as evidence on a 200 only",
		},
		{
			"a new-password field",
			html(`<form action="/register"><input name="user"><input type="text" autocomplete="new-password"></form>`),
			"a registration form's second field is not evidence that this page gates anything",
		},
		{
			"a 204 with an HTML content type",
			Answer{URL: base, Status: 204, Header: http.Header{"Content-Type": []string{"text/html"}},
				Body: []byte(`<form><input type="password"></form>`)},
			"a 200 specifically, and not any 2xx",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Signals(c.in).Gate; got != "" {
				t.Fatalf("%s must read as no gate — %s — but read as %q", c.name, c.why, got)
			}
		})
	}
}

func TestOnePageYieldsOneAnswerAndYieldsItTwice(t *testing.T) {
	// A page with both a SAML field and a password input has two signals in it. The precedence order
	// decides, and it decides the same way every time (I7).
	in := html(`<form action="/login"><input type="hidden" name="SAMLResponse" value="x">` +
		`<input name="user"><input type="password"><button>Go</button></form>`)

	first := Signals(in)
	if first.Gate != payload.GateSSOForm {
		t.Fatalf("sso-form outranks password-form; got %q", first.Gate)
	}
	if second := Signals(in); second.Gate != first.Gate {
		t.Fatalf("the same page read twice gave %q then %q", first.Gate, second.Gate)
	}
}

func TestARedirectIsRecordedWhetherOrNotItGates(t *testing.T) {
	// Where it points *is* the evidence, which is why no redirect is ever followed and why the target
	// travels beside a negative verdict too (§13.6).
	got := Signals(answer(302, map[string]string{"Location": "/dashboard"}))

	if got.Gate != "" {
		t.Fatalf("a same-origin hop to /dashboard is not a gate; got %q", got.Gate)
	}
	if got.Redirect == nil || got.Redirect.To != "/dashboard" {
		t.Fatalf("the target is recorded anyway; got %+v", got.Redirect)
	}
}

func TestAMetaRefreshIsRecordedWhetherOrNotItGates(t *testing.T) {
	got := Signals(html(`<meta http-equiv="refresh" content="0; url=/home">`))

	if got.Gate != "" {
		t.Fatalf("a same-origin refresh off a login path is not a gate; got %q", got.Gate)
	}
	if got.Refresh == nil || got.Refresh.To != "/home" {
		t.Fatalf("the refresh target is recorded anyway; got %+v", got.Refresh)
	}
}

func TestTheFirstMetaRefreshWins(t *testing.T) {
	// A page with two is a page whose author disagreed with themselves, and a browser follows the first
	// (I7).
	got := Signals(html(`<meta http-equiv="refresh" content="0; url=/home">` +
		`<meta http-equiv="refresh" content="0; url=/login">`))

	if got.Gate != "" || got.Refresh == nil || got.Refresh.To != "/home" {
		t.Fatalf("the first refresh decides; got gate %q refresh %+v", got.Gate, got.Refresh)
	}
}

func TestAFormIsAttachedEvenWhenNothingWasConcludedFromIt(t *testing.T) {
	// §13.3 requires the shape attached whenever a form was found. A reader told "no gate" needs to see
	// what was actually on the page.
	got := Signals(html(`<form action="/search"><input name="q"><button>Search</button></form>`))

	if got.Gate != "" {
		t.Fatalf("a site search box is not a login form; got %q", got.Gate)
	}
	if got.Form == nil {
		t.Fatal("the shape is attached whenever a form was found, including when nothing was concluded")
	}
	if got.Form.Username || !got.Form.Submit {
		t.Fatalf("`q` is deliberately absent from the username markers; got %+v", *got.Form)
	}
}

func TestTheSecondQuestionIsAskedForExactlyOneShape(t *testing.T) {
	cases := []struct {
		name string
		in   Answer
		want bool
	}{
		{"200, HTML, no form at all", html(`<div id="root"></div>`), true},
		{"200, HTML, a form", html(`<form><input name="q"></form>`), false},
		{"200, JSON", Answer{URL: base, Status: 200,
			Header: http.Header{"Content-Type": []string{"application/json"}}}, false},
		{"a gate was read", html(`<form><input type="password"></form>`), false},
		{"a 404", answer(404, nil), false},
		{"a 200 with no body at all", Answer{URL: base, Status: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}}}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Signals(c.in).NeedsState; got != c.want {
				t.Fatalf("§13.4's condition is no gate, 200, HTML and no form: %s gave %v, want %v",
					c.name, got, c.want)
			}
		})
	}
}

func TestTheGateRuleCannotBeAFunctionOfTheAnonymousReading(t *testing.T) {
	// §13.5 requires the record structurally incapable of gating. The strongest thing a test can check
	// is the consequence: a page whose *only* login evidence is an anonymous-view fact reads as no gate.
	got := Signals(html(`<div id="root"></div><a href="/login">Sign in</a>`))

	if got.Gate != "" {
		t.Fatalf("a sign-in link is an anonymous-view fact and not a gate; got %q", got.Gate)
	}
	if got.Anon == nil || got.Anon.LoginHref != "/login" {
		t.Fatalf("the reading is still recorded; got %+v", got.Anon)
	}
}

func TestTruncationIsReportedRatherThanAssumedAway(t *testing.T) {
	in := html(`<div id="root"></div>`)
	in.Truncated = true

	got := Signals(in)
	if got.Truncated == nil || !*got.Truncated {
		t.Fatalf("the body hit the cap and the record must say so; got %+v", got.Truncated)
	}

	clean := Signals(html(`<div id="root"></div>`))
	if clean.Truncated == nil || *clean.Truncated {
		t.Fatal("a body that fit says so too — nothing-known-about-the-body is the nil case")
	}
}

func TestNoBodyMeansNothingIsKnownAboutTheBody(t *testing.T) {
	got := Signals(answer(302, map[string]string{"Location": "/x"}))
	if got.Truncated != nil || got.Form != nil || got.Anon != nil {
		t.Fatalf("a 3xx keeps no body, so all three body facts stay absent; got %+v", got)
	}
}

func TestTheMediaTypeTravelsWithEveryReading(t *testing.T) {
	// A 200 that was not a page is one of the facts §13.6 keeps a field for.
	got := Signals(Answer{URL: base, Status: 200,
		Header: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}})

	if got.MediaType != "application/json" {
		t.Fatalf("the media type is recorded with its parameters dropped; got %q", got.MediaType)
	}
}
