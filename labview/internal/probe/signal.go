package probe

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// The pure input
// ---------------------------------------------------------------------------

// Answer is one response, reduced to everything the rules read and nothing else.
//
// It exists so that §13's rules can be exercised without a socket: `Do` produces one of these from a
// transport result, and every signal below is a function of it. A test that had to stand up a server
// to find out whether a bare 401 is a gate would be a test nobody writes.
//
// The body is present only when the fetch kept one, which it does only for an HTML 200 — so its
// presence is itself the evidence that a page answered (§13.3).
type Answer struct {
	// URL is the address that answered, credential-free. Every relative target on the page resolves
	// against it, which is why it is here rather than derived.
	URL string

	Status int
	Header http.Header

	Body      []byte
	Truncated bool
}

func (a Answer) header(name string) string {
	if a.Header == nil {
		return ""
	}
	return a.Header.Get(name)
}

// page is whether this answer carried a page the body rules may read.
//
// A 200 specifically, and not any 2xx. A 201, 204 or 206 at a service's root is not a page an
// application serves, and reading one as a page could only ever conclude a gate from a response that
// is not a document — the one direction §13.3 forbids.
func (a Answer) page() bool {
	return a.Status == http.StatusOK && HTML(MediaType(a.header("Content-Type")))
}

// ---------------------------------------------------------------------------
// The pure output
// ---------------------------------------------------------------------------

// Reading is what one answer means: at most one gate, plus the facts a sentence has to name.
//
// Every field except Gate is a *fact*, not a conclusion. §13.6 requires them to travel beside the
// verdict, because "no gate observed" is only actionable next to what was observed instead — a 200
// that was not a page, a 3xx that stayed put, a meta refresh that was not a gate, a form below the
// body cap.
type Reading struct {
	// Gate is the signal that fired, empty when none did. At most one: the signals are in
	// precedence order and the strongest wins, so a page with both a password field and a SAML
	// input yields one answer and yields it twice (I7).
	Gate payload.ProbeGate

	MediaType string
	Redirect  *payload.ProbeRedirect
	Refresh   *payload.ProbeRedirect
	Form      *payload.LoginFormShape
	Truncated *bool
	Anon      *payload.ProbeAnon

	// NeedsState is §13.4's entry condition, evaluated here so that the code which issues the
	// second request holds no rule of its own: no gate read, 200, HTML, and no form anywhere in the
	// body.
	NeedsState bool
}

// ---------------------------------------------------------------------------
// The seven signals
// ---------------------------------------------------------------------------

// Signals is §13.3: seven signals from one response, strongest first.
//
// **Nothing else read off that one response is a gate.** Not a bare 401 with no challenge header,
// not a 403, not a same-origin redirect to `/dashboard`, not a meta refresh with no `url=`, not a
// homepage carrying the words "Sign in" and no form. All of those read as *answered, no gate
// observed*, which leaves the exposure finding standing.
//
// The asymmetry is the whole point: this rule can only ever take a service **out** of the exposed
// count, so an omission here is a service reported as exposed that was in fact protected — visible,
// arguable and safe — rather than a service reported as protected that anyone can reach.
func Signals(a Answer) Reading {
	out := Reading{MediaType: MediaType(a.header("Content-Type"))}

	// A 3xx's target, recorded whether or not it gates. Where it points *is* the evidence, which is
	// also why no redirect is ever followed (§13.6).
	var redirect payload.ProbeRedirect
	var redirected bool
	if a.Status >= 300 && a.Status < 400 {
		if target, ok := Point(a.URL, a.header("Location")); ok {
			redirect, redirected = target, true
			out.Redirect = &target
		}
	}

	// The body, read only on an HTML 200 and only then.
	var body, reduced string
	if a.page() && len(a.Body) > 0 {
		body = string(a.Body)
		reduced = drawn(body)
		truncated := a.Truncated
		out.Truncated = &truncated
		out.Form = strongestForm(a.URL, forms(reduced))
	}

	// A meta refresh's target, recorded whether or not it gates.
	var refresh payload.ProbeRedirect
	var refreshed bool
	if reduced != "" {
		if target, ok := metaRefresh(a.URL, reduced); ok {
			refresh, refreshed = target, true
			out.Refresh = &target
		}
	}

	switch {
	// 1. The server asked for a credential, in the words HTTP has for asking. A bare 401 is not
	// this: an anonymous-enabled Grafana answers one while serving everybody.
	case (a.Status == http.StatusUnauthorized || a.Status == http.StatusProxyAuthRequired) &&
		a.header("WWW-Authenticate") != "":
		out.Gate = payload.GateChallenge

	// 2. A redirect that left the origin. Somewhere else is answering for this address, and on a
	// homelab that somewhere is an identity provider.
	case redirected && redirect.CrossOrigin:
		out.Gate = payload.GateRedirectOrigin

	// 3. A redirect that stayed on the origin and landed on a login path.
	case redirected && LoginPath(Path(redirect)):
		out.Gate = payload.GateRedirectLogin

	// 4. The same rule one layer up: a page whose only content is an instruction to go to the login
	// path, or off the origin entirely.
	case refreshed && (refresh.CrossOrigin || LoginPath(Path(refresh))):
		out.Gate = payload.GateMetaRefreshLogin

	// 5. A SAML request in a hidden field is a federation hand-off in progress, and nothing else
	// produces one.
	case body != "" && reSAMLField.MatchString(reduced):
		out.Gate = payload.GateSSOForm

	// 6. A password input anywhere on the page. Page-wide on purpose: a login form in a drawer, a
	// modal or a sidebar is still a login form.
	case body != "" && rePasswordInput.MatchString(reduced):
		out.Gate = payload.GatePasswordForm

	// 7. Sign-in with no password field at all — a magic link, a passkey, an emailed code. All
	// three parts on one form, which is what keeps it from firing on a newsletter signup.
	case out.Form != nil && CredentialForm(*out.Form):
		out.Gate = payload.GateCredentialForm
	}

	// The anonymous view, read **after** the switch and deliberately so. §13.5 requires the record to
	// be structurally incapable of gating; assigning it below every case is that requirement in the
	// only form a compiler can be held to — no case above can read a variable that does not exist yet.
	if reduced != "" {
		out.Anon = anonymousView(a.URL, reduced)
	}

	// §13.4's condition, exactly as written: no gate read, status 200, HTML, no form.
	out.NeedsState = out.Gate == "" && a.page() && out.Form == nil
	return out
}

// ---------------------------------------------------------------------------
// The meta refresh
// ---------------------------------------------------------------------------

// reRefreshURL is the `url=` inside a refresh directive's content. A refresh with no `url=` is a
// timed reload of the same page and is **not** a gate, which is why the target is required rather
// than defaulted to the current address (§13.3).
var reRefreshURL = regexp.MustCompile(`(?i)\burl\s*=\s*['"]?([^'";\s]+)`)

// metaRefresh is where a page's own meta refresh points, resolved through the one Point rule.
//
// The first refresh wins. A page with two is a page whose author disagreed with themselves, and the
// browser follows the first (I7).
func metaRefresh(base, reduced string) (payload.ProbeRedirect, bool) {
	for _, tag := range reMetaTag.FindAllString(reduced, -1) {
		if !strings.EqualFold(attr(tag, "http-equiv"), "refresh") {
			continue
		}
		m := reRefreshURL.FindStringSubmatch(attr(tag, "content"))
		if m == nil {
			continue
		}
		if target, ok := Point(base, m[1]); ok {
			return target, true
		}
	}
	return payload.ProbeRedirect{}, false
}
