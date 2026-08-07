package probe

import "testing"

const base = "https://app.example.com/"

func TestWhereSomethingPointsIsAnsweredOnce(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		to    string
		cross bool
		ok    bool
	}{
		{"a relative path", "/login", "/login", false, true},
		{"a bare name", "dashboard", "/dashboard", false, true},
		{"an absolute same-origin address", "https://app.example.com/login", "/login", false, true},
		{"another host", "https://sso.example.com/if/flow/x/", "https://sso.example.com/if/flow/x/", true, true},
		{"another scheme on the same host", "http://app.example.com/", "http://app.example.com/", true, true},
		{"a protocol-relative address", "//sso.example.com/login", "https://sso.example.com/login", true, true},
		{"a bare root", "/", "/", false, true},
		{"nothing", "", "", false, false},
		{"only a fragment", "#main", "/", false, true},
		{"a scheme with no host", "mailto:ops@example.com", "", false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Point(base, c.raw)
			if ok != c.ok {
				t.Fatalf("Point(%q) resolved = %v, want %v", c.raw, ok, c.ok)
			}
			if !ok {
				return
			}
			if got.To != c.to || got.CrossOrigin != c.cross {
				t.Fatalf("Point(%q) = %+v, want to %q crossOrigin %v", c.raw, got, c.to, c.cross)
			}
		})
	}
}

func TestARecordedTargetCarriesNoQueryNoFragmentAndNoCredential(t *testing.T) {
	// A redirect to an SSO endpoint carries the whole return URL and often a state token in its query.
	// None of that may reach a payload (I6).
	got, ok := Point(base, "https://user:secret@sso.example.com/if/flow/x/?next=https%3A%2F%2Fapp&state=abc123#top")
	if !ok {
		t.Fatal("the target must resolve")
	}
	if got.To != "https://sso.example.com/if/flow/x/" {
		t.Fatalf("query, fragment and userinfo are all dropped; got %q", got.To)
	}
}

func TestASameOriginTargetKeepsOnlyItsPath(t *testing.T) {
	// Repeating a host the reader already knows would put an address in the payload for nothing.
	got, _ := Point(base, "https://app.example.com/users/sign_in")
	if got.To != "/users/sign_in" {
		t.Fatalf("a same-origin target records the path alone; got %q", got.To)
	}
}

func TestATargetThatWillNotResolveIsNoTargetRatherThanTheBase(t *testing.T) {
	// Reported as the base would read as a same-origin hop that never happened, and a same-origin hop
	// to `/` is one prefix match away from being read as a login redirect.
	if _, ok := Point(base, "   "); ok {
		t.Fatal("whitespace is not a target")
	}
	if _, ok := Point("://nonsense", "/login"); ok {
		t.Fatal("an unparseable base yields no target")
	}
}

func TestTheTenLoginPathsAndTheThreeSpellingsThatCarryWeight(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		{"/login", true, ""},
		{"/Login", true, "a redirect's path is written by whatever generated it"},
		{"/login?next=/", true, "prefix match"},
		{"/signin", true, ""},
		{"/sign-in", true, ""},
		{"/users/sign_in", true, "Devise's own path, spelled the way Devise spells it"},
		{"/sso/saml", true, ""},
		{"/oauth2/start", true, ""},
		{"/auth/realms/x", true, ""},
		{"/outpost.goauthentik.io/start", true, ""},
		{"/if/flow/default-authentication-flow/", true, ""},
		{"/flows/-/default/", true, "Authentik's placeholder for no application context"},

		{"/authors", false, "`/auth/` keeps its trailing slash, or a blog's author index is a login page"},
		{"/authorize", false, "same reason"},
		{"/flows", false, "`/flows/-/` keeps the dash, or a workflow tool's own routes are a login page"},
		{"/flows/build-images/", false, "same reason"},
		{"/dashboard", false, ""},
		{"/", false, ""},
		{"", false, ""},
	}

	for _, c := range cases {
		if got := LoginPath(c.path); got != c.want {
			t.Fatalf("LoginPath(%q) = %v, want %v — %s", c.path, got, c.want, c.why)
		}
	}
}

func TestAWayOutIsToldFromAWayIn(t *testing.T) {
	// Login paths match by prefix, so every one of these is a login path *by name*. A page carrying one
	// is a page somebody is already signed in to (§13.5).
	for _, path := range []string{"/auth/logout", "/oauth2/sign_out", "/sso/logout", "/LOGOUT", "/users/log-out"} {
		if !LogoutPath(path) {
			t.Fatalf("LogoutPath(%q) must be true, or §13.5 reads a signed-in page as offering a way in", path)
		}
	}
	for _, path := range []string{"/login", "/blogs", "/signin"} {
		if LogoutPath(path) {
			t.Fatalf("LogoutPath(%q) must be false", path)
		}
	}
}

func TestAMediaTypeDropsItsParameters(t *testing.T) {
	cases := []struct{ header, want string }{
		{"text/html; charset=utf-8", "text/html"},
		{"TEXT/HTML", "text/html"},
		{" application/json ", "application/json"},
		{"multipart/form-data; boundary=--x9f2a", "multipart/form-data"},
		{"", ""},
	}
	for _, c := range cases {
		if got := MediaType(c.header); got != c.want {
			t.Fatalf("MediaType(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestWhatCountsAsAPage(t *testing.T) {
	for _, ok := range []string{"text/html", "application/xhtml+xml", "image/svg+html"} {
		if !HTML(ok) {
			t.Fatalf("HTML(%q) must be true", ok)
		}
	}
	for _, notOK := range []string{"application/json", "text/plain", "", "text/htmlish"} {
		if HTML(notOK) {
			t.Fatalf("HTML(%q) must be false", notOK)
		}
	}
}
