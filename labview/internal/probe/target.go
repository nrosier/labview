package probe

import (
	"net/url"
	"strings"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// Where does this point
// ---------------------------------------------------------------------------

// Point is the one answer to "where does this point" (§13.6).
//
// The redirect signal, the meta refresh and the form action all resolve through it, because three
// resolutions would be three answers to the same question and the difference between them is the
// difference between `redirect-origin` and `redirect-login`.
//
// What it records is reduced (I6). The query and the fragment go — a redirect to an SSO endpoint
// carries the whole return URL, and often a state token, in the query — and the origin is kept
// **only** when the target left the origin: a path is what a reader needs for a same-origin hop, and
// repeating the host they already know would put an address in the payload for nothing.
//
// A target that will not resolve is not a target. It is reported as no redirect at all rather than
// as one pointing at the base, which would read as a same-origin hop that never happened.
func Point(base, raw string) (payload.ProbeRedirect, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return payload.ProbeRedirect{}, false
	}

	from, err := url.Parse(base)
	if err != nil {
		return payload.ProbeRedirect{}, false
	}
	to, err := from.Parse(raw)
	if err != nil || to.Host == "" {
		return payload.ProbeRedirect{}, false
	}

	to.RawQuery, to.ForceQuery, to.Fragment, to.RawFragment = "", false, "", ""
	to.User = nil

	cross := !transport.SameOrigin(base, to.String())
	out := payload.ProbeRedirect{CrossOrigin: cross}
	if cross {
		out.To = to.String()
	} else {
		out.To = pathOnly(to)
	}
	return out, true
}

// Path is the path a resolved target landed on, which is what the login-path list is consulted
// with. It is derived from the recorded target rather than kept beside it, so the path a gate rested
// on and the path a reader is shown are one string.
func Path(r payload.ProbeRedirect) string {
	if !r.CrossOrigin {
		return r.To
	}
	u, err := url.Parse(r.To)
	if err != nil {
		return ""
	}
	return pathOnly(u)
}

func pathOnly(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// ---------------------------------------------------------------------------
// The login-path list
// ---------------------------------------------------------------------------

// LoginPaths is the one rule in §13 that decides on a *name*, so it is written once, in order, with
// the three load-bearing spellings intact:
//
//   - `/auth/` keeps its trailing slash. Bare `/auth` matches `/authors`, and a blog's author index
//     is not a login page.
//   - `/flows/-/` keeps the `-`, which is Authentik's own placeholder for no application context. A
//     bare `/flows` would read a workflow tool's own routes as a login page.
//   - `/users/sign_in` is Devise's path, spelled the way Devise spells it.
//
// Only `redirect-login` and `meta-refresh-login` consult this, and both only ever *add* a gate to a
// target that stayed on the origin — so a hand-rolled login path this list does not know costs a
// gate and can never invent one.
var LoginPaths = []string{
	"/login",
	"/signin",
	"/sign-in",
	"/users/sign_in",
	"/sso",
	"/oauth2",
	"/auth/",
	"/outpost.goauthentik.io",
	"/if/flow/",
	"/flows/-/",
}

// LoginPath is whether a path prefix-matches one of the ten. The comparison is case-insensitive
// because a redirect's path is written by whatever generated it and `/Login` is the same route.
func LoginPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	for _, prefix := range LoginPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// logoutMarkers are the spellings of signing *out*.
//
// §13.5 requires a logout link skipped **before** its path is read, and this is why: login-path
// matching is by prefix, so `/auth/logout`, `/oauth2/sign_out` and `/sso/logout` are all login paths
// by name. A page carrying one is a page somebody is already signed in to — the opposite reading.
var logoutMarkers = []string{"logout", "log-out", "log_out", "signout", "sign-out", "sign_out"}

// LogoutPath is whether a path is a way out rather than a way in.
func LogoutPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, marker := range logoutMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The media type
// ---------------------------------------------------------------------------

// MediaType is the content type with its parameters dropped (§13.6, I6).
//
// A charset says nothing a reader of this record needs, and a `boundary=` carries a generated token.
// Lower-cased, because the header's case is the server's choice and this value is compared.
func MediaType(header string) string {
	if semi := strings.IndexByte(header, ';'); semi >= 0 {
		header = header[:semi]
	}
	return strings.ToLower(strings.TrimSpace(header))
}

// HTML is whether a media type is a page. The `+html` arm catches `application/xhtml+xml`, which is
// what a strict XHTML application still serves and which carries the same forms.
func HTML(mediaType string) bool {
	return mediaType == "text/html" || strings.HasSuffix(mediaType, "+html") ||
		mediaType == "application/xhtml+xml"
}
