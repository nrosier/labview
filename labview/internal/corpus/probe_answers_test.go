package corpus

// The probe's canned answers, held as code (§23).
//
// Not a payload document, and the reason is in what a probe reads: a status, three headers and a
// fragment of HTML. A JSON file holding HTML in a string field would be a format invented for this
// one purpose, and the markup — which is the subject of half the rules below — would arrive escaped
// and unreadable. The API fixtures are documents because an API response is a document; these are not.
//
// The table is keyed on the **whole URL** rather than on the host, because the scheme and the trailing
// slash are part of what is under test: §13.2 picks `https` for a TLS router and `http` for one
// without, and asks at `/` and nowhere else. A typo in either produces a miss here rather than a pass,
// which is the point — everything absent from this table is a name that does not resolve.

// ---------------------------------------------------------------------------
// The bodies
// ---------------------------------------------------------------------------

// A login form. The password input is the signal, and it is in the markup, as always.
const htmlLogin = `<!doctype html><html><head><title>Sign in</title></head><body>
<form method="post" action="/login"><input type="text" name="username">
<input type="password" name="password"><button type="submit">Sign in</button></form>
</body></html>`

// An application's own homepage — and the near miss for the body rule.
//
// It says "Sign in" twice and links to an account page, which is what a great many open dashboards
// look like. No password field, so it is not a gate, and a rule that matched on the words rather than
// on the input would clear this exposure on the strength of a link.
const htmlApp = `<!doctype html><html><head><title>Dashboard</title></head><body>
<h1>Dashboard</h1><nav><a href="/account">Sign in</a></nav><p>Sign in for more.</p>
</body></html>`

// A redirect written in markup instead of in a header — and its near miss.
//
// The two differ in one URL and nothing else, which is the whole rule: where the browser is being sent
// decides, exactly as it does for a `Location`. A `/dashboard` refresh is an application routing to
// its own landing page.
const htmlRefreshLogin = `<!doctype html><html><head><title>Docs</title>
<meta http-equiv="refresh" content="0; url=/login?next=%2F"></head>
<body><p>Redirecting…</p></body></html>`

const htmlRefreshRouting = `<!doctype html><html><head><title>Home</title>
<meta http-equiv="refresh" content="0; url=/dashboard"></head>
<body><p>Redirecting…</p></body></html>`

// The SAML POST binding, which defeats every other clause at once.
//
// No password field, no `Location`, and an `action` that leaves the origin — which the form rule
// refuses on purpose, since a hosted newsletter box has one too. The hidden `SAMLRequest` is all that
// is left, and it is a parameter name only the SAML binding emits.
const htmlSAML = `<!doctype html><html><head><title>Redirecting</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="https://idp.probe.example.com/sso/post">
<input type="hidden" name="SAMLRequest" value="PHNhbWxwOkF1dGhuUmVxdWVzdD4=">
<input type="hidden" name="RelayState" value="/erp/">
<noscript><input type="submit" value="Continue"></noscript></form></body></html>`

// A magic-link login — and, below it, a newsletter box, which is the same three tags.
//
// Both have an email field and a submit button, so what separates them is the one thing the composite
// requires beyond a shape: a marker of intent. This one posts to `/login` on its own origin.
const htmlPasswordless = `<!doctype html><html><head><title>Portal</title></head><body>
<h1>Sign in</h1><form method="post" action="/login">
<input type="email" name="email" autocomplete="username" required>
<button type="submit">Email me a link</button></form></body></html>`

// §23's second deliberate trap: the same three tags posting **cross-origin** to a newsletter service.
// A cross-origin action is not evidence of a login, and this fixture must come out `open` while
// `htmlPasswordless` next to it comes out gated.
const htmlSignup = `<!doctype html><html><head><title>News</title></head><body>
<h1>Latest posts</h1><p>Nothing here is behind anything.</p>
<form method="post" action="https://lists.example.net/subscribe/post">
<input type="email" name="EMAIL" placeholder="you@example.com">
<button type="submit">Subscribe</button></form></body></html>`

// A client-rendered shell — the page the eighth signal exists for.
//
// There is no `<form>` and there is nothing to read. Whether this application has a login screen is
// not in this markup at any body size, because the markup is a script tag and an empty div: the screen
// is drawn after it arrives. Two services in `fixtures/probe/spa-shell` serve exactly this and differ
// only in what their current-user address answers, which is the whole of §13.4's rule.
const htmlShell = `<!doctype html><html><head><title>app</title>
<script type="module" src="/assets/index-4f2c9a.js"></script></head>
<body><div id="root"></div></body></html>`

// A page that served a stranger its content and offered to sign them in.
//
// The only pair here where neither service is gated and neither verdict is in question. What differs
// is what the report can *say*: this one carries content, links into itself and one
// `<a href="/login">Sign in</a>`, which together are a presence rather than an absence.
//
// The search form is load-bearing: §13.4 requires *no form anywhere* before it will spend a second
// request, so without it these two pages would each cost one and this fixture would be quietly editing
// the arithmetic of the state walk.
const htmlPortal = `<!doctype html><html lang="en"><head><title>Acme Portal</title></head>
<body><header><nav><a href="/status">Status</a> <a href="/docs">Documentation</a>
<a href="/changelog">Changelog</a></nav><a href="/login">Sign in</a></header>
<main><h1>Acme Portal</h1>
<p>Everything on this page is served to anybody who asks for it. The status board, the
documentation and the changelog are public, and an account is only needed to file a ticket
or to subscribe to an alert.</p>
<p>The last deployment finished eleven minutes ago and every region is currently green.</p>
<form method="get" action="/search"><input type="search" name="q" placeholder="Search the docs">
<button type="submit">Search</button></form></main></body></html>`

// §23's first deliberate trap: the same public page whose only login-shaped signal is a
// `/auth/`-prefixed **logout** link.
//
// A sign-out link's path is a login path by every prefix test worth writing, so a rule that read the
// path without reading the word would call this gated — and a real fleet's blog would then be reported
// as protected. The prose paragraph is here for the same reason: it is long enough to be content, so
// the *content served* half of the verdict is not what carries this case.
const htmlBlog = `<!doctype html><html lang="en"><head><title>Acme Notes</title></head>
<body><header><nav><a href="/archive">Archive</a> <a href="/tags">Tags</a></nav>
<a href="/auth/logout">Sign out</a></header>
<main><h1>Latest posts</h1>
<p>Everything on this page is served to anybody who asks for it, and none of it is behind
anything. The posts are public and the archive is public.</p>
<ul><li><a href="/posts/router">How to log in to your router</a></li>
<li><a href="/posts/backups">Keeping a backup you can actually restore</a></li></ul>
<form method="get" action="/search"><input type="search" name="q" placeholder="Search posts">
<button type="submit">Search</button></form></main></body></html>`

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

const htmlUTF8 = "text/html; charset=utf-8"

// probeAnswers is every address the fixture fleet answers at, keyed by the exact URL §13.2 builds.
var probeAnswers = map[string]answer{
	// A tunnel hostname serving the application's own login form.
	"https://login.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlLogin},

	// A proxy router with a certresolver, so `https`, answering with a challenge header.
	"https://challenge.probe.example.com/": {status: 401, challenge: `Basic realm="api"`},

	// A proxy router with no TLS, so `http`, handing the request to an identity provider.
	"http://crm.probe.example.com/": {
		status: 302, location: "https://sso.probe.example.com/application/o/crm/",
	},

	// A relative `Location`, which is what real applications send — resolved against the request URL,
	// so this stays on the origin and lands on a login path.
	"https://wiki.probe.example.com/": {status: 302, location: "/login?next=%2F"},

	// Open: an application homepage, from a public hostname.
	"https://dash.probe.example.com/": {status: 200, mediaType: "text/html", body: htmlApp},

	// Open: a same-origin redirect to a landing page, which is routing and not a gate.
	"https://routing.probe.example.com/": {status: 302, location: "/dashboard"},

	// The two addresses that are never asked, and they are in this table on purpose.
	//
	// Both services carry authentication this scan detected — a forward-auth middleware on the one, a
	// Cloudflare Access policy on the other — so §13.1 declines to ask them. An answer waiting here is
	// what turns that into a test: a revert that drops the eligibility check does not fail on a missing
	// entry and a resolve error, which would look like a broken network fixture. It fails because the
	// call log recorded the request.
	"https://gated.probe.example.com/":  {status: 200, mediaType: "text/html", body: htmlApp},
	"https://access.probe.example.com/": {status: 200, mediaType: "text/html", body: htmlApp},

	// Open, and declared as authenticating itself — the drift case of §14.
	"https://portal.probe.example.com/": {status: 200, mediaType: "text/html", body: htmlApp},

	// Gated: a redirect to a login written in markup, so it arrives wearing a 200.
	"https://docs.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlRefreshLogin},

	// Open, and the trap for the rule above: a refresh to the application's own landing page.
	"https://home.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlRefreshRouting},

	// Gated: the SAML POST binding, on a TLS router so `https`.
	"https://erp.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlSAML},

	// Gated: a login page with no password on it.
	"https://magic.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlPasswordless},

	// Open, and the trap for the rule above: the same three tags, as a newsletter box.
	"https://news.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlSignup},

	// Gated: a 302 to Authentik's own flow address, which is a login path the list has.
	"https://akportal.probe.example.com/": {
		status: 302, location: "/flows/-/default/authentication/",
	},

	// Open, and the trap for the rule above: an application routing to one of its own flows.
	// `/flows/123` is not `/flows/-/`, and the `-` is the whole difference.
	"https://dataflow.probe.example.com/": {status: 302, location: "/flows/123"},

	// Open, and the only pair here that is open on the strength of what it served rather than of what
	// it lacked. Both answer a form-bearing 200, so neither costs a second request, and neither verdict
	// is in question — §13.6's wording is what these two are for.
	"https://app.public.probe.example.com/":  {status: 200, mediaType: htmlUTF8, body: htmlPortal},
	"https://blog.public.probe.example.com/": {status: 200, mediaType: htmlUTF8, body: htmlBlog},

	// The eighth signal, and the four addresses behind it.
	//
	// Both shells answer the same form-less 200, so both cost a second request — the entries below are
	// what that request finds. `app` refuses at `/api/`, the first path in the walk, and names a
	// scheme, so the walk stops there without asking the other three. `anon` serves `/api/` and
	// `/api/me` like the public application it is and then refuses `/api/v1/me` with a bare 401, which
	// is deliberately *not* a gate — so its walk is three long and its verdict is unchanged.
	//
	// Every path not listed here answers 404, which is what a service with no API does. That is why
	// `anon`'s refusal sits at the third entry rather than the second: a walk that stopped early would
	// not prove the walk continues past a 200.
	"https://app.spa.probe.example.com/":     {status: 200, mediaType: htmlUTF8, body: htmlShell},
	"https://app.spa.probe.example.com/api/": {status: 401, challenge: `Basic realm="app"`},

	"https://anon.spa.probe.example.com/":          {status: 200, mediaType: htmlUTF8, body: htmlShell},
	"https://anon.spa.probe.example.com/api/":      {status: 200, mediaType: "application/json"},
	"https://anon.spa.probe.example.com/api/me":    {status: 200, mediaType: "application/json"},
	"https://anon.spa.probe.example.com/api/v1/me": {status: 401},

	// The LAN fallback. Its public hostname is absent from this table on purpose: the tunnel name does
	// not resolve from inside the fleet, so the walk falls through to the published port.
	"http://" + probeLanHost + ":18099/": {status: 200, mediaType: htmlUTF8, body: htmlLogin},
}
