package corpus

import (
	"net/url"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// `fixtures/probe` is §13 end to end, and it is the only root where LabView sends a request to
// something the fleet's own documents named rather than to an API it was configured with. So it is the
// only root where the **call log is evidence**: that nothing was asked at a database, that no request
// carried a credential, that two gated services were never asked at all, and that the arithmetic of
// §23's request count is what the guide says it is are all facts about what left the process.
//
// Eighteen stacks, one rule each, and half of them arranged in pairs whose two halves differ in one
// character, one URL or one attribute — because that is the size of the mistake each rule is guarding
// against.

// probeRun is one scan of the root with the probe on and a LAN host set.
//
// `probe.lanHost` is set here and nowhere else in the corpus, because §13.2's third vantage exists only
// when an operator supplied one and MUST never be guessed. The run below with it unset is the control.
func probeRun(t *testing.T, extra ...func(*config.Config)) (*recorder, payload.Overview) {
	t.Helper()
	rec, rt := probeStub()
	out := scanRoot(t, "probe", scanOptions{rt: rt, mutate: func(c *config.Config) {
		c.Probe.Enabled = true
		c.Probe.LanHost = probeLanHost
		for _, f := range extra {
			f(c)
		}
	}})
	return rec, out
}

// ---------------------------------------------------------------------------
// The root is what it claims to be
// ---------------------------------------------------------------------------

func TestTheProbeRootIsCountedExactlyOnce(t *testing.T) {
	_, out := probeRun(t)

	if got := out.Stats.Stacks; got != 18 {
		t.Errorf("stacks = %d, want 18", got)
	}
	if got := out.Stats.Services; got != 27 {
		t.Errorf("services = %d, want 27", got)
	}
}

// ---------------------------------------------------------------------------
// §23's second required conclusion
// ---------------------------------------------------------------------------

// *37 requests: one for each of the 20 services asked, one fallthrough, and 16 second requests.*
//
// The number is a required conclusion for this root, and it is asserted the only way a request count
// can honestly be asserted: against the call log, decomposed into the three things it is made of. A
// total alone would pass while one service was asked twice and another not at all.
//
// The three terms are independent. 20 is §13.1's eligibility — 27 services, five with no HTTP address
// and two withheld. The 1 is §13.2's fall-through, the second address of a service whose first did not
// resolve. The 16 are §13.4's second requests, which are counted on the state record rather than in
// the attempt list, so the log and the payload have to agree about them.
func TestTheRequestCountIsTheRequiredConclusionForThisRoot(t *testing.T) {
	rec, out := probeRun(t)

	var first, second int
	for _, c := range rec.all() {
		u, err := url.Parse(c.URL)
		if err != nil {
			t.Fatalf("unparseable request %q: %v", c.URL, err)
		}
		if u.Path == "/" {
			first++
		} else {
			second++
		}
	}

	if total := len(rec.all()); total != 37 {
		t.Errorf("%d requests left the process, want 37", total)
	}
	if first != 21 {
		t.Errorf("%d requests at service addresses, want 21 — one for each of 20 services and one fallthrough", first)
	}
	if second != 16 {
		t.Errorf("%d second requests, want 16", second)
	}

	// The fall-through is the one service asked twice, and it is asked at two *different* addresses.
	// Without this, a retry of the same address would satisfy the arithmetic above.
	if got := rec.count("https://vault.probe.example.com/"); got != 1 {
		t.Errorf("the unresolvable tunnel address was asked %d times, want 1", got)
	}
	if got := rec.count("http://" + probeLanHost + ":18099/"); got != 1 {
		t.Errorf("the LAN address was asked %d times, want 1", got)
	}

	// And the payload's own account of the second requests matches the log, since the report sums
	// them from the state records rather than from anything the transport counted.
	var asked int
	for _, key := range keys(out) {
		if p := find(out, key).Probe; p != nil && p.State != nil {
			asked += p.State.Asked
		}
	}
	if asked != second {
		t.Errorf("the state records account for %d second requests and %d were sent", asked, second)
	}
}

// The report sentence, which is the same three numbers in prose plus the skipped count (§13.6).
func TestTheProbeReportStatesWhatItAskedAndWhatItFoundOut(t *testing.T) {
	_, out := probeRun(t)
	rep := report(t, out, conn.TargetProbe)

	const want = "20 services probed — 10 gated, 9 open, 1 did not answer — " +
		"16 extra requests at current-user addresses — 2 services not asked (authentication already detected)"
	if rep.Detail != want {
		t.Errorf("report detail =\n  %q\nwant\n  %q", rep.Detail, want)
	}

	// One service did not answer, so the fleet-wide phase is partial — and partial is still a
	// success, because everything else was read (I4).
	if rep.Phase != payload.PhasePartial {
		t.Errorf("phase = %q, want partial: one service did not answer", rep.Phase)
	}
	if !rep.OK {
		t.Error("ok = false on a run that measured 19 of 20 services")
	}

	if got := out.Stats.ProbeGated; got != 10 {
		t.Errorf("probeGated = %d, want 10", got)
	}
	if got := out.Stats.ProbeOpen; got != 9 {
		t.Errorf("probeOpen = %d, want 9", got)
	}
}

// ---------------------------------------------------------------------------
// The eight signals
// ---------------------------------------------------------------------------

// Every signal, on the service that exists for it, with the fact its sentence names (§13.3, §13.4).
//
// The wording is asserted alongside the label because §13.6 requires the mapping from signal to
// sentence to be exhaustive: a gate whose reason sentence fell back to a generic phrase would still
// carry the right label, and a reader would be told a gate was found without being told what found it.
func TestEachGateSignalFiresOnTheServiceThatExistsForIt(t *testing.T) {
	_, out := probeRun(t)

	for _, c := range []struct {
		key  string
		gate payload.ProbeGate
		says string
	}{
		{"proxy-challenge/api", payload.GateChallenge, "answered 401 and named an authentication scheme"},
		{"sso-redirect/crm", payload.GateRedirectOrigin, "redirected off its own origin"},
		{"own-login/wiki", payload.GateRedirectLogin, "redirected to /login, a login path on its own origin"},
		{"authentik-flow/portal", payload.GateRedirectLogin, "/flows/-/default/authentication/, a login path on its own origin"},
		{"meta-refresh/docs", payload.GateMetaRefreshLogin, "own markup refreshed to /login"},
		{"saml-post/erp", payload.GateSSOForm, "carried a hidden SAML field"},
		{"tunnel-login/app", payload.GatePasswordForm, "carried a password input"},
		{"lan-fallback/vault", payload.GatePasswordForm, "carried a password input"},
		{"passwordless/magic", payload.GateCredentialForm, "no password field — posting to /login, which is passwordless sign-in"},
		{"spa-shell/app", payload.GateStateChallenge, "own client was refused at"},
	} {
		p := probeOf(t, out, c.key)
		if p.Gate != c.gate {
			t.Errorf("%s gate = %q, want %q", c.key, p.Gate, c.gate)
			continue
		}
		if !strings.Contains(p.Detail, c.says) {
			t.Errorf("%s: the sentence does not name what fired:\n  %q\ndoes not contain\n  %q",
				c.key, p.Detail, c.says)
		}
	}

	// And every member of the closed set is exercised by this root, so a signal added without a
	// fixture is visible here rather than in a fleet.
	fired := map[payload.ProbeGate]bool{}
	for _, key := range keys(out) {
		if p := find(out, key).Probe; p != nil && p.Gate != "" {
			fired[p.Gate] = true
		}
	}
	for _, g := range payload.ProbeGates {
		if !fired[g] {
			t.Errorf("no service in fixtures/probe fires %q", g)
		}
	}
}

// A gate takes a service out of the exposure count and nothing else (§13.6, I3).
//
// The method stays `none` — a probe never becomes a mechanism — and the figure stays subtractable,
// which is what `hasEdgeAuth = configuredEdgeAuth || probeGate` is written as two terms to keep.
func TestAProbedGateClearsTheFindingWithoutBecomingAMechanism(t *testing.T) {
	_, out := probeRun(t)

	var gated int
	for _, key := range keys(out) {
		svc := find(out, key)
		if !svc.ProbeGate() {
			continue
		}
		gated++
		if got := svc.Auth.Method; got != payload.AuthNone {
			t.Errorf("%s method = %q — a probe result became a mechanism", key, got)
		}
		if svc.Auth.ExposedWithoutAuth {
			t.Errorf("%s is still in the exposure finding despite a login page answering", key)
		}
		if svc.ConfiguredEdgeAuth() {
			t.Errorf("%s reads as configured edge authentication, so the figure stopped being subtractable", key)
		}
		if !fleet.External(svc.Ingress) {
			t.Errorf("%s was probed and is not externally reachable, so it should never have been a candidate", key)
		}
	}
	if gated != out.Stats.ProbeGated {
		t.Errorf("%d services carry a gate and the counter says %d", gated, out.Stats.ProbeGated)
	}
}

// ---------------------------------------------------------------------------
// The two traps
// ---------------------------------------------------------------------------

// §23's first trap: a public page whose only login-shaped signal is a `/auth/`-prefixed **logout**
// link, sitting beside a public page that really does offer a way in.
//
// Login-path matching is by prefix, so `/auth/logout` is a login path *by name*. §13.5 therefore
// requires a logout link to be skipped **before** its path is read — and this is the fixture where
// skipping it is the difference between a fleet's blog reading as protected and reading as public.
func TestALogoutLinkIsSkippedBeforeItsPathIsRead(t *testing.T) {
	_, out := probeRun(t)

	blog := probeOf(t, out, "public-portal/blog")
	if blog.Gate != "" {
		t.Fatalf("the blog is gated by %q, and its only login-shaped signal is a sign-out link", blog.Gate)
	}
	if service(t, out, "public-portal/blog").Auth.ExposedWithoutAuth != true {
		t.Error("the blog left the exposure count on the strength of a sign-out link")
	}
	if blog.Anon == nil {
		t.Fatal("no anonymous reading of a page that answered 200 with HTML")
	}
	if got := blog.Anon.LoginHref; strings.HasPrefix(got, "/auth/") {
		t.Errorf("the sign-out link was read as a way in: loginHref = %q", got)
	}

	// The page beside it, which offers a real one. Both are open; what differs is what the report can
	// say, and it is the presence of the sentence that proves the skip above is a skip and not a
	// reading that finds nothing anywhere.
	app := probeOf(t, out, "public-portal/app")
	if app.Gate != "" {
		t.Errorf("the portal is gated by %q; it serves its content to anybody", app.Gate)
	}
	if app.Anon == nil || app.Anon.LoginHref != "/login" || app.Anon.LoginLabel != "Sign in" {
		t.Errorf("the portal's way in was not read: %s", marshal(t, app.Anon))
	}
}

// §23's second trap: a newsletter box has the same three tags as a magic-link login, and the only
// thing separating them is where the form posts.
//
// §13.3 requires a **cross-origin action to be rejected** rather than read as a hand-off. Both records
// carry the shape they found — the shape is attached whenever a form was found, including when nothing
// was concluded from it — and they differ in one field.
func TestACrossOriginFormActionIsNotEvidenceOfALogin(t *testing.T) {
	_, out := probeRun(t)

	news := probeOf(t, out, "passwordless/news")
	if news.Gate != "" {
		t.Fatalf("a newsletter signup is read as %q", news.Gate)
	}
	if news.Form == nil {
		t.Fatal("the form shape was not attached to a record that concluded nothing from it")
	}
	if news.Form.Action != "" {
		t.Errorf("action = %q — a cross-origin action was recorded as a login destination", news.Form.Action)
	}

	magic := probeOf(t, out, "passwordless/magic")
	if magic.Gate != payload.GateCredentialForm {
		t.Fatalf("the magic-link login is read as %q, want credential-form", magic.Gate)
	}
	if magic.Form == nil || magic.Form.Action != "/login" {
		t.Errorf("the login's own action was not recorded: %s", marshal(t, magic.Form))
	}

	// The two shapes are otherwise identical, which is the whole of the trap: an identifier field, a
	// submit control, no password. Only the action differs.
	if a, b := *news.Form, *magic.Form; a.Password != b.Password || a.Username != b.Username ||
		a.Submit != b.Submit || a.OTP != b.OTP {
		t.Errorf("the two shapes differ in more than their action:\n  news  %s\n  magic %s",
			marshal(t, a), marshal(t, b))
	}
}

// ---------------------------------------------------------------------------
// What is deliberately not a gate
// ---------------------------------------------------------------------------

// §13.3's asymmetry, as a table: the probe can only ever take a service **out** of the exposed count,
// so every near miss below MUST leave the finding standing — and each says which clause came closest
// and what it lacked.
func TestTheNearMissesLeaveTheFindingStanding(t *testing.T) {
	_, out := probeRun(t)

	for _, c := range []struct {
		key  string
		says string
		why  string
	}{
		// One character. `/flows/-/` is Authentik's own placeholder for no application context; a bare
		// `/flows` prefix would read a workflow tool as a login page.
		{"authentik-flow/pipeline", "stayed on its own origin and is not a login path",
			"a redirect to one of the application's own flows"},

		// A same-origin redirect to a landing page is routing.
		{"open-app/routing", "which stayed on its own origin and is not a login path",
			"a 302 to /dashboard"},

		// The same rule through markup rather than a header, since both go through one redirect rule.
		{"meta-refresh/home", "neither left the origin nor landed on a login path",
			"a meta refresh to /dashboard"},

		// A homepage that says "Sign in" twice and links to an account page. Matching the words rather
		// than the input would clear this exposure on the strength of a link.
		{"open-app/dash", "No form was in the page at all",
			"a dashboard with a sign-in link and no password field"},

		// A **bare** 401 one address over. An anonymous-enabled Grafana answers exactly this way while
		// serving everybody, so reading it as a gate would take genuinely open services out of the
		// count. It is still named as a place to look, in the same sentence that says the finding
		// stands.
		{"spa-shell/anon", "but no scheme was named — worth a look, though the finding stands",
			"a refusal that named no authentication scheme"},
	} {
		p := probeOf(t, out, c.key)
		if p.Gate != "" {
			t.Errorf("%s is gated by %q: %s", c.key, p.Gate, c.why)
			continue
		}
		if !strings.Contains(p.Detail, c.says) {
			t.Errorf("%s: the sentence does not say what came closest:\n  %q\ndoes not contain\n  %q",
				c.key, p.Detail, c.says)
		}
		if !service(t, out, c.key).Auth.ExposedWithoutAuth {
			t.Errorf("%s left the exposure count: %s", c.key, c.why)
		}
	}
}

// ---------------------------------------------------------------------------
// The eighth signal
// ---------------------------------------------------------------------------

// §13.4's walk: sequential, in one fixed order, stopping at the first refusal — and the gate rests on
// whether that refusal named a scheme, on nothing else (§13.4).
//
// Both services serve the identical form-less shell, so the page cannot be what separates them. `app`
// is refused at the first address with a scheme; `anon` is served two addresses like the public
// application it is and then refused with a bare 401.
func TestTheStateWalkStopsAtTheFirstRefusalAndRestsOnTheScheme(t *testing.T) {
	rec, out := probeRun(t)

	app := probeOf(t, out, "spa-shell/app")
	if app.State == nil {
		t.Fatal("no state record on a form-less HTML 200")
	}
	if app.State.Asked != 1 || app.State.RefusedAt != "https://app.spa.probe.example.com/api/" {
		t.Errorf("the walk asked %d addresses and stopped at %q", app.State.Asked, app.State.RefusedAt)
	}
	if app.State.Challenge == nil || !*app.State.Challenge {
		t.Error("the refusal named a scheme and the record does not say so")
	}
	if app.Gate != payload.GateStateChallenge {
		t.Errorf("gate = %q, want state-challenge", app.Gate)
	}
	// Stopping means stopping: the second address of the list was never asked.
	if rec.asked("https://app.spa.probe.example.com/api/me") {
		t.Error("the walk continued past a refusal")
	}

	anon := probeOf(t, out, "spa-shell/anon")
	if anon.State == nil {
		t.Fatal("no state record on the second form-less shell")
	}
	if anon.State.Asked != 3 || anon.State.RefusedAt != "https://anon.spa.probe.example.com/api/v1/me" {
		t.Errorf("the walk asked %d addresses and stopped at %q", anon.State.Asked, anon.State.RefusedAt)
	}
	if anon.State.Challenge == nil || *anon.State.Challenge {
		t.Errorf("the bare refusal is recorded as naming a scheme: %s", marshal(t, anon.State))
	}
	if anon.Gate != "" {
		t.Errorf("a bare 401 became %q", anon.Gate)
	}

	// The walk is in the constant order of §13.4, which the run that finds nothing proves: three
	// services are refused nowhere and each asked all four in the same sequence.
	want := []string{"/api/", "/api/me", "/api/v1/me", "/api/v1/user"}
	for _, host := range []string{
		"https://dash.probe.example.com", "https://home.probe.example.com", "https://portal.probe.example.com",
	} {
		var got []string
		for _, c := range rec.all() {
			if address, ok := strings.CutPrefix(c.URL, host); ok && address != "/" {
				got = append(got, address)
			}
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s was walked %v, want %v", host, got, want)
		}
	}

	// And its addresses stay out of the recorded attempt list — the count travels on the state record
	// instead, because an attempt is a candidate that was rejected, not a question that was asked.
	for _, key := range keys(out) {
		p := find(out, key).Probe
		if p == nil {
			continue
		}
		for _, a := range p.Attempts {
			if strings.Contains(a.Endpoint, "/api") {
				t.Errorf("%s: a current-user address is in the attempt list: %q", key, a.Endpoint)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Eligibility: the requests that were not sent
// ---------------------------------------------------------------------------

// §13.1: a service whose gate this scan already detected is not asked, because the answer could not
// change the verdict in either direction.
//
// Both stacks have an answer waiting in the stub, deliberately. A revert that drops the eligibility
// check does not fail on a missing entry and a resolve error — which would look like a broken network
// fixture. It fails because the request was recorded.
func TestAServiceWhoseGateWasAlreadyDetectedIsNeverAsked(t *testing.T) {
	rec, out := probeRun(t)

	for _, c := range []struct {
		key, address, detected string
	}{
		// A forward-auth middleware named in labels, `inferred` — the harder half of the rule, since
		// an inferred gate is still authentication detected.
		{"gated-open/app", "https://gated.probe.example.com/", "a forward-auth middleware on its router"},

		// A Cloudflare Access policy, with no Traefik router in the stack at all — so the rule is not
		// about Traefik.
		{"access-gate/app", "https://access.probe.example.com/", "an Access policy on its tunnel route"},
	} {
		if svc := service(t, out, c.key); svc.Probe != nil {
			t.Errorf("%s was probed and %s was already detected: %s", c.key, c.detected, marshal(t, svc.Probe))
		}
		if rec.asked(c.address) {
			t.Errorf("%s: a request was sent to %s, whose answer could not have changed the verdict",
				c.key, c.address)
		}
		if !service(t, out, c.key).ConfiguredEdgeAuth() {
			t.Errorf("%s has no configured edge authentication, so withholding the request was wrong", c.key)
		}
	}

	// Two questions were declined, so the counter says 2. `access-gate/db` has the same Access policy
	// *and* a `tcp://` origin: the address test runs first, so it was never a candidate rather than a
	// withheld one. Swap those two and nothing extra is requested while this counter reads 3.
	if got := out.Meta.Probe.Skipped; got != 2 {
		t.Errorf("skipped = %d, want 2 — not asked and no address are different facts", got)
	}
	if svc := service(t, out, "access-gate/db"); svc.Probe != nil {
		t.Errorf("access-gate/db has no HTTP address and carries a probe record: %s", marshal(t, svc.Probe))
	}
}

// §13.2's rule that keeps the probe off a database without consulting a port number or an image name:
// **a service with `ports:` and no route of either kind yields no address at all**.
func TestNothingIsAskedWhereNoHTTPWasObserved(t *testing.T) {
	rec, out := probeRun(t)

	for _, c := range []struct {
		key, why string
	}{
		// Published ports, no route. An eligibility rule that read `ports:` would send an HTTP GET to
		// 5432 — and `probe.lanHost` being set in this run is exactly what would let it.
		{"dbonly/db", "a database with a published port and no route"},

		// The stated cost of the rule: a web UI that publishes a port and is routed by nothing is
		// never measured. Correct, and less than could be known.
		{"dbonly/adminer", "a web UI with a published port and no route"},

		// A tunnel route is not by itself evidence of HTTP. The scheme in `dockflare.service` is the
		// operator's own value, and it says these two do not speak it.
		{"tcp-tunnel/postgres-tunnel", "a tunnel route whose origin is `tcp://`"},
		{"tcp-tunnel/bastion", "a tunnel route whose origin is `ssh://`"},
	} {
		if svc := service(t, out, c.key); svc.Probe != nil {
			t.Errorf("%s was probed: %s (%s)", c.key, marshal(t, svc.Probe), c.why)
		}
	}

	// And nothing went anywhere near them, at any port or hostname.
	for _, c := range rec.all() {
		for _, forbidden := range []string{
			":15432", ":18081", "pg.probe.example.com", "ssh.probe.example.com",
			"access-db.probe.example.com",
		} {
			if strings.Contains(c.URL, forbidden) {
				t.Errorf("a request reached %s", c.URL)
			}
		}
	}

	// The two `tcp://` services stay in the exposed count — untouched, unmeasured, and honestly so. A
	// probe that guessed HTTP from a hostname would have reported them as open web services.
	for _, key := range []string{"tcp-tunnel/postgres-tunnel", "tcp-tunnel/bastion"} {
		if !service(t, out, key).Auth.ExposedWithoutAuth {
			t.Errorf("%s left the exposure count without being measured", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Addresses and vantages
// ---------------------------------------------------------------------------

// §13.2's table: which vantage was used, and the scheme it produced.
//
// The scheme is evidence, not a default: a Traefik router declaring TLS is asked over `https` and one
// without over `http`, and the stub is keyed on the whole URL so a wrong scheme is a miss here.
func TestTheVantageAndTheSchemeComeFromTheEvidence(t *testing.T) {
	_, out := probeRun(t)

	for _, c := range []struct {
		key      string
		vantage  payload.ProbeVantage
		endpoint string
		why      string
	}{
		{"tunnel-login/app", payload.VantagePublic, "https://login.probe.example.com",
			"a tunnel hostname is always asked over https"},
		{"own-login/wiki", payload.VantageTraefik, "https://wiki.probe.example.com",
			"a router declaring tls"},
		{"sso-redirect/crm", payload.VantageTraefik, "http://crm.probe.example.com",
			"a router with no tls, so http and not a guess"},
		{"lan-fallback/vault", payload.VantageLan, "http://" + probeLanHost + ":18099",
			"the published port, after the tunnel hostname failed to resolve"},
	} {
		p := probeOf(t, out, c.key)
		if p.Vantage != c.vantage {
			t.Errorf("%s vantage = %q, want %q (%s)", c.key, p.Vantage, c.vantage, c.why)
		}
		if p.Endpoint != c.endpoint {
			t.Errorf("%s endpoint = %q, want %q (%s)", c.key, p.Endpoint, c.endpoint, c.why)
		}
	}
}

// The fall-through, and what it costs to get wrong: a stage that stopped at the first failure would
// report *did not answer* about a service that answers perfectly well (§13.2).
//
// Only a transport failure falls through. The recorded attempt is what makes the second address
// answerable rather than mysterious.
func TestAnAddressThatDidNotResolveFallsThroughAndIsRecorded(t *testing.T) {
	_, out := probeRun(t)

	p := probeOf(t, out, "lan-fallback/vault")
	if p.Phase != payload.PhaseConnected {
		t.Fatalf("phase = %q — the second address answered", p.Phase)
	}
	if len(p.Attempts) != 1 {
		t.Fatalf("%d attempts recorded, want 1: the address that did not resolve", len(p.Attempts))
	}
	a := p.Attempts[0]
	if a.Endpoint != "https://vault.probe.example.com" {
		t.Errorf("the recorded attempt is %q", a.Endpoint)
	}
	if !strings.Contains(a.Why, "tunnel hostname vault.probe.example.com") {
		t.Errorf("the attempt does not say what made it a candidate: %q", a.Why)
	}
	if a.Phase != payload.PhaseResolve {
		t.Errorf("attempt phase = %q, want resolve", a.Phase)
	}
}

// An empty `lanHost` means **no LAN vantage, never a guessed one** (§13.2).
//
// The same fixture, the same stub, one setting removed: the tunnel hostname still fails, there is now
// nowhere to fall through to, and the service reads *No answer* — which is the honest outcome, and one
// request fewer.
func TestWithNoLANHostThereIsNoLANVantage(t *testing.T) {
	rec, out := probeRun(t, func(c *config.Config) { c.Probe.LanHost = "" })

	p := probeOf(t, out, "lan-fallback/vault")
	if p.Vantage != payload.VantagePublic {
		t.Errorf("vantage = %q, want public — the LAN address was invented", p.Vantage)
	}
	if conn.OK(p.Phase) {
		t.Errorf("phase = %q on a run with nowhere to fall through to", p.Phase)
	}
	for _, c := range rec.all() {
		if strings.Contains(c.URL, probeLanHost) {
			t.Errorf("a request reached %s with no lanHost configured", c.URL)
		}
	}
	if got := len(rec.all()); got != 36 {
		t.Errorf("%d requests, want 36 — one fewer than the run with a LAN host", got)
	}
}

// A service that did not answer is neither finding: counted in neither statistic, claiming no
// measurement, and worded *No answer* rather than *No login page* (§13.6).
//
// This is the direction that matters. Both outcomes are the same absence of a gate, and a probe that
// let the first read as the second would be inventing measurements out of network failures.
func TestAServiceThatDidNotAnswerHasNothingMeasuredAboutIt(t *testing.T) {
	_, out := probeRun(t)

	p := probeOf(t, out, "silent/ghost")
	if conn.OK(p.Phase) {
		t.Fatalf("phase = %q, want a failure", p.Phase)
	}
	if p.Status != nil {
		t.Errorf("a status of %d was recorded for an address that never answered", *p.Status)
	}
	if p.Gate != "" || p.Anon != nil || p.State != nil {
		t.Errorf("something was concluded from a failed request: %s", marshal(t, p))
	}
	if !strings.HasPrefix(p.Detail, "No answer from") {
		t.Errorf("the wording is not *No answer*: %q", p.Detail)
	}
	// The posture falls back to exactly what the configuration implies.
	if !service(t, out, "silent/ghost").Auth.ExposedWithoutAuth {
		t.Error("a service that did not answer left the exposure count")
	}
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

// I8 and §13.6, asserted against the log because that is the only place these facts exist: GET only,
// no query string, **no credential** — and not by omission, since no call path into the fetch may have
// one in scope — and at most four addresses per service.
func TestNothingTheProbeSentCarriedMoreThanAGET(t *testing.T) {
	rec, out := probeRun(t, func(c *config.Config) {
		// A configuration carrying every credential the program knows about. None of them has any
		// business reaching a scanned service, and a run with them unset could not tell.
		c.Traefik.Username, c.Traefik.Password = tfUser, tfPassword
		c.Authentik.Token = akToken
	})

	for _, c := range rec.all() {
		if c.Credential {
			t.Errorf("a credential was sent to %s", c.URL)
		}
		if c.Cookie != "" {
			t.Errorf("a cookie was sent to %s: %q", c.URL, c.Cookie)
		}
		u, err := url.Parse(c.URL)
		if err != nil {
			t.Fatalf("unparseable request %q: %v", c.URL, err)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("%s carries a query or a fragment", c.URL)
		}
	}

	// At most four addresses per service, counting the one that answered and the ones that did not.
	for _, key := range keys(out) {
		p := find(out, key).Probe
		if p == nil {
			continue
		}
		if addresses := len(p.Attempts) + 1; addresses > 4 {
			t.Errorf("%s was asked at %d addresses", key, addresses)
		}
	}
}

// No redirect is followed, because where a 3xx points **is** the evidence (§13.6).
//
// Two of the three redirect fixtures point somewhere the stub would happily answer, so a transport
// that followed them would show up as a request at the destination.
func TestNoRedirectIsFollowedBecauseTheDestinationIsTheEvidence(t *testing.T) {
	rec, out := probeRun(t)

	for _, address := range []string{
		"https://sso.probe.example.com/application/o/crm/",
		"https://wiki.probe.example.com/login",
		"https://dash.probe.example.com/dashboard",
		"https://docs.probe.example.com/login",
	} {
		if rec.asked(address) {
			t.Errorf("a redirect was followed to %s", address)
		}
	}

	// The destination is recorded instead, reduced by the one shared rule of §13.6: query and
	// fragment dropped, and the origin kept only when the target left it.
	for _, c := range []struct {
		key         string
		to          string
		crossOrigin bool
		field       string
	}{
		{"own-login/wiki", "/login", false, "redirect"},
		{"sso-redirect/crm", "https://sso.probe.example.com/application/o/crm/", true, "redirect"},
		{"meta-refresh/docs", "/login", false, "refresh"},
	} {
		p := probeOf(t, out, c.key)
		got := p.Redirect
		if c.field == "refresh" {
			got = p.Refresh
		}
		if got == nil {
			t.Errorf("%s: no %s recorded", c.key, c.field)
			continue
		}
		if got.To != c.to || got.CrossOrigin != c.crossOrigin {
			t.Errorf("%s %s = %s, want to=%q crossOrigin=%v", c.key, c.field, marshal(t, got), c.to, c.crossOrigin)
		}
	}
}

// ---------------------------------------------------------------------------
// What an anonymous caller was shown
// ---------------------------------------------------------------------------

// §13.5 is one pure function over a body already fetched, and it MUST be **structurally incapable of
// gating**. The worst a mistake in it can do is put a wrong sentence on a service that stays in the
// exposed count.
//
// So the record is attached to gated and open services alike — it describes a *response* — while the
// sentence it earns is reached only after §13.4's shortfall.
func TestTheAnonymousReadingDescribesAPageAndDecidesNothing(t *testing.T) {
	_, out := probeRun(t)

	// Attached wherever an HTML 200 was read, gate or no gate.
	for _, key := range []string{"tunnel-login/app", "saml-post/erp", "public-portal/app"} {
		if probeOf(t, out, key).Anon == nil {
			t.Errorf("%s: no anonymous reading of an HTML 200", key)
		}
	}
	// And nowhere a body was never read, since there is nothing to read a body from.
	for _, key := range []string{"sso-redirect/crm", "proxy-challenge/api", "silent/ghost"} {
		if p := probeOf(t, out, key); p.Anon != nil {
			t.Errorf("%s: an anonymous reading with no body: %s", key, marshal(t, p.Anon))
		}
	}

	// *Content was served* is 200 characters of visible text **and** 2 links, both required — and the
	// numbers come from drawn markup, with scripts and comments removed first.
	portal := probeOf(t, out, "public-portal/app")
	if portal.Anon.TextChars != 358 || portal.Anon.Links != 4 {
		t.Errorf("the portal read %d chars across %d links, want 358 and 4", portal.Anon.TextChars, portal.Anon.Links)
	}
	if !strings.Contains(portal.Detail, "It served 358 characters of visible text across 4 links and offered a way in") {
		t.Errorf("the both-halves sentence is not the one written: %q", portal.Detail)
	}

	// A shell is under both thresholds, so there is no positive evidence of an open service either and
	// the sentence says nothing about content — which is what keeps the narrower claim honest.
	shell := probeOf(t, out, "declared-open/portal")
	if shell.Anon.TextChars >= 200 || shell.Anon.Links >= 2 {
		t.Errorf("the shell is above a threshold: %s", marshal(t, shell.Anon))
	}
	if strings.Contains(shell.Detail, "characters of visible text") {
		t.Errorf("a shell earned the content sentence: %q", shell.Detail)
	}

	// A label longer than 24 characters is not kept (I6). The blog's only way-in link is a post
	// titled "How to log in to your router", which is 28 — so the path is reported and the words are
	// not, and the sentence falls back to naming the link.
	blog := probeOf(t, out, "public-portal/blog")
	if blog.Anon.LoginLabel != "" {
		t.Errorf("a %d-character label was kept: %q", len(blog.Anon.LoginLabel), blog.Anon.LoginLabel)
	}
	if !strings.Contains(blog.Detail, "offered a way in — a link to /posts/router") {
		t.Errorf("the label-less sentence is not the one written: %q", blog.Detail)
	}
}

// ---------------------------------------------------------------------------
// What a probe does not override (§13.6, §14)
// ---------------------------------------------------------------------------

// A declaration supplying the only protection is not overridden by an open answer. That is recorded as
// **unconfirmed**, never as drift — the probe contradicts nothing, because it cannot see an
// application's own login.
func TestAnOpenAnswerDoesNotContradictADeclaredGate(t *testing.T) {
	_, out := probeRun(t)

	svc := service(t, out, "declared-open/portal")
	if svc.Declared == nil {
		t.Fatal("the sidecar beside the compose file was not read")
	}
	if got := svc.Declared.AuthAgreement; got != payload.AgreementSupplies {
		t.Fatalf("agreement = %q, want supplies", got)
	}
	if svc.Auth.ExposedWithoutAuth {
		t.Error("the declaration did not clear the finding")
	}
	if got := svc.Auth.Method; got != payload.AuthNone {
		t.Errorf("method = %q — nothing anyone typed makes an undetected gate detected", got)
	}

	if len(svc.Declared.Drift) != 0 {
		t.Errorf("an open answer was read as drift: %v", svc.Declared.Drift)
	}
	if len(svc.Declared.Unconfirmed) != 1 ||
		!strings.Contains(svc.Declared.Unconfirmed[0], "read no login page, while the only account of a gate here is the declaration") {
		t.Errorf("the measurement that settled nothing is not recorded as unconfirmed: %v", svc.Declared.Unconfirmed)
	}
	if got := out.Stats.DeclarationDrift; got != 0 {
		t.Errorf("declarationDrift = %d, want 0 across this root", got)
	}
	if got := out.Stats.DeclaredAuthUnconfirmed; got != 1 {
		t.Errorf("declaredAuthUnconfirmed = %d, want 1", got)
	}
}

// An accepted exposure is still an exposure and MUST NOT be subtracted from the exposed count (§14).
//
// This service was signed off as open and now answers with a login form, so the probe is what takes it
// out of the finding — not the acceptance, which is counted in its own statistic and nothing else.
func TestAnAcceptanceIsCountedAndIsNotWhatClearsTheFinding(t *testing.T) {
	_, out := probeRun(t)

	svc := service(t, out, "tunnel-login/app")
	if svc.Declared == nil || svc.Declared.UnauthenticatedAccepted == nil {
		t.Fatal("the acceptance was not read")
	}
	if got := out.Stats.ExposureAccepted; got != 1 {
		t.Errorf("exposureAccepted = %d, want 1", got)
	}
	if !svc.ProbeGate() {
		t.Fatal("the probe found no gate, so this test is asserting the wrong thing")
	}
	if svc.Auth.ExposedWithoutAuth {
		t.Error("a probed gate did not clear the finding")
	}
}

// ---------------------------------------------------------------------------
// The switch beside Rescan
// ---------------------------------------------------------------------------

// §13.7: `probe.enabled` is the **default**, not the authority, and the payload always states what the
// build actually did.
func TestTheRequestOverridesTheConfiguredDefaultInBothDirections(t *testing.T) {
	// Configuration says on, the request says off. Nothing is sent.
	off := false
	recOff, out := scanRoot2(t, scanOptions{probe: &off, mutate: func(c *config.Config) {
		c.Probe.Enabled = true
		c.Probe.LanHost = probeLanHost
	}})
	if out.Meta.Probe.Enabled {
		t.Error("meta.probe.enabled = true on a build the request switched off")
	}
	if got := out.Meta.Probe.Source; got != payload.ProbeSourceRequest {
		t.Errorf("source = %q, want request", got)
	}
	if got := len(recOff.all()); got != 0 {
		t.Errorf("%d requests were sent by a build the request switched off", got)
	}
	if rep := report(t, out, conn.TargetProbe); rep.Phase != payload.PhaseDisabled {
		t.Errorf("phase = %q, want disabled", rep.Phase)
	}

	// Configuration says off — the default for this integration — and the request says on.
	on := true
	recOn, out := scanRoot2(t, scanOptions{probe: &on, mutate: func(c *config.Config) {
		c.Probe.LanHost = probeLanHost
	}})
	if !out.Meta.Probe.Enabled {
		t.Error("meta.probe.enabled = false on a build the request switched on")
	}
	if got := out.Meta.Probe.Source; got != payload.ProbeSourceRequest {
		t.Errorf("source = %q, want request", got)
	}
	if got := len(recOn.all()); got != 37 {
		t.Errorf("%d requests, want the same 37 as a configured run", got)
	}

	// And with no request at all the source names the configuration, so a reader can tell a scan that
	// probed because it was told to from one that probed because it always does.
	_, configured := probeRun(t)
	if got := configured.Meta.Probe.Source; got != payload.ProbeSourceConfig {
		t.Errorf("source = %q, want config", got)
	}
}

// I7 over the probe, which is the integration with the most to get wrong: concurrent requests across
// services, a sequential walk inside one, and several maps keyed on addresses.
func TestTwoIdenticalProbeScansProduceTheSameBytes(t *testing.T) {
	_, first := probeRun(t)
	_, second := probeRun(t)

	if a, b := marshal(t, first), marshal(t, second); a != b {
		t.Error("two identical probing scans of fixtures/probe differ")
	}
}

// ---------------------------------------------------------------------------
// Reading the probe back
// ---------------------------------------------------------------------------

// probeOf is one service's probe record, failing when there is none — because every caller below is
// asserting something about what was asked, and *nothing was asked* is a different test.
func probeOf(t *testing.T, out payload.Overview, key string) payload.ServiceProbe {
	t.Helper()
	svc := service(t, out, key)
	if svc.Probe == nil {
		t.Fatalf("%s was not probed", key)
	}
	return *svc.Probe
}

// scanRoot2 is `scanRoot` over the probe root with a fresh stub, for the runs that count requests
// against a recorder of their own.
func scanRoot2(t *testing.T, o scanOptions) (*recorder, payload.Overview) {
	t.Helper()
	rec, rt := probeStub()
	o.rt = rt
	return rec, scanRoot(t, "probe", o)
}
