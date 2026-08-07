package corpus

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
)

// `fixtures/traefik` is §12 end to end, and it is the only root where all three sources answer in one
// scan — the compose labels, the live routing table, and the identity provider — because the
// three-way cross-check reads all three at once (§23).
//
// The fleet is arranged so that each service is one rule. `wiki` is where the three sources agree;
// `crm` and `shop` differ only in their provider's `mode`, and that field is the whole difference
// between a finding and a non-finding; `dashboards` declares a gate the proxy is not applying;
// `legacy` is a router the proxy has switched off; `blog` declares a router the proxy never heard of;
// and the two `twin` stacks declare the same hostname, so the router that names it resolves to
// neither.

// tfRun is one scan of the root with the proxy switched on, and the identity provider with it.
//
// Both, always. The cross-check is not an optional extra that a second test can add later — a run
// with only the proxy enabled cannot reach any of §12's last four rules, and a reader of this file
// should not have to hold two different fleet states in their head.
func tfRun(t *testing.T, mode tfMode, extra ...func(*config.Config)) (*recorder, payload.Overview) {
	t.Helper()
	rec, rt := tfStub(t, mode)
	out := scanRoot(t, "traefik", scanOptions{
		rt: rt,
		mutate: func(c *config.Config) {
			c.Traefik.Enabled = true
			c.Authentik.Enabled = true
			c.Authentik.Token = akToken
			for _, f := range extra {
				f(c)
			}
		},
	})
	return rec, out
}

// ---------------------------------------------------------------------------
// The root is what it claims to be
// ---------------------------------------------------------------------------

func TestTheTraefikRootIsCountedExactlyOnce(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	if got := out.Stats.Stacks; got != 12 {
		t.Errorf("stacks = %d, want 12", got)
	}
	if got := out.Stats.Services; got != 12 {
		t.Errorf("services = %d, want 12", got)
	}
}

// ---------------------------------------------------------------------------
// Endpoint selection, and the credential that may not follow a guess
// ---------------------------------------------------------------------------

// §12: per candidate the URLs are `http://<name|container_name>:<port>` for each declared container
// port **plus 8080** — the port Traefik's dedicated API entrypoint conventionally serves.
//
// This root is built to need that last clause. `fixtures/traefik/edge` publishes 80 and 443 and
// nothing else, so 8080 is tried on the strength of Traefik's own default rather than of a declared
// port, and it is the only address that answers. A candidate list built from declared ports alone
// finds nothing here.
func TestTheAPIIsFoundOnTraefiksConventionalPortAndNotADeclaredOne(t *testing.T) {
	rec, out := tfRun(t, tfMode{})
	rep := report(t, out, conn.TargetTraefik)

	if rep.Endpoint != tfOrigin {
		t.Errorf("endpoint = %q, want %q", rep.Endpoint, tfOrigin)
	}
	if rep.Source != payload.SourceDiscovered {
		t.Errorf("endpoint source = %q, want discovered", rep.Source)
	}
	if rep.Phase != payload.PhaseConnected {
		t.Fatalf("phase = %q, want connected: %s", rep.Phase, rep.Detail)
	}

	// The declared ports were tried first and rejected, which is what makes 8080 a fall-through
	// rather than a first guess.
	for _, address := range []string{"http://edge-proxy:80/api/version", "http://edge-proxy:443/api/version"} {
		if !rec.asked(address) {
			t.Errorf("%s was never tried, so 8080 was not reached by falling through", address)
		}
	}

	// The handshake is `/api/version` and it needs no authentication (§12).
	if !rec.asked(tfOrigin + "/api/version") {
		t.Error("the proxy was never asked /api/version, so nothing proved this address was Traefik")
	}
}

// The credential rule, stated against the call log (§12).
//
// A candidate that answers `/api/version` is used **with no credential at all, and none is sent**. On
// this run the API answers on a container address that no label proved belongs to anybody, so nothing
// may ever be sent to it — and `none` is itself evidence about how the API is exposed, which MUST be
// reported as a note on the proxy service.
func TestADiscoveredProxyAddressIsNeverSentACredential(t *testing.T) {
	rec, out := tfRun(t, tfMode{})

	if got := out.Meta.Traefik.Credential; got != payload.CredentialNone {
		t.Errorf("credential = %q, want %q", got, payload.CredentialNone)
	}
	for _, c := range rec.all() {
		if strings.HasPrefix(c.URL, tfOrigin) && c.Credential {
			t.Errorf("a credential was sent to %s, which no label proved belongs to the proxy", c.URL)
		}
	}

	// An API that answers unauthenticated is a fact about the network, not a convenience, so it is
	// reported where a reader of the proxy service will meet it (§12).
	proxy := service(t, out, "edge/traefik")
	if !noted(proxy, "with no credential") {
		t.Errorf("the unauthenticated API is not reported on the proxy service: %v", proxy.Notes)
	}
}

// The other half of the credential rule: a credential MAY be sent to a hostname the scan proved
// belongs to the service whose own labels declare `api@internal` — that is ownership evidence.
//
// Here the API is behind an Authentik outpost on that hostname. The handshake is anonymous, the 401
// triggers the authenticated retry, and the session cookie the outpost sets on the way in MUST be
// replayed on the remaining requests — an outpost that does not get its cookie back answers 401
// again, which is what the stub does.
func TestAnOwnedHostnameMayBeAuthenticatedAndItsSessionIsReplayed(t *testing.T) {
	rec, out := tfRun(t, tfMode{gated: true}, func(c *config.Config) {
		c.Traefik.Username = tfUser
		c.Traefik.Password = tfPassword
	})
	rep := report(t, out, conn.TargetTraefik)

	if rep.Endpoint != tfGatedOrigin {
		t.Fatalf("endpoint = %q, want %q", rep.Endpoint, tfGatedOrigin)
	}
	if rep.Phase != payload.PhaseConnected {
		t.Fatalf("phase = %q, want connected: %s", rep.Phase, rep.Detail)
	}
	if got := out.Meta.Traefik.Credential; got != payload.CredentialBasic {
		t.Errorf("credential = %q, want %q", got, payload.CredentialBasic)
	}

	// The handshake came first and came anonymously. Without this the retry is indistinguishable
	// from a walk that authenticated on sight.
	var handshakes int
	for _, c := range rec.all() {
		if c.URL == tfGatedOrigin+"/api/version" {
			handshakes++
			if handshakes == 1 && c.Credential {
				t.Error("the first request to the owned hostname carried a credential")
			}
		}
	}
	if handshakes != 2 {
		t.Errorf("/api/version was asked %d times, want 2 — anonymous, then the retry", handshakes)
	}

	// And the cookie came back on everything after the exchange.
	for _, path := range []string{"/api/rawdata", "/api/entrypoints"} {
		var found bool
		for _, c := range rec.all() {
			if c.URL != tfGatedOrigin+path {
				continue
			}
			found = true
			if c.Cookie != tfSession {
				t.Errorf("%s carried cookie %q, want the session the outpost set", path, c.Cookie)
			}
		}
		if !found {
			t.Errorf("%s was never read, so the exchange did not complete", path)
		}
	}
}

// An Authentik API token is not a valid credential for the proxy (§12). The two integrations answer
// on two different origins in this root precisely so that a reader which reached for whatever token it
// had would be visible here.
func TestTheIdentityProviderTokenIsNotAProxyCredential(t *testing.T) {
	rec, _ := tfRun(t, tfMode{})

	for _, c := range rec.all() {
		if strings.HasPrefix(c.URL, tfOrigin) && c.Credential {
			t.Errorf("%s received a credential on a run whose only credential was an Authentik token", c.URL)
		}
	}
	// The token did reach the identity provider, so the check above is not passing by finding no
	// credentials anywhere.
	var reached bool
	for _, address := range rec.authenticated() {
		if strings.HasPrefix(address, akOutpostOrigin) {
			reached = true
		}
	}
	if !reached {
		t.Fatal("the Authentik token was never sent anywhere, so this proves nothing")
	}
}

// ---------------------------------------------------------------------------
// What the read obtained
// ---------------------------------------------------------------------------

// The counts, and the version — which is the one thing pinning that `/api/version`'s PascalCase
// fields are matched case-insensitively.
func TestTheProxyReadIsReportedWithItsVersionAndItsCounts(t *testing.T) {
	_, out := tfRun(t, tfMode{})
	tf := out.Meta.Traefik
	if tf == nil {
		t.Fatal("no proxy summary on a connected read")
	}

	if got := tf.Version; got != "3.1.2" {
		t.Errorf("version = %q, want 3.1.2 — the fixture answers in PascalCase", got)
	}
	if !tf.Reachable {
		t.Error("reachable = false on a read that answered")
	}
	if !tf.EntrypointsRead {
		t.Error("entrypointsRead = false, so chainComplete cannot be true")
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"routers", tf.Routers, 10},
		{"middlewares", tf.Middlewares, 5},
		{"services", tf.Services, 10},
		{"matchedServices", tf.MatchedServices, 8},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	rep := report(t, out, conn.TargetTraefik)
	if want := "10 routers, 5 middlewares, 10 services"; rep.Read != want {
		t.Errorf("read line = %q, want %q", rep.Read, want)
	}
}

// A service entry that is not a load balancer yields no backend evidence, and one router's service is
// missing from the map entirely — which a real Traefik also does for `api@internal`. Neither may throw
// (I4), and the read still reports every router.
func TestARouterWhoseBackendIsUnreadableStillAppears(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	var seen int
	for _, key := range keys(out) {
		if svc := find(out, key); svc != nil {
			seen += len(svc.TraefikLive)
		}
	}
	unmatchedCount := len(out.Meta.Traefik.UnmatchedRouters)
	if got := seen + unmatchedCount; got != out.Meta.Traefik.Routers {
		t.Errorf("%d routers were placed and %d left unmatched, but the read saw %d — one went missing",
			seen, unmatchedCount, out.Meta.Traefik.Routers)
	}
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

// §12's rule 2 is `@docker` routers only: Traefik derives those names from the labels of the container
// it found them on, so an exact match is that label round-tripping. A `@file` router's name was typed
// by hand in a file this scan cannot read.
//
// Both unmatched routers here are `@file`, and both traces MUST say so — a matcher that applied rule 2
// to them would tie `standalone@file` to nothing in particular and `twin-blue@file` to whichever twin
// sorted first.
func TestAFileProviderRouterNameIsNeverMatchedOn(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	for _, slug := range []string{"standalone@file", "twin-blue@file"} {
		u := unmatchedRouter(t, out, slug)
		var said bool
		for _, line := range u.Considered {
			if strings.Contains(line, "`file` provider") {
				said = true
			}
		}
		if !said {
			t.Errorf("%s: the trace does not say rule 2 was skipped for a file router: %v",
				slug, u.Considered)
		}
	}
}

// Rule 1's narrowing: an IP-form backend URL resolves **only** through container-IP lookup, and with
// no Docker state the rule is skipped rather than guessed (§12).
//
// The generic address lookup would read `192.0.2.10:8443` as a published host port and hand the router
// to whatever service published it — which is right for a tunnel origin and wrong for a container IP.
func TestAnIPFormBackendIsSkippedWithoutDockerState(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	u := unmatchedRouter(t, out, "standalone@file")
	if u.Reason != payload.UnmatchedNoCandidate {
		t.Errorf("reason = %q, want no-candidate", u.Reason)
	}
	var said bool
	for _, line := range u.Considered {
		if strings.Contains(line, "no Docker state") && strings.Contains(line, "192.0.2.10") {
			said = true
		}
	}
	if !said {
		t.Errorf("the trace does not say the container-IP table was unavailable: %v", u.Considered)
	}
}

// Rule 3 through the shared hostname index, and what a contested hostname must do: nothing.
//
// `twin-a/blue` and `twin-b/green` both declare `twin.example.com`, so the router naming it resolves
// to neither and is reported `ambiguous`.
func TestAContestedHostRuleResolvesToNeitherService(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	u := unmatchedRouter(t, out, "twin-blue@file")
	if u.Reason != payload.UnmatchedAmbiguous {
		t.Errorf("reason = %q, want ambiguous", u.Reason)
	}
	if !strings.Contains(u.Detail, "twin-a/blue") || !strings.Contains(u.Detail, "twin-b/green") {
		t.Errorf("the detail does not name both candidates: %q", u.Detail)
	}
	for _, key := range []string{"twin-a/blue", "twin-b/green"} {
		if svc := service(t, out, key); len(svc.TraefikLive) != 0 {
			t.Errorf("%s was given the contested router", key)
		}
	}
}

// §12's one deliberate asymmetry, and the rule it protects: because an unmatched router demonstrably
// **exists**, it MUST never produce a "declared but not live" note on anybody.
//
// `twin-a/blue` declares the router `twin-blue`, which the proxy is serving — as `twin-blue@file`,
// unmatched. So `twin-a/blue` gets no note. `twin-b/green` declares `twin-green`, which the proxy
// genuinely does not have, so it does. The two sit side by side because the check that gets this wrong
// passes on one of them.
func TestARouterThatExistsProducesNoDeclaredButAbsentNote(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	blue := service(t, out, "twin-a/blue")
	if noted(blue, "not among the routers") {
		t.Errorf("twin-a/blue is told its router is absent, and the proxy is serving it: %v", blue.Notes)
	}

	green := service(t, out, "twin-b/green")
	if !noted(green, "not among the routers") {
		t.Errorf("twin-b/green declares a router the proxy does not have and is not told: %v", green.Notes)
	}
}

// The declared-but-absent check runs against **every** router in the snapshot, not only the matched
// ones (§12) — `blog` declares a router that is nowhere in the table at all.
func TestALabelDeclaringARouterTheProxyIsNotServingIsReported(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	blog := service(t, out, "blog/blog")
	if !noted(blog, "not among the routers the proxy is serving") {
		t.Errorf("blog/blog declares a router the proxy never heard of and is not told: %v", blog.Notes)
	}
	// Its label-derived posture stands: the router is absent, so there is no live chain to supersede
	// it, and an absent router is not evidence that the gate is gone.
	if got := blog.Auth.Method; got != payload.AuthAuthentikForwardAuth {
		t.Errorf("blog/blog method = %q, want %q from its labels", got, payload.AuthAuthentikForwardAuth)
	}
	if got := blog.Auth.Confidence; got != payload.ConfidenceInferred {
		t.Errorf("blog/blog confidence = %q, want inferred", got)
	}
}

// ---------------------------------------------------------------------------
// The live chain is the chain
// ---------------------------------------------------------------------------

// §12's sharpest rule: **a label declaring an auth middleware the live chain does not contain is
// downgraded** — detection suppressed, the service free to land in the exposure finding, and a note
// naming the discrepancy.
//
// `dashboards` is that service. Its labels say `authentik@file`; the chain the proxy actually built
// for it contains no authentication middleware, including anything its entrypoints attach.
func TestALabelDeclaringAGateTheLiveChainLacksIsDowngraded(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	svc := service(t, out, "dashboards/dashboards")
	if got := svc.Auth.Method; got != payload.AuthNone {
		t.Errorf("method = %q, want none — the live chain has no authentication middleware", got)
	}
	if svc.ConfiguredEdgeAuth() {
		t.Error("dashboards reads as protected on the strength of a label the proxy is not applying")
	}
	if !noted(svc, "the label-derived gate is not reported") {
		t.Errorf("the discrepancy is not named: %v", svc.Notes)
	}
	// And it is therefore in the exposure finding, which is the point of the downgrade.
	if !external(svc) {
		t.Fatal("dashboards has no external ingress, so the downgrade changes nothing")
	}
}

// A router the proxy reports as disabled counts as neither protection nor working ingress, and its
// errors MUST be quoted verbatim (§12).
func TestADisabledRouterIsNeitherIngressNorProtectionAndItsErrorIsQuoted(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	svc := service(t, out, "legacy/legacy")
	if got := svc.Auth.Method; got != payload.AuthNone {
		t.Errorf("method = %q, want none — the router carrying the gate is switched off", got)
	}
	if !noted(svc, `middleware "authentik@file" does not exist for entryPoint websecure`) {
		t.Errorf("the proxy's own error is not quoted verbatim: %v", svc.Notes)
	}
	if !noted(svc, "disabled") {
		t.Errorf("nothing says the router is disabled: %v", svc.Notes)
	}
}

// A middleware defined in a Traefik **file provider** has no definition in any scanned stack and would
// otherwise only ever be `inferred` (§12). The proxy holds five of them, and that is reported on the
// proxy service as one fact rather than five.
func TestMiddlewaresOnlyTheProxyKnowsAboutAreReportedOnce(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	proxy := service(t, out, "edge/traefik")
	if !noted(proxy, "5 middlewares that no scanned compose file defines") {
		t.Errorf("the file-provider middlewares are not reported on the proxy: %v", proxy.Notes)
	}
	// Named, in sorted order (I7), because a count alone is not actionable.
	if !noted(proxy, "`authentik@file`, `compress@file`, `dashboard-auth@file`, `secured@file` and `sso@file`") {
		t.Errorf("the middlewares are not named in sorted order: %v", proxy.Notes)
	}
}

// A basic-auth middleware in the live chain yields `basic-auth` at `confirmed` (§12) — and the proxy's
// own dashboard is what carries it here.
func TestBasicAuthInTheLiveChainIsConfirmed(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	proxy := service(t, out, "edge/traefik")
	if got := proxy.Auth.Method; got != payload.AuthBasicAuth {
		t.Errorf("method = %q, want %q", got, payload.AuthBasicAuth)
	}
	if got := proxy.Auth.Confidence; got != payload.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed — the proxy reported the middleware itself", got)
	}
}

// Only a **complete** read lets a live chain supersede a label list, because a gate attached at an
// *entrypoint* appears in no router's own middleware list. A partial read notes the gap and changes no
// posture (§12).
//
// This is the assertion that a well-meaning simplification breaks. With `/api/entrypoints` failing, the
// same routing table is in hand and `dashboards` still shows no auth middleware — but the read cannot
// prove the entrypoints attach none, so the label stands and the note says why.
func TestAPartialProxyReadChangesNoPosture(t *testing.T) {
	_, full := tfRun(t, tfMode{})
	_, partial := tfRun(t, tfMode{entrypointsFail: true})

	rep := report(t, partial, conn.TargetTraefik)
	if rep.Phase != payload.PhasePartial {
		t.Fatalf("phase = %q, want partial: the entrypoint list failed", rep.Phase)
	}
	if !rep.OK {
		t.Error("a partial read reads as a failure; the routing table did arrive (I4)")
	}
	if partial.Meta.Traefik.EntrypointsRead {
		t.Error("entrypointsRead = true after a 500")
	}
	if !strings.Contains(rep.Detail, "no live chain may supersede a label") {
		t.Errorf("the detail does not say what the gap costs: %q", rep.Detail)
	}

	// The downgrade did not happen, and that is the whole rule.
	svc := service(t, partial, "dashboards/dashboards")
	if got := svc.Auth.Method; got != payload.AuthAuthentikForwardAuth {
		t.Errorf("dashboards method = %q, want %q — a partial read may not supersede its label",
			got, payload.AuthAuthentikForwardAuth)
	}
	if !noted(svc, "entrypoint list could not be read") {
		t.Errorf("the gap is not named on the service it would have changed: %v", svc.Notes)
	}
	// The complete read is the control: same fixture, same labels, opposite conclusion.
	if got := service(t, full, "dashboards/dashboards").Auth.Method; got != payload.AuthNone {
		t.Errorf("the complete read gives dashboards %q, so the two runs do not differ", got)
	}
}

// ---------------------------------------------------------------------------
// The three-way cross-check
// ---------------------------------------------------------------------------

// Agreement, and then the two shapes of disagreement (§12).
//
// `wiki` is the case where the labels, the proxy and the identity provider all say the same thing, and
// the note records all three agreeing — because a reader who only ever sees findings has no way to
// tell *checked and consistent* from *not checked*.
func TestWhereAllThreeSourcesAgreeTheNoteSaysSo(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	svc := service(t, out, "wiki/wiki")
	if !noted(svc, "The labels, the proxy and Authentik agree") {
		t.Errorf("the agreement is not recorded: %v", svc.Notes)
	}
	if got := svc.Auth.Method; got != payload.AuthAuthentikForwardAuth {
		t.Errorf("method = %q, want %q", got, payload.AuthAuthentikForwardAuth)
	}
	if got := svc.Auth.Confidence; got != payload.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", got)
	}
}

// Disagreement one: a forward-auth address pointing at an instance with no matching application.
//
// `docs` and `metrics` are both routed through the outpost, and Authentik reports no application
// matched to either — so the gate the chain applies is not the gate anyone configured for them.
func TestAForwardAuthAddressWithNoMatchingApplicationIsAFinding(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	for _, key := range []string{"docs/docs", "metrics/metrics"} {
		svc := service(t, out, key)
		if !noted(svc, "Authentik reports no application matched to this service") {
			t.Errorf("%s: the mismatch is not reported: %v", key, svc.Notes)
		}
	}
}

// Disagreement two, and its exemption — the pair this root exists for.
//
// `crm` and `shop` differ **only** in their proxy provider's `mode`. For `crm` the mode means the
// request never reaches the outpost, so the gate Authentik describes is not in the request path and
// that is the finding. For `shop` the mode is `proxy`, where the outpost *is* the backend, so there is
// nothing to report and the service MUST come out clean.
//
// A cross-check that ignored `mode` produces a false finding on `shop`; one that exempted too much
// produces silence on `crm`.
func TestTheProviderModeDecidesWhetherTheOutpostIsInThePath(t *testing.T) {
	_, out := tfRun(t, tfMode{})

	crm := service(t, out, "crm/crm")
	if !noted(crm, "requests reach this service without passing the outpost") {
		t.Errorf("crm/crm: the mode mismatch is not reported: %v", crm.Notes)
	}

	shop := service(t, out, "shop/shop")
	for _, n := range shop.Notes {
		if strings.Contains(n, "outpost") {
			t.Errorf("shop/shop is reported against, and its provider is in `proxy` mode "+
				"where the outpost is the backend: %q", n)
		}
	}
	// Both are still protected. The finding is about the path, not about the gate's existence.
	for key, svc := range map[string]payload.Service{"crm/crm": crm, "shop/shop": shop} {
		if got := svc.Auth.Method; got != payload.AuthAuthentikForwardAuth {
			t.Errorf("%s method = %q, want %q", key, got, payload.AuthAuthentikForwardAuth)
		}
	}
}

// The cross-check needs all three sources, so this root serves the identity-provider payload from a
// second origin in the same scan (§23). Its own read must be sound, or the findings above are
// artefacts of a failed read rather than of a disagreement.
func TestTheIdentityProviderAnswersInTheSameScanFromItsOwnOrigin(t *testing.T) {
	_, out := tfRun(t, tfMode{})
	rep := report(t, out, conn.TargetAuthentik)

	if rep.Endpoint != akOutpostOrigin {
		t.Errorf("endpoint = %q, want %q — this root puts the API on the outpost", rep.Endpoint, akOutpostOrigin)
	}
	if rep.Phase != payload.PhaseConnected {
		t.Fatalf("phase = %q, want connected: %s", rep.Phase, rep.Detail)
	}
	if want := "3 applications, 3 providers, 1 outpost"; rep.Read != want {
		t.Errorf("read line = %q, want %q", rep.Read, want)
	}
}

// ---------------------------------------------------------------------------
// Two successful reads that differ
// ---------------------------------------------------------------------------

// A route leaving the table is the one thing no fixture edit can produce: two *successful* reads of the
// same files that differ only in what the proxy returned (§17).
//
// The Docker provider derives a router and its like-named service from one container, so a route leaves
// as a pair. `docs` then has a label declaring a router the proxy is no longer serving — which is the
// same note `blog` carries permanently, arrived at by a change rather than by a typo.
func TestARouteLeavingTheTableIsSeenAsARouteLeavingTheTable(t *testing.T) {
	_, before := tfRun(t, tfMode{})
	_, after := tfRun(t, tfMode{dropRoute: "docs"})

	if before.Meta.Traefik.Routers != 10 || after.Meta.Traefik.Routers != 9 {
		t.Fatalf("routers went %d → %d, want 10 → 9",
			before.Meta.Traefik.Routers, after.Meta.Traefik.Routers)
	}
	if before.Meta.Traefik.Services != 10 || after.Meta.Traefik.Services != 9 {
		t.Errorf("services went %d → %d, want 10 → 9 — a route leaves as a router and a service",
			before.Meta.Traefik.Services, after.Meta.Traefik.Services)
	}

	svc := service(t, after, "docs/docs")
	if len(svc.TraefikLive) != 0 {
		t.Errorf("docs/docs still has %d live routers", len(svc.TraefikLive))
	}
	if !noted(svc, "not among the routers the proxy is serving") {
		t.Errorf("the withdrawn route is not reported: %v", svc.Notes)
	}
	// Its gate went with it: nothing in the labels declared one, so there is nothing left to stand on.
	if got := svc.Auth.Method; got != payload.AuthNone {
		t.Errorf("docs/docs method = %q, want none once its router is gone", got)
	}
}

// I7 over the proxy integration, including the order of the unmatched-router list and of every
// middleware chain resolved recursively.
func TestTwoIdenticalTraefikScansProduceTheSameBytes(t *testing.T) {
	_, first := tfRun(t, tfMode{})
	_, second := tfRun(t, tfMode{})

	if a, b := marshal(t, first), marshal(t, second); a != b {
		t.Error("two identical scans of fixtures/traefik differ")
	}
}

// ---------------------------------------------------------------------------
// Reading the proxy read back
// ---------------------------------------------------------------------------

// unmatchedRouter finds one unmatched router by its `name@provider` and fails when it is absent —
// a router that was expected to match nothing and instead matched something is a silent regression.
func unmatchedRouter(t *testing.T, out payload.Overview, name string) payload.UnmatchedRouter {
	t.Helper()
	if out.Meta.Traefik == nil {
		t.Fatal("no proxy summary")
	}
	for _, u := range out.Meta.Traefik.UnmatchedRouters {
		if u.Router.Router == name {
			return u
		}
	}
	var have []string
	for _, u := range out.Meta.Traefik.UnmatchedRouters {
		have = append(have, u.Router.Router)
	}
	t.Fatalf("%s is not unmatched, so something claimed it; unmatched are %v", name, have)
	return payload.UnmatchedRouter{}
}
