package corpus

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
)

// `fixtures/authentik` is §11 end to end: discovery over a fleet that offers four plausible
// addresses and serves the API on exactly one, the two-pass assembly that recovers what a
// least-privilege token cannot list, the four matching rules, and the applications that MUST match
// nothing.
//
// Every run here goes through the injected transport, so the assertions are about a scan and not
// about a unit. What the stub *recorded* carries as much weight as what it served: §11's rule that a
// discovered endpoint is a guess and a guess is never handed a credential is a statement about a
// request that must not exist, and the call log is the only place to see it.

// akRun is one scan of the root with the identity provider switched on.
//
// The token goes in because a read that is enabled needs one to send; `hides` is how much of its own
// list the instance will serve back (see akMode).
func akRun(t *testing.T, mode akMode) (*recorder, payload.Overview) {
	t.Helper()
	rec, rt := authentikStub(t, mode)
	out := scanRoot(t, "authentik", scanOptions{
		rt: rt,
		mutate: func(c *config.Config) {
			c.Authentik.Enabled = true
			c.Authentik.Token = akToken
		},
	})
	return rec, out
}

// ---------------------------------------------------------------------------
// The root is what it claims to be
// ---------------------------------------------------------------------------

func TestTheAuthentikRootIsCountedExactlyOnce(t *testing.T) {
	_, out := akRun(t, akMode{})

	if got := out.Stats.Stacks; got != 14 {
		t.Errorf("stacks = %d, want 14; a directory was double-counted or missed", got)
	}
	if got := out.Stats.Services; got != 18 {
		t.Errorf("services = %d, want 18", got)
	}
}

// ---------------------------------------------------------------------------
// Discovery, and the credential that must not follow a guess
// ---------------------------------------------------------------------------

// §11: candidates are ordered internal addresses before public hostnames, each is probed on
// `/api/v3/root/config/`, and **only a candidate that answers with a JSON object may receive the
// token**.
//
// This root is built so that the obvious guesses are wrong. The published host port is 9443, the
// public hostname is `sso.example.com`, and the outpost runs a `goauthentik` image too — so it is a
// candidate, and it answers 404. A reader that reached for the published port, the hostname, or the
// first `goauthentik` image it found would land somewhere that is not the API.
func TestTheEndpointIsTheOneAddressThatAnsweredAndNotTheObviousGuess(t *testing.T) {
	_, out := akRun(t, akMode{})
	rep := report(t, out, conn.TargetAuthentik)

	if rep.Endpoint != akOrigin {
		t.Errorf("endpoint = %q, want %q", rep.Endpoint, akOrigin)
	}
	if rep.Source != payload.SourceDiscovered {
		t.Errorf("endpoint source = %q, want discovered — nothing configured this address", rep.Source)
	}
	// The phase belongs to the two tests below — under this token the read is `partial`, and for a
	// reason that is about the application list rather than about which address answered. What matters
	// here is that discovery *arrived*: an endpoint with a `read` line behind it.
	if rep.Read == "" {
		t.Errorf("nothing was read from %s", rep.Endpoint)
	}

	// The rejected candidates are named, with what made each one a candidate (§15). An attempt list
	// that recorded the failure without the evidence would leave an operator with no way to tell a
	// wrong guess from a broken instance.
	if len(rep.Attempts) == 0 {
		t.Fatal("no attempts recorded, so discovery's walk is invisible")
	}
	for _, a := range rep.Attempts {
		if a.Endpoint == akOrigin {
			t.Errorf("the endpoint that answered is also listed as a failed attempt")
		}
		if a.Why == "" {
			t.Errorf("attempt %s carries no evidence for why it was a candidate", a.Endpoint)
		}
	}
}

// The rule an accident would break, stated against the call log.
//
// Every candidate is asked anonymously first. Only the one that answered may then be asked with the
// token — and the outpost, which answered 404, must never see it.
func TestTheTokenReachesOnlyTheAddressThatProvedItselfAnAPI(t *testing.T) {
	rec, _ := akRun(t, akMode{})

	for _, address := range rec.authenticated() {
		if !strings.HasPrefix(address, akOrigin+"/") {
			t.Errorf("the token was sent to %s, which never proved it was Authentik", address)
		}
	}

	// The handshake itself must be anonymous, or the check above is satisfied trivially by a walk
	// that authenticated nowhere because it probed nowhere.
	handshake := akOrigin + "/api/v3/root/config/"
	if !rec.asked(handshake) {
		t.Fatalf("%s was never asked, so nothing proved this address was an API", handshake)
	}
	for _, c := range rec.all() {
		if strings.HasSuffix(c.URL, "/api/v3/root/config/") && c.Credential {
			t.Errorf("the anonymous handshake to %s carried a credential", c.URL)
		}
	}
	if !rec.asked(akOutpostOrigin + "/api/v3/root/config/") {
		t.Error("the outpost was never probed, so the 404 branch of discovery is untested here")
	}
}

// ---------------------------------------------------------------------------
// §23's required conclusion
// ---------------------------------------------------------------------------

// The summary line's numbers are a required conclusion for this root (§23).
//
// They come from the run in which recovery closes the entire gap: the instance hides only the two
// withheld applications a provider list can rebuild, so all sixteen are accounted for and the read is
// `connected` rather than `partial`. `14 of 16` is the shortfall — fourteen served to this token out
// of the sixteen Authentik says exist — and the parenthesis is how much of it the provider lists
// closed.
//
// Asserted as the whole line rather than field by field, because the line is what an operator reads
// and because the arithmetic between the five numbers is the thing that can go wrong: a `listed` that
// silently included the rebuilt records would still produce five plausible numbers.
func TestTheReadLineIsTheRequiredConclusionForThisRoot(t *testing.T) {
	_, out := akRun(t, akMode{hides: []string{"rec-01", "wh-02"}})
	rep := report(t, out, conn.TargetAuthentik)

	const want = "14 of 16 applications (2 recovered from providers), 17 providers, 2 outposts"
	if rep.Read != want {
		t.Errorf("read line:\n got  %q\n want %q", rep.Read, want)
	}

	// The same numbers, in the fields the UI reads, so a change that fixed the prose without fixing
	// the counts still fails.
	ak := out.Meta.Authentik
	if ak == nil {
		t.Fatal("no identity-provider summary on a connected read")
	}
	if ak.ApplicationsConfigured == nil {
		t.Fatal("the unfiltered total was dropped; the shortfall rests on it (§11)")
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"applications", ak.Applications, 16},
		{"applicationsConfigured", *ak.ApplicationsConfigured, 16},
		{"applicationsWithheld", ak.ApplicationsWithheld, 2},
		{"applicationsRecovered", ak.ApplicationsRecovered, 2},
		{"providers", ak.Providers, 17},
		{"outposts", ak.Outposts, 2},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	// Recovery closed the gap, so there is nothing left to be partial about (§11).
	if rep.Phase != payload.PhaseConnected {
		t.Errorf("phase = %q, want connected: recovery closed the whole gap", rep.Phase)
	}
	if ak.Error != "" {
		t.Errorf("a read with no shortfall still reported %q", ak.Error)
	}
}

// The default run is the least-privilege token most fleets will use, and it is the one the shortfall
// reporting has to be honest under: the third withheld application is assigned a SAML provider, a
// kind LabView does not read, so nothing names it and recovery cannot reach it.
//
// `partial` exactly when that difference is non-zero (§11) — not merely when something was withheld.
func TestWhatRecoveryCannotReachIsReportedAsPartialAndCountedHonestly(t *testing.T) {
	_, out := akRun(t, akMode{})
	rep := report(t, out, conn.TargetAuthentik)
	ak := out.Meta.Authentik

	if rep.Phase != payload.PhasePartial {
		t.Fatalf("phase = %q, want partial: one withheld application could not be rebuilt", rep.Phase)
	}
	if ak.ApplicationsWithheld != 3 || ak.ApplicationsRecovered != 2 {
		t.Errorf("withheld/recovered = %d/%d, want 3/2", ak.ApplicationsWithheld, ak.ApplicationsRecovered)
	}
	// `withheld − recovered` is derived and never stored (§11), so the assertion is on what the
	// difference produced rather than on a field holding it.
	if !strings.Contains(rep.Detail, "1 of 3 applications") {
		t.Errorf("detail does not name the shortfall: %q", rep.Detail)
	}
	if !strings.Contains(rep.Read, "1 not visible to this token") {
		t.Errorf("read line does not carry the invisible count: %q", rep.Read)
	}
	// Both fixes, because either one resolves it and an operator holding a read-only token needs to
	// know which (§11).
	if rep.Hint == "" {
		t.Error("a partial read names no fix")
	}
}

// The superuser run is the widening one: `superuser_full_list=true` is sent unconditionally and is
// honoured here, so nothing is withheld and the two-pass assembly has nothing to recover.
//
// It is also where the parameter is proved to be sent at all. Sending it to an ordinary token proves
// nothing, which is why the stub requires both it and a superuser instance.
func TestASuperuserTokenIsServedTheWholeListAndNothingNeedsRecovering(t *testing.T) {
	rec, out := akRun(t, akMode{superuser: true})
	rep := report(t, out, conn.TargetAuthentik)
	ak := out.Meta.Authentik

	if rep.Phase != payload.PhaseConnected {
		t.Errorf("phase = %q, want connected: the whole list was served", rep.Phase)
	}
	if ak.ApplicationsWithheld != 0 || ak.ApplicationsRecovered != 0 {
		t.Errorf("withheld/recovered = %d/%d, want 0/0",
			ak.ApplicationsWithheld, ak.ApplicationsRecovered)
	}
	if ak.Applications != 16 {
		t.Errorf("applications = %d, want 16 — the whole list, none of it rebuilt", ak.Applications)
	}
	for _, app := range allApplications(out) {
		if app.DiscoveredVia != payload.DiscoveredViaList {
			t.Errorf("%s was rebuilt from a provider on a run that withheld nothing", app.Slug)
		}
	}

	// Sent on that one request and nowhere else — it is a property of the application list, and a
	// reader that appended it to every endpoint would be sending a parameter the others do not have.
	var sawOn, alsoOn []string
	for _, c := range rec.all() {
		if !strings.Contains(c.URL, "superuser_full_list=true") {
			continue
		}
		if strings.Contains(c.URL, "/core/applications/") {
			sawOn = append(sawOn, c.URL)
		} else {
			alsoOn = append(alsoOn, c.URL)
		}
	}
	if len(sawOn) == 0 {
		t.Error("superuser_full_list=true was never sent to the application list")
	}
	if len(alsoOn) > 0 {
		t.Errorf("superuser_full_list=true was sent to %v, which is not the application list", alsoOn)
	}
}

// ---------------------------------------------------------------------------
// The two passes
// ---------------------------------------------------------------------------

// §11: pass two skips any slug pass one produced — the list response wins, because it alone carries
// the launch URL and the group — and rebuilds the rest **in slug order** (I7).
//
// The fixture assigns every provider an application, so eleven of them name a slug pass one already
// returned. A recovery pass that did not defer to the list would duplicate all eleven and would strip
// the launch URLs off them.
func TestTheListWinsAndOnlyWhatItWithheldIsRebuilt(t *testing.T) {
	_, out := akRun(t, akMode{})

	seen := map[string]int{}
	var rebuilt []string
	for _, app := range allApplications(out) {
		seen[app.Slug]++
		if app.DiscoveredVia == payload.DiscoveredViaProvider {
			rebuilt = append(rebuilt, app.Slug)
		}
	}
	for slug, n := range seen {
		if n > 1 {
			t.Errorf("%s appears %d times; the recovery pass duplicated a listed application", slug, n)
		}
	}

	// Both recovered slugs, in slug order. `hidden-01` is absent because its SAML provider is a kind
	// LabView does not read, which is the outcome recovery cannot close.
	if got := strings.Join(rebuilt, ","); got != "rec-01,wh-02" {
		t.Errorf("rebuilt = %q, want %q (slug order, I7)", got, "rec-01,wh-02")
	}
}

// A rebuilt record is the narrower thing it is, and it MUST say so as the first line of its match
// trace (§11).
//
// `wh-02` is the case that proves it: recovered, then unmatched, because its provider addresses an
// unrelated external host. So the trace is readable and the reason is not *we never heard of it*.
func TestARebuiltRecordIsThinnerAndItsTraceSaysSoFirst(t *testing.T) {
	_, out := akRun(t, akMode{})

	u := unmatched(t, out, "wh-02")
	if u.Application.DiscoveredVia != payload.DiscoveredViaProvider {
		t.Fatalf("wh-02 discoveredVia = %q, want provider", u.Application.DiscoveredVia)
	}
	if u.Application.LaunchURL != "" {
		t.Errorf("a rebuilt record carries a launch URL %q; only the list response has one",
			u.Application.LaunchURL)
	}
	if len(u.Considered) == 0 {
		t.Fatal("no match trace on an unmatched application")
	}
	if first := u.Considered[0]; !strings.Contains(first, "rebuilt from a provider") {
		t.Errorf("the trace does not open by saying the record was rebuilt: %q", first)
	}
}

// `rec-01` is the other side: rebuilt, and then matched anyway, because its provider's redirect URI
// names a container. A rebuilt record can be tied by address or by name — never by a launch URL,
// because it has none.
func TestARebuiltRecordCanStillBeTiedByAnAddress(t *testing.T) {
	_, out := akRun(t, akMode{})

	svc := service(t, out, "archive/archive")
	if svc.Authentik == nil {
		t.Fatal("archive/archive has no identity-provider match")
	}
	i := indexOfApp(svc.Authentik.Applications, "rec-01")
	if i < 0 {
		t.Fatalf("rec-01 did not reach archive/archive; it has %v", slugsOf(svc.Authentik.Applications))
	}
	if got := svc.Authentik.Applications[i].DiscoveredVia; got != payload.DiscoveredViaProvider {
		t.Errorf("rec-01 discoveredVia = %q, want provider", got)
	}
	if got := strengthAt(*svc.Authentik, i); got != payload.StrengthAddress {
		t.Errorf("rec-01 strength = %q, want address — its redirect URI names a container", got)
	}
}

// ---------------------------------------------------------------------------
// The four matching rules
// ---------------------------------------------------------------------------

// Each application below is reachable by exactly one rule and unreachable by the others, so a
// reverted rule leaves its service unmatched rather than merely matched for a different reason.
//
// That is the fixture-revert contract (§23) applied to matching: a table that asserted only *matched*
// would pass with all four rules collapsed into one.
func TestEachMatchingRuleIsPinnedByAnApplicationOnlyItCanReach(t *testing.T) {
	_, out := akRun(t, akMode{})

	for _, c := range []struct {
		service  string
		slug     string
		strength payload.AuthentikMatchStrength
		rule     string
	}{
		{"wiki/wiki", "wiki-internal", payload.StrengthAddress,
			"rule 1 — a proxy provider's internal host, through the address lookup"},
		{"notebook/notebook", "nb-app", payload.StrengthAddress,
			"rule 2 — a bare-name host inside a URL the provider hands out"},
		{"docs/docs", "documentation", payload.StrengthHostname,
			"rule 3 — a hostname the service declares in a Traefik or Cloudflare label"},
		{"home-assistant/hass", "ha-portal", payload.StrengthName,
			"rule 4 — the application name once separators are normalised"},
		{"ledger/ledger", "fin-01", payload.StrengthName,
			"rule 4 — a provider name once the mechanism words are dropped"},
	} {
		svc := service(t, out, c.service)
		if svc.Authentik == nil {
			t.Errorf("%s: no match at all, so %s did not run", c.service, c.rule)
			continue
		}
		i := indexOfApp(svc.Authentik.Applications, c.slug)
		if i < 0 {
			t.Errorf("%s: %s did not reach it (has %v), so %s did not run",
				c.service, c.slug, slugsOf(svc.Authentik.Applications), c.rule)
			continue
		}
		if got := strengthAt(*svc.Authentik, i); got != c.strength {
			t.Errorf("%s: %s matched at strength %q, want %q (%s)",
				c.service, c.slug, got, c.strength, c.rule)
		}
		// Evidence is parallel to applications and is what I1 requires: the conclusion names what it
		// rests on.
		if i < len(svc.Authentik.Evidence) && strings.TrimSpace(svc.Authentik.Evidence[i]) == "" {
			t.Errorf("%s: %s matched on no stated evidence", c.service, c.slug)
		}
	}
}

// Confidence follows the match, not the provider (§11): `name` is `observed` and says so.
func TestAMatchByNameAloneIsObservedAndTheDetailSaysWhy(t *testing.T) {
	_, out := akRun(t, akMode{})

	svc := service(t, out, "home-assistant/hass")
	if svc.Authentik == nil {
		t.Fatal("home-assistant/hass has no match")
	}
	i := indexOfApp(svc.Authentik.Applications, "ha-portal")
	if i < 0 {
		t.Fatal("ha-portal did not reach home-assistant/hass")
	}
	if got := strengthAt(*svc.Authentik, i); got != payload.StrengthName {
		t.Fatalf("ha-portal strength = %q, want name", got)
	}

	// The confidence and the sentence that explains it both hang off the resolved posture rather than
	// off the match, because that is where a reader meets them: the drawer shows *how do we know* next
	// to the method, not next to the application list.
	if got := svc.Auth.Confidence; got != payload.ConfidenceObserved {
		t.Errorf("confidence = %q, want observed for a match by name alone", got)
	}
	if !strings.Contains(svc.Auth.Detail, "tied to this service by name alone") {
		t.Errorf("the detail does not say the tie was by name alone: %q", svc.Auth.Detail)
	}

	// And it changes no posture roll-up (§11): precedence sorts by mechanism before confidence, so an
	// observed OAuth gate is still an OAuth gate.
	if got := svc.Auth.Method; got != payload.AuthAuthentikOAuth {
		t.Errorf("method = %q, want %q — confidence must not weaken the mechanism",
			got, payload.AuthAuthentikOAuth)
	}
}

// ---------------------------------------------------------------------------
// The applications that MUST match nothing
// ---------------------------------------------------------------------------

// Four deliberate non-matches, each for a different reason, and each carrying that reason (§11: *why
// it was not matched is part of the answer*).
//
// `blocked` is the distinction worth having: a rule that found usable evidence and declined to
// resolve it is not the same as a rule that found nothing, and an operator reading `no-candidate`
// with no detail cannot tell which happened.
func TestAnApplicationThatIdentifiesNoOneServiceSaysWhyItDidNot(t *testing.T) {
	_, out := akRun(t, akMode{})

	for _, c := range []struct {
		slug   string
		reason payload.UnmatchedReason
		detail string
		why    string
	}{
		{"broad-app", payload.UnmatchedNoCandidate, "forward_domain",
			"an external host in forward_domain mode is the shared authentication domain"},
		{"ext-01", payload.UnmatchedNoCandidate, "not a container name",
			"an IP literal in a redirect URI addresses the host, where the standard ports belong to the proxy"},
		{"pair", payload.UnmatchedAmbiguous, "names `pair/blue` and `pair/green`",
			"a contested name decides against a match"},
		{"s01", payload.UnmatchedNoCandidate, "identifies exactly one scanned service",
			"a derived key shorter than three characters must not match"},
	} {
		u := unmatched(t, out, c.slug)
		if u.Reason != c.reason {
			t.Errorf("%s reason = %q, want %q (%s)", c.slug, u.Reason, c.reason, c.why)
		}
		if !strings.Contains(u.Detail, c.detail) {
			t.Errorf("%s detail does not mention %q (%s):\n %q", c.slug, c.detail, c.why, u.Detail)
		}
		// One line per rule tried, in the order tried — including the rules that could not run, which
		// MUST say so rather than be omitted (§11).
		if len(u.Considered) < 4 {
			t.Errorf("%s: trace has %d lines, want one per rule tried: %v",
				c.slug, len(u.Considered), u.Considered)
		}
	}
}

// The ambiguous application is the one that would do visible damage if arbitrated: `pair` names two
// services, and a match that picked either would claim a gate on a service that has none.
func TestAnAmbiguousApplicationClaimsAGateOnNeitherService(t *testing.T) {
	_, out := akRun(t, akMode{})

	for _, key := range []string{"pair/blue", "pair/green"} {
		svc := service(t, out, key)
		if svc.Authentik != nil {
			t.Errorf("%s was matched by the ambiguous `pair` application: %v",
				key, slugsOf(svc.Authentik.Applications))
		}
		if svc.ConfiguredEdgeAuth() {
			t.Errorf("%s reads as protected on the strength of an ambiguous match", key)
		}
	}
}

// A per-user launch URL template addresses a different address for every user, so it names no one
// service and MUST NOT be matched on (§11).
func TestAPerUserLaunchTemplateIsNotAnAddress(t *testing.T) {
	_, out := akRun(t, akMode{})

	u := unmatched(t, out, "pair")
	var said bool
	for _, line := range u.Considered {
		if strings.Contains(line, "per-user template") {
			said = true
		}
	}
	if !said {
		t.Errorf("the trace does not say the launch URL was a per-user template: %v", u.Considered)
	}
}

// ---------------------------------------------------------------------------
// What a provider means
// ---------------------------------------------------------------------------

// §11's provider table, asserted through the two services that sit either side of it.
//
// A proxy provider needs an outpost in the request path, so one assigned to none protects nothing —
// and `orphan` must therefore stay in the exposure finding. A SAML provider is enforced by the
// Authentik server itself, so `reports` is protected even though §4.2 has no `AuthMethod` member for
// SAML — which is the whole reason `ConfiguredEdgeAuth` and `Auth.Method` are different questions.
func TestAProviderProtectsSomethingOnlyWhenSomethingEnforcesIt(t *testing.T) {
	_, out := akRun(t, akMode{})

	orphan := service(t, out, "orphan/orphan")
	if orphan.Authentik == nil {
		t.Fatal("orphan/orphan has no match, so the no-outpost case is untested")
	}
	if orphan.ConfiguredEdgeAuth() {
		t.Error("a proxy provider assigned to no outpost reads as protecting orphan/orphan")
	}
	if !noted(orphan, "outpost") {
		t.Errorf("nothing says why the match protects nothing: %v", orphan.Notes)
	}

	reports := service(t, out, "reports/reports")
	if reports.Authentik == nil {
		t.Fatal("reports/reports has no match")
	}
	if !reports.ConfiguredEdgeAuth() {
		t.Error("a SAML provider is enforced by the server, so reports/reports is protected")
	}
	if reports.Auth.Method != payload.AuthNone {
		t.Errorf("reports/reports method = %q; SAML maps to no AuthMethod (§4.2)", reports.Auth.Method)
	}
}

// LDAP is a backchannel provider, so the backchannel list has to be read as well as the primary one —
// reading only the primary misses every LDAP gate (§11).
func TestABackchannelProviderIsReadAndIsAGate(t *testing.T) {
	_, out := akRun(t, akMode{})

	svc := service(t, out, "vault/vault")
	if got := svc.Auth.Method; got != payload.AuthAuthentikLDAP {
		t.Errorf("vault/vault method = %q, want %q — its only provider is a backchannel LDAP one",
			got, payload.AuthAuthentikLDAP)
	}
	if svc.Authentik == nil || !svc.Authentik.Enforced() {
		t.Error("vault/vault's LDAP provider does not read as enforced")
	}
}

// ---------------------------------------------------------------------------
// What the counts say about the fleet
// ---------------------------------------------------------------------------

// The roll-up, and the two rules inside it that a naive count would get wrong: a protected service
// with no ingress is nobody's `authProtected`, and the four services that reach the outside with
// nothing in front of them are the exposure finding.
func TestTheCountsFollowIngressAndNotMerelyProtection(t *testing.T) {
	_, out := akRun(t, akMode{})

	if got := out.Meta.Authentik.MatchedServices; got != 10 {
		t.Errorf("matchedServices = %d, want 10", got)
	}
	if got := out.Stats.AuthProtected; got != 8 {
		t.Errorf("authProtected = %d, want 8", got)
	}

	// home-assistant is protected and has no ingress, which is why the two numbers differ.
	hass := service(t, out, "home-assistant/hass")
	if !hass.ConfiguredEdgeAuth() {
		t.Error("home-assistant/hass is not protected, so it cannot be the reason for the gap")
	}
	if external(hass) {
		t.Errorf("home-assistant/hass ingress = %v, want nothing external", hass.Ingress)
	}

	if got := out.Stats.ExposedWithoutAuth; got != 4 {
		t.Errorf("exposedWithoutAuth = %d, want 4", got)
	}

	// Recomputed from the payload rather than read back off the counter, so the two have to agree.
	// `external` and not *has any ingress at all*: `internal` and `none` are both reachability a
	// finding about the outside world has nothing to say about, and counting them would put four
	// databases in the exposure list.
	exposed := map[string]bool{}
	for _, key := range keys(out) {
		if svc := find(out, key); external(*svc) && !svc.ConfiguredEdgeAuth() {
			exposed[key] = true
		}
	}
	for _, key := range []string{"idp/server", "orphan/orphan", "pair/blue", "pair/green"} {
		if !exposed[key] {
			t.Errorf("%s is not in the exposure finding, and it reaches the outside with no gate", key)
		}
	}
	if len(exposed) != 4 {
		t.Errorf("the exposure finding holds %d services, want 4: %v", len(exposed), exposed)
	}
}

// I7, over the whole integration: the same input produces the same bytes, including the order of the
// two assembly passes and of every parallel array hanging off a match.
func TestTwoIdenticalAuthentikScansProduceTheSameBytes(t *testing.T) {
	_, first := akRun(t, akMode{})
	_, second := akRun(t, akMode{})

	if a, b := marshal(t, first), marshal(t, second); a != b {
		t.Error("two identical scans of fixtures/authentik differ")
	}
}

// ---------------------------------------------------------------------------
// Reading a match back
// ---------------------------------------------------------------------------

// external is whether a service reaches the outside world — §4.1's `public`, `traefik` or `lan`.
//
// Through IsExternal rather than by listing the three members, so a new externally-reachable kind
// joins this test's arithmetic by being added to the vocabulary and nowhere else.
func external(s payload.Service) bool {
	for _, k := range s.Ingress {
		if k.IsExternal() {
			return true
		}
	}
	return false
}

// allApplications is every application record in the payload, from every matched service plus the
// unmatched list — which together is what the read assembled.
func allApplications(out payload.Overview) []payload.AuthentikApplication {
	var list []payload.AuthentikApplication
	for _, key := range keys(out) {
		if svc := find(out, key); svc != nil && svc.Authentik != nil {
			list = append(list, svc.Authentik.Applications...)
		}
	}
	if out.Meta.Authentik != nil {
		for _, u := range out.Meta.Authentik.UnmatchedApplications {
			list = append(list, u.Application)
		}
	}
	return list
}

// unmatched finds one unmatched application by slug and fails when it is absent — an application that
// was expected to match nothing and instead matched something is a silent regression, so the failure
// says which.
func unmatched(t *testing.T, out payload.Overview, slug string) payload.UnmatchedApplication {
	t.Helper()
	if out.Meta.Authentik == nil {
		t.Fatal("no identity-provider summary")
	}
	for _, u := range out.Meta.Authentik.UnmatchedApplications {
		if u.Application.Slug == slug {
			return u
		}
	}
	var have []string
	for _, u := range out.Meta.Authentik.UnmatchedApplications {
		have = append(have, u.Application.Slug)
	}
	t.Fatalf("%s is not unmatched, so something claimed it; unmatched are %v", slug, have)
	return payload.UnmatchedApplication{}
}

func indexOfApp(apps []payload.AuthentikApplication, slug string) int {
	for i, app := range apps {
		if app.Slug == slug {
			return i
		}
	}
	return -1
}

func slugsOf(apps []payload.AuthentikApplication) []string {
	out := make([]string, 0, len(apps))
	for _, app := range apps {
		out = append(out, app.Slug)
	}
	return out
}

// strengthAt reads the parallel strength array, applying §11's rule that a Strength shorter than
// Applications reads as StrengthName for the remainder — never as the strongest.
func strengthAt(m payload.AuthentikMatch, i int) payload.AuthentikMatchStrength {
	if i < len(m.Strength) {
		return m.Strength[i]
	}
	return payload.StrengthName
}
