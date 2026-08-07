package authentik

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
)

// minDerivedKey is the floor on a name-index key derived by stripping (§11).
//
// Two characters is not a name, it is a residue. Without this floor an application called
// `sso-db` would strip to `db` and pin itself to whichever service happens to be called that.
const minDerivedKey = 3

// forwardDomainMode is the proxy mode in which `external_host` is the *shared* authentication
// domain rather than the application's own address. Matching on it would attach every
// forward-domain application to the one service that answers `auth.example.com` (§11).
const forwardDomainMode = "forward_domain"

// Match is the whole match stage: which service each application was tied to, and why the rest
// were not.
type Match struct {
	// ByService is keyed on the fleet service key. Each value's three lists are parallel.
	ByService map[string]*payload.AuthentikMatch

	// Accounts is the posture accounts the matches support, keyed the same way, in the shared
	// vocabulary of §7 so that §4.2's stronger-wins rule runs in one place and not two.
	Accounts map[string][]labels.Account

	// Notes is what the match found and deliberately did not conclude, keyed the same way.
	//
	// Two things go in here, and both are things a reader would otherwise conclude wrongly from the
	// same payload:
	//
	//   - A provider whose kind needs an outpost and has none. §11 requires that be *reported as
	//     protecting nothing, with that as the stated reason*, and a note is the only place a reason
	//     can go — the account list is what the service is protected by, and this provider protects
	//     it by nothing. Without the note the payload would say a service published to the internet
	//     has no gate, while Authentik's own admin interface shows an application with a provider
	//     attached, and nothing would explain the disagreement.
	//   - An enforced proxy provider whose outpost a second ingress path does not pass. Here the
	//     account is real and reported; what the note adds is that it does not cover every way in.
	//
	// Neither is anybody's count. They are notes because §7 is where a fact that changes no figure
	// goes, and because both are statements about one service that a fleet-wide counter could only
	// blur.
	Notes map[string][]string

	// Unmatched is every application no service could be tied to, in the order the applications
	// were read (I7).
	Unmatched []payload.UnmatchedApplication
}

// Apply is §11's matching: four rules in descending strength, each requiring exactly one
// candidate.
//
// It does no network work. Everything it needs is the read and the fleet index, which is what
// makes the rules assertable as a table — the alternative is a test that needs a live Authentik to
// discover that rule 3 fires before rule 4.
func Apply(read Read, ix *fleet.Index) Match {
	m := Match{
		ByService: map[string]*payload.AuthentikMatch{},
		Accounts:  map[string][]labels.Account{},
		Notes:     map[string][]string{},
	}
	names := newNameIndex(ix)

	for _, app := range read.Applications {
		key, strength, evidence, trace := match(app, ix, names)
		if key == "" {
			m.Unmatched = append(m.Unmatched, unmatched(app, trace))
			continue
		}

		if m.ByService[key] == nil {
			m.ByService[key] = &payload.AuthentikMatch{}
		}
		got := m.ByService[key]
		got.Applications = append(got.Applications, app)
		got.Evidence = append(got.Evidence, evidence)
		got.Strength = append(got.Strength, strength)

		accounts, unenforced := accountsFor(app, strength, evidence)
		m.Accounts[key] = append(m.Accounts[key], accounts...)
		m.Notes[key] = append(m.Notes[key], unenforced...)
		m.Notes[key] = append(m.Notes[key], unpassedOutposts(app, key, ix)...)
	}
	return m
}

// MatchedServices is the count the summary reports.
func (m Match) MatchedServices() int { return len(m.ByService) }

// ---------------------------------------------------------------------------
// The trace
// ---------------------------------------------------------------------------

// outcome is what one rule did. The three that are not `matched` are the three §11 distinguishes,
// because they mean different things to a reader: nothing to go on, too much to go on, and
// something to go on that must not be resolved.
type outcome uint8

const (
	outcomeNoEvidence  outcome = iota // the rule could not run at all
	outcomeNoCandidate                // it ran and found nobody
	outcomeContested                  // it found more than one, so it must discard
	outcomeBlocked                    // it found usable evidence and deliberately declined
	outcomeMatched
)

// step is one line of the trace: which rule ran, what happened, and what it says.
type step struct {
	outcome outcome
	line    string
}

// ---------------------------------------------------------------------------
// The four rules
// ---------------------------------------------------------------------------

// match runs the four rules in order and returns the first that found exactly one service.
//
// A rule that could not run still produces a trace line. §11 requires that specifically — *No
// proxy provider, so there is no forwarded address to resolve* — because a trace with a rule
// missing reads as a rule that passed, and a reader cannot tell which.
func match(app payload.AuthentikApplication, ix *fleet.Index, names nameIndex) (key string, strength payload.AuthentikMatchStrength, evidence string, trace []step) {
	// A rebuilt record says so first. It is thinner than a listed one — no launch URL, no group,
	// only the providers this token may read — so a reader comparing two traces has to know which
	// evidence was even available (§11).
	if app.DiscoveredVia == payload.DiscoveredViaProvider {
		trace = append(trace, step{outcomeNoEvidence,
			"This application was rebuilt from a provider record because the list did not " +
				"return it, so it has no launch URL and no group to match on."})
	}

	for _, rule := range []func(payload.AuthentikApplication, *fleet.Index, nameIndex) (string, payload.AuthentikMatchStrength, string, step){
		ruleInternalHost,
		ruleURLHost,
		ruleHostname,
		ruleName,
	} {
		gotKey, gotStrength, gotEvidence, gotStep := rule(app, ix, names)
		trace = append(trace, gotStep)
		if gotKey != "" {
			return gotKey, gotStrength, gotEvidence, trace
		}
	}
	return "", "", "", trace
}

// ruleInternalHost is rule 1: a proxy provider's internal host, resolved through the address
// lookup. It is the strongest rule there is because it is not an inference at all — the provider
// is naming the address it forwards to.
func ruleInternalHost(app payload.AuthentikApplication, ix *fleet.Index, _ nameIndex) (string, payload.AuthentikMatchStrength, string, step) {
	var hosts []string
	for _, p := range app.Providers {
		if p.Kind == payload.ProviderProxy && strings.TrimSpace(p.InternalHost) != "" {
			hosts = append(hosts, p.InternalHost)
		}
	}
	if len(hosts) == 0 {
		return "", "", "", step{outcomeNoEvidence,
			"No proxy provider names an internal host, so there is no forwarded address to resolve."}
	}

	var found []string
	for _, host := range hosts {
		found = appendKeys(found, ix.ByURL(host))
	}
	switch {
	case len(found) == 1:
		return found[0], payload.StrengthAddress,
			"the proxy provider forwards to " + quote(hosts[0]), step{outcomeMatched, ""}
	case len(found) > 1:
		return "", "", "", step{outcomeContested,
			"The proxy provider's internal host " + quote(hosts[0]) + " resolves to " +
				list(found) + "."}
	default:
		return "", "", "", step{outcomeNoCandidate,
			"The proxy provider forwards to " + quote(hosts[0]) +
				", which addresses no scanned service."}
	}
}

// ruleURLHost is rule 2: a bare-name host inside a URL the provider hands out.
//
// Only a bare name. An IP literal in a redirect URI addresses the *host*, where the standard ports
// belong to the reverse proxy — reading it through the published-port table would attach the
// application to whatever answers on 443. That refusal is `blocked` rather than `no-candidate`,
// because the evidence was there and the rule declined it (§11).
func ruleURLHost(app payload.AuthentikApplication, ix *fleet.Index, _ nameIndex) (string, payload.AuthentikMatchStrength, string, step) {
	handed := handedOutURLs(app)
	if len(handed.URLs) == 0 {
		// A refusal outranks an absence. An application that carries a template *and* nothing else
		// is not an application with no URL, and reporting it as one would send an operator to
		// configure a field they already filled in (§11).
		if len(handed.Declined) > 0 {
			return "", "", "", step{outcomeBlocked, handed.Declined[0]}
		}
		return "", "", "", step{outcomeNoEvidence,
			"This application hands out no URL, so there is no host in one to resolve."}
	}

	var found, blocked []string
	var matchedURL string
	for _, raw := range handed.URLs {
		a := fleet.ParseAddress(raw)
		if a.Host == "" {
			continue
		}
		if !a.IsBareName() {
			blocked = appendOnce(blocked, a.Host)
			continue
		}
		if got := ix.ByName(a.Host); len(got) > 0 {
			found = appendKeys(found, got)
			if matchedURL == "" {
				matchedURL = raw
			}
		}
	}

	switch {
	case len(found) == 1:
		return found[0], payload.StrengthAddress,
			"a URL it hands out addresses this container: " + quote(matchedURL), step{outcomeMatched, ""}
	case len(found) > 1:
		return "", "", "", step{outcomeContested,
			"The URLs it hands out address " + list(found) + "."}
	case len(blocked) > 0:
		return "", "", "", step{outcomeBlocked,
			"The only host in a URL it hands out is " + quote(blocked[0]) +
				", which is not a container name — the standard ports there belong to the " +
				"reverse proxy, not to any one service."}
	default:
		return "", "", "", step{outcomeNoCandidate,
			"No host in a URL it hands out is a scanned container name."}
	}
}

// ruleHostname is rule 3: a hostname named by one of those URLs and declared by the service itself
// in a Cloudflare or Traefik label.
//
// The hostname index deduplicates by service key, so one service naming one hostname in both a
// tunnel route *and* a Traefik rule is one candidate rather than a contested pair (§11).
func ruleHostname(app payload.AuthentikApplication, ix *fleet.Index, _ nameIndex) (string, payload.AuthentikMatchStrength, string, step) {
	handed := handedOutURLs(app)

	var hostnames []string
	for _, raw := range handed.URLs {
		if a := fleet.ParseAddress(raw); a.Host != "" && !a.IsIP() {
			hostnames = appendOnce(hostnames, a.Host)
		}
	}
	if len(hostnames) == 0 {
		return "", "", "", step{outcomeNoEvidence,
			"This application names no hostname, so there is no declared route to match."}
	}

	var found []string
	var matched string
	for _, host := range hostnames {
		if got := ix.ByHostname(host); len(got) > 0 {
			found = appendKeys(found, got)
			if matched == "" {
				matched = host
			}
		}
	}
	switch {
	case len(found) == 1:
		return found[0], payload.StrengthHostname,
			"this service declares the hostname " + quote(matched), step{outcomeMatched, ""}
	case len(found) > 1:
		return "", "", "", step{outcomeContested,
			"The hostname " + quote(matched) + " is declared by " + list(found) + "."}
	default:
		return "", "", "", step{outcomeNoCandidate,
			"No service declares " + quote(hostnames[0]) + " in a Cloudflare or Traefik label."}
	}
}

// ruleName is rule 4: a name — the application slug, its name, or any of its providers' names —
// that identifies exactly one service's stack, compose or container name.
//
// Three forms are compared, narrowing only when the wider one found nobody: as written, with
// separators removed, and with mechanism words removed. The first form with *any* entry decides,
// and a contested entry decides against a match — because a narrower form finding one service after
// a wider form found two is not a tie broken, it is a coincidence of stripping.
func ruleName(app payload.AuthentikApplication, _ *fleet.Index, names nameIndex) (string, payload.AuthentikMatchStrength, string, step) {
	candidates := []string{app.Slug, app.Name}
	for _, p := range app.Providers {
		candidates = append(candidates, p.Name)
	}

	var tried []string
	for _, form := range []struct {
		derive func(string) string
		tight  bool
		what   string
	}{
		{func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }, false, "as written"},
		{tighten, true, "with separators removed"},
		{stripMechanism, true, "with mechanism words removed"},
	} {
		for _, raw := range candidates {
			key := form.derive(raw)
			if key == "" || len([]rune(key)) < minDerivedKey {
				continue
			}
			tried = appendOnce(tried, key)

			found := names.lookup(key, form.tight)
			if len(found) == 0 {
				continue
			}
			// The first form with any entry decides, either way.
			if len(found) > 1 {
				return "", "", "", step{outcomeContested,
					"The name " + quote(key) + " (" + form.what + ") names " + list(found) + "."}
			}
			return found[0], payload.StrengthName,
				"its name " + quote(raw) + " names this service", step{outcomeMatched, ""}
		}
	}

	if len(tried) == 0 {
		return "", "", "", step{outcomeNoEvidence,
			"Every name this application carries is shorter than " + strconv.Itoa(minDerivedKey) +
				" characters once derived, which is too short to identify a service."}
	}
	return "", "", "", step{outcomeNoCandidate,
		"None of its names matches a stack, compose or container name: tried " + list(tried) + "."}
}

// handedOut is every URL an application hands a browser, and the evidence that was deliberately
// not treated as one.
type handedOut struct {
	// URLs are the addresses the rules may resolve.
	URLs []string

	// Declined is one sentence per piece of usable evidence this refused to read as an address.
	//
	// §11 requires such a refusal reported as *blocked* rather than as an absence, and the reason
	// is what a reader does with it. "This application hands out no URL" tells an operator to go
	// and configure one. "Its launch URL addresses a different address for every user" tells them
	// the URL they already configured is not the kind of URL that can identify a service — which is
	// not something they would work out from a blank trace line, and not something they should have
	// to.
	Declined []string
}

// handedOutURLs is what an application hands a browser, and what was declined.
//
// Two refusals, and both are §11's.
//
// A launch URL may contain `%(username)s`-style placeholders. That URL addresses a different
// address for every user, so it identifies no one service and MUST NOT be matched on.
//
// An external host is matched *except* in forward-domain mode, where it is the shared
// authentication domain every forward-domain application answers on — the one service that serves
// that domain is the identity provider itself, so resolving it would attach every such application
// to the gate rather than to the thing behind it.
func handedOutURLs(app payload.AuthentikApplication) handedOut {
	var out handedOut

	if raw := strings.TrimSpace(app.LaunchURL); raw != "" {
		if isTemplate(raw) {
			out.Declined = append(out.Declined, "Its launch URL "+quote(raw)+
				" is a per-user template, which addresses a different address for every user "+
				"and so names no one service.")
		} else {
			out.URLs = appendOnce(out.URLs, raw)
		}
	}
	for _, p := range app.Providers {
		if host := strings.TrimSpace(p.ExternalHost); host != "" {
			if strings.EqualFold(p.Mode, forwardDomainMode) {
				out.Declined = append(out.Declined, "Its proxy provider is in "+
					quote(forwardDomainMode)+" mode, so the external host "+quote(host)+
					" is the authentication domain shared by every application in that mode "+
					"rather than this application's own address.")
			} else {
				out.URLs = appendOnce(out.URLs, host)
			}
		}
		for _, uri := range p.RedirectURIs {
			if raw := strings.TrimSpace(uri); raw != "" {
				out.URLs = appendOnce(out.URLs, raw)
			}
		}
	}
	return out
}

// isTemplate reports whether a URL is a per-user one. Authentik writes these as Python
// percent-formatting — `https://%(username)s.example.com` — and the marker is the placeholder
// syntax rather than any particular field name.
func isTemplate(raw string) bool {
	return strings.Contains(raw, "%(") || strings.Contains(raw, "{{") || strings.Contains(raw, "${")
}

// ---------------------------------------------------------------------------
// The name index
// ---------------------------------------------------------------------------

// nameIndex is the raw and the tight lookup, kept apart.
//
// Merged, a stack called `foo-bar` and a service called `foobar` would collide into one contested
// key and both would be discarded — two services that a reader can tell apart at a glance, made
// unmatchable by an index that could not (§11).
type nameIndex struct {
	raw   map[string][]string
	tight map[string][]string
}

func newNameIndex(ix *fleet.Index) nameIndex {
	n := nameIndex{raw: map[string][]string{}, tight: map[string][]string{}}
	if ix == nil {
		return n
	}
	for _, key := range ix.Keys() {
		svc := ix.Service(key)
		stack := ix.Stack(key)
		if svc == nil || stack == nil {
			continue
		}
		for _, name := range []string{stack.ID, svc.Name, svc.ContainerName} {
			n.add(name, key)
		}
	}
	return n
}

func (n nameIndex) add(name, key string) {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" {
		return
	}
	n.raw[low] = appendOnce(n.raw[low], key)
	if t := tighten(low); t != "" {
		n.tight[t] = appendOnce(n.tight[t], key)
	}
}

// lookup asks the raw index for a name as written and the tight index for a derived one. A derived
// key is only ever compared against derived keys: `foobar` matching the raw name `foobar` is a
// match either way, and matching it against the raw `foo-bar` is what the two indexes exist to
// prevent.
func (n nameIndex) lookup(key string, tight bool) []string {
	if tight {
		return n.tight[key]
	}
	return n.raw[key]
}

// tighten removes everything that is a separator rather than a name.
func tighten(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mechanismWords are the words that describe a mechanism rather than a thing.
//
// The list holds protocol and English words only, nothing fleet-specific — a fleet-specific entry
// would be this program guessing at somebody's naming (I2). `authentik` is deliberately absent:
// an application genuinely called `authentik` is the identity provider's own, and stripping the
// word would leave nothing and match nobody.
//
// Stripping applies to the Authentik side only. A *service* called `sso` is called that, and
// erasing the word on the fleet side would make the index unable to find it at all.
//
// `for` is here because Authentik's own provider wizard offers `Provider for <application>` as the
// default name, so it is the commonest provider name in any fleet — and leaving it in reduces that
// name to `for<something>`, which matches nothing and cannot be made to.
var mechanismWords = []string{
	"sso", "auth", "oauth", "oauth2", "oidc", "openid", "saml", "ldap", "proxy",
	"forward", "forwardauth", "gate", "login", "signin", "sign", "in", "app",
	"application", "provider", "outpost", "the", "and", "for",
}

// stripMechanism removes mechanism words from a name and tightens what is left.
func stripMechanism(s string) string {
	var kept []string
	for _, tok := range labels.Tokens(s) {
		if !isMechanismWord(tok) {
			kept = append(kept, tok)
		}
	}
	return tighten(strings.Join(kept, ""))
}

func isMechanismWord(tok string) bool {
	for _, w := range mechanismWords {
		if tok == w {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Why it was not matched
// ---------------------------------------------------------------------------

// unmatched turns a trace into the answer §11 requires: a reason, a one-line detail, and the trace
// itself with one line per rule tried in the order tried.
//
// The reason is `ambiguous` exactly when something was contested — not when something was blocked,
// which is a deliberate refusal, and not when nothing was found, which is an absence. The detail is
// the first contested line, then the first blocked one, then a generic fallback: a reader wants the
// strongest thing that went wrong, and a contested rule is a fleet problem while a blocked one is
// this program declining to guess.
func unmatched(app payload.AuthentikApplication, trace []step) payload.UnmatchedApplication {
	out := payload.UnmatchedApplication{
		Application: app,
		Reason:      payload.UnmatchedNoCandidate,
		Considered:  []string{},
	}

	var contested, blocked string
	for _, s := range trace {
		if s.line != "" {
			out.Considered = append(out.Considered, s.line)
		}
		switch {
		case s.outcome == outcomeContested && contested == "":
			contested = s.line
			out.Reason = payload.UnmatchedAmbiguous
		case s.outcome == outcomeBlocked && blocked == "":
			blocked = s.line
		}
	}

	switch {
	case contested != "":
		out.Detail = contested
	case blocked != "":
		out.Detail = blocked
	default:
		out.Detail = "Nothing this application carries identifies exactly one scanned service."
	}
	return out
}

// ---------------------------------------------------------------------------
// Posture accounts
// ---------------------------------------------------------------------------

// accountsFor is what one match says about a service's gate, in §7's vocabulary.
//
// Confidence follows the *match*, never the provider: how firmly the application was tied to this
// service is the uncertain part, and which provider protects it is what Authentik said. This
// changes no posture roll-up — precedence sorts by mechanism before confidence, and neither the
// gate test nor the exposure verdict reads confidence at all — so this is about what a reader is
// told, not about what is concluded (§11).
//
// A provider kind that maps to no AuthMethod produces no account. That is what keeps a
// SAML-protected service out of the exposure finding without claiming a mechanism §4.2 has no
// member for.
//
// The second return is the reasons — one line per provider that was configured and enforces
// nothing. They are notes rather than accounts because an account is something the service is
// protected *by*, and these protect it by nothing.
func accountsFor(app payload.AuthentikApplication, strength payload.AuthentikMatchStrength, evidence string) ([]labels.Account, []string) {
	var out []labels.Account
	var unenforced []string
	for _, p := range app.Providers {
		method, ok := Method(p.Kind)
		if !ok {
			continue
		}
		if NeedsOutpost(p.Kind) && len(p.Outposts) == 0 {
			// Assigned to no outpost, so nothing carries it. Reported as protecting nothing, with
			// that as the stated reason rather than as a silent omission (§11).
			//
			// This is the one finding in the whole program that removes protection a reader would
			// otherwise have believed in, so the sentence has to name the application and the
			// provider: without them the note is unactionable, and the operator's next step is to
			// open that provider in Authentik and assign it an outpost.
			unenforced = append(unenforced, "Authentik application "+quote(app.Slug)+" has a "+
				string(p.Kind)+" provider "+quote(p.Name)+" that is assigned to no outpost, so "+
				"nothing stands in the request path: it protects nothing")
			continue
		}

		detail := "Authentik application " + quote(app.Slug) + " has a " + string(p.Kind) + " provider"
		confidence := payload.ConfidenceConfirmed
		if strength == payload.StrengthName {
			confidence = payload.ConfidenceObserved
			detail += " — tied to this service by name alone"
		}

		acct := labels.Account{
			Method:     method,
			Detail:     detail,
			Confidence: confidence,
			Evidence:   []string{evidence},
			Live:       true,
		}
		if len(p.Outposts) > 0 {
			noun := "outpost "
			if len(p.Outposts) > 1 {
				noun = "outposts "
			}
			acct.Evidence = append(acct.Evidence, "carried by "+noun+list(p.Outposts))
		}
		if p.InternalHost != "" {
			acct.Address = p.InternalHost
		}
		out = append(out, acct)
	}
	return out, unenforced
}

// unpassedOutposts is the finding that needs both halves of this program's inputs at once: an
// enforced proxy provider, and an ingress path that does not go through the outpost enforcing it.
//
// **What it rests on.** A proxy provider's `internal_host` is the address its outpost forwards
// authenticated traffic *to*. A tunnel route resolved to `self-network` is a declared origin that
// addresses this container over a docker network. When the outpost forwards to this service and a
// tunnel also delivers to it, the tunnel is a second door into the same room and the outpost is
// standing at the first one. Neither record says this on its own: Authentik does not know a tunnel
// exists, the compose file does not know a provider exists, and both statements are ordinary.
//
// **What it does not say.** Only that the outpost is not in that path. Not that the service is
// unprotected — a tunnel route can carry a Cloudflare Access policy, which is a gate this program
// reads separately and reports as its own account — and not that anything is misconfigured, because
// an operator may have meant exactly this. Anything stronger would be a conclusion drawn from two
// facts that are individually normal.
//
// It is deliberately narrow in three ways. The provider must be enforced, so `orphan`'s
// outpost-less provider produces the *other* note and not this one — there is no enforcement to
// route around, and claiming a bypass would be doubly wrong. The provider's internal host must
// resolve to *this* service, so a provider forwarding somewhere else is not made this service's
// problem. And the origin must be `self-network`, which is the one resolution that means *straight
// to the container*: an origin that resolved to another scanned service is a hop, and that hop is
// where the gate on that path is to be looked for.
func unpassedOutposts(app payload.AuthentikApplication, key string, ix *fleet.Index) []string {
	svc := ix.Service(key)
	if svc == nil {
		return nil
	}

	var out []string
	for _, p := range app.Providers {
		if p.Kind != payload.ProviderProxy || !p.Enforced() || p.InternalHost == "" {
			continue
		}
		if forwarded, ok := fleet.GateService(ix, p.InternalHost); !ok || forwarded != key {
			continue
		}
		for _, route := range svc.Cloudflare {
			if route.Origin == nil || route.Origin.Kind != payload.OriginSelfNetwork {
				continue
			}
			noun := "outpost "
			if len(p.Outposts) > 1 {
				noun = "outposts "
			}
			out = append(out, "the tunnel route for "+quote(route.Hostname)+" delivers to "+
				quote(route.Origin.Address)+", which is the address the "+noun+list(p.Outposts)+
				" enforcing Authentik application "+quote(app.Slug)+" forwards to — so a request "+
				"arriving over the tunnel does not pass that outpost")
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Wording
// ---------------------------------------------------------------------------

func quote(s string) string { return "`" + s + "`" }

// list is a human list of service keys or names, sorted so that a trace line is the same line on
// two reads (I7).
func list(in []string) string {
	got := append([]string{}, in...)
	sort.Strings(got)
	for i, v := range got {
		got[i] = quote(v)
	}
	switch len(got) {
	case 0:
		return "nothing"
	case 1:
		return got[0]
	case 2:
		return got[0] + " and " + got[1]
	default:
		return strings.Join(got[:len(got)-1], ", ") + " and " + got[len(got)-1]
	}
}

func appendKeys(into []string, keys []string) []string {
	for _, k := range keys {
		into = appendOnce(into, k)
	}
	return into
}

func appendOnce(into []string, v string) []string {
	for _, existing := range into {
		if existing == v {
			return into
		}
	}
	return append(into, v)
}
