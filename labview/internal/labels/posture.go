package labels

import (
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
)

// providerNotIdentified is the evidence line §7 requires on a mechanism whose provider could
// not be named. It is the honest end of the hint rule: the mechanism is real, and who runs it
// is not something the scanned configuration said.
const providerNotIdentified = "provider not identified from the scanned config"

// noGateNamed is the evidence for a `none` posture. It states what was read rather than
// leaving the strongest finding in the report resting on an empty list.
const noGateNamed = "no gate is named by this service's labels or environment"

// Account is one account of one service's gate: what it is, how it was established, and the
// evidence for it.
//
// Every source produces accounts and none produces a verdict, because §4.2's rule is about
// two accounts of one service disagreeing — the stronger reported, the weaker kept as
// evidence — and that rule can only run in one place if the sources all speak the same
// vocabulary. Resolve is that place.
type Account struct {
	Method     payload.AuthMethod
	Detail     string
	Confidence payload.AuthConfidence
	Evidence   []string
	// Address is where the gate this account describes is reached, when its definition named
	// one. It is carried rather than only quoted in evidence so that the service answering that
	// address can be found and the gate drawn *on* the ingress path (§22.5) — resolving it is
	// the fleet index's job, and re-walking the middleware chain to recover it here would be a
	// second implementation of §7's recursion.
	Address string

	// Live says an integration read this account off a running system — the proxy's own chain, the
	// identity provider's own records — rather than from a scanned configuration value.
	//
	// It decides nothing on its own; it is only the tie-break in the ordering, for the case §4.2's
	// two keys leave undecided. See ordered.
	Live bool
}

// Input is everything the label reading of a posture needs. The service arrives with its
// Cloudflare and Traefik routes already read, because those are the routes this reads.
type Input struct {
	Service  payload.Service
	Registry Registry
	Hints    Hints

	// LDAPEnvHints are matched against environment *keys* by equality; OAuthEnvHints as
	// substrings of a key. Both are configurable, so neither may be trusted with a value:
	// no environment value ever reaches an evidence line from here (I6). What a matched
	// value can do is name a provider, and then the *hint* is what gets quoted.
	LDAPEnvHints  []string
	OAuthEnvHints []string
}

// FromLabels is every account one service's labels and environment support, plus the notes
// §7 requires (§5, stage 12a).
//
// The order accounts come out in does not decide anything — Resolve orders them — but it is
// fixed anyway: routers by name, middlewares in the order the chain was written, then the
// environment in the order §6 resolved it (I7).
func FromLabels(in Input) ([]Account, []string) {
	var accounts []Account
	var notes []string

	for _, route := range in.Service.Traefik {
		for _, ref := range route.Middlewares {
			got, gotNotes := in.classify(ref, route.Router, 0, map[string]bool{})
			accounts = append(accounts, got...)
			notes = append(notes, gotNotes...)
		}
	}
	accounts = append(accounts, in.fromAccessPolicies()...)
	accounts = append(accounts, in.fromEnv()...)

	return collapse(accounts), dedupeStrings(notes)
}

// classify reads one middleware reference (§7).
//
// The registry definition is consulted first and the name only when no stack defines the
// middleware anywhere. That order is the whole of I3 in this file: a middleware called
// `authentik` whose address points at somebody else's gatekeeper is that gatekeeper, and the
// only way to know is to read the definition.
func (in Input) classify(ref, router string, depth int, seen map[string]bool) ([]Account, []string) {
	bare := BareName(ref)
	if bare == "" || depth > maxChainDepth || seen[bare] {
		return nil, nil
	}
	seen[bare] = true

	def, ok := in.Registry.Lookup(ref)
	if !ok {
		return in.fromName(ref, router)
	}
	applied := "router " + quote(router) + " applies middleware " + quote(ref)

	switch strings.ToLower(def.Type) {
	case "forwardauth":
		address := strings.TrimSpace(def.Fields["address"])
		acct := Account{
			Method:     payload.AuthForwardAuth,
			Detail:     strings.TrimSpace(ref),
			Confidence: payload.ConfidenceObserved,
			Address:    address,
			Evidence: []string{applied,
				"middleware " + quote(bare) + " is a forwardauth to " +
					secrets.RedactURIs(address) + ", defined by " + def.Where()},
		}
		if hint, matched := in.Hints.Match(address); matched {
			acct.Method = payload.AuthAuthentikForwardAuth
			acct.Evidence = append(acct.Evidence, "its address names "+quote(hint))
		} else {
			acct.Evidence = append(acct.Evidence, providerNotIdentified)
		}
		return []Account{acct}, nil

	case "basicauth", "digestauth":
		// The fields are never quoted: a basicauth definition's `users` are password
		// hashes, and an evidence line is part of the payload (I6).
		return []Account{{
			Method:     payload.AuthBasicAuth,
			Detail:     strings.TrimSpace(ref),
			Confidence: payload.ConfidenceObserved,
			Evidence: []string{applied,
				"middleware " + quote(bare) + " is a " + strings.ToLower(def.Type) +
					" defined by " + def.Where()},
		}}, nil

	case "chain":
		var accounts []Account
		var notes []string
		for _, inner := range splitList(def.Fields["middlewares"]) {
			got, gotNotes := in.classify(inner, router, depth+1, seen)
			for i := range got {
				got[i].Evidence = append(got[i].Evidence,
					"reached through chain "+quote(bare)+", defined by "+def.Where())
			}
			accounts = append(accounts, got...)
			notes = append(notes, gotNotes...)
		}
		return accounts, notes

	default:
		// Everything else Traefik can do to a request leaves it answerable by anyone.
		return nil, nil
	}
}

// fromName is the fallback of last resort: no stack defines this middleware, so its name is
// the only evidence there is (§7).
//
// The tokens are matched by equality and never as substrings. That is what separates
// `dashboard-auth` and `sso-gate`, which are gates, from `oauth-headers` and `secured`, which
// are not — and getting it wrong in the generous direction is worse than getting it wrong in
// the strict one, because it invents protection.
func (in Input) fromName(ref, router string) ([]Account, []string) {
	bare := BareName(ref)
	toks := Tokens(bare)
	if !namesAGate(toks) {
		return nil, nil
	}
	acct := Account{
		Method:     payload.AuthForwardAuth,
		Detail:     strings.TrimSpace(ref),
		Confidence: payload.ConfidenceInferred,
		Evidence: []string{
			"router " + quote(router) + " applies middleware " + quote(ref),
			"no scanned compose file defines " + quote(bare) + ", so its name is the evidence",
		},
	}
	hint, matched := in.Hints.Match(bare)
	switch {
	case hasToken(toks, authentikMark):
		acct.Method = payload.AuthAuthentikForwardAuth
		acct.Evidence = append(acct.Evidence, "its name names "+quote(authentikMark))
	case matched:
		acct.Method = payload.AuthAuthentikForwardAuth
		acct.Evidence = append(acct.Evidence, "its name names "+quote(hint))
	default:
		acct.Evidence = append(acct.Evidence, providerNotIdentified)
	}
	note := "Middleware " + quote(ref) + " is not defined in any scanned compose file, so the " +
		"gate on router " + quote(router) + " is inferred from its name alone"
	return []Account{acct}, []string{note}
}

// gateTokens are the words that make a middleware name read as a gate.
var gateTokens = []string{"auth", "sso", authentikMark}

func namesAGate(toks []string) bool {
	for _, want := range gateTokens {
		if hasToken(toks, want) {
			return true
		}
	}
	return false
}

func hasToken(toks []string, want string) bool {
	for _, t := range toks {
		if t == want {
			return true
		}
	}
	return false
}

// fromAccessPolicies reads a Cloudflare Access policy on a tunnel route.
//
// It is a gate Cloudflare enforces at its own edge, before the request reaches the fleet, and
// it needs no reverse proxy to be in force — which is why it is read here rather than
// anywhere near the router labels. The mechanism is `other-oauth`: an OIDC gate whose
// provider is Cloudflare, named and not guessed.
func (in Input) fromAccessPolicies() []Account {
	var accounts []Account
	for _, route := range in.Service.Cloudflare {
		if route.Access == nil {
			continue
		}
		evidence := []string{"tunnel route " + quote(route.Hostname) +
			" carries a Cloudflare Access policy"}
		if route.Access.Policy != "" {
			evidence = append(evidence, "its policy is "+quote(route.Access.Policy))
		}
		if route.Access.Group != "" {
			evidence = append(evidence, "its group is "+quote(route.Access.Group))
		}
		if n := len(route.Access.Emails); n > 0 {
			evidence = append(evidence, "it names "+plural(n, "address", "addresses"))
		}
		accounts = append(accounts, Account{
			Method:     payload.AuthOtherOAuth,
			Detail:     "Cloudflare Access",
			Confidence: payload.ConfidenceObserved,
			Evidence:   evidence,
		})
	}
	return accounts
}

// fromEnv reads the two mechanisms an application configures for itself.
//
// An environment key is a claim about what the application does, which is why it is
// `observed` rather than `inferred`: the operator wrote the value and the application acts
// on it. What the key cannot say is who is at the other end, and that is where the hints come
// in — and where they stop. A directory at `ldap://ldap-server.internal` is a directory, and
// calling it Authentik because the word `server` appears in both is the mistake this whole
// mechanism exists to avoid.
func (in Input) fromEnv() []Account {
	var accounts []Account
	if acct, ok := in.envAccount(in.ldapKeys(), payload.AuthAuthentikLDAP, payload.AuthLDAP,
		"configures an LDAP directory"); ok {
		accounts = append(accounts, acct)
	}
	if acct, ok := in.envAccount(in.oauthKeys(), payload.AuthAuthentikOAuth, payload.AuthOtherOAuth,
		"configures OIDC or OAuth"); ok {
		accounts = append(accounts, acct)
	}
	return accounts
}

// envAccount builds one account out of the environment entries that matched, preferring the
// entry whose value names a provider so that the strongest reading of the same evidence wins.
func (in Input) envAccount(matched []payload.EnvVar, named, generic payload.AuthMethod,
	what string) (Account, bool) {
	if len(matched) == 0 {
		return Account{}, false
	}
	for _, e := range matched {
		if hint, ok := in.Hints.Match(envValue(e)); ok {
			return Account{
				Method:     named,
				Detail:     e.Key,
				Confidence: payload.ConfidenceObserved,
				Evidence: []string{"environment " + quote(e.Key) + " " + what,
					"its value names " + quote(hint)},
			}, true
		}
	}
	return Account{
		Method:     generic,
		Detail:     matched[0].Key,
		Confidence: payload.ConfidenceObserved,
		Evidence: []string{"environment " + quote(matched[0].Key) + " " + what,
			providerNotIdentified},
	}, true
}

// ldapKeys are the environment entries whose key *is* one of the LDAP hints. Equality, not
// containment: `LDAP_BIND_PASSWORD` contains `LDAP_` and is not an address.
func (in Input) ldapKeys() []payload.EnvVar {
	var out []payload.EnvVar
	for _, e := range in.Service.Env {
		if envValue(e) == "" || falsy(envValue(e)) {
			continue // a variable set to nothing configures nothing
		}
		for _, hint := range in.LDAPEnvHints {
			if strings.EqualFold(e.Key, hint) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// oauthKeys are the environment entries whose key contains one of the OAuth hints. Those
// hints are key fragments — `OIDC`, `ISSUER`, `CLIENT_ID` — because the keys an application
// uses for OIDC are named after the protocol rather than standardised.
func (in Input) oauthKeys() []payload.EnvVar {
	var out []payload.EnvVar
	for _, e := range in.Service.Env {
		if envValue(e) == "" || falsy(envValue(e)) {
			continue
		}
		upper := strings.ToUpper(e.Key)
		for _, hint := range in.OAuthEnvHints {
			if hint != "" && strings.Contains(upper, strings.ToUpper(hint)) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// envValue is an entry's value, with a declared-but-unset variable reading as empty.
func envValue(e payload.EnvVar) string {
	if e.Value == nil {
		return ""
	}
	return *e.Value
}

// Resolve reduces every account of one service to the one posture the payload carries (§4.2).
//
// The strongest confidence wins; a tie goes to AuthMethod precedence. Every account that lost
// stays as an evidence line, because the disagreement is itself a thing to know — a label
// naming a gate the proxy is not applying reads very differently from no label at all, and
// the payload has one place to say so.
func Resolve(groups ...[]Account) payload.AuthPosture {
	all := ordered(groups...)
	if len(all) == 0 {
		return payload.AuthPosture{
			Method:     payload.AuthNone,
			Confidence: payload.ConfidenceObserved,
			Evidence:   []string{noGateNamed},
		}
	}

	win := all[0]
	out := payload.AuthPosture{
		Method:     win.Method,
		Detail:     win.Detail,
		Confidence: win.Confidence,
		Evidence:   append([]string{}, win.Evidence...),
	}
	for _, other := range all[1:] {
		if other.Method != win.Method || other.Detail != win.Detail {
			out.Evidence = append(out.Evidence, "also "+string(other.Method)+
				" ("+string(other.Confidence)+") from "+other.Detail)
		}
		out.Evidence = append(out.Evidence, other.Evidence...)
	}
	out.Evidence = dedupeStrings(out.Evidence)
	if out.Method == payload.AuthNone && len(out.Evidence) == 0 {
		out.Evidence = []string{noGateNamed}
	}
	return out
}

// ordered is §4.2's precedence, in one place: strongest confidence first, ties broken by method
// precedence, and accounts that name no method dropped.
//
// Both Resolve and GateAddress read it, so the address a gate is reached at can never come from a
// different account than the method reported beside it.
//
// **The third key.** Two accounts can agree on confidence and on method and still be different
// accounts — an LDAP gate the identity provider records and the same gate hinted at by an
// environment key resolve to `authentik-ldap` at `observed` from both directions. Left to the two
// keys above, the winner would be whichever group the caller happened to pass first, and the caller
// passes labels first. A live account wins that tie: at equal confidence it names the provider and
// what enforces it, where the scanned account names the key that hinted at it, and the detail a
// reader is shown should be the one that says something. The loser is kept as evidence either way,
// so nothing is lost by choosing — only the order of two sentences changes.
func ordered(groups ...[]Account) []Account {
	var all []Account
	for _, g := range groups {
		for _, a := range g {
			if a.Method != "" {
				all = append(all, a)
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if a, b := all[i].Confidence.Rank(), all[j].Confidence.Rank(); a != b {
			return a < b
		}
		if a, b := all[i].Method.Rank(), all[j].Method.Rank(); a != b {
			return a < b
		}
		return all[i].Live && !all[j].Live
	})
	return all
}

// GateAddress is where the winning gate is reached, or empty when no account named an address.
//
// A weaker account's address is used when the winner has none: an inferred gate whose middleware
// no compose file defines has no address to give, and the next account down still describes a real
// gate on the same service. What is never done is inventing one from a name.
func GateAddress(groups ...[]Account) string {
	for _, a := range ordered(groups...) {
		if a.Address != "" {
			return a.Address
		}
	}
	return ""
}

// collapse merges accounts that say the same thing about the same gate.
//
// Two routers carrying one middleware are one gate, and a chain reached twice is one gate.
// Without this the evidence would repeat itself once per router, which reads as more
// corroboration than there is.
func collapse(accounts []Account) []Account {
	if len(accounts) < 2 {
		return accounts
	}
	var out []Account
	at := map[string]int{}
	for _, a := range accounts {
		key := string(a.Method) + "\x00" + a.Detail + "\x00" + string(a.Confidence)
		if i, seen := at[key]; seen {
			out[i].Evidence = dedupeStrings(append(out[i].Evidence, a.Evidence...))
			continue
		}
		at[key] = len(out)
		out = append(out, a)
	}
	return out
}

// dedupeStrings keeps the first occurrence of each line, preserving order.
func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
