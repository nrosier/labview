package traefikapi

import (
	"strings"

	"github.com/nrosier/labview/internal/authentik"
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
)

// proxyMode is the provider mode in which the outpost *is* the backend.
//
// It is the one exemption in the three-way cross-check. In proxy mode the outpost terminates the
// request and forwards upstream itself, so there is no middleware for it to be and an empty router
// chain is what a correct deployment looks like — reporting a bypass there would invent a finding
// on a working setup (§12). The `shop` and `crm` fixtures differ in this field alone.
const proxyMode = "proxy"

// PostureInput is everything the live reading of one service's posture needs.
//
// It is a struct rather than eight arguments because every field is a fact from a different stage —
// the match, the label pass, the identity-provider read, the fleet index — and a caller that got
// the order wrong would silently cross-check the wrong service.
type PostureInput struct {
	// Routers is the live routers matched to this service, in `name@provider` order.
	Routers []payload.TraefikLiveRouter

	// Reachable is whether the proxy API answered at all.
	//
	// It is separate from ChainComplete because *the proxy said there is no gate here* and *nobody
	// asked the proxy anything* are different facts, and only the first is a finding. Every note
	// below is a sentence about what the proxy reported; a read that was switched off, or never
	// resolved, reported nothing, and a scan that said "this router is not among the ones the proxy
	// is serving" on the strength of an empty snapshot would be inventing one (I4 is *degrade and
	// say so*, not *conclude anyway*).
	//
	// So an unreachable read contributes nothing at all: no accounts, no notes, no suppression. The
	// reader learns the proxy was not read from §15's connection block, which is where that belongs.
	Reachable bool

	// ChainComplete is the read's own conclusion: reachable, and the entrypoints were read. Only
	// a complete read lets a live chain supersede a label list (§12).
	ChainComplete bool

	// Absent is the routers this service's labels declare that the proxy is not serving.
	Absent []string

	// LabelAccounts is what §7 concluded from labels and environment. It is read for one purpose:
	// to tell whether a label declared a gate the live chain does not contain.
	LabelAccounts []labels.Account

	// Hints is how a forward-auth address is attributed to the SSO provider *in this fleet*
	// (stage 9). Without it a forward-auth is a real gate whose operator is unnamed.
	Hints labels.Hints

	// Index resolves a forward-auth address back to the service that answers it.
	Index *fleet.Index

	// AuthentikKey is the service key the identity-provider API answered on, empty when it did
	// not answer. It is the strongest possible attribution of a forward-auth address: the far end
	// answered as an Authentik API, which no name match can establish.
	AuthentikKey string

	// Applications is this service's matched Authentik applications, nil when it has none.
	Applications *payload.AuthentikMatch
}

// Posture is what the live read concludes about one service.
type Posture struct {
	// Accounts is in the shared vocabulary of §7, so that §4.2's stronger-wins rule runs in one
	// place and not three.
	Accounts []labels.Account

	// Notes is what a reader is told, in the order the checks ran.
	Notes []string

	// Suppress is the downgrade: a label declared an auth middleware the live chain does not
	// contain, so the label-derived detection MUST be discarded and the service is free to land in
	// the exposure finding (§12).
	//
	// It is a flag rather than an empty account list because "the live read says there is no gate"
	// and "the live read had nothing to say" are different facts, and only the first one licenses
	// overriding what the labels claimed.
	Suppress bool
}

// PostureOf is §12's whole posture contribution for one service.
func PostureOf(in PostureInput) Posture {
	var out Posture

	// Nothing to read from. See PostureInput.Reachable: every note below is a claim about what the
	// proxy reported, so a read that did not happen makes none of them.
	if !in.Reachable {
		return out
	}

	// A router the proxy refuses is neither protection nor working ingress, and its errors are
	// quoted verbatim because they are the proxy's own words about its own configuration.
	for _, r := range in.Routers {
		if note := ErrorNote(r); note != "" {
			out.Notes = append(out.Notes, note)
		}
	}

	// A labelled router the proxy is not serving. The scan cannot tell whether the container
	// started after the proxy lost its socket, whether the rule is malformed in a way only Traefik
	// can see, or whether `traefik.enable` is off on the running container — and it does not try.
	// What it can say is that the router is not among the ones being served.
	for _, name := range in.Absent {
		out.Notes = append(out.Notes, "This service's labels declare router "+quote(name)+
			", which is not among the routers the proxy is serving")
	}

	working := workingRouters(in.Routers)
	live, addresses := liveAccounts(in, working)

	switch {
	case !in.ChainComplete:
		// A partial read notes the gap and changes no posture (§12). The label-derived posture
		// stands, and the discrepancy is reported rather than acted on.
		out.Notes = append(out.Notes, partialNotes(in, live)...)
		return out

	case len(working) == 0:
		// No live chain to be the chain. A service whose labels declare a gate and whose router
		// the proxy is not serving keeps its label posture — there is no live counterpart to
		// supersede it, which is what separates `blog` from `dashboards`.
		return out

	default:
		out.Accounts = live
		if suppressed, note := downgrade(in, live); suppressed {
			out.Suppress = true
			out.Notes = append(out.Notes, note)
		}
		out.Notes = append(out.Notes, crossCheck(in, addresses)...)
		return out
	}
}

// workingRouters is the matched routers that are in a request path at all.
func workingRouters(in []payload.TraefikLiveRouter) []payload.TraefikLiveRouter {
	var out []payload.TraefikLiveRouter
	for _, r := range in {
		if Working(r) {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The live chain is the chain
// ---------------------------------------------------------------------------

// liveAccounts is every gate the working routers' chains contain, and the forward-auth addresses
// among them.
//
// Confidence is `confirmed` throughout, and that is the point of the whole integration: the proxy
// is reporting the chain it *built*, which is neither a label that might not have been served nor a
// name a rule inferred a meaning from.
func liveAccounts(in PostureInput, working []payload.TraefikLiveRouter) ([]labels.Account, []string) {
	var accounts []labels.Account
	var addresses []string

	for _, r := range working {
		for _, mw := range r.Middlewares {
			method, ok := authMethodOf(mw.Type)
			if !ok {
				continue
			}

			acct := labels.Account{
				Method:     method,
				Detail:     mw.Name,
				Confidence: payload.ConfidenceConfirmed,
				Evidence:   []string{"the proxy's own chain for router " + quote(r.Router) + " contains " + quote(mw.Name)},
				Live:       true,
			}
			if mw.ViaChain != "" {
				acct.Evidence = append(acct.Evidence, "reached through chain "+quote(mw.ViaChain))
			}
			if mw.ViaEntrypoint != nil && *mw.ViaEntrypoint {
				acct.Evidence = append(acct.Evidence,
					"attached at entrypoint "+list(r.EntryPoints)+" rather than to the router")
			}

			if method == payload.AuthForwardAuth {
				address := strings.TrimSpace(mw.Address)
				acct.Address = address
				if address != "" {
					addresses = append(addresses, address)
					// The address is redacted, because a forward-auth address is a URL from a
					// document this program did not write and a query string in one is a place a
					// credential can sit (I6, §20).
					acct.Evidence = append(acct.Evidence,
						"it is a forwardauth to "+secrets.RedactURIs(address))
				}
				if provider, named := in.attribute(address); named {
					acct.Method = payload.AuthAuthentikForwardAuth
					acct.Evidence = append(acct.Evidence, provider)
				}
			}
			accounts = append(accounts, acct)
		}
	}
	return accounts, addresses
}

// attribute is whether a forward-auth address resolves to a provider identity, and the evidence
// line saying how.
//
// Two ways, strongest first. The address resolving to the service the identity-provider API
// answered on is not an inference at all — that far end answered as an Authentik API. A hint match
// is the fallback of §7, and says the address *names* the provider this fleet runs.
func (in PostureInput) attribute(address string) (string, bool) {
	if address == "" {
		return "", false
	}
	if key, ok := fleet.GateService(in.Index, address); ok && key != "" && key == in.AuthentikKey {
		return "its address resolves to " + quote(key) + ", which answered as the Authentik API", true
	}
	if hint, matched := in.Hints.Match(address); matched {
		return "its address names " + quote(hint), true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// The downgrade
// ---------------------------------------------------------------------------

// downgrade is §12's sharpest conclusion and the only direction in which this integration could
// mislead: a label declaring an auth middleware that the live chain does not contain.
//
// It fires only on a complete read and only where a working router exists, because both of those
// are what make the absence of a gate in the chain an *assertion* rather than a gap. The
// `dashboards` and `metrics` fixtures differ in nothing else: both declare `authentik@file` and
// both have an empty router chain, and only the second one's entrypoint carries the gate.
func downgrade(in PostureInput, live []labels.Account) (bool, string) {
	claimed := claimedGates(in.LabelAccounts)
	if len(claimed) == 0 {
		return false, ""
	}
	for _, acct := range live {
		if acct.Method.Detected() {
			return false, ""
		}
	}

	return true, "This service's labels declare " + list(claimed) +
		", and the chain the proxy built for " + list(routerNamesOf(in.Routers)) +
		" contains no authentication middleware — including anything its entrypoints attach. " +
		"The live chain is what requests pass through, so the label-derived gate is not reported"
}

// claimedGates is the middlewares the label pass concluded were gates, by the name it recorded.
func claimedGates(accounts []labels.Account) []string {
	var out []string
	for _, acct := range accounts {
		if !acct.Method.Detected() {
			continue
		}
		if name := strings.TrimSpace(acct.Detail); name != "" {
			out = appendOnce(out, name)
		}
	}
	return out
}

func routerNamesOf(in []payload.TraefikLiveRouter) []string {
	var out []string
	for _, r := range in {
		out = appendOnce(out, r.Router)
	}
	return out
}

// partialNotes is what a partial read says instead of downgrading.
//
// The wording is deliberately about reporting rather than concluding: the entrypoints were not
// read, so an empty router chain is not evidence that no gate is attached, and a reader has to be
// able to tell this note from the downgrade's.
func partialNotes(in PostureInput, live []labels.Account) []string {
	claimed := claimedGates(in.LabelAccounts)
	if len(claimed) == 0 {
		return nil
	}
	for _, acct := range live {
		if acct.Method.Detected() {
			return nil
		}
	}
	return []string{"This service's labels declare " + list(claimed) +
		", and the chain the proxy reported contains no authentication middleware. The entrypoint " +
		"list could not be read, so a gate attached at an entrypoint would be invisible here — the " +
		"difference is reported and the label-derived posture stands"}
}

// ---------------------------------------------------------------------------
// The three-way cross-check
// ---------------------------------------------------------------------------

// crossCheck is where labels, proxy and identity provider are held against each other.
//
// Each source alone is unremarkable — no label to check, an empty chain like any other, a provider
// that looks correctly configured. Held together they can say that an outpost is standing *beside*
// the request path rather than in it, which is the finding, and the reason this reads all three
// rather than two (§12). `crm` is the disagreement and `shop` is the exemption.
func crossCheck(in PostureInput, addresses []string) []string {
	var notes []string

	forwarded := forwardsToProvider(in, addresses)
	carried := carriedProviders(in.Applications)

	switch {
	case forwarded != "" && len(carried) > 0:
		notes = append(notes, "The labels, the proxy and Authentik agree: router "+
			list(routerNamesOf(in.Routers))+" forwards authentication to "+quote(forwarded)+
			", and Authentik reports "+list(carried)+" served by an outpost for an application "+
			"matched to this service")

	case forwarded != "" && in.AuthentikKey != "":
		// The proxy forwards to the identity provider and the identity provider has nothing for
		// this service. The gate is real and what it will decide is not something Authentik was
		// able to show, which is a different finding from an absent gate.
		notes = append(notes, "Router "+list(routerNamesOf(in.Routers))+" forwards authentication to "+
			quote(forwarded)+", and Authentik reports no application matched to this service with a "+
			"provider an outpost serves")

	case forwarded == "" && len(carried) > 0:
		// Somebody set up a gate and believes it is in force. Nothing in the proxy forwards to it.
		notes = append(notes, "Authentik reports "+list(carried)+" served by an outpost for an "+
			"application matched to this service, and the chain the proxy built for "+
			list(routerNamesOf(in.Routers))+" forwards authentication nowhere — so requests reach "+
			"this service without passing the outpost")
	}
	return notes
}

// forwardsToProvider is the service key a live forward-auth address resolves to, when that is the
// service the identity-provider API answered on.
func forwardsToProvider(in PostureInput, addresses []string) string {
	if in.AuthentikKey == "" {
		return ""
	}
	for _, address := range addresses {
		if key, ok := fleet.GateService(in.Index, address); ok && key == in.AuthentikKey {
			return key
		}
	}
	return ""
}

// carriedProviders is this service's matched providers that an outpost actually serves and whose
// mode puts them in the request path, by name.
//
// Three conditions, and each one is a separate way the cross-check would otherwise be wrong: a
// kind no outpost carries is not a forward-auth arrangement at all, a provider assigned to no
// outpost is in nobody's request path, and a provider in proxy mode *is* the backend.
func carriedProviders(match *payload.AuthentikMatch) []string {
	if match == nil {
		return nil
	}
	var out []string
	for _, app := range match.Applications {
		for _, p := range app.Providers {
			if !authentik.NeedsOutpost(p.Kind) || len(p.Outposts) == 0 {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(p.Mode), proxyMode) {
				continue
			}
			name := strings.TrimSpace(p.Name)
			if name == "" {
				name = app.Slug
			}
			out = appendOnce(out, name)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The credential note
// ---------------------------------------------------------------------------

// CredentialNote is what the proxy service is told about its own API.
//
// An API that answered with no credential is not a convenience, it is a fact about how that API is
// exposed on the network it is on — anything that can reach the port can read the whole routing
// table. §12 requires it reported as a note rather than left implicit in a summary field.
func CredentialNote(r Read) string {
	if !r.Reachable() || r.Credential != payload.CredentialNone {
		return ""
	}
	return "The proxy's API at " + quote(r.Endpoint) + " answered " + quote(pathVersion) +
		" and " + quote(pathRawData) + " with no credential, so anything that can reach it can " +
		"read the whole routing table"
}
