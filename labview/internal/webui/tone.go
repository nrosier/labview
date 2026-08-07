package webui

import (
	"sort"

	"github.com/nrosier/labview/internal/payload"
)

// §22.1: **colour is categorical and centralised.** One mapping from every union member to a
// colour and a label, with a defined fallback for an unknown member — which is why adding a member
// is a breaking change (§16).
//
// This file is that mapping, and it is the only one. The stylesheet keys off `Tone`, never off a
// member name, so a member added to the payload without a term here renders as the fallback rather
// than as an invisible chip.

// Tone is the categorical colour. Five of them, and two are spoken for:
//
//   - ToneAlert is the **one reserved emphasis colour**, for the one condition §22.1 reserves it
//     for: reachable from outside with no gate. Exactly one term carries it, and a test says so.
//   - ToneWarn is the second, weaker warning, for exactly the three §22.1 lists: an ambiguous
//     match, a proxy API answering unauthenticated, and a failed connection phase.
//
// The other three are ordinary categories and carry no severity.
type Tone string

const (
	ToneNeutral Tone = "neutral"
	ToneInfo    Tone = "info"
	ToneGood    Tone = "good"
	ToneWarn    Tone = "warn"
	ToneAlert   Tone = "alert"
)

// Set names one closed vocabulary. The payload's own unions plus the four readings §22.2 and §22.6
// require the UI to name — a probe outcome, a declaration state, an integration match state and
// the exposure finding — which are derived from payload fields rather than stored as members
// (§4 lists the same distinction for NoAuthReason and friends).
type Set string

const (
	SetIngressKind     Set = "ingressKind"
	SetAuthMethod      Set = "authMethod"
	SetAuthConfidence  Set = "authConfidence"
	SetNetworkScope    Set = "networkScope"
	SetOriginKind      Set = "originKind"
	SetProviderKind    Set = "authentikProviderKind"
	SetMatchStrength   Set = "authentikMatchStrength"
	SetUnmatchedReason Set = "unmatchedReason"
	SetDiscoveredVia   Set = "discoveredVia"
	SetEndpointSource  Set = "endpointSource"
	SetCredential      Set = "traefikCredential"
	SetConnectionPhase Set = "connectionPhase"
	SetProbeVantage    Set = "probeVantage"
	SetProbeGate       Set = "probeGate"
	SetMechanism       Set = "declaredAuthMechanism"
	SetAgreement       Set = "declaredAuthAgreement"
	SetEnvSource       Set = "envVarSource"
	SetMountType       Set = "mountType"
	SetHealth          Set = "healthState"
	SetBuildSource     Set = "buildStampSource"
	SetNodeKind        Set = "graphNodeKind"
	SetEdgeKind        Set = "graphEdgeKind"
	SetEdgeFlow        Set = "edgeFlow"
	SetEdgeFlowSource  Set = "edgeFlowSource"
	SetProbeRunSource  Set = "probeRunSource"
	SetLoginMethod     Set = "loginMethod"
	SetLoginFailure    Set = "loginFailureReason"

	// The four derived readings. Each is a fact the payload states in a field the UI has to turn
	// into a filterable member (§22.6), so the member spellings below are as much contract as the
	// payload's own — they appear in a shared URL.
	SetProbeOutcome Set = "probeOutcome"
	SetDeclState    Set = "declarationState"
	SetMatchState   Set = "matchState"
	SetFinding      Set = "finding"
)

// Term is one member: its label, its tone, and a mark that carries the same distinction without
// colour (§22.1: colour MUST never be the only carrier of a distinction).
type Term struct {
	Member string `json:"member"`
	Label  string `json:"label"`
	Tone   Tone   `json:"tone"`
	// Mark is the non-colour carrier. Required for the two emphasis tones and empty otherwise,
	// because a mark on every chip in a dense table is noise that stops being read.
	Mark string `json:"mark,omitempty"`
	// Note is the one line explaining the member, shown in the legend and on hover.
	Note string `json:"note,omitempty"`
	// Unknown is true only for the fallback: a member this build has no term for. It is not a
	// member of any set and is never offered as a filter value.
	Unknown bool `json:"unknown,omitempty"`
}

// The derived members. Spelled out as constants because they are written into shared URLs.
const (
	// Probe outcomes. The three that can follow from a probe having run, plus not having run.
	OutcomeGated     = "gated"
	OutcomeOpen      = "open"
	OutcomeNoAnswer  = "no-answer"
	OutcomeNotProbed = "not-probed"

	// Declaration states. `drift` and `not-confirmed` are two readings that are never merged
	// (§22.2).
	DeclAuth         = "declared-auth"
	DeclProtected    = "declared-protected"
	DeclNotConfirmed = "not-confirmed"
	DeclDrift        = "drift"
	DeclAccepted     = "accepted"

	// Integration match states (§22.6).
	MatchMatched   = "matched"
	MatchUnmatched = "unmatched"
	MatchRebuilt   = "rebuilt"
	MatchAmbiguous = "ambiguous"

	// Findings. FindingExposed is the one condition the reserved colour is for.
	FindingExposed  = "exposed-without-auth"
	FindingGated    = "gated"
	FindingAccepted = "exposure-accepted"
	FindingNone     = "no-ingress"
)

// vocabulary is the whole mapping. Every closed set of §4 appears, in the canonical order of its
// own slice, so a chip row is sorted by the payload's precedence rather than alphabetically (I7).
var vocabulary = map[Set][]Term{
	SetIngressKind: {
		{Member: string(payload.IngressPublic), Label: "Public", Tone: ToneInfo, Note: "a tunnel route with a hostname — reachable from the internet"},
		{Member: string(payload.IngressTraefik), Label: "Proxy", Tone: ToneInfo, Note: "a Traefik router with hosts or a rule"},
		{Member: string(payload.IngressLan), Label: "LAN", Tone: ToneInfo, Note: "a published host port"},
		{Member: string(payload.IngressInternal), Label: "Internal", Tone: ToneNeutral, Note: "expose:, or a real network shared with another scanned service"},
		{Member: string(payload.IngressNone), Label: "No ingress", Tone: ToneNeutral, Note: "nothing reaches it"},
	},
	SetAuthMethod: {
		{Member: string(payload.AuthAuthentikForwardAuth), Label: "Authentik forward-auth", Tone: ToneGood, Note: "an Authentik outpost answers on the path"},
		{Member: string(payload.AuthAuthentikOAuth), Label: "Authentik OAuth", Tone: ToneGood, Note: "an Authentik OAuth2/OIDC provider fronts it"},
		{Member: string(payload.AuthAuthentikLDAP), Label: "Authentik LDAP", Tone: ToneGood, Note: "an Authentik LDAP provider fronts it"},
		{Member: string(payload.AuthForwardAuth), Label: "Forward-auth", Tone: ToneGood, Note: "a forward-auth middleware, provider unnamed"},
		{Member: string(payload.AuthOtherOAuth), Label: "OAuth", Tone: ToneGood, Note: "an OAuth/OIDC gate that is not Authentik"},
		{Member: string(payload.AuthLDAP), Label: "LDAP", Tone: ToneGood, Note: "an LDAP gate that is not Authentik"},
		{Member: string(payload.AuthBasicAuth), Label: "Basic auth", Tone: ToneInfo, Note: "an HTTP basic-auth middleware"},
		{Member: string(payload.AuthNone), Label: "No gate detected", Tone: ToneNeutral, Note: "no gate was detected — which is not the same as none existing"},
	},
	SetAuthConfidence: {
		{Member: string(payload.ConfidenceConfirmed), Label: "Confirmed", Tone: ToneGood, Note: "an API reported the gate and named the service"},
		{Member: string(payload.ConfidenceObserved), Label: "Observed", Tone: ToneInfo, Note: "a scanned value states it, or an API tied it by name alone"},
		{Member: string(payload.ConfidenceInferred), Label: "Inferred", Tone: ToneNeutral, Note: "it rests on a middleware name"},
	},
	SetNetworkScope: {
		{Member: string(payload.ScopeExternal), Label: "External", Tone: ToneInfo, Note: "declared external: — may carry containers this scan never saw"},
		{Member: string(payload.ScopeStackLocal), Label: "Stack-local", Tone: ToneNeutral, Note: "created by one compose project"},
	},
	SetOriginKind: {
		{Member: string(payload.OriginSelfNetwork), Label: "Itself, over the network", Tone: ToneGood, Note: "the origin host is this service's own name"},
		{Member: string(payload.OriginSelfHostPort), Label: "Itself, via a host port", Tone: ToneGood, Note: "the origin port is a host port this service publishes"},
		{Member: string(payload.OriginFleetService), Label: "Another service", Tone: ToneInfo, Note: "a scanned service sharing a network, named as the hop"},
		{Member: string(payload.OriginUnresolved), Label: "Unresolved", Tone: ToneNeutral, Note: "no match, an FQDN, or a tie between reachable candidates"},
	},
	SetProviderKind: {
		{Member: string(payload.ProviderProxy), Label: "Proxy", Tone: ToneInfo},
		{Member: string(payload.ProviderOAuth2), Label: "OAuth2", Tone: ToneInfo},
		{Member: string(payload.ProviderLDAP), Label: "LDAP", Tone: ToneInfo},
		{Member: string(payload.ProviderSAML), Label: "SAML", Tone: ToneInfo},
		{Member: string(payload.ProviderRADIUS), Label: "RADIUS", Tone: ToneInfo},
		{Member: string(payload.ProviderSCIM), Label: "SCIM", Tone: ToneInfo},
		{Member: string(payload.ProviderOther), Label: "Other", Tone: ToneNeutral, Note: "a kind this build does not model — the raw kind is shown beside it"},
	},
	SetMatchStrength: {
		{Member: string(payload.StrengthAddress), Label: "By address", Tone: ToneGood, Note: "the provider's address resolved to this service"},
		{Member: string(payload.StrengthHostname), Label: "By hostname", Tone: ToneInfo, Note: "a declared hostname matched"},
		{Member: string(payload.StrengthName), Label: "By name", Tone: ToneNeutral, Note: "names matched, and nothing stronger did"},
	},
	SetUnmatchedReason: {
		{Member: string(payload.UnmatchedAmbiguous), Label: "Ambiguous", Tone: ToneWarn, Mark: "?", Note: "more than one candidate, and guessing would attach a gate to a service that has none"},
		{Member: string(payload.UnmatchedNoCandidate), Label: "No candidate", Tone: ToneNeutral, Note: "nothing in the scan answers to it"},
		{Member: string(payload.UnmatchedInternal), Label: "Internal", Tone: ToneNeutral, Note: "an internal record that names no service"},
	},
	SetDiscoveredVia: {
		{Member: string(payload.DiscoveredViaList), Label: "Listed", Tone: ToneNeutral, Note: "the application list returned it"},
		{Member: string(payload.DiscoveredViaProvider), Label: "Rebuilt", Tone: ToneInfo, Note: "rebuilt from a provider because the list withheld it — a thinner record"},
	},
	SetEndpointSource: {
		{Member: string(payload.SourceConfig), Label: "Configured", Tone: ToneNeutral, Note: "the operator named it"},
		{Member: string(payload.SourceDiscovered), Label: "Discovered", Tone: ToneInfo, Note: "the scan found it"},
		{Member: string(payload.SourceDefault), Label: "Built-in default", Tone: ToneNeutral, Note: "a built-in fallback path"},
	},
	SetCredential: {
		{Member: string(payload.CredentialNone), Label: "Answered unauthenticated", Tone: ToneWarn, Mark: "?", Note: "the proxy API answered with no credential, which is itself evidence about how it is exposed"},
		{Member: string(payload.CredentialBasic), Label: "Basic credential", Tone: ToneNeutral, Note: "a credential was needed and supplied"},
	},
	SetConnectionPhase: phaseTerms(),
	SetProbeVantage: {
		{Member: string(payload.VantagePublic), Label: "From the internet", Tone: ToneInfo},
		{Member: string(payload.VantageTraefik), Label: "Through the proxy", Tone: ToneInfo},
		{Member: string(payload.VantageLan), Label: "From the LAN", Tone: ToneInfo},
	},
	SetProbeGate: {
		{Member: string(payload.GateChallenge), Label: "Challenge", Tone: ToneGood, Note: "401 or 407 with a WWW-Authenticate header"},
		{Member: string(payload.GateRedirectOrigin), Label: "Redirect off-origin", Tone: ToneGood, Note: "a 3xx whose Location resolves to a different origin"},
		{Member: string(payload.GateRedirectLogin), Label: "Redirect to a login path", Tone: ToneGood},
		{Member: string(payload.GateMetaRefreshLogin), Label: "Meta refresh to a login path", Tone: ToneGood},
		{Member: string(payload.GateSSOForm), Label: "SSO form", Tone: ToneGood, Note: "a hidden SAMLRequest or SAMLResponse input"},
		{Member: string(payload.GatePasswordForm), Label: "Password form", Tone: ToneGood},
		{Member: string(payload.GateCredentialForm), Label: "Credential form", Tone: ToneGood, Note: "username, submit and login intent, with no password field"},
		{Member: string(payload.GateStateChallenge), Label: "State challenge", Tone: ToneGood, Note: "the page's own client was refused with a scheme"},
	},
	SetMechanism: {
		{Member: string(payload.MechanismAppLocalAccounts), Label: "App accounts", Tone: ToneInfo},
		{Member: string(payload.MechanismAppLDAP), Label: "App LDAP", Tone: ToneInfo},
		{Member: string(payload.MechanismAppOIDC), Label: "App OIDC", Tone: ToneInfo},
		{Member: string(payload.MechanismAppSAML), Label: "App SAML", Tone: ToneInfo},
		{Member: string(payload.MechanismAppToken), Label: "App token", Tone: ToneInfo},
		{Member: string(payload.MechanismMTLS), Label: "mTLS", Tone: ToneInfo},
		{Member: string(payload.MechanismNetworkRestricted), Label: "Network-restricted", Tone: ToneInfo},
		{Member: string(payload.MechanismExternalProxy), Label: "External proxy", Tone: ToneInfo},
		{Member: string(payload.MechanismOther), Label: "Other", Tone: ToneNeutral, Note: "must carry a detail (§4.5)"},
	},
	SetAgreement: {
		{Member: string(payload.AgreementSupplies), Label: "Supplies the gate", Tone: ToneInfo, Note: "the service would be exposed and the declaration is the only protection"},
		{Member: string(payload.AgreementRedundant), Label: "Redundant", Tone: ToneNeutral, Note: "declared and detected in the same family"},
		{Member: string(payload.AgreementConflicts), Label: "Conflicts", Tone: ToneInfo, Note: "same layer, different family — a drift entry"},
		{Member: string(payload.AgreementSupplements), Label: "Supplements", Tone: ToneNeutral, Note: "declared in a layer with nothing detected in it"},
	},
	SetEnvSource: {
		{Member: string(payload.EnvFromEnvFile), Label: "env file", Tone: ToneNeutral},
		{Member: string(payload.EnvFromEnvironment), Label: "environment:", Tone: ToneNeutral},
		{Member: string(payload.EnvFromShellDefault), Label: "shell default", Tone: ToneNeutral, Note: "an interpolation default, not a value anything set"},
	},
	SetMountType: {
		{Member: string(payload.MountBind), Label: "Bind", Tone: ToneNeutral},
		{Member: string(payload.MountVolume), Label: "Volume", Tone: ToneNeutral},
		{Member: string(payload.MountTmpfs), Label: "tmpfs", Tone: ToneNeutral},
		{Member: string(payload.MountNpipe), Label: "npipe", Tone: ToneNeutral},
		{Member: string(payload.MountUnknown), Label: "Unknown", Tone: ToneNeutral, Note: "the entry did not parse as any known form"},
	},
	SetHealth: {
		{Member: string(payload.HealthHealthy), Label: "Healthy", Tone: ToneGood},
		{Member: string(payload.HealthUnhealthy), Label: "Unhealthy", Tone: ToneInfo, Note: "the container's own health check is failing"},
		{Member: string(payload.HealthStarting), Label: "Starting", Tone: ToneNeutral},
		{Member: string(payload.HealthNone), Label: "No health check", Tone: ToneNeutral},
	},
	SetBuildSource: {
		{Member: string(payload.BuildFromImage), Label: "From the image", Tone: ToneNeutral, Note: "LABVIEW_BUILD_SHA was set at build time"},
		{Member: string(payload.BuildFromCheckout), Label: "From a checkout", Tone: ToneNeutral, Note: "read from a .git directory at startup"},
		{Member: string(payload.BuildUnknown), Label: "Unknown", Tone: ToneNeutral, Note: "neither — the commit is absent entirely"},
	},
	SetNodeKind: {
		{Member: string(payload.NodeService), Label: "Service", Tone: ToneNeutral},
		{Member: string(payload.NodeNetwork), Label: "Network", Tone: ToneNeutral},
		{Member: string(payload.NodeVolume), Label: "Volume", Tone: ToneNeutral},
		{Member: string(payload.NodeExternal), Label: "Outside the fleet", Tone: ToneNeutral},
	},
	SetEdgeKind: {
		{Member: string(payload.EdgeNetwork), Label: "Membership", Tone: ToneNeutral, Note: "co-membership is not a relation between services (§8)"},
		{Member: string(payload.EdgeDependsOn), Label: "Depends on", Tone: ToneInfo},
		{Member: string(payload.EdgeVolume), Label: "Mounts", Tone: ToneNeutral},
		{Member: string(payload.EdgeIngress), Label: "Ingress path", Tone: ToneInfo},
		{Member: string(payload.EdgeAuth), Label: "Gate", Tone: ToneGood},
	},
	SetEdgeFlow: {
		{Member: string(payload.FlowToNetwork), Label: "Outbound", Tone: ToneNeutral, Note: "this service is the dependent"},
		{Member: string(payload.FlowToService), Label: "Inbound", Tone: ToneNeutral, Note: "something else on that network depends on it"},
		{Member: string(payload.FlowBoth), Label: "Both", Tone: ToneNeutral},
	},
	SetEdgeFlowSource: {
		{Member: string(payload.FlowSourceObserved), Label: "Observed", Tone: ToneInfo, Note: "compose states it"},
		{Member: string(payload.FlowSourceDeclared), Label: "Declared", Tone: ToneNeutral, Note: "only a sidecar states it — drawn dashed"},
		{Member: string(payload.FlowSourceBoth), Label: "Observed and declared", Tone: ToneInfo},
	},
	SetProbeRunSource: {
		{Member: string(payload.ProbeSourceConfig), Label: "From configuration", Tone: ToneNeutral},
		{Member: string(payload.ProbeSourceRequest), Label: "From this request", Tone: ToneInfo},
	},
	SetLoginMethod: {
		// The naming hazard of §4.7, restated where it would otherwise be relabelled: `passwd` is
		// a file of bcrypt hashes and has nothing to do with HTTP basic authentication.
		{Member: string(payload.MethodPasswd), Label: "Password", Tone: ToneNeutral, Note: "a local credential file"},
		{Member: string(payload.MethodOIDC), Label: "Single sign-on", Tone: ToneNeutral, Note: "an OIDC provider"},
	},
	SetLoginFailure: {
		{Member: string(payload.FailCredentials), Label: "Incorrect username or password", Tone: ToneNeutral},
		{Member: string(payload.FailThrottled), Label: "Too many attempts — try again shortly", Tone: ToneNeutral},
		{Member: string(payload.FailMethodUnavailable), Label: "That sign-in method is not configured", Tone: ToneNeutral},
		{Member: string(payload.FailSessionExpired), Label: "Your session expired", Tone: ToneNeutral},
		{Member: string(payload.FailOIDCState), Label: "The sign-in could not be verified — start again", Tone: ToneNeutral},
		{Member: string(payload.FailOIDCProvider), Label: "The provider could not be reached", Tone: ToneNeutral},
		{Member: string(payload.FailOIDCToken), Label: "The provider's answer could not be verified", Tone: ToneNeutral},
		{Member: string(payload.FailOIDCIdentity), Label: "The provider named nobody this build can accept", Tone: ToneNeutral},
	},

	SetProbeOutcome: {
		// Findings lead (§22.2): answered with no login page, then answered with one, then did not
		// answer. This order is the Probe view's order.
		{Member: OutcomeOpen, Label: "Answered, no login page", Tone: ToneInfo, Note: "the probe read no gate signal — a finding, not a verdict about the application"},
		{Member: OutcomeGated, Label: "Answered with a gate", Tone: ToneGood, Note: "one of the eight signals fired"},
		{Member: OutcomeNoAnswer, Label: "Did not answer", Tone: ToneNeutral, Note: "no response, so neither gated nor open"},
		{Member: OutcomeNotProbed, Label: "Not probed", Tone: ToneNeutral, Note: "no external ingress, no address, or the probe was off"},
	},
	SetDeclState: {
		{Member: DeclDrift, Label: "Drift", Tone: ToneInfo, Note: "a declaration the scan contradicts"},
		{Member: DeclNotConfirmed, Label: "Not confirmed", Tone: ToneNeutral, Note: "a declaration the scan could not corroborate — never merged with drift"},
		{Member: DeclAccepted, Label: "Exposure accepted", Tone: ToneInfo, Note: "an operator stated the exposure is intended — still exposed"},
		{Member: DeclProtected, Label: "Declared protection", Tone: ToneInfo, Note: "the declaration supplies the only gate"},
		{Member: DeclAuth, Label: "Declares a gate", Tone: ToneNeutral},
	},
	SetMatchState: {
		{Member: MatchMatched, Label: "Matched", Tone: ToneGood},
		{Member: MatchUnmatched, Label: "Unmatched", Tone: ToneNeutral, Note: "shown as unattached, never hidden (§22.5)"},
		{Member: MatchRebuilt, Label: "Rebuilt", Tone: ToneInfo, Note: "reconstructed from a provider because the list withheld it"},
		{Member: MatchAmbiguous, Label: "Ambiguous", Tone: ToneWarn, Mark: "?", Note: "more than one candidate"},
	},
	SetFinding: {
		// The one reserved colour, for the one condition §22.1 reserves it for.
		{Member: FindingExposed, Label: "Reachable with no gate", Tone: ToneAlert, Mark: "!", Note: "something outside the container network can answer, and no gate was detected"},
		{Member: FindingAccepted, Label: "Still exposed, accepted", Tone: ToneInfo, Note: "an operator accepted it — the exposure is unchanged (§14 rule 3)"},
		{Member: FindingGated, Label: "Gated", Tone: ToneGood},
		{Member: FindingNone, Label: "Not reachable", Tone: ToneNeutral},
	},
}

// phaseTerms is the connection phases. Built rather than written out because the tone follows one
// rule — a failed phase warns, the two that stopped before the network do not, and a full or
// partial read does not — and writing fifteen tones by hand is fifteen chances to give a failure
// the colour of an outcome (§15).
func phaseTerms() []Term {
	notes := map[payload.ConnectionPhase]string{
		payload.PhaseDisabled:      "switched off in configuration",
		payload.PhaseNotConfigured: "nothing to talk to",
		payload.PhaseNotFound:      "the thing to talk to does not exist",
		payload.PhaseCredential:    "a credential was needed and was absent or blank",
		payload.PhaseResolve:       "DNS said no",
		payload.PhaseConnect:       "refused, unreachable, or no route",
		payload.PhaseTLS:           "the handshake failed — not a reason to trust the wire anyway (§2.4)",
		payload.PhaseTimeout:       "no answer inside the budget",
		payload.PhaseAuthenticate:  "answered 401",
		payload.PhaseAuthorize:     "answered 403",
		payload.PhasePath:          "answered 404 or 405 — right host, wrong route",
		payload.PhaseStatus:        "answered with another non-2xx",
		payload.PhaseProtocol:      "answered, but not as this API",
		payload.PhasePartial:       "read enough to be useful, not all of it",
		payload.PhaseConnected:     "a full read",
	}
	labels := map[payload.ConnectionPhase]string{
		payload.PhaseDisabled:      "Disabled",
		payload.PhaseNotConfigured: "Not configured",
		payload.PhaseNotFound:      "Not found",
		payload.PhaseCredential:    "Credential",
		payload.PhaseResolve:       "DNS",
		payload.PhaseConnect:       "Connect",
		payload.PhaseTLS:           "TLS",
		payload.PhaseTimeout:       "Timeout",
		payload.PhaseAuthenticate:  "Unauthenticated",
		payload.PhaseAuthorize:     "Forbidden",
		payload.PhasePath:          "Wrong path",
		payload.PhaseStatus:        "Status",
		payload.PhaseProtocol:      "Protocol",
		payload.PhasePartial:       "Partial read",
		payload.PhaseConnected:     "Connected",
	}

	out := make([]Term, 0, len(payload.ConnectionPhases))
	for _, p := range payload.ConnectionPhases {
		t := Term{Member: string(p), Label: labels[p], Note: notes[p]}
		switch {
		case p == payload.PhaseConnected:
			t.Tone = ToneGood
		case p == payload.PhasePartial:
			// `ok` stays true for a partial read, and treating it as a failure would hide what was
			// read (§15). It is still the one non-failure that needs a banner, so it warns.
			t.Tone, t.Mark = ToneWarn, "?"
		case p.BeforeTheNetwork():
			// An outcome rather than a fault: nothing was attempted, so nothing failed.
			t.Tone = ToneNeutral
		default:
			t.Tone, t.Mark = ToneWarn, "?"
		}
		out = append(out, t)
	}
	return out
}

// Sets is every set name, sorted, for the generator and for the coverage of the legend.
func Sets() []Set {
	out := make([]Set, 0, len(vocabulary))
	for s := range vocabulary {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Terms is one set's members in canonical order.
func Terms(set Set) []Term { return vocabulary[set] }

// Members is one set's member spellings in canonical order — the values a filter offers and a
// shared URL carries.
func Members(set Set) []string {
	terms := vocabulary[set]
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		out = append(out, t.Member)
	}
	return out
}

// TermOf is the label and tone for one member, with §22.1's defined fallback.
//
// The fallback is deliberately colourless and deliberately keeps the raw spelling: a member added
// to the payload by a later version is a different protocol (§16), and the honest rendering of one
// is the text the payload sent plus a mark saying this build does not know it — not a guess at
// which category it belongs to.
func TermOf(set Set, member string) Term {
	for _, t := range vocabulary[set] {
		if t.Member == member {
			return t
		}
	}
	return UnknownTerm(member)
}

// UnknownTerm is §22.1's defined fallback, as its own function so the generated contract can carry it
// for the browser to use on the same condition (contract.go). Called with an empty member it is the
// template: the tone, the mark and the sentence, with the spelling to be filled in from whatever the
// payload actually sent.
func UnknownTerm(member string) Term {
	return Term{
		Member:  member,
		Label:   member,
		Tone:    ToneNeutral,
		Mark:    "·",
		Note:    "a member this build does not know — the payload is a later protocol (§16)",
		Unknown: true,
	}
}

// Label is TermOf's label, for the many places that want only the words.
func Label(set Set, member string) string { return TermOf(set, member).Label }
