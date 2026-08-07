package webui

import (
	"github.com/nrosier/labview/internal/payload"
)

// §22.3: **every counter in `stats` has a card, and every card is a link.**
//
// The table below is that requirement as data, and the reason it is data is §23's second check: *for
// each counter, the card exists, it is a link, and its destination shows exactly the rows the number
// counted.* A check needs both halves in Go — the number and the destination — which is why a card
// carries a State rather than a URL string, and why the count is a **path into the payload** rather
// than a function.
//
// Three properties follow from stating it this way:
//
//   - **The card and its destination cannot disagree about the reading.** The destination's rows are
//     filtered by the tag rules of §22.6, and each of those rules is the same reading its counter is
//     counted from (tagrules.go). `auth-protected` is the exclusion `auth=-none`, because the counter
//     is `method.Detected()` and `methodOf` normalises an absent method to `none` — one normalisation,
//     used by the counter, the tag and the filter.
//   - **The browser reads the number from the payload, not from a card.** The path is in the generated
//     contract, so the overview is the payload's own numbers with labels and links attached — §22.1's
//     *may relabel, never conclude*, made structural.
//   - **An optional count that is absent renders *not reported*, never `0`** (§22.3). The count returns
//     a presence flag, and `Optional` says which cards must have somewhere to put the sentence about
//     what would make the number available.
//
// Two cards count their own destination's rows instead of naming a path: failing connections and scan
// warnings. That is not an exception to the rule that a number comes from the payload — both are
// lengths of a payload list (one of them filtered by §22.8's banner test) and nothing in `stats`
// counts them. It also makes their exactness structural rather than asserted.

// Card is one overview card.
type Card struct {
	// ID is stable and is what a test names when the card's number and destination disagree.
	ID string

	// Label is the card's heading, and Unit is what the number counts, singular — so a card can read
	// *3 stacks* rather than *3*.
	Label string
	Unit  string

	// Note is the honest reading: what the number includes, what it does not, or what would make an
	// absent one available (§22.3).
	Note string

	// Path is the dotted payload path of the number. Empty means the number is the destination's row
	// count — see the two cases in the file comment.
	Path string

	// Dest is where the card links: a view with a filter pre-applied, or a view with a panel that
	// lists the records behind the number (§22.3's two allowed destinations).
	Dest State

	// Exact records whether §23's second check asserts `len(Rows(Dest)) == count` for this card.
	//
	// It is false for exactly one family: the integration summaries, whose numbers count records the
	// *provider* holds. `providers`, `outposts` and `middlewares` have no row set in this fleet at all
	// — a middleware is not a service — and `applications` counts what the identity provider listed,
	// including applications that match nothing here. Reporting those numbers is right; claiming a
	// row-for-row correspondence with them would be the fiction §22.3 forbids. Each of them still
	// links to the view that shows the records it can show, and says so in its note.
	Exact bool

	// Optional marks a count that can be absent, which MUST render as *not reported* (§22.3, §15).
	Optional bool

	// Lead marks the one card §22.3 requires to be visible without scrolling.
	Lead bool

	// Tone is the card's colour. §22.5 reserves the alert colour for one meaning — reachable without
	// authentication — and this is the other place it may appear.
	Tone Tone

	// Segments expands this card into one per member of Set: §22.3's by-auth-method distribution,
	// where each segment links to the services with that method.
	Segments bool
	Set      Set

	// Member is the segment's member, on an expanded segment card only.
	Member string
}

// Count is the card's number, and whether the payload reported it.
//
// A `false` is *not reported* and never `0` (§22.3, §15's absence rule): an optional integration count
// the provider never supplied is not a count of zero, and the difference is the whole reason the field
// is a pointer in Appendix A.
func (c Card) Count(ov payload.Overview) (int, bool) {
	if c.Path == "" {
		// The number is the destination's rows, so the two cannot come apart.
		return len(Rows(c.Dest, ov)), true
	}
	for _, v := range valuesAt(ov, c.Path) {
		if n, ok := asInt(v); ok {
			return n, true
		}
	}
	return 0, false
}

// Cards is the overview's cards for a payload, in §22.3's order, with the distribution expanded.
//
// Takes the payload because one card is a distribution: a segment per auth method. The members come
// from the closed vocabulary **plus any member the payload carries that this build does not know**,
// because a distribution that silently dropped a member would report a total that does not add up,
// and §16 says a payload from a later version is read as far as it can be rather than filtered to what
// this build expected.
func Cards(ov payload.Overview) []Card {
	out := make([]Card, 0, len(CardTable)+len(ov.Stats.ByAuthMethod))
	for _, c := range CardTable {
		if !c.Segments {
			out = append(out, c)
			continue
		}
		for _, member := range segmentMembers(c, ov) {
			out = append(out, c.segment(member))
		}
	}
	return out
}

// segment is one member of a distribution card.
func (c Card) segment(member string) Card {
	term := TermOf(c.Set, member)
	seg := Card{
		ID:     c.ID + "/" + member,
		Label:  term.Label,
		Unit:   c.Unit,
		Note:   term.Note,
		Path:   c.Path + PathSeparator + member,
		Dest:   c.Dest.Including(DimAuth, member),
		Exact:  c.Exact,
		Tone:   ToneNeutral,
		Set:    c.Set,
		Member: member,
	}
	if member == string(payload.AuthNone) {
		// The one segment that is a finding rather than a mechanism. It warns rather than alerts: no
		// detected mechanism is not the same statement as reachable without authentication, and the
		// alert colour is reserved for that one (§22.5).
		seg.Tone = ToneWarn
	}
	return seg
}

// segmentMembers is the distribution's members: the vocabulary first, in canonical order, then
// anything else the payload counted.
func segmentMembers(c Card, ov payload.Overview) []string {
	known := Members(c.Set)
	out := make([]string, 0, len(known)+len(ov.Stats.ByAuthMethod))
	out = append(out, known...)
	for method := range ov.Stats.ByAuthMethod {
		out = appendOnceString(out, string(method))
	}
	// Sorted after the known members, so the order is deterministic whatever the map iteration did.
	sortStrings(out[len(known):])
	return out
}

// CardOf finds a card by id.
func CardOf(ov payload.Overview, id string) (Card, bool) {
	for _, c := range Cards(ov) {
		if c.ID == id {
			return c, true
		}
	}
	return Card{}, false
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

// services is the destination every service-shaped card starts from.
func services() State { return State{View: SlugServices} }

// CardTable is §22.3's table, in the order the overview lays it out: the exposure finding first and
// above the fold, then the fleet, reachability, declarations, probe, networks, and the integrations
// last — findings before inventory, which is the same order §22.2 gives the views.
var CardTable = []Card{
	{
		ID:    "exposedWithoutAuth",
		Label: "Exposed without authentication",
		Unit:  "service",
		Note:  "reachable from outside with no gate this scan could find, read off the stored finding rather than recomputed (§4.2)",
		Path:  "stats.exposedWithoutAuth",
		Dest:  State{View: SlugServices, Exposed: true},
		Exact: true,
		Lead:  true,
		Tone:  ToneAlert,
	},

	// Fleet.
	{
		ID:    "stacks",
		Label: "Stacks",
		Unit:  "stack",
		Note:  "one directory holding a compose file; a directory whose children hold them is not itself a stack (§6)",
		Path:  "stats.stacks",
		Dest:  State{View: SlugStacks},
		Exact: true,
	},
	{
		ID:    "services",
		Label: "Services",
		Unit:  "service",
		Note:  "every service in every compose file, whether or not a container for it was ever read",
		Path:  "stats.services",
		Dest:  services(),
		Exact: true,
	},
	{
		ID:    "running",
		Label: "Running",
		Unit:  "container",
		Note:  "counted off the Engine's boolean; a service whose container was never read is not running and is not stopped either (§22.8)",
		Path:  "stats.running",
		Dest:  State{View: SlugContainers}.Including(DimState, StateRunning),
		Exact: true,
	},

	// Reachability. One card per ingress kind, each including that member rather than equalling it:
	// a service both public and on the LAN is counted by both, exactly as the counters count it.
	{
		ID:    "publicServices",
		Label: "Public",
		Unit:  "service",
		Note:  "reachable from outside the LAN by some path",
		Path:  "stats.publicServices",
		Dest:  services().Including(DimIngress, string(payload.IngressPublic)),
		Exact: true,
	},
	{
		ID:    "traefikServices",
		Label: "Behind the proxy",
		Unit:  "service",
		Note:  "a route into it exists, from labels or from the proxy's own table; being routed is not being gated (§8)",
		Path:  "stats.traefikServices",
		Dest:  services().Including(DimIngress, string(payload.IngressTraefik)),
		Exact: true,
	},
	{
		ID:    "lanServices",
		Label: "On the LAN",
		Unit:  "service",
		Note:  "a published port on the host, which is a gate nothing enforces",
		Path:  "stats.lanServices",
		Dest:  services().Including(DimIngress, string(payload.IngressLan)),
		Exact: true,
	},
	{
		ID:    "internalServices",
		Label: "Internal only",
		Unit:  "service",
		Note:  "reachable only from a compose network, so whatever else is on that network can reach it (§16)",
		Path:  "stats.internalServices",
		Dest:  services().Including(DimIngress, string(payload.IngressInternal)),
		Exact: true,
	},
	{
		ID:    "noIngressServices",
		Label: "No ingress found",
		Unit:  "service",
		Note:  "no path into it was found — which is not the same as none existing (§4)",
		Path:  "stats.noIngressServices",
		Dest:  services().Including(DimIngress, string(payload.IngressNone)),
		Exact: true,
	},
	{
		ID:    "authProtected",
		Label: "Authentication detected",
		Unit:  "service",
		Note:  "a mechanism was identified; the destination is every service whose method is not `none`, which is what the counter tests",
		Path:  "stats.authProtected",
		Dest:  services().Excluding(DimAuth, string(payload.AuthNone)),
		Exact: true,
		Tone:  ToneGood,
	},
	{
		ID:       "byAuthMethod",
		Label:    "By mechanism",
		Unit:     "service",
		Note:     "the whole partition, so the segments add up to the service count",
		Path:     "stats.byAuthMethod",
		Dest:     services(),
		Exact:    true,
		Segments: true,
		Set:      SetAuthMethod,
	},

	// Declarations (§14).
	{
		ID:    "declaredAuth",
		Label: "Declared authentication",
		Unit:  "service",
		Note:  "the operator declared a mechanism; a declaration is a claim and never evidence (§14 rule 1)",
		Path:  "stats.declaredAuth",
		Dest:  State{View: SlugDeclarations}.Including(DimDecl, DeclAuth),
		Exact: true,
	},
	{
		ID:    "declaredAuthProtected",
		Label: "Protected — declared",
		Unit:  "service",
		Note:  "the declaration supplies the gate the scan could not see (§14 rule 2), read off the agreement",
		Path:  "stats.declaredAuthProtected",
		Dest:  State{View: SlugDeclarations}.Including(DimDecl, DeclProtected),
		Exact: true,
	},
	{
		ID:    "declaredAuthUnconfirmed",
		Label: "Declared, not confirmed",
		Unit:  "service",
		Note:  "declared and not observed — kept apart from drift, which is a declaration the evidence contradicts (§22.2)",
		Path:  "stats.declaredAuthUnconfirmed",
		Dest:  State{View: SlugDeclarations}.Including(DimDecl, DeclNotConfirmed),
		Exact: true,
	},
	{
		ID:    "exposureAccepted",
		Label: "Exposure accepted",
		Unit:  "service",
		Note:  "an operator decision, listed as still exposed: an acceptance records who decided and changes nothing about reachability (§14 rule 3)",
		Path:  "stats.exposureAccepted",
		Dest:  State{View: SlugDeclarations, Accepted: true},
		Exact: true,
		Tone:  ToneWarn,
	},
	{
		ID:    "declarationDrift",
		Label: "Declaration drift",
		Unit:  "entry",
		Note:  "entries, not services: a service with two drift entries contributes two, and the destination lists entries",
		Path:  "stats.declarationDrift",
		Dest:  State{View: SlugDeclarations, Drift: true},
		Exact: true,
		Tone:  ToneWarn,
	},
	{
		ID:    "declaredDependencies",
		Label: "Declared dependencies",
		Unit:  "edge",
		Note:  "declared references that resolved to a scanned service; one that named nothing is drift instead, and drew no edge (§14)",
		Path:  "stats.declaredDependencies",
		Dest: State{View: SlugDiagrams, Diagram: DiagramDependencies, Panel: PanelEdges}.
			Including(DimState, EdgeDeclared),
		Exact: true,
	},

	// Probe (§13).
	{
		ID:    "probeGated",
		Label: "Probe found a gate",
		Unit:  "service",
		Note:  "an anonymous request met a login page, a redirect to one, or a challenge",
		Path:  "stats.probeGated",
		Dest:  State{View: SlugProbe}.Including(DimProbe, OutcomeGated),
		Exact: true,
		Tone:  ToneGood,
	},
	{
		ID:    "probeOpen",
		Label: "Probe answered, no gate",
		Unit:  "service",
		Note:  "answered an anonymous request with no gate signal — a finding about the path, not a verdict about the application (§13.3)",
		Path:  "stats.probeOpen",
		Dest:  State{View: SlugProbe}.Including(DimProbe, OutcomeOpen),
		Exact: true,
		Tone:  ToneWarn,
	},

	// Networks (§8).
	{
		ID:    "networks",
		Label: "Networks",
		Unit:  "network",
		Note:  "every network some compose file names, external ones included; a name is not a promise it exists (§16)",
		Path:  "stats.networks",
		Dest:  State{View: SlugNetworks},
		Exact: true,
	},
	{
		ID:    "connectingNetworks",
		Label: "Connecting",
		Unit:  "network",
		Note:  "two or more members, so something on it can reach something else; co-membership is still not a dependency (§16)",
		Path:  "stats.connectingNetworks",
		Dest:  State{View: SlugNetworks}.Including(DimState, NetConnecting),
		Exact: true,
	},
	{
		ID:    "crossStackNetworks",
		Label: "Cross-stack",
		Unit:  "network",
		Note:  "joins two or more stacks, which is how a stack boundary stops being a reachability boundary",
		Path:  "stats.crossStackNetworks",
		Dest:  State{View: SlugNetworks}.Including(DimState, NetCrossStack),
		Exact: true,
	},
	{
		ID:    "soloLocalNetworks",
		Label: "Solo, local",
		Unit:  "network",
		Note:  "one member and nothing outside the scan: it connects nothing, and no diagram draws it (§8)",
		Path:  "stats.soloLocalNetworks",
		Dest:  State{View: SlugNetworks}.Including(DimState, NetSoloLocal),
		Exact: true,
	},

	// Identity provider (§11). These are the provider's numbers about its own records.
	{
		ID:    "authentikApplications",
		Label: "Identity applications",
		Unit:  "application",
		Note:  "what the identity provider listed, including applications that protect nothing in this fleet — the view shows the ones this scan could place",
		Path:  "meta.authentik.applications",
		Dest:  State{View: SlugIdentity},
	},
	{
		ID:       "authentikApplicationsConfigured",
		Label:    "Applications configured",
		Unit:     "application",
		Note:     "the provider's own total, when it reported one; absent means it did not, which is not the same as zero (§15)",
		Path:     "meta.authentik.applicationsConfigured",
		Dest:     State{View: SlugIdentity},
		Optional: true,
	},
	{
		ID:    "authentikApplicationsWithheld",
		Label: "Withheld from the list",
		Unit:  "application",
		Note:  "the list returned fewer than the provider says exist; shown beside recovered, because `partial` is their difference (§11)",
		Path:  "meta.authentik.applicationsWithheld",
		Dest:  State{View: SlugIdentity},
		Tone:  ToneWarn,
	},
	{
		ID:    "authentikApplicationsRecovered",
		Label: "Recovered from providers",
		Unit:  "application",
		Note:  "rebuilt from provider records because the list withheld them; the destination marks each as rebuilt",
		Path:  "meta.authentik.applicationsRecovered",
		Dest:  State{View: SlugIdentity}.Including(DimMatch, MatchRebuilt),
	},
	{
		ID:    "authentikProviders",
		Label: "Providers",
		Unit:  "provider",
		Note:  "provider records the identity API holds; a provider is not a service and has no row of its own here",
		Path:  "meta.authentik.providers",
		Dest:  State{View: SlugIdentity},
	},
	{
		ID:    "authentikOutposts",
		Label: "Outposts",
		Unit:  "outpost",
		Note:  "the forward-auth deployments the provider knows about — the mechanism a proxied service's gate runs on (§11)",
		Path:  "meta.authentik.outposts",
		Dest:  State{View: SlugIdentity},
	},
	{
		ID:    "authentikMatchedServices",
		Label: "Services matched to identity",
		Unit:  "service",
		Note:  "a match is a hostname or a provider record lining up with a scanned service; the strength of each is on the row (§11)",
		Path:  "meta.authentik.matchedServices",
		Dest:  services().Including(DimMatch, MatchMatched),
	},
	{
		ID:    "authentikUnmatchedApplications",
		Label: "Unmatched applications",
		Unit:  "application",
		Note:  "an application this fleet has no service for, each with the reason, the detail and what was considered",
		Path:  "",
		Dest:  State{View: SlugIdentity}.Including(DimMatch, MatchUnmatched),
		Exact: true,
	},

	// Reverse proxy (§12).
	{
		ID:    "traefikRouters",
		Label: "Live routers",
		Unit:  "router",
		Note:  "routers the running proxy reports, which is a different set from the routers declared in labels",
		Path:  "meta.traefik.routers",
		Dest:  State{View: SlugProxy},
	},
	{
		ID:    "traefikMiddlewares",
		Label: "Middlewares",
		Unit:  "middleware",
		Note:  "the proxy's middleware records; a middleware chain belongs to a router, so it has no row of its own",
		Path:  "meta.traefik.middlewares",
		Dest:  State{View: SlugProxy},
	},
	{
		ID:    "traefikServicesLive",
		Label: "Proxy services",
		Unit:  "service",
		Note:  "the proxy's own service objects — its view of where a router sends traffic, not this fleet's services",
		Path:  "meta.traefik.services",
		Dest:  State{View: SlugProxy},
	},
	{
		ID:    "traefikMatchedServices",
		Label: "Services matched to the proxy",
		Unit:  "service",
		Note:  "services a live router was traced to, which is fewer than the services carrying proxy labels when the proxy is not serving one (§17)",
		Path:  "meta.traefik.matchedServices",
		Dest:  services().Including(DimMatch, MatchMatched),
	},
	{
		ID:    "traefikUnmatchedRouters",
		Label: "Unmatched routers",
		Unit:  "router",
		Note:  "a live router pointing at nothing this scan found — a stale route, or a service outside the tree",
		Path:  "",
		Dest:  State{View: SlugProxy}.Including(DimMatch, MatchUnmatched),
		Exact: true,
		Tone:  ToneWarn,
	},

	// System (§15, §22.8).
	{
		ID:    "failingConnections",
		Label: "Failing connections",
		Unit:  "connection",
		Note:  "partial reads and every failure that is not a setting; disabled and not-configured are settings, not faults (§22.8)",
		Path:  "",
		Dest:  State{View: SlugDiagnostics}.Including(DimState, ReportFailing),
		Exact: true,
		Tone:  ToneWarn,
	},
	{
		ID:    "warnings",
		Label: "Scan warnings",
		Unit:  "warning",
		Note:  "what the scan could not do, in its own words — the list is bounded, and this is all of it",
		Path:  "",
		Dest:  State{View: SlugDiagnostics, Panel: PanelWarnings},
		Exact: true,
		Tone:  ToneWarn,
	},
	{
		ID:    "build",
		Label: "This build",
		Unit:  "",
		Note:  "version, commit and where the stamp came from: linker flags, the module's own build info, or unknown (§3.4)",
		Path:  "",
		Dest:  State{View: SlugDiagnostics, Panel: "build:stamp"},
	},
}

// StatsPaths is every counter in `stats`, as a path — the left-hand side of §23's second check.
//
// Derived by walking Appendix A rather than listed, so a counter added to the payload without a card
// fails the check instead of being quietly uncarded. That is the whole point of the check: `stats` is
// the one place in the payload where a new field is a new claim on the overview.
func StatsPaths() []string {
	const prefix = "stats" + PathSeparator
	var out []string
	for _, path := range PayloadPaths() {
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			out = append(out, path)
		}
	}
	return out
}
