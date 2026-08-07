package corpus

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// The graph root: eight stacks whose only subject is what a line in a picture means (§8, §14).
//
// Nothing here is exposed, nothing is gated and no integration is read. What is under test is the one
// claim a diagram makes that a table cannot: that these two things are connected. Every stack is a
// case where the obvious drawing would be wrong — a network shared by four stacks that connects none
// of them, a dependency with no network to travel over, a solo network that is counted and not drawn,
// and five references that resolve to nothing.
//
// It is also the root the diagram-export check runs over, so the arrowheads and the provenance below
// are what that export renders.

// ---------------------------------------------------------------------------
// The counters
// ---------------------------------------------------------------------------

func TestTheNetsRootIsCountedExactlyOnce(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})
	got := out.Stats

	for _, c := range []struct {
		name string
		got  int
		want int
		why  string
	}{
		{"stacks", got.Stacks, 8, "eight stacks"},
		{"services", got.Services, 16, "and sixteen services"},

		// Nothing in this root is reachable from anywhere. That is deliberate: an exposure finding
		// would be the loudest thing in the payload, and this root is about quiet relations.
		{"publicServices", got.PublicServices, 0, "no tunnel routes"},
		{"traefikServices", got.TraefikServices, 0, "no proxy routers"},
		{"lanServices", got.LanServices, 0, "no published ports"},
		{"exposedWithoutAuth", got.ExposedWithoutAuth, 0, "so there is nothing to be exposed"},

		{"internalServices", got.InternalServices, 11, "eleven share a real network with a scanned service"},
		{"noIngressServices", got.NoIngressServices, 5, "five are alone wherever they are"},

		// Five declared dependencies resolved to a scanned service and were drawn. The three broken
		// references in `badref` and `disjoint` are counted as drift instead — counting them here
		// would report a relation the graph does not contain.
		{"declaredDependencies", got.DeclaredDependencies, 5, "five references resolved"},
		{"declarationDrift", got.DeclarationDrift, 3, "and three did not"},

		{"networks", got.Networks, 9, "nine networks across the eight stacks"},
		{"connectingNetworks", got.ConnectingNetworks, 3, "three carry something between services"},
		{"crossStackNetworks", got.CrossStackNetworks, 1, "`backup`, shared by four stacks"},
		{"soloLocalNetworks", got.SoloLocalNetworks, 5, "five have a single member and no external declaration"},
	} {
		if c.got != c.want {
			t.Errorf("stats.%s = %d, want %d: %s", c.name, c.got, c.want, c.why)
		}
	}
}

// ---------------------------------------------------------------------------
// §8 — which networks are drawn
// ---------------------------------------------------------------------------

// A solo network is drawn when something the scan cannot see might be on it (§8).
//
// `lonely` is the pair, and it is the sharpest distinction in the section: two networks with exactly
// one scanned member each, one of them drawn and one not. `island` is this stack's own, so only this
// stack's services could ever join it and none has — the node would say a service is on a network,
// which every service is. `outside` is declared external, so a container this scan never saw may be on
// it, and *that* is a statement about what this service can reach.
func TestASoloNetworkIsDrawnWhenItIsExternalAndNotWhenItIsThisStacksOwn(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	drawn := drawnNetworks(out)
	if drawn["lonely_island"] {
		t.Error("lonely_island is drawn: it is this stack's own and has one member, so it connects nothing")
	}
	if !drawn["outside"] {
		t.Error("outside is not drawn: it is external, so something this scan cannot see may be on it")
	}

	// Both are still counted, and only one of them is solo-local — the count is of networks in the
	// fleet, and an operator looking for a network they created has to find it either way.
	if len(drawn)+out.Stats.SoloLocalNetworks != out.Stats.Networks {
		t.Errorf("%d drawn + %d solo != %d networks", len(drawn), out.Stats.SoloLocalNetworks, out.Stats.Networks)
	}

	// And neither member counts as having internal ingress, because in both cases there is no other
	// scanned service on the network to reach. An external network is a statement about reach, not
	// evidence of a neighbour.
	for _, key := range []string{"lonely/edge-facing", "lonely/islanded"} {
		if got := service(t, out, key).Ingress; marshal(t, got) != marshal(t, []payload.IngressKind{payload.IngressNone}) {
			t.Errorf("%s ingress = %s, want none: no other scanned service is on its network",
				key, marshal(t, got))
		}
	}
}

// Four stacks on one network, and not one connection between them (§8).
//
// This is the rule the whole root is built around. `backup` joins four stacks, and co-membership means
// only that these containers can address each other — which is not a relation anybody stated. Two of
// the four *are* connected, by declarations in their own sidecars, and `shared-d/monitor` is on the
// same network and connected to nothing: draw a leg from it to a database and the picture claims the
// monitor needs that database, which nothing in this fleet says.
func TestCoMembershipOfANetworkIsNotAConnection(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	// The monitor is a member.
	if !fleetHas(service(t, out, "shared-d/monitor").Ingress, payload.IngressInternal) {
		t.Error("shared-d/monitor is not internal, and it is on the shared backup network")
	}
	if !drawnNetworks(out)["backup"] {
		t.Error("the backup network is not drawn, and four stacks are on it")
	}

	// And it is the endpoint of no relation at all.
	for _, e := range out.Graph.Edges {
		if e.Kind == payload.EdgeNetwork {
			continue
		}
		if e.Source == "svc:shared-d/monitor" || e.Target == "svc:shared-d/monitor" {
			t.Errorf("shared-d/monitor is an endpoint of %s: nothing in this fleet says it needs "+
				"anything or that anything needs it", e.ID)
		}
	}

	// Its membership leg carries no arrowhead either. An arrowhead is a dependency crossing the
	// network, and no dependency crosses it on this service's behalf.
	leg := networkEdge(t, out, "svc:shared-d/monitor", "net:backup")
	if leg.Flow != "" {
		t.Errorf("its membership leg has flow %q, want none: it is a co-member and nothing more", leg.Flow)
	}
}

// ---------------------------------------------------------------------------
// §8 — the arrowheads
// ---------------------------------------------------------------------------

// Where the arrowhead sits, and whether it was measured or asserted (§8).
//
// `layered` is five services on one network, and the five legs below take four different shapes. The
// direction says which end of the network a dependency crosses toward; the provenance says whether
// anything measured it, and decides whether the leg renders dashed. Both are read off the dependencies
// the network actually carries, which is why a fifth service that declares nothing gets neither.
func TestAMembershipLegCarriesTheDependenciesThatCrossIt(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	for _, c := range []struct {
		key    string
		flow   payload.EdgeFlow
		source payload.EdgeFlowSource
		why    string
	}{
		// Needed by `web` and needs `cache`, so the leg carries an arrowhead at each end.
		{"layered/api", payload.FlowBoth, payload.FlowSourceObserved,
			"web needs it and it needs the cache, both by compose"},

		// Needed by two services, by two different provenances. `both` renders solid: something
		// crossing this leg was measured, and a dashed leg would understate it.
		{"layered/cache", payload.FlowToService, payload.FlowSourceBoth,
			"api needs it by compose and extra needs it by declaration"},

		// A declaration and nothing else, so the leg renders dashed.
		{"layered/extra", payload.FlowToNetwork, payload.FlowSourceDeclared,
			"it needs the cache, and only the sidecar says so"},

		{"layered/web", payload.FlowToNetwork, payload.FlowSourceObserved, "it needs api, by compose"},
	} {
		leg := networkEdge(t, out, "svc:"+c.key, "net:layered_inner")
		if leg.Flow != c.flow {
			t.Errorf("%s leg flow = %q, want %q: %s", c.key, leg.Flow, c.flow, c.why)
		}
		if leg.FlowSource != c.source {
			t.Errorf("%s leg flowSource = %q, want %q: %s", c.key, leg.FlowSource, c.source, c.why)
		}
	}

	// The fifth service on the same network declares nothing and nothing declares it. Its leg is bare,
	// and it must be named as a co-member rather than as anything this stack is connected to.
	bare := networkEdge(t, out, "svc:layered/probe", "net:layered_inner")
	if bare.Flow != "" || bare.FlowSource != "" {
		t.Errorf("layered/probe leg = %q/%q, want both absent: nothing crosses the network for it",
			bare.Flow, bare.FlowSource)
	}
}

// A dependency inside one network is drawn through it and names it (§8).
//
// `via` is what makes a dependency edge answerable: two services that need each other over a network
// are a different fact from two that need each other over something else, and the network's name is
// how a reader checks the first claim.
func TestADependencyThatHasANetworkToTravelOverNamesIt(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	for _, c := range []struct {
		source string
		target string
		via    string
	}{
		{"svc:layered/web", "svc:layered/api", "layered_inner"},
		{"svc:layered/api", "svc:layered/cache", "layered_inner"},

		// Declared rather than observed, and it travels the same network as the two above.
		{"svc:layered/extra", "svc:layered/cache", "layered_inner"},

		// Across stacks, over the network the four stacks share.
		{"svc:shared-a/db-a", "svc:shared-c/backup-agent", "backup"},
		{"svc:shared-b/db-b", "svc:shared-c/backup-agent", "backup"},

		// Within a stack, over its own network.
		{"svc:badref/caller", "svc:badref/cache", "badref_side"},
	} {
		e := edge(t, out, payload.EdgeDependsOn, c.source, c.target)
		if marshal(t, e.Via) != marshal(t, []string{c.via}) {
			t.Errorf("%s -> %s via = %s, want [%q]", c.source, c.target, marshal(t, e.Via), c.via)
		}
		// The label is what a reader sees on the line, and it is the network's name rather than a
		// restatement of the two endpoints they are already looking at.
		if e.Label != c.via {
			t.Errorf("%s -> %s label = %q, want %q", c.source, c.target, e.Label, c.via)
		}
	}
}

// A dependency with no network to travel over is drawn straight, and said out loud (§8, §14).
//
// The honest drawing and the honest sentence. These two services cannot address each other: whatever
// they do together, they do it over the host's cron, an off-fleet queue, a shared volume — something
// this scan does not see. Drawing the line is right, because somebody stated the relation; drawing it
// *through* a network would be inventing the mechanism.
func TestADependencyWithNoSharedNetworkIsDrawnStraightAndTheGapIsStated(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	// Declared, across stacks, with no network in common.
	declared := edge(t, out, payload.EdgeDependsOn, "svc:disjoint/back", "svc:shared-c/backup-agent")
	if len(declared.Via) != 0 {
		t.Errorf("via = %v, want none: these two share no network", declared.Via)
	}
	if declared.DeclaredBy == nil || declared.DeclaredBy.Detail == "" {
		t.Errorf("declaredBy = %v, want the sidecar and the detail it gave", declared.DeclaredBy)
	}

	// Observed, inside one stack, with no network in common. Compose stated the ordering and the
	// networks make it unaddressable — which is a thing worth telling an operator.
	observed := edge(t, out, payload.EdgeDependsOn, "svc:disjoint/front", "svc:disjoint/back")
	if len(observed.Via) != 0 {
		t.Errorf("via = %v, want none: front-side and back-side are separate networks", observed.Via)
	}
	if observed.DeclaredBy != nil {
		t.Errorf("declaredBy = %v on a compose depends_on", observed.DeclaredBy)
	}

	// Both ends of both relations are told, in the same words. A note on one side only would leave the
	// other service's drawer showing a line it cannot explain.
	for _, key := range []string{"disjoint/front", "disjoint/back"} {
		svc := service(t, out, key)
		if !noted(svc, "the two share no network") {
			t.Errorf("%s is not told its dependency has no network to travel over; notes = %v",
				key, svc.Notes)
		}
		if !noted(svc, "this scan cannot see") {
			t.Errorf("%s does not say the mechanism is unknown; notes = %v", key, svc.Notes)
		}
	}
}

// ---------------------------------------------------------------------------
// §14 — resolving a reference
// ---------------------------------------------------------------------------

// A bare name means the sibling, and a name two stacks use means neither (§14).
//
// Four references in one file, and the interesting thing is that they fail and succeed in four
// different ways. Guessing on any of them would put a line in a picture whose entire value is that a
// line means something — so each failure is reported against the file and draws nothing.
func TestABrokenReferenceIsReportedAgainstItsFileAndDrawsNothing(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})
	caller := service(t, out, "badref/caller")

	if caller.Declared == nil {
		t.Fatal("badref/caller has no declaration")
	}

	// All four references are kept as written, including the ones that resolved to nothing. A dropped
	// reference is a typo the operator cannot see.
	if len(caller.Declared.DependsOn) != 4 {
		t.Errorf("dependsOn = %v, want all four references as written", caller.Declared.DependsOn)
	}

	if len(caller.Declared.Drift) != 2 {
		t.Fatalf("drift = %v, want two: the missing service and the self-reference", caller.Declared.Drift)
	}
	for _, want := range []string{
		// Names nothing. Usually a rename nobody carried over.
		"`nope/missing` in `.labview` names no scanned service",
		// Names itself, which is not a relation.
		"names this very service; a dependency on itself is not a relation",
	} {
		found := false
		for _, d := range caller.Declared.Drift {
			if strings.Contains(d, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no drift entry says %q; drift = %v", want, caller.Declared.Drift)
		}
	}

	// One edge from four references. The bare `cache` resolved to the sibling — which is also all
	// compose's own `depends_on` can ever mean — and `badref/cache` is the same service the long way,
	// so it is dropped without a word: the file says nothing wrong, it says it twice.
	count := 0
	for _, e := range out.Graph.Edges {
		if e.Kind == payload.EdgeDependsOn && e.Source == "svc:badref/caller" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("badref/caller has %d dependency edges, want one: two of its four references name "+
			"the same sibling and two resolve to nothing", count)
	}

	// And the sibling, not the service of the same name one stack over.
	e := edge(t, out, payload.EdgeDependsOn, "svc:badref/caller", "svc:badref/cache")
	if e.DeclaredBy == nil {
		t.Error("the resolved reference does not say which file declared it")
	}
	for _, other := range out.Graph.Edges {
		if other.Kind == payload.EdgeDependsOn && other.Target == "svc:layered/cache" &&
			other.Source == "svc:badref/caller" {
			t.Error("a bare `cache` in badref resolved across stacks instead of to its own sibling")
		}
	}
}

// An ambiguous name resolves to neither candidate, and both are named (§14).
//
// Two stacks have a service called `probe` and the stack writing the reference has none, so there is
// no sibling to prefer and no way to choose. Picking one would be a coin toss drawn as a fact. The
// drift entry names both candidates and the form that would have worked, because the operator's next
// action is to edit that line.
func TestAnAmbiguousReferenceNamesEveryCandidateAndResolvesToNone(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})
	front := service(t, out, "disjoint/front")

	if len(front.Declared.Drift) != 1 {
		t.Fatalf("drift = %v, want one entry for the ambiguous reference", front.Declared.Drift)
	}
	entry := front.Declared.Drift[0]
	for _, want := range []string{
		"names 2 services",
		"`layered/probe`",
		"`shared-d/probe`",
		"written as `stack/service`",
	} {
		if !strings.Contains(entry, want) {
			t.Errorf("the drift entry does not contain %q: %q", want, entry)
		}
	}

	// Neither candidate got an edge. This is the assertion that catches an implementation which picks
	// the first match and reports the ambiguity anyway.
	for _, e := range out.Graph.Edges {
		if e.Kind != payload.EdgeDependsOn || e.Source != "svc:disjoint/front" {
			continue
		}
		if e.Target == "svc:layered/probe" || e.Target == "svc:shared-d/probe" {
			t.Errorf("an ambiguous reference was resolved anyway: %s", e.ID)
		}
	}
}

// A dependency is declared on the dependent, and the target needs no file of its own (§14).
//
// `shared-c` has no sidecar at all, and two databases in two other stacks each name it. Both relations
// have to reach it, derived from their statements rather than from anything of its own — a
// `required_by` key on the target would have to be edited for every database anybody adds, which is
// the work this design exists to avoid.
func TestATargetNeedsNoFileOfItsOwnToBeRequiredByTwoStacks(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	if agent := service(t, out, "shared-c/backup-agent"); agent.Declared != nil {
		t.Errorf("shared-c/backup-agent has a declaration, and its stack has no sidecar: %v", agent.Declared)
	}

	// Three relations arrive at it, from three stacks, and one of them travels no network.
	var arriving []string
	for _, e := range out.Graph.Edges {
		if e.Kind == payload.EdgeDependsOn && e.Target == "svc:shared-c/backup-agent" {
			arriving = append(arriving, e.Source)
		}
	}
	want := []string{"svc:disjoint/back", "svc:shared-a/db-a", "svc:shared-b/db-b"}
	if marshal(t, arriving) != marshal(t, want) {
		t.Errorf("relations arriving at the agent = %s, want %s", marshal(t, arriving), marshal(t, want))
	}

	// One of the two references was written `stack/service` and the other bare. Both resolved, and the
	// bare one resolved across stacks because nothing in its own project answers to the name.
	if e := edge(t, out, payload.EdgeDependsOn, "svc:shared-b/db-b", "svc:shared-c/backup-agent"); e.DeclaredBy == nil {
		t.Error("the bare cross-stack reference lost its provenance")
	}

	// The detail one of them supplied is carried to the edge, because it is the answer to the question
	// the line provokes: what do these two do together.
	e := edge(t, out, payload.EdgeDependsOn, "svc:shared-a/db-a", "svc:shared-c/backup-agent")
	if e.DeclaredBy == nil || !strings.Contains(e.DeclaredBy.Detail, "Nightly dump target") {
		t.Errorf("declaredBy = %v, want the detail from the sidecar", e.DeclaredBy)
	}

	// And the agent's own membership leg carries an inbound arrowhead, from the dependencies that
	// cross the shared network toward it.
	leg := networkEdge(t, out, "svc:shared-c/backup-agent", "net:backup")
	if leg.Flow != payload.FlowToService {
		t.Errorf("the agent's leg flow = %q, want %q: two databases need it over this network",
			leg.Flow, payload.FlowToService)
	}
	if leg.FlowSource != payload.FlowSourceDeclared {
		t.Errorf("the agent's leg flowSource = %q, want %q: nothing measured either relation",
			leg.FlowSource, payload.FlowSourceDeclared)
	}
}

// ---------------------------------------------------------------------------
// Reading the graph
// ---------------------------------------------------------------------------

// drawnNetworks is the network node names in the graph.
func drawnNetworks(out payload.Overview) map[string]bool {
	drawn := map[string]bool{}
	for _, n := range out.Graph.Nodes {
		if n.Kind == payload.NodeNetwork {
			drawn[strings.TrimPrefix(n.ID, "net:")] = true
		}
	}
	return drawn
}

// edge finds one edge by kind and endpoints, and fails naming what was there instead.
func edge(t *testing.T, out payload.Overview, kind payload.GraphEdgeKind, source, target string) payload.GraphEdge {
	t.Helper()
	var sameKind []string
	for _, e := range out.Graph.Edges {
		if e.Kind != kind {
			continue
		}
		if e.Source == source && e.Target == target {
			return e
		}
		sameKind = append(sameKind, e.Source+" -> "+e.Target)
	}
	t.Fatalf("no %s edge %s -> %s; the graph has %s", kind, source, target, strings.Join(sameKind, ", "))
	return payload.GraphEdge{}
}

// networkEdge finds a membership leg. It is separate from edge because the leg's endpoints are a
// service and a network, and reading a flow off the wrong one of the two would silently invert it.
func networkEdge(t *testing.T, out payload.Overview, svc, net string) payload.GraphEdge {
	t.Helper()
	return edge(t, out, payload.EdgeNetwork, svc, net)
}
