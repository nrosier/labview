package fleet

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// TestLayeredLegs is §8's flow rules over the stack written for them. Five services sit on
// `layered_inner` and each leg says something different about what crosses it.
//
// The case that matters most is `cache`: `api` needs it by compose and `extra` needs it by
// declaration, so the leg carries both provenances and must read `both` — which renders **solid**,
// because something crossing it was measured. A leg that read `declared` here would be dashed, and
// dashing it would claim the relation was never observed.
func TestLayeredLegs(t *testing.T) {
	a := analyze(t, "nets")

	for _, tc := range []struct {
		service string
		flow    payload.EdgeFlow
		source  payload.EdgeFlowSource
		why     string
	}{
		{
			service: "web", flow: payload.FlowToNetwork, source: payload.FlowSourceObserved,
			why: "web needs api and nothing on the network needs web",
		},
		{
			service: "api", flow: payload.FlowBoth, source: payload.FlowSourceObserved,
			why: "web needs api and api needs cache, so an arrowhead at each end",
		},
		{
			service: "cache", flow: payload.FlowToService, source: payload.FlowSourceBoth,
			why: "api needs it by compose and extra by declaration; mixed provenance renders solid",
		},
		{
			service: "extra", flow: payload.FlowToNetwork, source: payload.FlowSourceDeclared,
			why: "its one dependency is declared only, so the leg is dashed",
		},
		{
			// The other half of the rule: on the network, in no dependency, so no arrowhead at all.
			// It is a co-member of the network rather than anything this stack is connected to.
			service: "probe", flow: "", source: "",
			why: "on the network and in no dependency",
		},
	} {
		t.Run(tc.service, func(t *testing.T) {
			e := a.edge(t, edgeID(payload.EdgeNetwork,
				PrefixService+"layered/"+tc.service, PrefixNetwork+"layered_inner"))
			if e.Flow != tc.flow {
				t.Errorf("flow = %q, want %q — %s", e.Flow, tc.flow, tc.why)
			}
			if e.FlowSource != tc.source {
				t.Errorf("flowSource = %q, want %q — %s", e.FlowSource, tc.source, tc.why)
			}
		})
	}
}

// TestFlowSourceBothIsNotDashed states the rendering contract the `both` member exists for, so that
// a renderer written later has something to fail against: dashed iff `declared`.
func TestFlowSourceBothIsNotDashed(t *testing.T) {
	a := analyze(t, "nets")

	for _, e := range a.Graph.Edges {
		if e.Kind != payload.EdgeNetwork {
			continue
		}
		// A leg with a flow always says where the flow came from, and a leg without one says
		// nothing at all — the two fields are set and cleared together.
		if (e.Flow == "") != (e.FlowSource == "") {
			t.Errorf("%s: flow = %q but flowSource = %q; the two must be set together",
				e.ID, e.Flow, e.FlowSource)
		}
		if e.FlowSource != "" && e.FlowSource != payload.FlowSourceObserved &&
			e.FlowSource != payload.FlowSourceDeclared && e.FlowSource != payload.FlowSourceBoth {
			t.Errorf("%s: flowSource = %q, which is outside the closed set", e.ID, e.FlowSource)
		}
	}
}

// TestADependencyOnlyMarksTheNetworksItCrosses is why the leg rule tests `via` rather than merely
// asking whether the service is in a dependency. A service on two networks whose dependency crosses
// one of them must carry an arrowhead on that leg and nothing on the other, or the picture claims a
// relation travels over a network it never touches.
func TestADependencyOnlyMarksTheNetworksItCrosses(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		DeclaredNetworks: []payload.NetworkDecl{{Name: "front"}, {Name: "back"}},
		Services: []payload.Service{
			// `web` is on both networks and depends on `db`, which is only on `back`.
			{Name: "web", Networks: []string{"s_front", "s_back"}, DependsOn: []string{"db"}},
			{Name: "db", Networks: []string{"s_back"}},
			// `sidecar` is on `front` so that network is drawn at all; it depends on nothing.
			{Name: "sidecar", Networks: []string{"s_front"}},
		},
	}}
	ix := NewIndex(stacks)
	nets := NewNetworks(stacks)
	deps := Dependencies(ix, nets)
	g := BuildGraph(GraphInput{Stacks: stacks, Index: ix, Networks: nets, Deps: deps})

	legs := map[string]payload.GraphEdge{}
	for _, e := range g.Edges {
		if e.Kind == payload.EdgeNetwork {
			legs[e.ID] = e
		}
	}
	crossed := legs[edgeID(payload.EdgeNetwork, PrefixService+"s/web", PrefixNetwork+"s_back")]
	if crossed.Flow != payload.FlowToNetwork {
		t.Errorf("web's leg to the network it crosses = %q, want %q", crossed.Flow, payload.FlowToNetwork)
	}
	untouched := legs[edgeID(payload.EdgeNetwork, PrefixService+"s/web", PrefixNetwork+"s_front")]
	if untouched.Flow != "" {
		t.Errorf("web's leg to s_front carries flow %q; the dependency never travels over it", untouched.Flow)
	}
}

// TestAnUnreachablePairMarksNoLeg is the same rule at its limit: `disjoint/front → back` crosses
// nothing, so it puts an arrowhead on no leg at all. Both of its networks happen to be solo-local and
// therefore undrawn, which is why the direct edge is the only honest drawing of the pair (§8).
func TestAnUnreachablePairMarksNoLeg(t *testing.T) {
	a := analyze(t, "nets")

	for _, e := range a.Graph.Edges {
		if e.Kind != payload.EdgeNetwork {
			continue
		}
		if e.Source == PrefixService+"disjoint/front" || e.Source == PrefixService+"disjoint/back" {
			t.Errorf("edge %q exists; neither of disjoint's networks connects anything", e.ID)
		}
	}
	if !a.hasEdge(edgeID(payload.EdgeDependsOn,
		PrefixService+"disjoint/front", PrefixService+"disjoint/back")) {
		t.Error("the pair has neither a leg nor a direct edge, so the dependency is drawn nowhere")
	}
}

// TestSoloLocalNetworksAreCountedNotDrawn is the omission the §8 identity rests on, checked from the
// graph's side: `lonely_island` is in the counters and is not a node, and its member therefore has
// no membership edge to draw.
func TestSoloLocalNetworksAreCountedNotDrawn(t *testing.T) {
	a := analyze(t, "nets")

	if a.hasNode(PrefixNetwork + "lonely_island") {
		t.Error("a solo-local network was drawn; the identity of §8 no longer holds")
	}
	for _, e := range a.Graph.Edges {
		if e.Target == PrefixNetwork+"lonely_island" {
			t.Errorf("edge %q points at a network that is not drawn", e.ID)
		}
	}
	// The external network with one member is drawn: something this scan cannot see may be on it.
	if !a.hasNode(PrefixNetwork + "outside") {
		t.Error("an external network with one member was omitted")
	}
}

// TestNetworkNodeCountsComeOffTheNode is I1 as a graph rule: MemberCount and StackCount are counted
// from the membership index and never inferred from the spokes beside them, which a renderer may cap.
func TestNetworkNodeCountsComeOffTheNode(t *testing.T) {
	a := analyze(t, "nets")

	for _, n := range a.Graph.Nodes {
		if n.Kind != payload.NodeNetwork {
			continue
		}
		net, ok := a.Nets.Get(n.Label)
		if !ok {
			t.Errorf("node %q names no real network", n.ID)
			continue
		}
		if n.MemberCount == nil || n.StackCount == nil {
			t.Errorf("%s: member or stack count absent; a renderer would have to count spokes", n.ID)
			continue
		}
		if *n.MemberCount != len(net.Members) {
			t.Errorf("%s: memberCount = %d, want %d", n.ID, *n.MemberCount, len(net.Members))
		}
		if *n.StackCount != len(net.Stacks) {
			t.Errorf("%s: stackCount = %d, want %d", n.ID, *n.StackCount, len(net.Stacks))
		}
		if n.Scope != net.Scope() {
			t.Errorf("%s: scope = %q, want %q", n.ID, n.Scope, net.Scope())
		}
	}
}

// TestRunningIsAbsentWhenDockerWasNotRead is §22.8: a stopped service and a service nothing is known
// about are different facts, so the field is absent rather than false.
func TestRunningIsAbsentWhenDockerWasNotRead(t *testing.T) {
	a := analyze(t, "nets")

	for _, n := range a.Graph.Nodes {
		if n.Kind == payload.NodeService && n.Running != nil {
			t.Errorf("%s carries running=%v with no Docker snapshot read", n.ID, *n.Running)
		}
	}
}

// TestVolumeEdgesJoinMountsToDeclaredVolumes applies the scan's own naming rule in reverse: a mount
// naming `database` in a stack whose project is `authentik` joins the declared `authentik_database`.
func TestVolumeEdgesJoinMountsToDeclaredVolumes(t *testing.T) {
	a := analyze(t, "apps")

	for _, tc := range []struct{ service, volume, target string }{
		{"authentik/postgresql", "authentik_database", "/var/lib/postgresql/data"},
		{"authentik/redis", "authentik_redis", "/data"},
	} {
		if !a.hasNode(PrefixVolume + tc.volume) {
			t.Errorf("no node for declared volume %q", tc.volume)
			continue
		}
		e := a.edge(t, edgeID(payload.EdgeVolume,
			PrefixService+tc.service, PrefixVolume+tc.volume))
		if e.Label != tc.target {
			t.Errorf("%s → %s label = %q, want the mount target %q",
				tc.service, tc.volume, e.Label, tc.target)
		}
	}
}

// TestBindMountsGetNoVolumeNode is the other half of the join: a bind mount names a path on the host
// rather than a declared volume, and a mount naming no declared volume gets no node. It is still on
// the service, which is where the Storage view reads it from.
func TestBindMountsGetNoVolumeNode(t *testing.T) {
	a := analyze(t, "apps")

	for _, n := range a.Graph.Nodes {
		if n.Kind != payload.NodeVolume {
			continue
		}
		if n.Label == "" || n.Label[0] == '.' || n.Label[0] == '/' {
			t.Errorf("volume node %q is a host path, not a declared volume", n.ID)
		}
	}
	// emby mounts `./config` and `/mnt/media`, and declares no volumes at all.
	for _, e := range a.Graph.Edges {
		if e.Kind == payload.EdgeVolume && e.Source == PrefixService+"emby/emby" {
			t.Errorf("emby's bind mounts produced volume edge %q", e.ID)
		}
	}
	svc := a.Index.Service("emby/emby")
	if len(svc.Mounts) != 2 {
		t.Errorf("emby has %d mounts, want 2 — they belong on the service either way", len(svc.Mounts))
	}
}

// TestGraphIsDeterministic is I7 read off the one object every view is derived from: two builds over
// one fleet produce the same nodes and edges in the same order.
func TestGraphIsDeterministic(t *testing.T) {
	first := analyze(t, "nets")
	second := BuildGraph(GraphInput{
		Stacks: first.Stacks, Index: first.Index, Networks: first.Nets,
		Deps: first.Deps, Proxies: first.Proxies,
	})

	if len(first.Graph.Nodes) != len(second.Nodes) {
		t.Fatalf("node counts differ: %d then %d", len(first.Graph.Nodes), len(second.Nodes))
	}
	for i := range first.Graph.Nodes {
		if first.Graph.Nodes[i].ID != second.Nodes[i].ID {
			t.Errorf("node %d = %q then %q", i, first.Graph.Nodes[i].ID, second.Nodes[i].ID)
		}
	}
	if len(first.Graph.Edges) != len(second.Edges) {
		t.Fatalf("edge counts differ: %d then %d", len(first.Graph.Edges), len(second.Edges))
	}
	for i := range first.Graph.Edges {
		if first.Graph.Edges[i].ID != second.Edges[i].ID {
			t.Errorf("edge %d = %q then %q", i, first.Graph.Edges[i].ID, second.Edges[i].ID)
		}
	}
}

// TestEveryEdgeEndpointIsANode is the structural invariant a renderer depends on: an edge pointing at
// an id no node carries is a line into nowhere.
func TestEveryEdgeEndpointIsANode(t *testing.T) {
	for _, root := range []string{"nets", "apps", "edge"} {
		a := analyze(t, root)
		for _, e := range a.Graph.Edges {
			if !a.hasNode(e.Source) {
				t.Errorf("%s: edge %q has no source node", root, e.ID)
			}
			if !a.hasNode(e.Target) {
				t.Errorf("%s: edge %q has no target node", root, e.ID)
			}
		}
	}
}

// TestNodeAndEdgeIDsAreUnique is what the shared dedup map buys, asserted rather than assumed: two
// nodes with one id would make a selection ambiguous and a drawer open the wrong object.
func TestNodeAndEdgeIDsAreUnique(t *testing.T) {
	for _, root := range []string{"nets", "apps", "edge"} {
		a := analyze(t, root)
		seen := map[string]bool{}
		for _, n := range a.Graph.Nodes {
			if seen[n.ID] {
				t.Errorf("%s: duplicate node id %q", root, n.ID)
			}
			seen[n.ID] = true
		}
		for _, e := range a.Graph.Edges {
			if seen[e.ID] {
				t.Errorf("%s: duplicate edge id %q", root, e.ID)
			}
			seen[e.ID] = true
		}
	}
}

// TestGateIsDrawnOnThePath is §22.5's requirement that a gate sit *on* an ingress path rather than
// beside its far end. The gate comes in as a resolved service key, so the edge is between two
// services and a diagram can route the path through it.
func TestGateIsDrawnOnThePath(t *testing.T) {
	a := analyze(t, "edge")

	g := BuildGraph(GraphInput{
		Stacks: a.Stacks, Index: a.Index, Networks: a.Nets, Deps: a.Deps, Proxies: a.Proxies,
		Gates: map[string]string{
			"hostport/app": "hostport/socketproxy",
			// A gate that is the service itself, and one that names nothing scanned: both are
			// dropped rather than drawn as a self-loop or an edge into nowhere.
			"hostport/media":  "hostport/media",
			"hostport/worker": "somewhere/else",
		},
	})

	want := edgeID(payload.EdgeAuth,
		PrefixService+"hostport/socketproxy", PrefixService+"hostport/app")
	var found int
	for _, e := range g.Edges {
		if e.Kind != payload.EdgeAuth {
			continue
		}
		found++
		if e.ID != want {
			t.Errorf("unexpected auth edge %q", e.ID)
		}
	}
	if found != 1 {
		t.Errorf("drew %d auth edges, want 1", found)
	}
}
