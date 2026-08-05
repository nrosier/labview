package fleet

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// TestNetworkCorpusCounters is the counted conclusion §8 requires of fixtures/nets, in the four
// numbers the Overview draws.
//
// They are asserted as literals rather than recomputed from the index, because a test that derives
// its expectation the same way the code does cannot fail when the rule is reverted (§23). The
// fleet is nine networks: badref_side, disjoint_front-side, disjoint_back-side, layered_inner,
// outside, lonely_island, backup, shared-b_default and shared-d_watch.
func TestNetworkCorpusCounters(t *testing.T) {
	a := analyze(t, "nets")

	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"networks", a.Stats.Networks, 9},
		{"connecting", a.Stats.ConnectingNetworks, 3},
		{"cross-stack", a.Stats.CrossStackNetworks, 1},
		{"solo-local", a.Stats.SoloLocalNetworks, 5},
		{"drawn nodes", DrawnNetworkNodes(a.Graph), 4},
	} {
		if tc.got != tc.want {
			t.Errorf("%s networks = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// The identity of §8: every network is either drawn or solo-local, and none is both. The two
	// sides are counted from different code — the graph decides what to draw, the index decides
	// what is solo-local — which is what makes the check worth making.
	if !NetworkIdentityHolds(a.Graph, a.Stats) {
		t.Errorf("drawn network nodes (%d) + solo-local (%d) != total networks (%d)",
			DrawnNetworkNodes(a.Graph), a.Stats.SoloLocalNetworks, a.Stats.Networks)
	}
}

// TestNetworkNames pins the resolved real names: a stack-local network is `${project}_${key}` and
// an external one is verbatim, because that is the name the Engine would show and the name two
// stacks have to agree on to share anything.
func TestNetworkNames(t *testing.T) {
	a := analyze(t, "nets")

	want := []string{
		"badref_side",
		"disjoint_front-side", "disjoint_back-side",
		"layered_inner",
		"outside", "lonely_island",
		"backup",
		"shared-b_default",
		"shared-d_watch",
	}
	got := a.Nets.Names()
	if len(got) != len(want) {
		t.Fatalf("networks = %v, want %v", got, want)
	}
	for _, name := range want {
		if _, ok := a.Nets.Get(name); !ok {
			t.Errorf("network %q missing; got %v", name, got)
		}
	}
}

// TestNetworkPredicates walks the four predicates over the networks each exists for, so that a
// changed definition fails here rather than only in the counters.
func TestNetworkPredicates(t *testing.T) {
	a := analyze(t, "nets")

	for _, tc := range []struct {
		network                                  string
		scope                                    payload.NetworkScope
		members, stacks                          int
		connecting, crossStack, soloLocal, drawn bool
	}{
		// The four stacks on one external network: the only cross-stack network in the corpus.
		{"backup", payload.ScopeExternal, 4, 4, true, true, false, true},
		// One stack's own network carrying three dependencies.
		{"layered_inner", payload.ScopeStackLocal, 5, 1, true, false, false, true},
		{"badref_side", payload.ScopeStackLocal, 2, 1, true, false, false, true},
		// External with one scanned member: something this scan cannot see may be on it, which
		// is a real statement about what the service can reach, so the node is kept.
		{"outside", payload.ScopeExternal, 1, 1, false, false, false, true},
		// This stack's own network that nothing else joined: counted, not drawn.
		{"lonely_island", payload.ScopeStackLocal, 1, 1, false, false, true, false},
		{"shared-b_default", payload.ScopeStackLocal, 1, 1, false, false, true, false},
		{"shared-d_watch", payload.ScopeStackLocal, 1, 1, false, false, true, false},
	} {
		net, ok := a.Nets.Get(tc.network)
		if !ok {
			t.Errorf("network %q missing", tc.network)
			continue
		}
		if net.Scope() != tc.scope {
			t.Errorf("%s scope = %q, want %q", tc.network, net.Scope(), tc.scope)
		}
		if len(net.Members) != tc.members {
			t.Errorf("%s members = %d (%v), want %d", tc.network, len(net.Members), net.Members, tc.members)
		}
		if len(net.Stacks) != tc.stacks {
			t.Errorf("%s stacks = %d (%v), want %d", tc.network, len(net.Stacks), net.Stacks, tc.stacks)
		}
		if net.Connecting() != tc.connecting {
			t.Errorf("%s connecting = %v, want %v", tc.network, net.Connecting(), tc.connecting)
		}
		if net.CrossStack() != tc.crossStack {
			t.Errorf("%s crossStack = %v, want %v", tc.network, net.CrossStack(), tc.crossStack)
		}
		if net.SoloLocal() != tc.soloLocal {
			t.Errorf("%s soloLocal = %v, want %v", tc.network, net.SoloLocal(), tc.soloLocal)
		}
		if net.Drawn() != tc.drawn {
			t.Errorf("%s drawn = %v, want %v", tc.network, net.Drawn(), tc.drawn)
		}
		if got := a.hasNode(PrefixNetwork + tc.network); got != tc.drawn {
			t.Errorf("%s node present = %v, want %v", tc.network, got, tc.drawn)
		}
	}
}

// TestSharedIsInDependentOrder pins the order `via` comes out in: the dependent's compose order,
// which is the order the operator wrote and the only one that is theirs rather than this scanner's.
func TestSharedIsInDependentOrder(t *testing.T) {
	a := analyze(t, "nets")

	// db-b joins `backup` then `default`; backup-agent joins only `backup`.
	if got := a.Nets.Shared("shared-b/db-b", "shared-c/backup-agent"); !equalStrings(got, []string{"backup"}) {
		t.Errorf("shared = %v, want [backup]", got)
	}
	// A service shares no network with itself: a self-dependency is not a relation, and reporting
	// one would put a loop on a diagram.
	if got := a.Nets.Shared("shared-b/db-b", "shared-b/db-b"); len(got) != 0 {
		t.Errorf("shared with self = %v, want none", got)
	}
	// Two stack-local networks in one stack are still two networks.
	if a.Nets.SharesAny("disjoint/front", "disjoint/back") {
		t.Error("disjoint/front and disjoint/back share a network, want none")
	}
}

// TestNeighboursDoesNotCountSelf is the co-membership rule from the other side: `monitor` is on the
// shared network with three other services, so it has neighbours; `islanded` is alone on its own,
// so it has none — and that is what decides whether `internal` is in its ingress set.
func TestNeighboursDoesNotCountSelf(t *testing.T) {
	a := analyze(t, "nets")

	if !a.Nets.HasNeighbour("shared-d/monitor") {
		t.Error("shared-d/monitor has no neighbour, want three")
	}
	if a.Nets.HasNeighbour("lonely/islanded") {
		t.Errorf("lonely/islanded has neighbours %v, want none", a.Nets.Neighbours("lonely/islanded"))
	}
	// External with nobody else scanned on it is still nobody else scanned on it. Something
	// unseen may be there, and `internal` claims a scanned neighbour (§4.1).
	if a.Nets.HasNeighbour("lonely/edge-facing") {
		t.Errorf("lonely/edge-facing has neighbours %v, want none", a.Nets.Neighbours("lonely/edge-facing"))
	}
}

// TestExternalScopeSurvivesAnOmission is the first-pass rule: one stack declaring a network
// external scopes it for every stack, even one whose own file left the flag out. Otherwise the
// scope of a shared network would depend on which stack happened to be scanned first.
func TestExternalScopeSurvivesAnOmission(t *testing.T) {
	stacks := []payload.AppStack{
		{
			ID: "a", ProjectName: "a",
			DeclaredNetworks: []payload.NetworkDecl{{Name: "shared"}},
			Services:         []payload.Service{{Name: "one", Networks: []string{"shared"}}},
		},
		{
			ID: "b", ProjectName: "b",
			DeclaredNetworks: []payload.NetworkDecl{{Name: "shared", External: true}},
			Services:         []payload.Service{{Name: "two", Networks: []string{"shared"}}},
		},
	}
	nets := NewNetworks(stacks)

	net, ok := nets.Get("shared")
	if !ok {
		t.Fatalf("network `shared` missing; got %v", nets.Names())
	}
	if net.Scope() != payload.ScopeExternal {
		t.Errorf("scope = %q, want %q", net.Scope(), payload.ScopeExternal)
	}
	if !net.CrossStack() {
		t.Error("shared is not cross-stack, want cross-stack")
	}
}
