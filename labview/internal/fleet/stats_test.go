package fleet

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// TestStatsOverTheNetsCorpus is every counter §8 and §14 make computable without enrichment, over the
// corpus of eight stacks and sixteen services.
//
// The declaration counters are zero here on purpose: §14's walk lives in `declare` and has not run,
// so this asserts that nothing in this package invents an agreement or a drift entry of its own.
func TestStatsOverTheNetsCorpus(t *testing.T) {
	s := analyze(t, "nets").Stats

	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"stacks", s.Stacks, 8},
		{"services", s.Services, 16},

		// Nothing in this corpus publishes a port or declares a route.
		{"public", s.PublicServices, 0},
		{"traefik", s.TraefikServices, 0},
		{"lan", s.LanServices, 0},
		// Eleven services share a network with another scanned service; five are alone.
		{"internal", s.InternalServices, 11},
		{"no ingress", s.NoIngressServices, 5},

		// No Docker snapshot, no labels, no probe.
		{"running", s.Running, 0},
		{"auth protected", s.AuthProtected, 0},
		{"exposed without auth", s.ExposedWithoutAuth, 0},
		{"probe gated", s.ProbeGated, 0},
		{"probe open", s.ProbeOpen, 0},

		// Five declared references resolved; three were refused and are counted as drift instead.
		{"declared dependencies", s.DeclaredDependencies, 5},

		// §14's walk has not run.
		{"declared auth", s.DeclaredAuth, 0},
		{"declared auth protected", s.DeclaredAuthProtected, 0},
		{"declared auth unconfirmed", s.DeclaredAuthUnconfirmed, 0},
		{"exposure accepted", s.ExposureAccepted, 0},
		{"declaration drift", s.DeclarationDrift, 0},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// The ingress kinds partition this corpus because no service carries two of them, which is what
	// makes the two numbers above add up to the service count. That is a property of these fixtures
	// rather than of the vocabulary — the three external kinds overlap in general (§22.1).
	if s.InternalServices+s.NoIngressServices != s.Services {
		t.Errorf("internal (%d) + none (%d) != services (%d)",
			s.InternalServices, s.NoIngressServices, s.Services)
	}
}

// TestByAuthMethodPartitions is §22.1's rule about a distribution: every member is present even at
// zero, because a member missing from a distribution reads as a member that cannot occur.
func TestByAuthMethodPartitions(t *testing.T) {
	s := analyze(t, "nets").Stats

	if len(s.ByAuthMethod) != len(payload.AuthMethods) {
		t.Errorf("byAuthMethod has %d members, want all %d", len(s.ByAuthMethod), len(payload.AuthMethods))
	}
	total := 0
	for _, m := range payload.AuthMethods {
		n, ok := s.ByAuthMethod[m]
		if !ok {
			t.Errorf("byAuthMethod is missing %q, which reads as a member that cannot occur", m)
		}
		total += n
	}
	if total != s.Services {
		t.Errorf("byAuthMethod sums to %d, want %d — a distribution that partitions", total, s.Services)
	}
	// Nothing was detected anywhere, so every service is `none` — and `none` is a member of the
	// distribution rather than an absence from it.
	if s.ByAuthMethod[payload.AuthNone] != s.Services {
		t.Errorf("none = %d, want %d", s.ByAuthMethod[payload.AuthNone], s.Services)
	}
}

// TestOverlappingIngressCountersAreIndependent is why the three external counters are separate tests
// rather than a switch: `apps/outline` is reachable by a tunnel, by a Traefik router and on the LAN,
// and it is counted in all three.
func TestOverlappingIngressCountersAreIndependent(t *testing.T) {
	a := analyze(t, "apps")

	set := a.Index.Service("outline/outline").Ingress
	for _, kind := range []payload.IngressKind{
		payload.IngressPublic, payload.IngressTraefik, payload.IngressLan,
	} {
		if !Has(set, kind) {
			t.Errorf("outline's ingress = %v, want it to carry %q", set, kind)
		}
	}

	// Six services in the corpus, and the three counters overlap, so they sum past the count of
	// services carrying any of them. A partition would make that impossible.
	sum := a.Stats.PublicServices + a.Stats.TraefikServices + a.Stats.LanServices
	distinct := 0
	for _, key := range a.Index.Keys() {
		if External(a.Index.Service(key).Ingress) {
			distinct++
		}
	}
	if sum <= distinct {
		t.Errorf("public+traefik+lan = %d and %d services are externally reachable; "+
			"the counters are not overlapping, so one of them stopped being counted",
			sum, distinct)
	}
}

// TestProbeCountersLeaveAFailedRequestOut is §13.3 and I4 in one counter: a probe that never got a
// response is neither gated nor open, and counting it as open would turn a failed request into a
// finding.
func TestProbeCountersLeaveAFailedRequestOut(t *testing.T) {
	status := 200
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		Services: []payload.Service{
			{Name: "gated", Probe: &payload.ServiceProbe{Gate: payload.GatePasswordForm, Status: &status}},
			{Name: "open", Probe: &payload.ServiceProbe{Status: &status}},
			// Asked and never answered: no status, no gate.
			{Name: "silent", Probe: &payload.ServiceProbe{}},
			// Not asked at all.
			{Name: "unasked"},
		},
	}}
	s := Stats(StatsInput{Stacks: stacks, Networks: NewNetworks(stacks)})

	if s.ProbeGated != 1 {
		t.Errorf("probeGated = %d, want 1", s.ProbeGated)
	}
	if s.ProbeOpen != 1 {
		t.Errorf("probeOpen = %d, want 1: a failed request is not an open service", s.ProbeOpen)
	}
}

// TestExposedWithoutAuthIsReadOffTheService is §4.2's storage rule as a counter test: the number comes
// off the stored boolean, so the finding a reader sees in the drawer and the number on the card cannot
// come apart.
func TestExposedWithoutAuthIsReadOffTheService(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		Services: []payload.Service{
			// Reachable and unprotected — but the boolean is what this counter reads, and here it
			// is false. A counter that re-derived the verdict would report 1 and disagree with the
			// drawer beside it.
			{
				Name: "unflagged", Ports: []payload.PortMapping{{Published: "80"}},
				Auth: payload.AuthPosture{Method: payload.AuthNone},
			},
			{
				Name: "flagged", Ports: []payload.PortMapping{{Published: "81"}},
				Auth: payload.AuthPosture{Method: payload.AuthNone, ExposedWithoutAuth: true},
			},
		},
	}}
	s := Stats(StatsInput{Stacks: stacks, Networks: NewNetworks(stacks)})

	if s.ExposedWithoutAuth != 1 {
		t.Errorf("exposedWithoutAuth = %d, want 1 — the stored boolean, not a re-derived verdict",
			s.ExposedWithoutAuth)
	}
}

// TestDriftCountsEntriesNotServices is §22.3's promise about the destination: the drift list shows one
// row per entry, so a service with two drift entries counts twice.
func TestDriftCountsEntriesNotServices(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		Services: []payload.Service{{
			Name: "app",
			Declared: &payload.ServiceDeclaration{
				Declaration: payload.Declaration{File: "s/.labview"},
				Drift:       []string{"first", "second"},
			},
		}},
	}}
	s := Stats(StatsInput{Stacks: stacks, Networks: NewNetworks(stacks)})

	if s.DeclarationDrift != 2 {
		t.Errorf("declarationDrift = %d, want 2 entries", s.DeclarationDrift)
	}
}

// TestAcceptedExposureIsNeverSubtracted is §14 rule 3. An accepted exposure is still an exposure: the
// acceptance gets its own counter and stands beside the exposed count rather than reducing it.
func TestAcceptedExposureIsNeverSubtracted(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		Services: []payload.Service{{
			Name:  "app",
			Ports: []payload.PortMapping{{Published: "80"}},
			Auth:  payload.AuthPosture{Method: payload.AuthNone, ExposedWithoutAuth: true},
			Declared: &payload.ServiceDeclaration{
				Declaration:             payload.Declaration{File: "s/.labview"},
				UnauthenticatedAccepted: &payload.AcceptedExposure{Reason: "read-only status page"},
			},
		}},
	}}
	s := Stats(StatsInput{Stacks: stacks, Networks: NewNetworks(stacks)})

	if s.ExposureAccepted != 1 {
		t.Errorf("exposureAccepted = %d, want 1", s.ExposureAccepted)
	}
	if s.ExposedWithoutAuth != 1 {
		t.Errorf("exposedWithoutAuth = %d, want 1: an accepted exposure is still an exposure",
			s.ExposedWithoutAuth)
	}
}

// TestNetworkIdentityHoldsAcrossEveryRoot is the §8 identity where it is worth the most: over trees
// nobody wrote it for. A network drawn and counted as solo-local, or neither, is a defect the diagram
// would only show as a quietly missing node.
func TestNetworkIdentityHoldsAcrossEveryRoot(t *testing.T) {
	for _, root := range []string{"nets", "apps", "edge"} {
		a := analyze(t, root)
		if !NetworkIdentityHolds(a.Graph, a.Stats) {
			t.Errorf("%s: drawn (%d) + solo-local (%d) != networks (%d)",
				root, DrawnNetworkNodes(a.Graph), a.Stats.SoloLocalNetworks, a.Stats.Networks)
		}
	}
}
