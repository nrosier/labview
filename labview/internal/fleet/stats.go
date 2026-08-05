package fleet

import "github.com/nrosier/labview/internal/payload"

// StatsInput is the fleet as every earlier stage left it, plus the two indexes whose counts must
// not be recomputed from a second walk (§8).
type StatsInput struct {
	Stacks   []payload.AppStack
	Networks *Networks
	Deps     Deps
}

// Stats counts every card on the Overview (§22.3).
//
// Each counter here is a promise: its card links to a view showing exactly these rows and
// displaying exactly this number, so a counter that cannot be reproduced by filtering the payload
// is a defect in this function rather than in the UI. Every one of them is therefore counted off
// a field a reader can see on the service — never off a rule re-derived here.
func Stats(in StatsInput) payload.OverviewStats {
	s := payload.OverviewStats{
		Stacks:       len(in.Stacks),
		ByAuthMethod: map[payload.AuthMethod]int{},
	}

	// ByAuthMethod partitions, so every member is present even at zero: a distribution with a
	// member missing reads as a member that cannot occur (§22.1).
	for _, m := range payload.AuthMethods {
		s.ByAuthMethod[m] = 0
	}

	each(in.Stacks, func(_ payload.AppStack, svc payload.Service, _ string) {
		s.Services++
		if svc.Docker != nil && svc.Docker.Running {
			s.Running++
		}

		// The three external counters overlap — one service can be public and lan at once — so
		// these are independent tests rather than a switch (§22.1).
		if Has(svc.Ingress, payload.IngressPublic) {
			s.PublicServices++
		}
		if Has(svc.Ingress, payload.IngressTraefik) {
			s.TraefikServices++
		}
		if Has(svc.Ingress, payload.IngressLan) {
			s.LanServices++
		}
		if Has(svc.Ingress, payload.IngressInternal) {
			s.InternalServices++
		}
		if Has(svc.Ingress, payload.IngressNone) {
			s.NoIngressServices++
		}

		method := svc.Auth.Method
		if method == "" {
			method = payload.AuthNone
		}
		s.ByAuthMethod[method]++
		if method.Detected() {
			s.AuthProtected++
		}
		// Read off the stored boolean, never recomputed: the finding a reader sees and the number
		// this counter reports must not be able to come apart (§4.2).
		if svc.Auth.ExposedWithoutAuth {
			s.ExposedWithoutAuth++
		}

		if svc.Probe != nil {
			switch {
			case svc.Probe.Gate != "":
				s.ProbeGated++
			case svc.Probe.Status != nil:
				// Answered, no gate observed. A probe that never got a response is neither
				// gated nor open, and counting it as open would turn a failed request into a
				// finding (§13.3, I4).
				s.ProbeOpen++
			}
		}

		d := svc.Declared
		if d == nil {
			return
		}
		if len(d.Auth) > 0 {
			s.DeclaredAuth++
		}
		// Protected — declared. Rule 2's one verdict, and the agreement is the only place it is
		// recorded, so this counter reads it rather than re-testing the condition (§14).
		if d.AuthAgreement == payload.AgreementSupplies {
			s.DeclaredAuthProtected++
		}
		if len(d.Unconfirmed) > 0 {
			s.DeclaredAuthUnconfirmed++
		}
		// An accepted exposure is still an exposure: this counter stands beside the exposed count
		// and is never subtracted from it (§14 rule 3).
		if d.UnauthenticatedAccepted != nil {
			s.ExposureAccepted++
		}
		// Entries, not services — the destination lists drift entries as its rows, and a service
		// with two drift entries shows two (§22.3).
		s.DeclarationDrift += len(d.Drift)
	})

	// References that resolved. A declaration naming nothing, itself, or two services in other
	// stacks drew no edge and is counted as drift instead — counting it here would report a
	// relation the graph does not contain (§14).
	for _, d := range in.Deps.Resolved {
		if d.Declared {
			s.DeclaredDependencies++
		}
	}

	for _, net := range in.Networks.All() {
		s.Networks++
		if net.Connecting() {
			s.ConnectingNetworks++
		}
		if net.CrossStack() {
			s.CrossStackNetworks++
		}
		if net.SoloLocal() {
			s.SoloLocalNetworks++
		}
	}

	return s
}

// DrawnNetworkNodes counts the network nodes in a graph. It reads the graph rather than the index
// deliberately: the identity below is only worth checking if the two sides are counted from
// different places.
func DrawnNetworkNodes(g payload.Graph) int {
	n := 0
	for _, node := range g.Nodes {
		if node.Kind == payload.NodeNetwork {
			n++
		}
	}
	return n
}

// NetworkIdentityHolds is the checkable identity of §8: every network is either drawn as a node or
// is solo-local, and none is both.
//
// It exists because the two numbers come from different code — the graph decides what to draw, the
// index decides what is solo-local — so if the two rules ever disagree, this is what says so
// rather than a diagram quietly missing a network.
func NetworkIdentityHolds(g payload.Graph, s payload.OverviewStats) bool {
	return DrawnNetworkNodes(g)+s.SoloLocalNetworks == s.Networks
}
