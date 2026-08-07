package fleet

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// TestOriginResolution is §9's table over the corpus it was written for.
//
// The rule that matters most here is the one nothing asserts directly: **no image, vendor or naming
// convention is consulted anywhere in this resolution**. `apps/proxy` is identified as a hop by
// publishing the host port another stack's origin addresses and by sharing a network with it —
// which is why the two unresolved cases in `edge/tunnelorigin` stay unresolved even though one of
// their candidates is called `edge-a` and runs a reverse-proxy image.
func TestOriginResolution(t *testing.T) {
	for _, tc := range []struct {
		root    string
		service string
		kind    payload.OriginKind
		hop     string
		// evidence is a fragment the conclusion must quote, so a rule that reaches the right
		// verdict for the wrong reason still fails.
		evidence string
	}{
		{
			// The origin host is the service's own name. Compose publishes it as a DNS alias, so
			// the container is addressing itself and there is no hop to look for.
			root: "apps", service: "jellyfin/jellyfin", kind: payload.OriginSelfNetwork,
			evidence: "own service name",
		},
		{
			// The same rule via container_name, which is the same container answering to the same
			// alias.
			root: "apps", service: "authentik/server", kind: payload.OriginSelfNetwork,
			evidence: "own container name",
		},
		{
			// An IP literal addresses the host, and 8920 is a port this service itself publishes:
			// the tunnel reaches it with nothing in between.
			root: "apps", service: "emby/emby", kind: payload.OriginSelfHostPort,
			evidence: "host port 8920 is published by this service",
		},
		{
			// The hop. `https://10.10.0.5` names no port, so 443 comes from the scheme; the
			// gateway publishes 443 twice (tcp and udp), which must collapse to one candidate; and
			// the two share the external `proxy` network, which is what lets it forward at all.
			root: "apps", service: "outline/outline", kind: payload.OriginFleetService,
			hop: "proxy/gateway", evidence: "the `https` scheme names",
		},
		{
			root: "edge", service: "hostport/media", kind: payload.OriginSelfHostPort,
			evidence: "host port 8096 is published by this service",
		},
		{
			// Nothing in this scan publishes 19999 — a proxy on another host, outside the root, or
			// a stale label. Unknowable from here, so it is reported as unknown.
			root: "edge", service: "tunnelorigin/offsite", kind: payload.OriginUnresolved,
			evidence: "no scanned service publishes host port 19999",
		},
		{
			// A genuine tie: two reachable services declare 8443. Only one can hold it, but which
			// is not observable, so neither is named as the hop.
			root: "edge", service: "tunnelorigin/ambiguous", kind: payload.OriginUnresolved,
			evidence: "each of which shares a network with this service",
		},
	} {
		t.Run(tc.root+"/"+tc.service, func(t *testing.T) {
			a := analyze(t, tc.root)
			route := a.route(t, tc.service)
			if route.Origin == nil {
				t.Fatalf("route %q has no resolved origin", route.Hostname)
			}
			if route.Origin.Kind != tc.kind {
				t.Errorf("kind = %q, want %q (evidence: %s)", route.Origin.Kind, tc.kind, route.Origin.Evidence)
			}
			if route.Origin.HopKey != tc.hop {
				t.Errorf("hopKey = %q, want %q", route.Origin.HopKey, tc.hop)
			}
			if !strings.Contains(route.Origin.Evidence, tc.evidence) {
				t.Errorf("evidence = %q, want it to quote %q", route.Origin.Evidence, tc.evidence)
			}
			// The raw value is the evidence and is kept verbatim (I1).
			if route.Origin.Address != route.Service {
				t.Errorf("address = %q, want the label's own value %q", route.Origin.Address, route.Service)
			}
		})
	}
}

// TestAmbiguousOriginNamesBothCandidates is the other half of a refused tie: a conclusion that
// merely said "unresolved" would leave the reader nothing to act on, so the candidates are named.
func TestAmbiguousOriginNamesBothCandidates(t *testing.T) {
	a := analyze(t, "edge")
	route := a.route(t, "tunnelorigin/ambiguous")

	for _, want := range []string{"tunnelorigin/edge-a", "tunnelorigin/edge-b"} {
		if !strings.Contains(route.Origin.Evidence, want) {
			t.Errorf("evidence = %q, want it to name %q", route.Origin.Evidence, want)
		}
	}
	// The port came from the address here, not from the `https` scheme, so the conclusion must not
	// claim the scheme supplied it.
	if strings.Contains(route.Origin.Evidence, "scheme names") {
		t.Errorf("evidence = %q, want no scheme note: the address wrote :8443 itself", route.Origin.Evidence)
	}
	if route.Origin.Port != "8443" {
		t.Errorf("port = %q, want 8443", route.Origin.Port)
	}
}

// TestUnresolvedOriginKeepsItsEdgeAndSaysSo is §9's rendering consequence. An invented hop would be
// a claim about the path and dropping the edge would hide a route that exists, so the direct edge
// stays and a service note is the only thing that says the path is unknown.
func TestUnresolvedOriginKeepsItsEdgeAndSaysSo(t *testing.T) {
	a := analyze(t, "edge")

	if !a.hasEdge(pathID(
		PrefixHostname+"offsite.edge.example.com", PrefixService+"tunnelorigin/offsite", "tunnel")) {
		t.Error("the unresolved route lost its direct edge; an absent edge hides a route that exists")
	}

	svc := a.Index.Service("tunnelorigin/offsite")
	found := false
	for _, note := range svc.Notes {
		if strings.Contains(note, "could not be resolved to a scanned service") &&
			strings.Contains(note, "the path it really takes is unknown") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note says the path is unknown; notes: %v", svc.Notes)
	}
}

// TestResolvedOriginIsDrawnAsAChain is the resolved case's rendering consequence: the tunnel is
// drawn through the hop, which is the only drawing the config proves.
//
// `outline` also carries a Traefik router for the same hostname, so it is the case that pins §22.5's
// *one path per route*: the tunnel's path goes through the gateway, the router's goes straight to
// the service, and the two are two edges rather than one merged by their endpoints.
func TestResolvedOriginIsDrawnAsAChain(t *testing.T) {
	a := analyze(t, "apps")

	for _, id := range []string{
		edgeID(payload.EdgeIngress, NodeOutside, PrefixHostname+"docs.example.com"),
		pathID(PrefixHostname+"docs.example.com", PrefixService+"proxy/gateway", "tunnel"),
		pathID(PrefixService+"proxy/gateway", PrefixService+"outline/outline", "https://10.10.0.5"),
	} {
		if !a.hasEdge(id) {
			t.Errorf("missing chain edge %q", id)
		}
	}
	// The tunnel's own direct edge is not also drawn, which would claim a second tunnel path that
	// does not exist.
	if a.hasEdge(pathID(
		PrefixHostname+"docs.example.com", PrefixService+"outline/outline", "tunnel")) {
		t.Error("the tunnel is drawn both through the hop and straight to the service")
	}
	// The Traefik router's path is direct and survives, labelled with the router rather than folded
	// into the tunnel's leg.
	router := pathID(PrefixHostname+"docs.example.com", PrefixService+"outline/outline", "outline")
	if !a.hasEdge(router) {
		t.Errorf("missing the router's own path %q", router)
	}
	if got := a.edge(t, router).Label; got != "outline" {
		t.Errorf("router path label = %q, want the router name", got)
	}
}

// TestProxiesComeFromResolutionNotFromNames is where `role: "proxy"` comes from: something resolved
// to this service as a hop. Nothing in `apps/proxy` says it is a proxy — no DockFlare labels, no
// annotation naming the stacks it fronts — and the role is still assigned.
func TestProxiesComeFromResolutionNotFromNames(t *testing.T) {
	a := analyze(t, "apps")

	if !a.Proxies["proxy/gateway"] {
		t.Errorf("proxies = %v, want proxy/gateway", sortedKeys(a.Proxies))
	}
	if len(a.Proxies) != 1 {
		t.Errorf("proxies = %v, want exactly one", sortedKeys(a.Proxies))
	}
	for _, n := range a.Graph.Nodes {
		if n.ID == PrefixService+"proxy/gateway" && n.Role != payload.RoleProxy {
			t.Errorf("gateway role = %q, want %q", n.Role, payload.RoleProxy)
		}
	}

	// The two candidates in the refused tie get no role: a hop nothing resolved to is not a hop.
	e := analyze(t, "edge")
	for _, key := range []string{"tunnelorigin/edge-a", "tunnelorigin/edge-b"} {
		if e.Proxies[key] {
			t.Errorf("%s was made a proxy by a tie that resolved to nothing", key)
		}
	}
}

// TestOriginEdgeCasesOutsideTheCorpus covers the two rows of §9's table the fixture tree has no
// natural case for: an origin naming no host at all, and an FQDN, which DNS resolves outside this
// fleet however much it looks like a container name.
func TestOriginEdgeCasesOutsideTheCorpus(t *testing.T) {
	for _, tc := range []struct {
		name, address, evidence string
	}{
		{"no host", "http://", "the origin address names no host"},
		{
			// `known.example.com` is a hostname this very fleet declares, and it is still not
			// evidence that the name resolves there.
			"fqdn", "https://known.example.com", "resolved outside this fleet",
		},
		{
			"ip with no port", "http://10.0.0.9",
			"", // http supplies 80; see below for the genuinely portless case
		},
		{"portless scheme", "tcp://10.0.0.9", "names no port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stacks := []payload.AppStack{{
				ID: "s", ProjectName: "s",
				Services: []payload.Service{{
					Name:     "app",
					Networks: []string{"s_default"},
					Cloudflare: []payload.CloudflareRoute{{
						Hostname: "known.example.com", Service: tc.address,
					}},
				}},
			}}
			ix := NewIndex(stacks)
			nets := NewNetworks(stacks)
			Origins(ix, nets)

			origin := ix.Service("s/app").Cloudflare[0].Origin
			if origin == nil {
				t.Fatal("no origin resolved")
			}
			if origin.Kind != payload.OriginUnresolved {
				t.Fatalf("kind = %q, want %q", origin.Kind, payload.OriginUnresolved)
			}
			if tc.evidence != "" && !strings.Contains(origin.Evidence, tc.evidence) {
				t.Errorf("evidence = %q, want it to quote %q", origin.Evidence, tc.evidence)
			}
		})
	}
}

// TestMembershipBreaksAPortTie is the disambiguating rule stated on its own: two services publish
// one host port, and only the one that shares a network with the service it supposedly fronts can
// forward to it.
func TestMembershipBreaksAPortTie(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		DeclaredNetworks: []payload.NetworkDecl{{Name: "front"}, {Name: "back"}},
		Services: []payload.Service{
			{
				Name: "app", Networks: []string{"s_front"},
				Cloudflare: []payload.CloudflareRoute{{
					Hostname: "app.example.com", Service: "http://10.0.0.9:8443",
				}},
			},
			// Shares `front` with app: can forward to it.
			{Name: "near", Networks: []string{"s_front"}, Ports: []payload.PortMapping{{Published: "8443"}}},
			// Publishes the same port and shares nothing: cannot forward to it, so it is not a rival.
			{Name: "far", Networks: []string{"s_back"}, Ports: []payload.PortMapping{{Published: "8443"}}},
		},
	}}
	ix := NewIndex(stacks)
	nets := NewNetworks(stacks)
	proxies := Origins(ix, nets)

	origin := ix.Service("s/app").Cloudflare[0].Origin
	if origin.Kind != payload.OriginFleetService || origin.HopKey != "s/near" {
		t.Fatalf("origin = %q via %q, want fleet-service via s/near (evidence: %s)",
			origin.Kind, origin.HopKey, origin.Evidence)
	}
	if proxies["s/far"] {
		t.Error("s/far was made a proxy despite sharing no network with the service it would front")
	}
}

// TestByURLDoesNotFallThroughToAHostPort is the boundary between §9's reading and the index's: a
// port in a URL says nothing about which container answers it, and that reading needs an IP literal
// to license it.
func TestByURLDoesNotFallThroughToAHostPort(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		Services: []payload.Service{
			{Name: "publisher", Ports: []payload.PortMapping{{Published: "9000"}}},
		},
	}}
	ix := NewIndex(stacks)

	if got := ix.ByURL("http://elsewhere:9000"); len(got) != 0 {
		t.Errorf("ByURL matched %v on a port alone", got)
	}
	if got := ix.ByURL("http://publisher:9000"); !equalStrings(got, []string{"s/publisher"}) {
		t.Errorf("ByURL by container name = %v, want [s/publisher]", got)
	}
}
