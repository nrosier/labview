package fleet

import (
	"sort"

	"github.com/nrosier/labview/internal/payload"
)

// Node id prefixes. Every id is `<prefix>:<name>`, which keeps the four diagrams' node sets
// disjoint without a second field to disambiguate them, and makes an edge readable on its own.
const (
	PrefixService  = "svc:"
	PrefixNetwork  = "net:"
	PrefixVolume   = "vol:"
	PrefixHostname = "host:"
	PrefixApp      = "app:"
	PrefixProvider = "provider:"
	PrefixOutpost  = "outpost:"
	PrefixRouter   = "router:"
	// NodeOutside is the single node standing for everything beyond the fleet — the left-hand
	// end of every ingress path (§22.5).
	NodeOutside = "outside"
)

// GraphInput is everything the graph is built from. It is a struct rather than a long parameter
// list because the graph is stage 13 and reads the conclusions of every stage before it; a new
// enrichment adds a field here rather than a second graph.
type GraphInput struct {
	Stacks   []payload.AppStack
	Index    *Index
	Networks *Networks
	Deps     Deps
	// Proxies are the services something resolved to as a hop, or whose proxy API answered.
	// They stay ordinary service nodes; the role only lets the UI colour them (§9).
	Proxies map[string]bool
	// Gates maps a service key to the key of the scanned service that gates it — the outpost
	// whose forward-auth address a middleware on its path names. It is what lets the gate be
	// drawn *on* an ingress path rather than only beside its far end (§22.5).
	Gates map[string]string
	// Authentik and Traefik are optional and used only for their unmatched records, which are
	// shown as unattached nodes rather than hidden (§22.5).
	Authentik *payload.AuthentikSummary
	Traefik   *payload.TraefikSummary
}

// BuildGraph is the one graph object every view reads (§22.4): the whole relation set, uncapped.
// Caps are presentation defaults and belong to a renderer, so nothing is dropped here (§16).
//
// Nodes come out grouped — services in scan order, then drawn networks in scan order, then
// volumes, then everything outside the fleet — and edges grouped by kind in the order of the
// closed set. Two runs over one fleet therefore produce the same bytes (I7).
func BuildGraph(in GraphInput) payload.Graph {
	b := &builder{in: in, seen: map[string]bool{}}

	b.serviceNodes()
	b.networkNodes()
	b.volumeNodes()

	b.membershipEdges()
	b.dependencyEdges()
	b.volumeEdges()
	b.ingressEdges()
	b.authEdges()

	return payload.Graph{Nodes: b.nodes, Edges: b.edges}
}

type builder struct {
	in    GraphInput
	nodes []payload.GraphNode
	edges []payload.GraphEdge
	seen  map[string]bool
}

// node adds a node once. Repeats are normal — two routes reach one service, two stacks mount one
// external volume — and the first spelling wins so the order stays scan order.
func (b *builder) node(n payload.GraphNode) {
	if b.seen[n.ID] {
		return
	}
	b.seen[n.ID] = true
	b.nodes = append(b.nodes, n)
}

// edge adds an edge, deduplicated by id.
func (b *builder) edge(e payload.GraphEdge) {
	if b.seen[e.ID] {
		return
	}
	b.seen[e.ID] = true
	b.edges = append(b.edges, e)
}

func edgeID(kind payload.GraphEdgeKind, source, target string) string {
	return string(kind) + "|" + source + "|" + target
}

// pathID is edgeID for the ingress diagram, which is **one path per route** (§22.5) rather than one
// edge per pair. A hostname served by both a tunnel and a Traefik router reaches its service by two
// mechanisms, and an id built from the pair alone would merge them into one edge labelled with
// whichever was read first — losing a route the payload plainly contains.
func pathID(source, target, label string) string {
	return edgeID(payload.EdgeIngress, source, target) + "|" + label
}

func (b *builder) serviceNodes() {
	for _, stack := range b.in.Stacks {
		for i := range stack.Services {
			svc := stack.Services[i]
			key := Key(stack.ID, svc.Name)
			n := payload.GraphNode{
				ID:      PrefixService + key,
				Label:   svc.Name,
				Kind:    payload.NodeService,
				Stack:   stack.ID,
				Auth:    svc.Auth.Method,
				Ingress: Winner(svc.Ingress),
			}
			// Running is absent rather than false when Docker was not read: a stopped service
			// and a service nothing is known about are different facts (§22.8).
			if svc.Docker != nil {
				running := svc.Docker.Running
				n.Running = &running
			}
			if b.in.Proxies[key] {
				n.Role = payload.RoleProxy
			}
			b.node(n)
		}
	}
}

// networkNodes draws every network except the solo-local ones, which connect nothing. That
// omission is exactly what makes `drawn network nodes + solo-local networks = total networks` a
// checkable identity (§8).
//
// MemberCount and StackCount are counted on the node from the membership index and never
// inferred from the spokes beside it, which a renderer may cap (I1).
func (b *builder) networkNodes() {
	for _, net := range b.in.Networks.All() {
		if !net.Drawn() {
			continue
		}
		members, stacks := len(net.Members), len(net.Stacks)
		b.node(payload.GraphNode{
			ID:          PrefixNetwork + net.Name,
			Label:       net.Name,
			Kind:        payload.NodeNetwork,
			Scope:       net.Scope(),
			MemberCount: &members,
			StackCount:  &stacks,
		})
	}
}

func (b *builder) volumeNodes() {
	for _, stack := range b.in.Stacks {
		for _, vol := range stack.DeclaredVolumes {
			b.node(payload.GraphNode{
				ID:    PrefixVolume + vol.Name,
				Label: vol.Name,
				Kind:  payload.NodeVolume,
			})
		}
	}
}

// membershipEdges is one edge per service per drawn network, carrying the arrowhead and the
// styling of §8.
func (b *builder) membershipEdges() {
	for _, key := range b.in.Index.Keys() {
		for _, name := range b.in.Networks.Of(key) {
			net, ok := b.in.Networks.Get(name)
			if !ok || !net.Drawn() {
				continue
			}
			flow, source := b.leg(key, name)
			b.edge(payload.GraphEdge{
				ID:         edgeID(payload.EdgeNetwork, PrefixService+key, PrefixNetwork+name),
				Source:     PrefixService + key,
				Target:     PrefixNetwork + name,
				Kind:       payload.EdgeNetwork,
				Flow:       flow,
				FlowSource: source,
			})
		}
	}
}

// leg decides what crosses one service's connection to one network.
//
// A dependency contributes only when that network is among the ones the pair shares, so a
// dependency with an empty `via` puts an arrowhead on nothing — which is why it keeps its direct
// edge instead (§8).
func (b *builder) leg(key, network string) (payload.EdgeFlow, payload.EdgeFlowSource) {
	var out, in bool
	var observed, declared bool

	for _, d := range b.in.Deps.Resolved {
		if !contains(d.Via, network) {
			continue
		}
		switch {
		case d.From == key:
			out = true
		case d.To == key:
			in = true
		default:
			continue
		}
		if d.Observed {
			observed = true
		}
		if d.Declared {
			declared = true
		}
	}

	var flow payload.EdgeFlow
	switch {
	case out && in:
		flow = payload.FlowBoth
	case out:
		flow = payload.FlowToNetwork
	case in:
		flow = payload.FlowToService
	default:
		// The common case: the service is on the network and nothing crosses it. Both fields
		// stay absent rather than carrying a member that would read as a claim.
		return "", ""
	}

	// A leg every one of whose dependencies was declared renders dashed; mixed provenance stays
	// solid, because something crossing it was measured.
	switch {
	case observed && declared:
		return flow, payload.FlowSourceBoth
	case declared:
		return flow, payload.FlowSourceDeclared
	default:
		return flow, payload.FlowSourceObserved
	}
}

// dependencyEdges emits every resolved dependency. They are all in the payload: whether a
// renderer draws one is decided by `via`, and that is a rendering rule rather than an analysis
// one (§8, §16).
func (b *builder) dependencyEdges() {
	for _, d := range b.in.Deps.Resolved {
		e := payload.GraphEdge{
			ID:     edgeID(payload.EdgeDependsOn, PrefixService+d.From, PrefixService+d.To),
			Source: PrefixService + d.From,
			Target: PrefixService + d.To,
			Kind:   payload.EdgeDependsOn,
			Label:  labelOf(d.Via),
			Via:    d.Via,
		}
		// declaredBy is present only when a declaration is the *only* account of this pair. A
		// pair compose already resolved is one edge and an observed one, and dashing it would
		// claim the relation was never measured (§14).
		if d.DeclaredOnly() {
			e.DeclaredBy = &payload.EdgeDeclaredBy{File: d.File, Detail: d.Detail}
		}
		b.edge(e)
	}
}

// labelOf names the networks a dependency crosses, which is what the dependency diagram labels
// its edges with (§22.5).
func labelOf(via []string) string {
	switch len(via) {
	case 0:
		return ""
	case 1:
		return via[0]
	default:
		out := via[0]
		for _, name := range via[1:] {
			out += ", " + name
		}
		return out
	}
}

// volumeEdges joins a service to a volume its stack declares. The join applies the same naming
// rule the scan applied — an `external:` or `name:`-overridden volume is verbatim, everything
// else is `${project}_${key}` — in reverse, within the declaring stack. A mount naming no
// declared volume is an anonymous or ad-hoc one and gets no node; it is still on the service.
func (b *builder) volumeEdges() {
	for _, stack := range b.in.Stacks {
		for _, svc := range stack.Services {
			key := Key(stack.ID, svc.Name)
			for _, m := range svc.Mounts {
				if m.Type != payload.MountVolume || m.Source == "" {
					continue
				}
				name, ok := declaredVolume(stack, m.Source)
				if !ok {
					continue
				}
				b.edge(payload.GraphEdge{
					ID:     edgeID(payload.EdgeVolume, PrefixService+key, PrefixVolume+name),
					Source: PrefixService + key,
					Target: PrefixVolume + name,
					Kind:   payload.EdgeVolume,
					Label:  m.Target,
				})
			}
		}
	}
}

func declaredVolume(stack payload.AppStack, source string) (string, bool) {
	for _, vol := range stack.DeclaredVolumes {
		if vol.Name == source || vol.Name == stack.ProjectName+"_"+source {
			return vol.Name, true
		}
	}
	return "", false
}

// ingressEdges draws one path per route: outside → hostname → tunnel or router → origin →
// service (§22.5).
//
// A tunnel whose origin resolved to another scanned service is drawn as a chain through that
// hop, which is §9's table. Every other kind — including `unresolved` — keeps the direct edge:
// an invented hop would be a claim about the path, and dropping the edge would hide a route that
// exists.
func (b *builder) ingressEdges() {
	for _, key := range b.in.Index.Keys() {
		svc := b.in.Index.Service(key)

		for _, route := range svc.Cloudflare {
			if route.Hostname == "" {
				continue
			}
			b.hostname(route.Hostname)
			target := PrefixService + key
			source := PrefixHostname + route.Hostname
			if route.Origin != nil && route.Origin.Kind == payload.OriginFleetService && route.Origin.HopKey != "" {
				hop := PrefixService + route.Origin.HopKey
				b.ingress(source, hop, "tunnel")
				b.ingress(hop, target, route.Origin.Address)
				continue
			}
			b.ingress(source, target, "tunnel")
		}

		for _, route := range svc.Traefik {
			if len(route.Hosts) == 0 {
				continue
			}
			for _, host := range route.Hosts {
				b.hostname(host)
				b.ingress(PrefixHostname+host, PrefixService+key, route.Router)
			}
		}
	}
}

// hostname adds the left-hand end of an ingress path. The `outside → hostname` edge is one per
// hostname rather than one per route — two routes answering for one name enter the fleet at the same
// place — so it keeps the pair-based id and collapses.
func (b *builder) hostname(host string) {
	b.node(payload.GraphNode{ID: NodeOutside, Label: "outside", Kind: payload.NodeExternal})
	b.node(payload.GraphNode{
		ID:    PrefixHostname + host,
		Label: host,
		Kind:  payload.NodeExternal,
	})
	b.edge(payload.GraphEdge{
		ID:     edgeID(payload.EdgeIngress, NodeOutside, PrefixHostname+host),
		Source: NodeOutside,
		Target: PrefixHostname + host,
		Kind:   payload.EdgeIngress,
	})
}

func (b *builder) ingress(source, target, label string) {
	b.edge(payload.GraphEdge{
		ID:     pathID(source, target, label),
		Source: source,
		Target: target,
		Kind:   payload.EdgeIngress,
		Label:  label,
	})
}

// authEdges is the identity-and-auth diagram: which application protects which service and at
// what strength, the providers and outposts behind it, the gate on each path, and every
// unmatched record as an unattached node rather than a hidden one (§22.5).
func (b *builder) authEdges() {
	// The gate first, so a path's gate is drawn even where the identity provider was never read.
	for _, key := range sortedKeys(b.in.Gates) {
		gate := b.in.Gates[key]
		if gate == "" || gate == key || !b.in.Index.Has(gate) || !b.in.Index.Has(key) {
			continue
		}
		b.edge(payload.GraphEdge{
			ID:     edgeID(payload.EdgeAuth, PrefixService+gate, PrefixService+key),
			Source: PrefixService + gate,
			Target: PrefixService + key,
			Kind:   payload.EdgeAuth,
			Label:  string(b.in.Index.Service(key).Auth.Method),
		})
	}

	for _, key := range b.in.Index.Keys() {
		match := b.in.Index.Service(key).Authentik
		if match == nil {
			continue
		}
		for i, app := range match.Applications {
			b.application(app)
			// A strength shorter than the application list reads as `name` for the remainder,
			// never as the strongest (§4.3).
			strength := payload.StrengthName
			if i < len(match.Strength) {
				strength = match.Strength[i]
			}
			b.edge(payload.GraphEdge{
				ID:     edgeID(payload.EdgeAuth, PrefixApp+app.Slug, PrefixService+key),
				Source: PrefixApp + app.Slug,
				Target: PrefixService + key,
				Kind:   payload.EdgeAuth,
				Label:  string(strength),
			})
		}
	}

	if b.in.Authentik != nil {
		for _, un := range b.in.Authentik.UnmatchedApplications {
			b.application(un.Application)
		}
	}
	if b.in.Traefik != nil {
		for _, un := range b.in.Traefik.UnmatchedRouters {
			b.node(payload.GraphNode{
				ID:    PrefixRouter + un.Router.Router + "@" + un.Router.Provider,
				Label: un.Router.Router,
				Kind:  payload.NodeExternal,
			})
		}
	}
}

// application adds one application and the providers and outposts behind it.
func (b *builder) application(app payload.AuthentikApplication) {
	b.node(payload.GraphNode{
		ID:    PrefixApp + app.Slug,
		Label: app.Name,
		Kind:  payload.NodeExternal,
	})
	for _, provider := range app.Providers {
		b.node(payload.GraphNode{
			ID:    PrefixProvider + provider.Name,
			Label: provider.Name,
			Kind:  payload.NodeExternal,
		})
		b.edge(payload.GraphEdge{
			ID:     edgeID(payload.EdgeAuth, PrefixProvider+provider.Name, PrefixApp+app.Slug),
			Source: PrefixProvider + provider.Name,
			Target: PrefixApp + app.Slug,
			Kind:   payload.EdgeAuth,
			Label:  string(provider.Kind),
		})
		// Outposts come off the API in whatever order it listed them; sorting them here is what
		// keeps two reads of one provider producing the same graph (I7).
		outposts := append([]string(nil), provider.Outposts...)
		sort.Strings(outposts)
		for _, outpost := range outposts {
			b.node(payload.GraphNode{
				ID:    PrefixOutpost + outpost,
				Label: outpost,
				Kind:  payload.NodeExternal,
			})
			b.edge(payload.GraphEdge{
				ID:     edgeID(payload.EdgeAuth, PrefixOutpost+outpost, PrefixProvider+provider.Name),
				Source: PrefixOutpost + outpost,
				Target: PrefixProvider + provider.Name,
				Kind:   payload.EdgeAuth,
			})
		}
	}
}
