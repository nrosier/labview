package fleet

import "github.com/nrosier/labview/internal/payload"

// Network is one real network, with everything the whole fleet knows about it.
//
// Members are service keys in scan order and Stacks the distinct stacks among them, both
// counted from what the scan saw and never from what a diagram drew (§8, I1): a node's spokes
// are capped, MemberCount and StackCount are not.
type Network struct {
	Name string
	// Members are the `stack/service` keys attached to this network, in scan order.
	Members []string
	// Stacks are the distinct stacks among the members, in scan order.
	Stacks []string
	// External is true when at least one stack declares this network `external:`, which means
	// containers this scan never saw may be on it.
	External bool
}

// Scope says who can be on the network — never how severe it is (§4.1).
func (n *Network) Scope() payload.NetworkScope {
	if n.External {
		return payload.ScopeExternal
	}
	return payload.ScopeStackLocal
}

// Connecting reports whether the network carries something between services: two or more
// scanned members.
func (n *Network) Connecting() bool { return len(n.Members) >= 2 }

// CrossStack reports whether the network joins two or more stacks.
func (n *Network) CrossStack() bool { return len(n.Stacks) >= 2 }

// SoloLocal is stack-local with a single member: only that one stack's services could ever
// join it and none other has, so it connects nothing.
//
// This is *exactly* the set the fleet graph omits, which is what makes `drawn network nodes +
// solo-local networks = total networks` a checkable identity (§8). An external network with one
// member is not solo-local: something outside the scan may be on it, and that is a real
// statement about what its member can reach.
func (n *Network) SoloLocal() bool { return !n.External && len(n.Members) == 1 }

// Drawn reports whether the fleet graph carries a node for this network. It is the negation of
// SoloLocal in one place, so the graph and the counters cannot disagree about which side of the
// identity a network falls on.
func (n *Network) Drawn() bool { return !n.SoloLocal() }

// Networks is the one fleet-wide membership index of §8, built once over real networks and
// shared by everything that asks about them: the `internal` ingress rule, the graph's network
// nodes and edges, the network counters, and `via` on a dependency edge. Three readings of one
// relation rather than three relations that agree today.
//
// It is built from Service.Networks, which the scan has already resolved: the implicit
// `default` materialized, `${project}_${key}` applied, and an `external:` network kept under
// its verbatim name. `depends_on` is deliberately not consulted — a dependency across two
// disjoint networks is not reachability (§8).
type Networks struct {
	order     []string
	byName    map[string]*Network
	byService map[string][]string
}

// NewNetworks builds the index. Networks come out in first-seen order, which is scan order,
// and a service's networks stay in its own compose order — the order `via` is written in.
func NewNetworks(stacks []payload.AppStack) *Networks {
	idx := &Networks{
		byName:    map[string]*Network{},
		byService: map[string][]string{},
	}

	// External is a property of the network, not of one stack's opinion of it: one stack
	// declaring `external: true` means the network exists outside this project even if a
	// second stack's file forgot to say so. Collected before membership so that a network
	// whose only declaring stack has no service on it is still scoped correctly.
	external := map[string]bool{}
	for _, stack := range stacks {
		for _, decl := range stack.DeclaredNetworks {
			if decl.External {
				external[decl.Name] = true
			}
		}
	}

	each(stacks, func(stack payload.AppStack, svc payload.Service, key string) {
		for _, name := range svc.Networks {
			if name == "" {
				continue
			}
			net, ok := idx.byName[name]
			if !ok {
				net = &Network{Name: name, External: external[name]}
				idx.byName[name] = net
				idx.order = append(idx.order, name)
			}
			net.Members = appendOnce(net.Members, key)
			net.Stacks = appendOnce(net.Stacks, stack.ID)
			idx.byService[key] = appendOnce(idx.byService[key], name)
		}
	})
	return idx
}

// Names is every real network, in scan order.
func (idx *Networks) Names() []string { return idx.order }

// All is every network, in scan order.
func (idx *Networks) All() []*Network {
	out := make([]*Network, 0, len(idx.order))
	for _, name := range idx.order {
		out = append(out, idx.byName[name])
	}
	return out
}

// Get returns one network by name.
func (idx *Networks) Get(name string) (*Network, bool) {
	net, ok := idx.byName[name]
	return net, ok
}

// Of is the reverse reading: the real networks one service is on, in its compose order.
func (idx *Networks) Of(key string) []string { return idx.byService[key] }

// Shared is the real networks a pair of services both sit on, in the *first* service's compose
// order. That ordering is the contract for `via` on a dependency edge, which §8 requires in the
// dependent's compose order.
//
// An empty result for a pair compose orders means neither container can address the other —
// which is a finding, not an absence (§8).
func (idx *Networks) Shared(a, b string) []string {
	if a == b {
		return nil
	}
	var out []string
	for _, name := range idx.byService[a] {
		if contains(idx.byService[b], name) {
			out = append(out, name)
		}
	}
	return out
}

// SharesAny reports whether two services have any real network in common. It is the
// reachability test §9 uses to break a host-port tie, and the same relation Shared reports, so
// a candidate that cannot be reached can never be picked as a hop.
func (idx *Networks) SharesAny(a, b string) bool { return len(idx.Shared(a, b)) > 0 }

// Neighbours is every other scanned service reachable from this one over any shared network,
// in scan order. It is what the `internal` ingress rule asks about, and the count a service's
// view of a network reports as merely-reachable co-members.
func (idx *Networks) Neighbours(key string) []string {
	var out []string
	for _, name := range idx.byService[key] {
		for _, member := range idx.byName[name].Members {
			if member != key {
				out = appendOnce(out, member)
			}
		}
	}
	return out
}

// HasNeighbour reports whether any other scanned service shares a real network with this one.
// The `internal` ingress kind rests on exactly this question (§4.1), and asking it here rather
// than at the call site is what keeps the ingress set and the graph reading one index.
func (idx *Networks) HasNeighbour(key string) bool {
	for _, name := range idx.byService[key] {
		if len(idx.byName[name].Members) > 1 {
			return true
		}
	}
	return false
}
