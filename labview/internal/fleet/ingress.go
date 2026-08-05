package fleet

import "github.com/nrosier/labview/internal/payload"

// IngressSet is the one constructor §8 requires: deduplicated, in the canonical order of §4.1,
// never empty, and withholding `internal` from any set that already carries `public`, `traefik`
// or `lan`.
//
// The withholding is what makes the set answer a question worth asking — *is a neighbour the
// only way in* — rather than restating that a container listens on a network, which is true of
// nearly every service in a fleet.
//
// Nothing here combines two kinds into a third, and there is no second constructor. Callers
// that need one winner call Winner; callers that need the union across a stack call Rollup.
func IngressSet(kinds ...payload.IngressKind) []payload.IngressKind {
	seen := map[payload.IngressKind]bool{}
	for _, k := range kinds {
		if k != "" {
			seen[k] = true
		}
	}

	external := false
	for _, k := range payload.ExternalIngressKinds {
		if seen[k] {
			external = true
		}
	}
	if external {
		delete(seen, payload.IngressInternal)
		delete(seen, payload.IngressNone)
	}

	out := make([]payload.IngressKind, 0, len(payload.IngressKinds))
	for _, k := range payload.IngressKinds {
		// `none` is the answer only when there is nothing else to say, so it can never sit
		// beside another kind however it reached this constructor.
		if seen[k] && k != payload.IngressNone {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return []payload.IngressKind{payload.IngressNone}
	}
	return out
}

// ServiceIngress reads one service's evidence (§4.1) and hands it to the one constructor.
//
// The evidence, in the order of the table: a Cloudflare route with a hostname; a Traefik route
// with hosts or a rule; a non-empty `ports:`; a non-empty `expose:` or a real network shared
// with another scanned service.
//
// `ports:` and `expose:` are two different reachability claims and both are read. For both the
// **presence** of an entry is the signal and never a parsed port number, which is why this
// function looks at lengths and at nothing inside a PortMapping.
func ServiceIngress(svc payload.Service, nets *Networks, key string) []payload.IngressKind {
	var kinds []payload.IngressKind

	for _, route := range svc.Cloudflare {
		if route.Hostname != "" {
			kinds = append(kinds, payload.IngressPublic)
			break
		}
	}
	for _, route := range svc.Traefik {
		if len(route.Hosts) > 0 || route.Rule != "" {
			kinds = append(kinds, payload.IngressTraefik)
			break
		}
	}
	if len(svc.Ports) > 0 {
		kinds = append(kinds, payload.IngressLan)
	}
	if len(svc.Expose) > 0 || nets.HasNeighbour(key) {
		kinds = append(kinds, payload.IngressInternal)
	}
	return IngressSet(kinds...)
}

// Rollup is a stack's ingress: the union of its services' sets.
//
// This is the one place the withholding MUST NOT apply (§8). A stack with one published service
// and one internal-only service is both things at once, and a roll-up that dropped `internal`
// would say the stack has no internal-only service in it. Because the constructor withholds
// unconditionally, the union is built here directly rather than by calling it.
func Rollup(sets ...[]payload.IngressKind) []payload.IngressKind {
	seen := map[payload.IngressKind]bool{}
	for _, set := range sets {
		for _, k := range set {
			if k != "" && k != payload.IngressNone {
				seen[k] = true
			}
		}
	}

	out := make([]payload.IngressKind, 0, len(payload.IngressKinds))
	for _, k := range payload.IngressKinds {
		if seen[k] && k != payload.IngressNone {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return []payload.IngressKind{payload.IngressNone}
	}
	return out
}

// StackIngress is Rollup over a stack's services, reading the sets already stored on them.
func StackIngress(stack payload.AppStack) []payload.IngressKind {
	sets := make([][]payload.IngressKind, 0, len(stack.Services))
	for _, svc := range stack.Services {
		sets = append(sets, svc.Ingress)
	}
	return Rollup(sets...)
}

// Winner is the single kind a graph node's one fill colour needs, and it exists for no other
// reason (§8). It is the most exposed member of the set, which — because the set is in the
// canonical order of §4.1, most exposed first — is its first element.
func Winner(set []payload.IngressKind) payload.IngressKind {
	for _, k := range payload.IngressKinds {
		if contains(kindStrings(set), string(k)) {
			return k
		}
	}
	return payload.IngressNone
}

// External reports whether a set means something outside the container network can answer. It
// asks its own question over its own three kinds rather than testing "not internal", so that
// the exposure finding and the stale-acceptance check are provably asking the same thing (§4.1).
func External(set []payload.IngressKind) bool {
	for _, k := range set {
		if k.IsExternal() {
			return true
		}
	}
	return false
}

// Has reports whether a set carries one kind.
func Has(set []payload.IngressKind, want payload.IngressKind) bool {
	for _, k := range set {
		if k == want {
			return true
		}
	}
	return false
}

// MissingAndUnexpected compares a declared expected ingress with the detected set and reports
// the difference in **both** directions (§8, §14): what was expected and is not there, and what
// is there and was not expected. Both lists come out in canonical order.
//
// One direction alone is the failure this prevents: reporting only what is missing hides a
// service that picked up an exposure nobody expected.
func MissingAndUnexpected(expected, detected []payload.IngressKind) (missing, unexpected []payload.IngressKind) {
	for _, k := range payload.IngressKinds {
		switch {
		case Has(expected, k) && !Has(detected, k):
			missing = append(missing, k)
		case Has(detected, k) && !Has(expected, k):
			unexpected = append(unexpected, k)
		}
	}
	return missing, unexpected
}

// kindStrings is the bridge to the shared contains helper, which works on strings so that one
// membership test serves every list in this package.
func kindStrings(set []payload.IngressKind) []string {
	out := make([]string, 0, len(set))
	for _, k := range set {
		out = append(out, string(k))
	}
	return out
}
