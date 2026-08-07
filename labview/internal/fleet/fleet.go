// Package fleet is §8 and §9: the conclusions that can only be drawn with the whole fleet in
// hand — ingress sets, the network membership index, the fleet index, tunnel origins, resolved
// dependencies, the graph and the counters.
//
// Nothing here reads a file or opens a socket. Every function takes the parsed fleet and
// returns conclusions, so the same tree produces the same payload twice (I7).
//
// The organising rule of the package is that a relation is computed **once**. §8 requires one
// ingress-set constructor and one fleet-wide membership index, shared by the `internal` rule,
// the graph's network nodes and the network counters, so that the three are provably one
// relation rather than three readings that agree today. Every function here that could have
// been a per-service convenience is instead a method on one of those two indexes.
package fleet

import (
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// Key is how a service is named everywhere outside its own stack: `stack/service`.
//
// It is the identity the sidecar's qualified references use, the key the membership index and
// the fleet index are keyed by, and the tail of a graph node id. A service name alone is not
// an identity — two stacks may each have a `db` — which is the whole reason this exists.
func Key(stack, service string) string { return stack + "/" + service }

// SplitKey is Key inverted, for a reference already known to be qualified.
func SplitKey(key string) (stack, service string) {
	stack, service, _ = strings.Cut(key, "/")
	return stack, service
}

// each walks the fleet in scan order, which is the order every index is built in and the
// order every list this package produces comes out in (I7).
func each(stacks []payload.AppStack, fn func(stack payload.AppStack, svc payload.Service, key string)) {
	for _, stack := range stacks {
		for _, svc := range stack.Services {
			fn(stack, svc, Key(stack.ID, svc.Name))
		}
	}
}

// sortedKeys is the fixed order for iterating a map whose values are being reported.
func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// appendOnce adds a value to a list that is being kept in first-seen order, if it is not
// already there. The lists this builds are short — a service's networks, a network's stacks —
// so a linear scan is both simpler and faster than carrying a set beside every one of them.
func appendOnce(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

func contains(list []string, v string) bool {
	for _, existing := range list {
		if existing == v {
			return true
		}
	}
	return false
}
