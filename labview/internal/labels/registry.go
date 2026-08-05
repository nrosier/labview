package labels

import (
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// Definition is one middleware a compose file defines.
//
// Fields are the label subkeys under the type, lower-cased and joined — which is where a
// forwardauth's `address` and a chain's `middlewares` live. Stack and Service are kept
// because a definition is evidence and evidence has a location: "defined by apps/authentik"
// is what makes the conclusion answerable (I1).
type Definition struct {
	Name    string
	Type    string
	Fields  map[string]string
	Stack   string
	Service string
}

// Where is the definition's location, for an evidence line.
func (d Definition) Where() string { return d.Stack + "/" + d.Service }

// Registry is every middleware definition in the fleet, keyed by bare name (§7).
//
// It is fleet-wide on purpose: a service references `authentik@docker`, and the middleware
// that reference names is defined on a *different* service in a *different* stack. A
// per-stack registry would resolve nothing that matters and would push every cross-stack
// gate onto the name-guessing path.
type Registry struct {
	defs map[string]Definition
}

// NewRegistry collects the middleware definitions of every stack (§7).
//
// The walk is in scan order — stacks as discovered, services as declared, label keys sorted
// — so the registry two runs over one tree build is the same registry, including which
// definition won a collision (I7).
func NewRegistry(stacks []payload.AppStack, prefix string) Registry {
	r := Registry{defs: map[string]Definition{}}
	for _, stack := range stacks {
		for _, svc := range stack.Services {
			for _, d := range middlewareDefs(svc.Labels, prefix) {
				d.Stack, d.Service = stack.ID, svc.Name
				r.add(d)
			}
		}
	}
	return r
}

// add resolves a name collision the one way §7 permits: an auth type wins over a non-auth
// type, so a `headers` middleware defined in one stack cannot shadow the `forwardauth` of
// the same name in another and quietly remove a gate from the report. Between two of a kind
// the first in scan order stands.
func (r Registry) add(d Definition) {
	prev, exists := r.defs[d.Name]
	if !exists {
		r.defs[d.Name] = d
		return
	}
	if isAuthType(d.Type) && !isAuthType(prev.Type) {
		r.defs[d.Name] = d
	}
}

// Lookup finds the definition a reference names, with its provider suffix stripped.
func (r Registry) Lookup(ref string) (Definition, bool) {
	d, ok := r.defs[BareName(ref)]
	return d, ok
}

// Len is how many middlewares the fleet defines, for the diagnostics view.
func (r Registry) Len() int { return len(r.defs) }

// Names lists the registry's keys in a fixed order.
func (r Registry) Names() []string {
	out := make([]string, 0, len(r.defs))
	for name := range r.defs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ServicesDefiningAddress is the set of `stack/service` keys whose middleware definitions
// hold an address containing mark. Provider discovery uses it to find the service that
// defines a forward-auth pointing at Authentik's own outpost endpoint (§7).
func (r Registry) ServicesDefiningAddress(mark string) map[string]bool {
	out := map[string]bool{}
	for _, d := range r.defs {
		if strings.Contains(strings.ToLower(d.Fields["address"]), strings.ToLower(mark)) {
			out[d.Where()] = true
		}
	}
	return out
}

// BareName strips a middleware reference's provider suffix.
//
// `authentik@docker` and `authentik@file` are the same middleware named through two
// providers, and a service that references one while another stack defines the other is
// describing one gate. Keying on the bare name is what lets the reference resolve; the
// reference itself is kept as written wherever it is reported.
func BareName(ref string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(ref), "@")
	return name
}

// middlewareDefs reads the `traefik.http.middlewares.<name>.<type>.<field>` labels of one
// service. The segment after the name is the type — `forwardauth`, `basicauth`, `chain`,
// `headers` — and everything after that is a field of it.
func middlewareDefs(lbls map[string]string, prefix string) []Definition {
	byName := map[string]*Definition{}
	var order []string
	for _, key := range sortedKeys(lbls) {
		rest, ok := afterPrefix(key, prefix)
		if !ok {
			continue
		}
		segments := strings.Split(rest, ".")
		if len(segments) < 4 || !strings.EqualFold(segments[0], "http") ||
			!strings.EqualFold(segments[1], "middlewares") {
			continue
		}
		// A four-segment key — `…middlewares.foo.compress=true` — is a definition whose
		// value belongs to the type itself. It is recorded under the empty field name, for
		// one reason: a *found* definition is what keeps a middleware off the name-guessing
		// path, and a middleware with no sub-settings has still been found (§7).
		name, kind, field := segments[2], strings.ToLower(segments[3]), lowerJoin(segments[4:])
		d := byName[name]
		if d == nil {
			d = &Definition{Name: name, Type: kind, Fields: map[string]string{}}
			byName[name] = d
			order = append(order, name)
		}
		// One name with two types in one file is a malformed label set rather than a
		// collision between stacks; an auth type still wins, for the same reason.
		if isAuthType(kind) && !isAuthType(d.Type) {
			d.Type = kind
		}
		d.Fields[field] = lbls[key]
	}
	out := make([]Definition, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// isAuthType reports whether a middleware type is a gate.
//
// These three are the whole of Traefik's authentication vocabulary. Everything else it can
// do to a request — headers, compression, rate limits, redirects — leaves the request
// answerable by anyone, and reading one of them as a gate is the mistake that turns an open
// service into a protected-looking one.
func isAuthType(kind string) bool {
	switch strings.ToLower(kind) {
	case "forwardauth", "basicauth", "digestauth":
		return true
	}
	return false
}
