package traefikapi

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
)

// chainDepth is the recursion limit of §12: a `chain` middleware is resolved five levels deep.
//
// A limit rather than a cycle check alone, because a chain nesting deeper than this is a proxy
// configuration no reader is going to follow on a page either, and an unbounded walk over a
// document this program did not write is an unbounded walk (I8).
const chainDepth = 5

// Snapshot is the routing table as the proxy reported it, with nothing tied to a service yet.
//
// It is plain data on purpose. Everything §12 concludes — the chain expansion, the three matching
// rules, the downgrade, the cross-check — is a function of this value, so each of them can be
// asserted against a literal snapshot rather than against a live proxy.
type Snapshot struct {
	Version string

	// Routers is in `name@provider` order, which is the order they are reported in (I7).
	Routers []RawRouter

	// Middlewares is keyed on the lower-cased `name@provider` reference, because that is how a
	// router names one and comparison has to be case-insensitive in one place rather than at
	// every lookup.
	Middlewares map[string]RawMiddleware

	// Services is keyed the same way.
	Services map[string]RawService

	// Entrypoints maps an entrypoint name to the middleware references attached to it.
	Entrypoints map[string][]string

	// EntrypointsRead is whether `/api/entrypoints` was obtained. It is the second half of
	// `chainComplete`, and a live chain may supersede a label list only when it is true.
	EntrypointsRead bool
}

// RawRouter is one router as reported. Name is `name@provider`; Provider is the half of it that
// decides whether matching rule 2 may apply at all.
type RawRouter struct {
	Name        string
	Provider    string
	Status      string
	Errors      []string
	Rule        string
	Service     string
	EntryPoints []string
	Middlewares []string
	TLS         bool
}

// RawService is one backend as reported: the addresses the proxy holds, and the status it last
// observed for each. An address with no entry in the status map carries no status, and Appendix A
// requires that read as *nothing is known* rather than as healthy.
type RawService struct {
	Servers []payload.TraefikLiveServer
	Errors  []string
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// Live is every router in the snapshot, with its chain expanded and its backend attached.
//
// This runs over the whole snapshot rather than over the matched routers, because two of §12's
// requirements are about routers nobody matched: the declared-but-absent check has to see every
// router the proxy is serving, and an unmatched router is reported in full.
func (s Snapshot) Live() []payload.TraefikLiveRouter {
	out := make([]payload.TraefikLiveRouter, 0, len(s.Routers))
	for _, raw := range s.Routers {
		out = append(out, s.live(raw))
	}
	return out
}

func (s Snapshot) live(raw RawRouter) payload.TraefikLiveRouter {
	r := payload.TraefikLiveRouter{
		Router:      raw.Name,
		Provider:    raw.Provider,
		Status:      raw.Status,
		Errors:      raw.Errors,
		Rule:        raw.Rule,
		Hosts:       labels.RuleHosts(raw.Rule),
		EntryPoints: raw.EntryPoints,
		Middlewares: s.chain(raw),
		Service:     raw.Service,
		Servers:     s.servers(raw),
		TLS:         raw.TLS,
		Evidence:    []string{},
	}
	if r.Errors == nil {
		r.Errors = []string{}
	}
	if r.Hosts == nil {
		r.Hosts = []string{}
	}
	if r.EntryPoints == nil {
		r.EntryPoints = []string{}
	}
	return r
}

// servers is the backends the proxy holds for this router's service.
//
// The lookup tries the router's own spelling and then the provider-qualified one, because a
// docker-provider router names its service bare — `wiki-web` — while the services section is
// keyed `wiki-web@docker`. Both spellings are the same service and neither is a guess.
func (s Snapshot) servers(raw RawRouter) []payload.TraefikLiveServer {
	ref := strings.TrimSpace(raw.Service)
	if ref == "" {
		return []payload.TraefikLiveServer{}
	}
	for _, key := range []string{ref, ref + "@" + raw.Provider} {
		if svc, ok := s.Services[strings.ToLower(key)]; ok {
			if svc.Servers == nil {
				return []payload.TraefikLiveServer{}
			}
			return svc.Servers
		}
	}
	return []payload.TraefikLiveServer{}
}

// chain is the router's whole middleware chain: its own list, expanded, followed by whatever its
// entrypoints attach.
//
// The entrypoint half is merged only when the entrypoints were read. Merging what was not read
// would be an empty list standing in for an unknown one, which is the reading that would let the
// downgrade of §12 fire on a service whose gate this program simply had not looked for — the
// `metrics` fixture is exactly that case.
func (s Snapshot) chain(raw RawRouter) []payload.TraefikLiveMiddleware {
	out := []payload.TraefikLiveMiddleware{}
	seen := map[string]bool{}

	for _, ref := range raw.Middlewares {
		out = s.expand(out, ref, "", nil, 1, seen)
	}

	if s.EntrypointsRead {
		attached := true
		for _, ep := range raw.EntryPoints {
			for _, ref := range s.Entrypoints[strings.ToLower(strings.TrimSpace(ep))] {
				out = s.expand(out, ref, "", &attached, 1, seen)
			}
		}
	}
	return out
}

// expand resolves one middleware reference into the chain, following a `chain` recursively.
//
// Three things are deliberately reported rather than dropped: a reference the proxy holds no
// definition for, a nesting deeper than the limit, and the chain middleware itself. A chain whose
// entries appeared with no sign of where they came from would leave a reader unable to find them
// in the proxy's configuration, which is why every entry records its `viaChain`.
//
// `seen` spans the whole router. A middleware named by both the router and its entrypoint is one
// middleware, not two, and the same map is what stops a chain that refers back to itself.
func (s Snapshot) expand(into []payload.TraefikLiveMiddleware, ref, viaChain string, viaEntrypoint *bool, depth int, seen map[string]bool) []payload.TraefikLiveMiddleware {
	ref = strings.TrimSpace(ref)
	key := strings.ToLower(ref)
	if key == "" {
		return into
	}

	if depth > chainDepth {
		return append(into, payload.TraefikLiveMiddleware{
			Name: ref,
			Errors: []string{"chain nesting is deeper than " + strconv.Itoa(chainDepth) +
				" levels, so this middleware was not resolved"},
			ViaChain:      viaChain,
			ViaEntrypoint: viaEntrypoint,
		})
	}
	if seen[key] {
		return into
	}
	seen[key] = true

	def, ok := s.Middlewares[key]
	if !ok {
		// Named by a router and held by nothing. Reported by name with no type, because that is
		// the whole of what is known — and a reference the proxy cannot resolve is a router that
		// will not serve, which a reader needs to see rather than have inferred from an absence.
		return append(into, payload.TraefikLiveMiddleware{
			Name:          ref,
			Errors:        []string{"the proxy holds no definition for this middleware"},
			ViaChain:      viaChain,
			ViaEntrypoint: viaEntrypoint,
		})
	}

	entry := payload.TraefikLiveMiddleware{
		Name:          def.Name,
		Type:          def.Type,
		Address:       def.Address,
		Errors:        def.Errors,
		ViaChain:      viaChain,
		ViaEntrypoint: viaEntrypoint,
	}
	if entry.Errors == nil {
		entry.Errors = []string{}
	}
	if entry.Name == "" {
		entry.Name = ref
	}
	into = append(into, entry)

	if def.isChain() {
		for _, inner := range def.Chain {
			into = s.expand(into, inner, entry.Name, viaEntrypoint, depth+1, seen)
		}
	}
	return into
}

// ---------------------------------------------------------------------------
// What a router counts for
// ---------------------------------------------------------------------------

// Working reports whether a router is in a request path at all.
//
// A router the proxy says is disabled, or that carries errors, is neither protection nor working
// ingress (§12) — the `legacy` fixture is a disabled router whose chain contains a real gate, and
// counting it would credit a service with a protection no request ever passes through.
//
// An empty status is working. §12 names two exclusions and this is neither of them: the proxy
// returned the router, and treating silence as disabled would drop every router from a build that
// does not populate the field.
func Working(r payload.TraefikLiveRouter) bool {
	if len(r.Errors) > 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.Status)) {
	case "", "enabled":
		return true
	default:
		return false
	}
}

// ErrorNote is the note a broken or disabled router puts on its service, quoting what the proxy
// said verbatim (§12). Empty when the router is working.
func ErrorNote(r payload.TraefikLiveRouter) string {
	if Working(r) {
		return ""
	}
	what := "The proxy reports router " + quote(r.Router)
	switch {
	case len(r.Errors) > 0 && strings.TrimSpace(r.Status) != "":
		what += " as " + quote(r.Status) + " with " + errorPhrase(r.Errors)
	case len(r.Errors) > 0:
		what += " with " + errorPhrase(r.Errors)
	default:
		what += " as " + quote(r.Status)
	}
	return what + ", so it is neither working ingress nor protection"
}

// errorPhrase quotes the proxy's errors verbatim. They are the proxy's words about its own
// configuration and this program has no better ones (§12).
func errorPhrase(errs []string) string {
	noun := "error "
	if len(errs) > 1 {
		noun = "errors "
	}
	return noun + list(errs)
}

// sortRouters puts routers in `name@provider` order. The proxy's map order is not an order, and a
// payload that changed between two identical reads would make the change note of §17 useless (I7).
func sortRouters(in []RawRouter) {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Name < in[j].Name })
}
