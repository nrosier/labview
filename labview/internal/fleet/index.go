package fleet

import (
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// Index is the fleet index of §9: published host ports, container DNS names, container IPs,
// declared hostnames, and lookups from a name or a URL to candidate services.
//
// It is produced by the same stage as origin resolution and shared by every later stage — the
// identity-provider match, the proxy cross-check and the probe all ask it the same questions, so
// none of them may build a second index of its own.
//
// Every list it returns holds service keys in scan order, deduplicated. A lookup that finds two
// candidates returns two: nothing here breaks a tie, because the rule for breaking one differs
// by caller and belongs at the caller (§9, §11, §12).
type Index struct {
	// stacks is the live fleet, so Service returns a pointer later stages can write notes and
	// conclusions through rather than a copy that would silently be discarded.
	stacks []payload.AppStack
	keys   []string
	at     map[string]position

	hostPorts map[string][]string
	dnsNames  map[string][]string
	ips       map[string][]string
	hostnames map[string][]string
	inStack   map[string]map[string]string
}

type position struct{ stack, service int }

// NewIndex builds the index over the fleet as scanned. Docker state is read where it is present
// — container IPs and Engine-reported publications are facts about the same fleet — which is why
// the snapshot is taken before this stage runs (§5).
func NewIndex(stacks []payload.AppStack) *Index {
	ix := &Index{
		stacks:    stacks,
		at:        map[string]position{},
		hostPorts: map[string][]string{},
		dnsNames:  map[string][]string{},
		ips:       map[string][]string{},
		hostnames: map[string][]string{},
		inStack:   map[string]map[string]string{},
	}

	for si := range stacks {
		stack := &stacks[si]
		for vi := range stack.Services {
			svc := &stack.Services[vi]
			key := Key(stack.ID, svc.Name)

			ix.keys = append(ix.keys, key)
			ix.at[key] = position{stack: si, service: vi}
			if ix.inStack[stack.ID] == nil {
				ix.inStack[stack.ID] = map[string]string{}
			}
			ix.inStack[stack.ID][svc.Name] = key

			// Compose publishes a service's name and its container_name as DNS aliases on its
			// networks, so both are names that address this container and neither is a guess
			// about it.
			ix.add(ix.dnsNames, svc.Name, key)
			ix.add(ix.dnsNames, svc.ContainerName, key)

			for _, p := range svc.Ports {
				ix.add(ix.hostPorts, p.Published, key)
			}
			for _, route := range svc.Cloudflare {
				ix.add(ix.hostnames, route.Hostname, key)
			}
			for _, route := range svc.Traefik {
				for _, host := range route.Hosts {
					ix.add(ix.hostnames, host, key)
				}
			}
			if svc.Docker != nil {
				ix.add(ix.dnsNames, svc.Docker.Name, key)
				for _, ip := range svc.Docker.IPAddresses {
					ix.add(ix.ips, ip, key)
				}
				for _, p := range svc.Docker.PublishedPorts {
					ix.add(ix.hostPorts, p.Published, key)
				}
			}
		}
	}
	return ix
}

// add records one lookup key, case-folded, skipping empties and repeats. Repeats are the norm
// rather than the exception — `443:443/tcp` beside `443:443/udp`, a container_name equal to the
// service name — and §9 requires them collapsed by service key rather than counted as rivals.
func (ix *Index) add(into map[string][]string, lookup, key string) {
	lookup = strings.ToLower(strings.TrimSpace(lookup))
	if lookup == "" {
		return
	}
	into[lookup] = appendOnce(into[lookup], key)
}

// Keys is every service key in scan order.
func (ix *Index) Keys() []string { return ix.keys }

// Has reports whether a key names a scanned service.
func (ix *Index) Has(key string) bool { _, ok := ix.at[key]; return ok }

// Service returns the live service, or nil. Writing through the pointer is how later stages
// attach conclusions to the fleet the index was built over.
func (ix *Index) Service(key string) *payload.Service {
	at, ok := ix.at[key]
	if !ok {
		return nil
	}
	return &ix.stacks[at.stack].Services[at.service]
}

// Stack returns the live stack a key belongs to, or nil.
func (ix *Index) Stack(key string) *payload.AppStack {
	at, ok := ix.at[key]
	if !ok {
		return nil
	}
	return &ix.stacks[at.stack]
}

// ByHostPort is the candidates publishing one host port. A host port can only be held by one
// service at a time, so a single candidate *identifies* rather than suggests — and several
// candidates is a tie the scan cannot see through (§9).
func (ix *Index) ByHostPort(port string) []string { return ix.hostPorts[fold(port)] }

// ByName is the candidates a container DNS name addresses: a service name, a container_name, or
// the name the Engine reported.
func (ix *Index) ByName(name string) []string { return ix.dnsNames[fold(name)] }

// ByIP is the candidates holding one container IP, from the Docker snapshot.
func (ix *Index) ByIP(ip string) []string { return ix.ips[fold(ip)] }

// ByHostname is the candidates that declare one hostname, from a tunnel route or a Traefik rule.
func (ix *Index) ByHostname(host string) []string { return ix.hostnames[fold(host)] }

// ByURL resolves an address to candidate services by asking, in order, the three questions the
// address itself licenses: a declared hostname is the strongest reading, then a container name,
// then a container IP. It never falls through to a host port, because a port in a URL says
// nothing about which container answers it — that reading is §9's and needs an IP literal to
// license it.
func (ix *Index) ByURL(raw string) []string {
	a := ParseAddress(raw)
	if a.Host == "" {
		return nil
	}
	if got := ix.ByHostname(a.Host); len(got) > 0 {
		return got
	}
	if a.IsIP() {
		return ix.ByIP(a.Host)
	}
	return ix.ByName(a.Host)
}

// InStack resolves a service name inside one stack. It is what makes a bare declared reference
// prefer the declaring stack's own service (§14): compose's own `depends_on` reaches no further
// than its project, so a bare name written beside a service of that name means the sibling.
func (ix *Index) InStack(stack, name string) (string, bool) {
	key, ok := ix.inStack[stack][name]
	return key, ok
}

// Reachable filters candidates to those sharing a real network with one service, in scan order.
// It is the rule that breaks a host-port tie: a candidate sharing no network with the service it
// supposedly fronts cannot forward to it (§9).
func Reachable(nets *Networks, from string, candidates []string) []string {
	var out []string
	for _, c := range candidates {
		if c != from && nets.SharesAny(from, c) {
			out = append(out, c)
		}
	}
	return out
}

// GateService resolves a forward-auth address to the one scanned service that answers it, which is
// what lets a gate be drawn on an ingress path rather than only beside its far end (§22.5).
//
// Exactly one candidate or nothing: an address two services answer to is a tie, and picking
// between them by iteration order would draw a gate in front of a service that has none.
func GateService(ix *Index, address string) (string, bool) {
	if candidates := ix.ByURL(address); len(candidates) == 1 {
		return candidates[0], true
	}
	return "", false
}

func fold(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
