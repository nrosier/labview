package fleet

import "github.com/nrosier/labview/internal/payload"

// Origins resolves every tunnel route's declared origin (§9).
//
// A tunnel rarely terminates at the container whose labels declare it: the declared origin
// normally names a reverse proxy that forwards over a shared network. The conclusion is recorded
// on every route whose origin service is non-empty, and it is drawn from what the fleet
// publishes and what it can reach — **no image, vendor or naming convention is consulted
// anywhere in this resolution**, which is what keeps a service called `nginx` from being made a
// proxy by its name.
//
// It returns the keys of the services something resolved to as a hop, which is one half of where
// `role: "proxy"` comes from (§9); the other half is the service whose Traefik API answered.
func Origins(ix *Index, nets *Networks) map[string]bool {
	proxies := map[string]bool{}

	for _, key := range ix.Keys() {
		svc := ix.Service(key)
		for i := range svc.Cloudflare {
			route := &svc.Cloudflare[i]
			if route.Service == "" {
				continue
			}
			target, note := resolveOrigin(ix, nets, key, svc, route.Service)
			route.Origin = &target
			if note != "" {
				svc.Notes = append(svc.Notes, note)
			}
			if target.Kind == payload.OriginFleetService && target.HopKey != "" {
				proxies[target.HopKey] = true
			}
		}
	}
	return proxies
}

// resolveOrigin is the whole of the §9 table, in the order the table states it. It returns the
// conclusion and, for `unresolved`, the service note that says which reason applied — an
// unresolved origin keeps its direct edge, so without the note nothing on the page would
// distinguish it from a resolved one.
func resolveOrigin(ix *Index, nets *Networks, key string, svc *payload.Service, address string) (payload.OriginTarget, string) {
	a := ParseAddress(address)
	target := payload.OriginTarget{
		Address: a.Raw,
		Host:    a.Host,
		Port:    a.Port,
		Kind:    payload.OriginUnresolved,
	}

	switch {
	case a.Host == "":
		target.Evidence = "the origin address names no host"
		return target, unresolvedNote(svc, a, target.Evidence)

	// The origin host is this service's own name or container_name. Compose publishes both as
	// DNS aliases on the service's networks, so this is the container addressing itself and
	// there is no hop to look for.
	case !a.IsIP() && namesSelf(svc, a.Host):
		target.Kind = payload.OriginSelfNetwork
		target.Evidence = "the origin host `" + a.Host + "` is this service's own " +
			selfNameKind(svc, a.Host) + ", which compose publishes as a DNS alias on its networks"
		return target, ""

	// An IP literal addresses the host, so the port is a published host port — which is why a
	// single match identifies rather than suggests: only one service can hold a host port.
	case a.IsIP():
		return resolveHostPort(ix, nets, key, svc, a, target)

	// A bare name addresses a container, so the port says nothing about ownership and the name
	// is the whole of the evidence.
	case a.IsBareName():
		return resolveContainerName(ix, nets, key, svc, a, target)

	// An FQDN is resolved by DNS outside this fleet. Whatever it points at, the scan cannot see
	// it, and a name that happens to match a container is not evidence that it resolves there.
	default:
		target.Evidence = "the origin host `" + a.Host +
			"` is a fully qualified name, resolved outside this fleet"
		return target, unresolvedNote(svc, a, target.Evidence)
	}
}

// resolveHostPort is the IP-literal path: the port is a published host port.
func resolveHostPort(ix *Index, nets *Networks, key string, svc *payload.Service, a Address, target payload.OriginTarget) (payload.OriginTarget, string) {
	if a.Port == "" {
		target.Evidence = "the origin addresses the host at `" + a.Host +
			"` and names no port, so no published host port identifies it"
		return target, unresolvedNote(svc, a, target.Evidence)
	}

	publishers := ix.ByHostPort(a.Port)

	// This service's own publication comes first: a route whose origin is the container's own
	// published port reaches it with nothing in between, and asking the fleet for rivals would
	// invent a hop in front of a service that needs none.
	if contains(publishers, key) {
		target.Kind = payload.OriginSelfHostPort
		target.Evidence = "host port " + a.Port + " is published by this service" + schemeNote(a)
		return target, ""
	}

	// Network membership breaks a port tie: a candidate sharing no network with the service it
	// supposedly fronts cannot forward to it.
	reachable := Reachable(nets, key, publishers)
	switch len(reachable) {
	case 1:
		target.Kind = payload.OriginFleetService
		target.HopKey = reachable[0]
		target.Evidence = "`" + reachable[0] + "` publishes host port " + a.Port +
			schemeNote(a) + " and shares " + sharedPhrase(nets.Shared(key, reachable[0])) +
			" with this service"
		return target, ""
	case 0:
		if len(publishers) > 0 {
			target.Evidence = "host port " + a.Port + " is published by " +
				listPhrase(publishers) + ", none of which shares a network with this service"
		} else {
			target.Evidence = "no scanned service publishes host port " + a.Port
		}
		return target, unresolvedNote(svc, a, target.Evidence)
	default:
		// A genuine tie stays unresolved — never a winner picked by iteration order.
		target.Evidence = "host port " + a.Port + " is published by " + listPhrase(reachable) +
			", each of which shares a network with this service"
		return target, unresolvedNote(svc, a, target.Evidence)
	}
}

// resolveContainerName is the bare-name path: the name addresses a container.
func resolveContainerName(ix *Index, nets *Networks, key string, svc *payload.Service, a Address, target payload.OriginTarget) (payload.OriginTarget, string) {
	named := ix.ByName(a.Host)
	reachable := Reachable(nets, key, named)

	switch len(reachable) {
	case 1:
		target.Kind = payload.OriginFleetService
		target.HopKey = reachable[0]
		target.Evidence = "`" + a.Host + "` is a container DNS name of `" + reachable[0] +
			"`, which shares " + sharedPhrase(nets.Shared(key, reachable[0])) + " with this service"
		return target, ""
	case 0:
		switch {
		case len(named) > 0:
			target.Evidence = "`" + a.Host + "` is a container DNS name of " + listPhrase(named) +
				", which shares no network with this service"
		default:
			target.Evidence = "no scanned service answers to the container name `" + a.Host + "`"
		}
		return target, unresolvedNote(svc, a, target.Evidence)
	default:
		target.Evidence = "`" + a.Host + "` is a container DNS name of " + listPhrase(reachable) +
			", each of which shares a network with this service"
		return target, unresolvedNote(svc, a, target.Evidence)
	}
}

// namesSelf reports whether a host is one of this service's own DNS names. The Engine-reported
// container name is included where there is one, because that is the same container answering to
// the same alias.
func namesSelf(svc *payload.Service, host string) bool {
	if fold(svc.Name) == host || fold(svc.ContainerName) == host {
		return true
	}
	return svc.Docker != nil && fold(svc.Docker.Name) == host
}

// selfNameKind says which of the two aliases matched, so the evidence quotes the right one.
func selfNameKind(svc *payload.Service, host string) string {
	if fold(svc.Name) == host {
		return "service name"
	}
	return "container name"
}

// schemeNote states when a port came from the scheme rather than from the address, so a reader
// can see why `https://10.10.0.5` was matched against 443.
func schemeNote(a Address) string {
	if a.PortFrom == PortScheme {
		return " (the port the `" + a.Scheme + "` scheme names, the address stating none)"
	}
	return ""
}

// unresolvedNote is the service note §9 requires beside an unresolved origin. The direct edge is
// kept deliberately — an invented hop would be a claim about the path and dropping the edge would
// hide a route that exists — so this sentence is the only thing that says the path is unknown.
func unresolvedNote(svc *payload.Service, a Address, reason string) string {
	return "the tunnel origin `" + a.Raw + "` declared on `" + svc.Name +
		"` could not be resolved to a scanned service: " + reason +
		"; the route is drawn straight to this service because the path it really takes is unknown"
}

// sharedPhrase names the networks a pair shares, which is the evidence a hop can forward at all.
func sharedPhrase(nets []string) string {
	switch len(nets) {
	case 0:
		return "no network"
	case 1:
		return "network `" + nets[0] + "`"
	default:
		return "networks " + quoteList(nets)
	}
}

// listPhrase names candidate services, so a tie is answerable rather than merely reported.
func listPhrase(keys []string) string {
	if len(keys) == 1 {
		return "`" + keys[0] + "`"
	}
	return quoteList(keys)
}

func quoteList(items []string) string {
	out := ""
	for i, it := range items {
		switch {
		case i == 0:
		case i == len(items)-1:
			out += " and "
		default:
			out += ", "
		}
		out += "`" + it + "`"
	}
	return out
}
