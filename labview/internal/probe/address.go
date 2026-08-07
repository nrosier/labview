package probe

import (
	"net"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// Where a request may be sent
// ---------------------------------------------------------------------------

// AddressCap is §13.6's containment bound: at most four addresses per service. Three vantages, and a
// service with several tunnel hostnames or several routers could otherwise turn one fleet into a
// hundred requests.
const AddressCap = 4

// Target is one address the probe may ask, and the vantage that produced it.
//
// Why carries the evidence the address came from — a hostname, a router name, a published port — and
// exists so that a report can say *where* an address came from without a second lookup. No rule reads
// it.
type Target struct {
	Vantage payload.ProbeVantage
	URL     string
	Why     string
}

// Addresses is §13.2, and every address in it comes **from evidence already on the service, never
// from a port number and never from an image name**.
//
// The walk is most- to least-exposed: public, then traefik, then lan. A service with `ports:` and no
// route of either kind yields **no address at all**, which is what keeps the probe off a database
// without anyone consulting a port number to guess what it is.
func Addresses(s payload.Service, lanHost string) []Target {
	var out []Target
	seen := map[string]bool{}

	add := func(vantage payload.ProbeVantage, address, why string) {
		if address == "" || seen[address] || len(out) >= AddressCap {
			return
		}
		seen[address] = true
		out = append(out, Target{Vantage: vantage, URL: address, Why: why})
	}

	// public — a tunnel route with a resolved hostname whose origin speaks HTTP. Always `https`: a
	// tunnel hostname is served by Cloudflare's own edge, which terminates TLS whatever the origin
	// scheme behind it is.
	for _, route := range s.Cloudflare {
		host := hostname(route.Hostname)
		if host == "" || !httpOrigin(route) {
			continue
		}
		add(payload.VantagePublic, "https://"+host+"/", "tunnel hostname "+host)
	}

	// traefik — a router's own host. **Only HTTP routers are parsed** (§7), so a non-empty route list
	// is itself the evidence that this is HTTP; no scheme is guessed from anything else.
	for _, route := range s.Traefik {
		for _, h := range route.Hosts {
			if host := hostname(h); host != "" {
				add(payload.VantageTraefik, scheme(route.TLS)+"://"+host+"/", "router "+route.Router)
			}
		}
	}
	for _, live := range s.TraefikLive {
		for _, h := range live.Hosts {
			if host := hostname(h); host != "" {
				add(payload.VantageTraefik, scheme(live.TLS)+"://"+host+"/", "live router "+live.Router)
			}
		}
	}

	// lan — only for a service one of the two above already found to be HTTP, only with a configured
	// lanHost, and only for a published port whose bind address answers there. An empty lanHost means
	// **no LAN vantage, never a guessed one**.
	if len(out) == 0 || lanHost == "" {
		return out
	}
	for _, port := range publishedPorts(s) {
		if !singlePort(port.Published) || !bindAnswersAt(port.Raw, lanHost) {
			continue
		}
		add(payload.VantageLan, "http://"+net.JoinHostPort(lanHost, port.Published)+"/", "published port "+port.Raw)
	}
	return out
}

// publishedPorts is the compose declarations first and the Engine's own report second. Both are
// evidence of the same thing and either may carry a bind address the other does not — a long-form
// mapping in the file, a runtime publication the file never mentioned.
func publishedPorts(s payload.Service) []payload.PortMapping {
	out := append([]payload.PortMapping(nil), s.Ports...)
	if s.Docker != nil {
		out = append(out, s.Docker.PublishedPorts...)
	}
	return out
}

// singlePort is whether a published field names one port rather than a range.
//
// `8000-8010:8000-8010` publishes eleven ports and names none of them, so there is no single address
// to ask. Ranges yield no LAN vantage rather than a request to the first port in one — a guess, and
// §13.2 permits none.
func singlePort(published string) bool {
	if published == "" {
		return false
	}
	for _, r := range published {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func scheme(tls bool) string {
	if tls {
		return "https"
	}
	return "http"
}

// hostname is a route host reduced to something a request can be sent to, and empty when it is not
// one.
//
// A pattern is not an address. `*.example.com` and `{subdomain:[a-z]+}.example.com` are both hosts a
// router matches and neither is a host that resolves, so both yield no address rather than a request
// to a literal asterisk.
func hostname(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" || strings.ContainsAny(host, "*{}()[]/ ") {
		return ""
	}
	return host
}

// httpOrigin is §13.2's scheme test on a tunnel route: `http`, `https` or **absent**.
//
// Absent counts, because `cloudflared` accepts a bare `host:port` origin and serves it over HTTP —
// omitting the scheme is the common spelling, not a missing fact. What this excludes is the tunnel's
// other origin kinds: `ssh://`, `rdp://`, `tcp://`, `unix:` and `bastion`, none of which would answer
// a GET and all of which are named in the file this reads.
func httpOrigin(route payload.CloudflareRoute) bool {
	origin := strings.TrimSpace(route.Service)
	if origin == "" && route.Origin != nil {
		origin = route.Origin.Address
	}
	if origin == "" {
		return false
	}
	sep := strings.Index(origin, "://")
	if sep < 0 {
		// A bare `host:port`, unless it is one of the schemeless spellings the tunnel config uses.
		bare := strings.ToLower(origin)
		return bare != "hello_world" && bare != "http_status:404" &&
			!strings.HasPrefix(bare, "unix:") && !strings.HasPrefix(bare, "http_status:")
	}
	switch strings.ToLower(origin[:sep]) {
	case "http", "https":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Does a published port answer at the LAN host
// ---------------------------------------------------------------------------

// wildcardBinds are the bind addresses that answer on every interface the host has.
var wildcardBinds = map[string]bool{"": true, "0.0.0.0": true, "::": true, "*": true}

// loopbackBinds are the spellings of "this machine only". A port bound to one of these does **not**
// answer at a LAN address, which is exactly the case §13.2's third condition exists to exclude — a
// reverse proxy publishing `127.0.0.1:8080:80` is deliberately unreachable from the network.
var loopbackBinds = map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true}

// bindAnswersAt reads the bind address out of a port mapping's **raw text** and asks whether a
// request to lanHost would arrive.
//
// The raw text and not a parsed field, because §6 keeps the bind address only in `Raw` — the presence
// of a published port is the signal and the exact text is the evidence, so no rule may depend on a
// parsed port number. This one depends on the parsed *host*, which is a different thing.
func bindAnswersAt(raw, lanHost string) bool {
	bind := strings.ToLower(bindOf(raw))
	want := strings.ToLower(strings.TrimSpace(lanHost))

	switch {
	case wildcardBinds[bind]:
		return true
	case bind == want:
		return true
	case loopbackBinds[bind]:
		// Only if the reader pointed `probe.lanHost` at this machine, which is a legitimate setup and
		// the one case where a loopback publication does answer.
		return loopbackBinds[want]
	default:
		return false
	}
}

// bindOf is the host part of a short-form port mapping, and empty when there is none.
//
// The short form is `[[host_ip:]host:]container[/protocol]`, so a bind address is present only with
// three or more fields. An IPv6 literal is bracketed, which is the one case a plain colon split gets
// wrong.
func bindOf(raw string) string {
	spec := strings.TrimSpace(raw)
	if slash := strings.LastIndexByte(spec, '/'); slash >= 0 {
		spec = spec[:slash]
	}
	if spec == "" {
		return ""
	}

	if strings.HasPrefix(spec, "[") {
		if end := strings.Index(spec, "]"); end > 0 {
			return spec[1:end]
		}
		return ""
	}

	fields := strings.Split(spec, ":")
	if len(fields) < 3 {
		return ""
	}
	return fields[0]
}
