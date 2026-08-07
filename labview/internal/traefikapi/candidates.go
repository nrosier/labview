package traefikapi

import (
	"strings"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// MaxCandidates bounds discovery. It is transport.AttemptCap so that the number of addresses a
// reader sees in an attempt list and the number actually tried are the same number (I8).
const MaxCandidates = transport.AttemptCap

// apiPort is the port Traefik's dedicated API entrypoint conventionally serves.
//
// It is appended to every candidate's declared ports rather than substituted for them, because a
// proxy that publishes only 80 and 443 — the ordinary arrangement, and what the `edge` fixture
// pins — declares no port the API is on at all. This is mechanism from the vendor's own
// documentation, not a guess at an operator's convention (I2, I3).
const apiPort = "8080"

// maxPortsPerCandidate bounds one service's contribution.
//
// Bounded here as well as at the read, because the cap at the read is on the whole list and one
// proxy declaring a dozen ports would otherwise fill it and hide every other candidate.
const maxPortsPerCandidate = 3

// Candidate is one address discovery may try.
type Candidate struct {
	URL string

	// Why is the evidence, for the attempt list. It names the service and which of §12's three
	// signals made it a candidate — never an environment value (I2, I6).
	Why string

	// Internal is true for a container address and false for a public hostname. Internal
	// candidates are tried first, for the same reason as §11: the public hostname of a proxy
	// dashboard is normally behind the gate the proxy itself applies.
	Internal bool

	// Key is the fleet service key this address belongs to. It is what makes the endpoint that
	// answered attributable to a service, which is one half of where `role: "proxy"` comes from.
	Key string

	// Owned is whether this address may ever receive a credential.
	//
	// True only for a service whose own labels declare `api@internal` — the operator saying
	// *this container serves the proxy API*, which is ownership evidence. False for a service
	// that is a candidate because something's tunnel origin resolved to it, and false for one
	// that merely runs the Traefik image: an address that only *looks* like a proxy MUST never
	// receive a credential (§12).
	Owned bool
}

// Candidates is the addresses §12's discovery may probe, in the order it must probe them.
//
// The three signals are weighed per service, and a service picked up by more than one records the
// strongest. `proxies` is the set of service keys something's tunnel origin resolved to (§9),
// which is why origin resolution has to run ahead of this read (§5).
//
// This is a pure function of the scanned fleet. It lives here because it is §12's rule, and it
// takes the fleet as an argument because the read itself holds no fleet knowledge — the boundary
// is the argument list, not a comment.
func Candidates(stacks []payload.AppStack, proxies map[string]bool) []Candidate {
	var internal, public []Candidate

	for _, stack := range stacks {
		for i := range stack.Services {
			svc := stack.Services[i]
			// The one spelling of a service key. A second one here would be a key that looked
			// right in an attempt list and matched nothing in the index.
			key := fleet.Key(stack.ID, svc.Name)

			owned, why := signal(key, svc, proxies)
			if why == "" {
				continue
			}

			for _, name := range dnsNames(svc) {
				for _, port := range apiPorts(svc) {
					internal = append(internal, Candidate{
						URL:      "http://" + name + ":" + port,
						Why:      why,
						Internal: true,
						Key:      key,
						Owned:    owned,
					})
				}
			}
			// Only the hostnames the API's *own* router declares. Another router on the same
			// container answers some application, and a credential sent there would go to
			// whatever that application is (§12).
			for _, host := range apiHostnames(svc, owned) {
				public = append(public, Candidate{
					// https, because a hostname declared on a Traefik rule or a tunnel route is
					// reached over TLS. Certificate verification is never disabled, so a
					// candidate whose certificate will not verify is rejected as `tls` — the
					// correct answer, and not a reason to weaken the check (§21).
					URL:      "https://" + host,
					Why:      why,
					Internal: false,
					Key:      key,
					Owned:    owned,
				})
			}
		}
	}
	return append(internal, public...)
}

// signal is which of §12's three signals identified this service, strongest first, and whether
// that signal is ownership evidence.
//
// The order is the table's order and it matters: the declared `api@internal` router is the only
// signal that is the operator stating the fact, so a service carrying it stays owned even if it
// also runs the image or something resolved to it.
func signal(key string, svc payload.Service, proxies map[string]bool) (owned bool, why string) {
	switch {
	case declaresInternalAPI(svc):
		return true, quote(key) + " declares a router whose service is " + quote(internalAPIService)
	case proxies[key]:
		// Observed, and established without consulting any image or name: something else's
		// tunnel origin resolved to this container over a shared network (§9).
		return false, quote(key) + " is where another service's tunnel origin resolved"
	case runsTraefikImage(svc):
		return false, quote(key) + " runs the image " + quote(strings.TrimSpace(svc.Image))
	default:
		return false, ""
	}
}

// declaresInternalAPI reports whether any of this service's own routers serves the proxy API.
func declaresInternalAPI(svc payload.Service) bool {
	for _, r := range svc.Traefik {
		if strings.EqualFold(strings.TrimSpace(r.Service), internalAPIService) {
			return true
		}
	}
	return false
}

// runsTraefikImage is the last-resort signal, and the same precedent as §11's Authentik test: the
// image is the vendor's own name for the software, which is evidence about what the container is
// even though it says nothing about what any operator called it.
func runsTraefikImage(svc payload.Service) bool {
	image := strings.ToLower(strings.TrimSpace(svc.Image))
	if image == "" {
		return false
	}
	// The repository segment only. A tag such as `:traefik-v3` on an unrelated image is not a
	// statement about what the image is, and matching the whole reference would read it as one.
	if at := strings.LastIndex(image, "@"); at >= 0 {
		image = image[:at]
	}
	if colon := strings.LastIndex(image, ":"); colon > strings.LastIndex(image, "/") {
		image = image[:colon]
	}
	return image == "traefik" || strings.HasSuffix(image, "/traefik")
}

// dnsNames is the names that address this container on the fleet's networks: the container name
// compose assigned, and the compose service name. Both are aliases compose publishes, so neither
// is a guess (§9).
func dnsNames(svc payload.Service) []string {
	var out []string
	for _, name := range []string{svc.ContainerName, svc.Name} {
		if name = strings.TrimSpace(name); name != "" {
			out = appendOnce(out, name)
		}
	}
	return out
}

// apiPorts is the container ports to try, declared ones first and 8080 last.
//
// A declared target port is evidence about this container; 8080 is evidence about Traefik. The
// declared ones come first because an operator who moved the API said so, and 8080 is appended
// rather than substituted because a proxy publishing 80 and 443 declares nothing about its API.
func apiPorts(svc payload.Service) []string {
	var out []string
	for _, p := range svc.Ports {
		if target := strings.TrimSpace(p.Target); target != "" {
			out = appendOnce(out, target)
		}
	}
	if svc.Docker != nil {
		for _, p := range svc.Docker.PublishedPorts {
			if target := strings.TrimSpace(p.Target); target != "" {
				out = appendOnce(out, target)
			}
		}
	}
	out = appendOnce(out, apiPort)

	if len(out) > maxPortsPerCandidate {
		out = out[:maxPortsPerCandidate]
	}
	return out
}

// apiHostnames is the public hostnames a credential may follow, which is a narrower set than
// every hostname this service answers on.
//
// For an owned service it is the hostnames declared on the `api@internal` router itself — the
// address the scan proved is the API's own. For an unowned candidate every declared hostname is
// fair game to *probe* anonymously, because a proxy discovered by origin or by image still has to
// be found somewhere; what it will not get is a credential, and `Owned` is what carries that.
func apiHostnames(svc payload.Service, owned bool) []string {
	var out []string
	if owned {
		for _, r := range svc.Traefik {
			if !strings.EqualFold(strings.TrimSpace(r.Service), internalAPIService) {
				continue
			}
			for _, host := range r.Hosts {
				if host = strings.TrimSpace(host); host != "" {
					out = appendOnce(out, host)
				}
			}
		}
		return out
	}

	for _, r := range svc.Cloudflare {
		if host := strings.TrimSpace(r.Hostname); host != "" {
			out = appendOnce(out, host)
		}
	}
	for _, r := range svc.Traefik {
		for _, host := range r.Hosts {
			if host = strings.TrimSpace(host); host != "" {
				out = appendOnce(out, host)
			}
		}
	}
	return out
}
