package authentik

import (
	"strings"

	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
)

// defaultAPIPort is the port Authentik's server listens on for HTTP, and tlsAPIPort for HTTPS.
//
// These are mechanism, not naming: they are what the vendor's image binds, so using them where a
// service declares no ports is reading Authentik's own documentation rather than guessing at an
// operator's convention (I2, I3).
const (
	defaultAPIPort = "9000"
	tlsAPIPort     = "9443"
)

// Candidates is the addresses §11's discovery may probe, in the order it must probe them: every
// internal address before any public hostname.
//
// Internal first because the public hostname of an identity provider is normally behind the gate it
// runs — probing it would get a login page with a 200, which is the one answer discovery cannot tell
// from success without reading the body. Reaching the API on the fleet's own network avoids the
// question entirely.
//
// This is a pure function of the scanned fleet. It lives here because it is §11's rule, and it takes
// the fleet as an argument because the read itself holds no fleet knowledge — the boundary is the
// argument list, not a comment.
func Candidates(stacks []payload.AppStack, reg labels.Registry) []Candidate {
	identified := map[string]bool{}
	for _, key := range labels.AuthentikServices(stacks, reg) {
		identified[key] = true
	}
	if len(identified) == 0 {
		return nil
	}

	var internal, public []Candidate
	for _, stack := range stacks {
		for _, svc := range stack.Services {
			key := stack.ID + "/" + svc.Name
			if !identified[key] {
				continue
			}
			why := whyAuthentik(key, svc)

			for _, name := range dnsNames(svc) {
				for _, port := range apiPorts(svc) {
					internal = append(internal, Candidate{
						URL:      scheme(port) + "://" + name + ":" + port,
						Why:      why,
						Internal: true,
					})
				}
			}
			for _, host := range hostnames(svc) {
				public = append(public, Candidate{
					// https, because a hostname declared on a tunnel route or a Traefik rule is
					// reached over TLS. Certificate verification is never disabled, so a candidate
					// with a certificate that will not verify is rejected as `tls` — which is the
					// correct answer and not a reason to weaken the check (§21).
					URL:      "https://" + host,
					Why:      why,
					Internal: false,
				})
			}
		}
	}
	return append(internal, public...)
}

// whyAuthentik is the evidence line an attempt list carries. It names what identified the service,
// which is the difference between a list of addresses that failed and a diagnosis (§15).
func whyAuthentik(key string, svc payload.Service) string {
	if image := strings.TrimSpace(svc.Image); strings.Contains(strings.ToLower(image), "authentik") {
		return quote(key) + " runs the image " + quote(image)
	}
	return quote(key) + " defines a forward-auth address at Authentik's own outpost endpoint"
}

// dnsNames is the names that address this container on the fleet's networks: the container name
// compose assigned, and the compose service name. Both are aliases compose publishes, so neither is
// a guess (§9).
func dnsNames(svc payload.Service) []string {
	var out []string
	for _, name := range []string{svc.ContainerName, svc.Name} {
		if name = strings.TrimSpace(name); name != "" {
			out = appendOnce(out, name)
		}
	}
	return out
}

// apiPorts is the container ports to try, declared ones first.
//
// A declared target port is evidence about this container; the default is evidence about the image.
// The declared ones come first because an operator who moved the listener said so in the compose
// file, and the default is appended rather than substituted because a service published behind
// Traefik commonly declares no ports at all.
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
	out = appendOnce(out, defaultAPIPort)

	// Bounded here as well as at the read, because the cap at the read is on the whole list and one
	// service with a dozen declared ports would otherwise fill it and hide every other candidate.
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// scheme is http unless the port is one that is TLS by convention of the image itself.
func scheme(port string) string {
	switch port {
	case tlsAPIPort, "443":
		return "https"
	default:
		return "http"
	}
}

// hostnames is every hostname this service declares it answers on, tunnel routes before Traefik
// rules, deduplicated in declaration order.
func hostnames(svc payload.Service) []string {
	var out []string
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
