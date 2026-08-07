package probe

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

func tunnel(hostname, origin string) payload.CloudflareRoute {
	return payload.CloudflareRoute{Hostname: hostname, Service: origin, Raw: map[string]string{}}
}

func router(name, host string, tls bool) payload.TraefikRoute {
	return payload.TraefikRoute{Router: name, Hosts: []string{host}, TLS: tls,
		PathPrefixes: []string{}, Entrypoints: []string{}, Middlewares: []string{}}
}

func port(raw, published string) payload.PortMapping {
	return payload.PortMapping{Raw: raw, Published: published, Target: "80", Protocol: "tcp"}
}

func urls(targets []Target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, string(t.Vantage)+" "+t.URL)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTheThreeVantagesComeFromTheEvidenceSection132Names(t *testing.T) {
	cases := []struct {
		name    string
		service payload.Service
		lanHost string
		want    []string
	}{
		{
			name:    "a tunnel hostname is always asked over https",
			service: payload.Service{Cloudflare: []payload.CloudflareRoute{tunnel("app.example.com", "http://app:8080")}},
			want:    []string{"public https://app.example.com/"},
		},
		{
			name:    "a router that declares TLS is asked over https",
			service: payload.Service{Traefik: []payload.TraefikRoute{router("app", "app.lan", true)}},
			want:    []string{"traefik https://app.lan/"},
		},
		{
			name:    "a router that does not is asked over http",
			service: payload.Service{Traefik: []payload.TraefikRoute{router("app", "app.lan", false)}},
			want:    []string{"traefik http://app.lan/"},
		},
		{
			name: "the walk runs most- to least-exposed",
			service: payload.Service{
				Cloudflare: []payload.CloudflareRoute{tunnel("app.example.com", "http://app:8080")},
				Traefik:    []payload.TraefikRoute{router("app", "app.lan", true)},
				Ports:      []payload.PortMapping{port("8080:80", "8080")},
			},
			lanHost: "nas.lan",
			want: []string{
				"public https://app.example.com/",
				"traefik https://app.lan/",
				"lan http://nas.lan:8080/",
			},
		},
		{
			name: "a service with ports and no route of either kind yields no address at all",
			service: payload.Service{
				Ports: []payload.PortMapping{port("5432:5432", "5432")},
			},
			lanHost: "nas.lan",
			want:    nil,
		},
		{
			name: "an empty lanHost means no LAN vantage rather than a guessed one",
			service: payload.Service{
				Traefik: []payload.TraefikRoute{router("app", "app.lan", false)},
				Ports:   []payload.PortMapping{port("8080:80", "8080")},
			},
			lanHost: "",
			want:    []string{"traefik http://app.lan/"},
		},
		{
			name: "a tunnel origin that would not answer a GET yields nothing",
			service: payload.Service{
				Cloudflare: []payload.CloudflareRoute{tunnel("ssh.example.com", "ssh://box:22")},
			},
			want: nil,
		},
		{
			name: "a scheme-less tunnel origin counts, because cloudflared accepts one",
			service: payload.Service{
				Cloudflare: []payload.CloudflareRoute{tunnel("app.example.com", "app:8080")},
			},
			want: []string{"public https://app.example.com/"},
		},
		{
			name: "a live router is evidence as much as a labelled one",
			service: payload.Service{
				TraefikLive: []payload.TraefikLiveRouter{{Router: "app@file", Hosts: []string{"app.lan"}, TLS: true}},
			},
			want: []string{"traefik https://app.lan/"},
		},
		{
			name: "the same host from a label and from the live table is one address",
			service: payload.Service{
				Traefik:     []payload.TraefikRoute{router("app", "app.lan", true)},
				TraefikLive: []payload.TraefikLiveRouter{{Router: "app@docker", Hosts: []string{"app.lan"}, TLS: true}},
			},
			want: []string{"traefik https://app.lan/"},
		},
		{
			name: "a host pattern is not an address",
			service: payload.Service{
				Traefik: []payload.TraefikRoute{router("wild", "*.example.com", true)},
			},
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := urls(Addresses(c.service, c.lanHost))
			if !equal(got, c.want) {
				t.Fatalf("%s\n got %v\nwant %v", c.name, got, c.want)
			}
		})
	}
}

func TestAtMostFourAddressesPerService(t *testing.T) {
	// §13.6's containment bound. A service with six tunnel hostnames would otherwise turn one fleet into
	// a great many requests.
	s := payload.Service{Cloudflare: []payload.CloudflareRoute{
		tunnel("a.example.com", "http://app:80"),
		tunnel("b.example.com", "http://app:80"),
		tunnel("c.example.com", "http://app:80"),
		tunnel("d.example.com", "http://app:80"),
		tunnel("e.example.com", "http://app:80"),
		tunnel("f.example.com", "http://app:80"),
	}}

	if got := Addresses(s, "nas.lan"); len(got) != AddressCap {
		t.Fatalf("want at most %d addresses, got %d", AddressCap, len(got))
	}
}

func TestALANAddressNeedsAPublishedPortThatAnswersThere(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		lanHost string
		want    bool
	}{
		{"no bind address at all", "8080:80", "nas.lan", true},
		{"the wildcard bind", "0.0.0.0:8080:80", "nas.lan", true},
		{"the IPv6 wildcard", "[::]:8080:80", "nas.lan", true},
		{"a loopback bind and a LAN host", "127.0.0.1:8080:80", "nas.lan", false},
		{"a loopback bind and a loopback host", "127.0.0.1:8080:80", "localhost", true},
		{"an IPv6 loopback bind and a LAN host", "[::1]:8080:80", "nas.lan", false},
		{"the bind address the reader named", "10.0.0.4:8080:80", "10.0.0.4", true},
		{"a different interface", "10.0.0.4:8080:80", "10.0.0.9", false},
		{"a protocol suffix does not confuse it", "0.0.0.0:8080:80/udp", "nas.lan", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bindAnswersAt(c.raw, c.lanHost); got != c.want {
				t.Fatalf("a port published as %q reachable at %q = %v, want %v",
					c.raw, c.lanHost, got, c.want)
			}
		})
	}
}

func TestALoopbackPublicationYieldsNoLANAddress(t *testing.T) {
	// A reverse proxy publishing `127.0.0.1:8080:80` is deliberately unreachable from the network, and
	// asking `http://nas.lan:8080/` would report *no answer* about an address that was never offered.
	s := payload.Service{
		Traefik: []payload.TraefikRoute{router("app", "app.lan", false)},
		Ports:   []payload.PortMapping{port("127.0.0.1:8080:80", "8080")},
	}

	got := urls(Addresses(s, "nas.lan"))
	if !equal(got, []string{"traefik http://app.lan/"}) {
		t.Fatalf("want the router address only, got %v", got)
	}
}

func TestAPortRangeIsNotASingleAddress(t *testing.T) {
	s := payload.Service{
		Traefik: []payload.TraefikRoute{router("app", "app.lan", false)},
		Ports:   []payload.PortMapping{{Raw: "8000-8010:8000-8010", Published: "8000-8010", Target: "8000-8010"}},
	}

	got := urls(Addresses(s, "nas.lan"))
	if !equal(got, []string{"traefik http://app.lan/"}) {
		t.Fatalf("a range names no single port to ask; got %v", got)
	}
}

func TestARuntimePublicationCountsAsEvidenceToo(t *testing.T) {
	// A port the Engine reports and the compose file never mentioned is the same fact from another
	// source (§10).
	s := payload.Service{
		Traefik: []payload.TraefikRoute{router("app", "app.lan", false)},
		Docker: &payload.DockerState{
			PublishedPorts: []payload.PortMapping{port("0.0.0.0:9000:80", "9000")},
		},
	}

	got := urls(Addresses(s, "nas.lan"))
	if !equal(got, []string{"traefik http://app.lan/", "lan http://nas.lan:9000/"}) {
		t.Fatalf("got %v", got)
	}
}

func TestNoAddressIsEverAskedWithAQueryStringOrAPath(t *testing.T) {
	// GET only, no query string (§13.6). The address is the service's own root, whatever path a route
	// declared.
	s := payload.Service{Cloudflare: []payload.CloudflareRoute{
		{Hostname: "app.example.com", Service: "http://app:8080", Path: "/only/this", Raw: map[string]string{}},
	}}

	got := Addresses(s, "")
	if len(got) != 1 || got[0].URL != "https://app.example.com/" {
		t.Fatalf("the root and nothing else; got %+v", got)
	}
}
