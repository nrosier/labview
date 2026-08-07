package labels

import (
	"strings"
	"testing"
)

func TestTraefikRouter(t *testing.T) {
	routes, notes := Traefik(map[string]string{
		"traefik.enable":                                             "true",
		"traefik.http.routers.web.rule":                              "Host(`a.example.com`, `b.example.com`) && PathPrefix(`/api`)",
		"traefik.http.routers.web.entryPoints":                       "websecure,web",
		"traefik.http.routers.web.middlewares":                       "authentik@docker,compress@file",
		"traefik.http.routers.web.tls.certResolver":                  "cloudflare",
		"traefik.http.routers.web.service":                           "web-backend",
		"traefik.http.services.web-backend.loadbalancer.server.port": "3000",
	}, "traefik")

	if len(notes) != 0 {
		t.Fatalf("notes = %q, want none", notes)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	r := routes[0]
	if r.Router != "web" {
		t.Errorf("router = %q", r.Router)
	}
	if got := strings.Join(r.Hosts, ","); got != "a.example.com,b.example.com" {
		t.Errorf("hosts = %q", got)
	}
	if got := strings.Join(r.PathPrefixes, ","); got != "/api" {
		t.Errorf("pathPrefixes = %q", got)
	}
	// Entry point order is the operator's, not sorted: it is one label value, and Traefik
	// reads it in order.
	if got := strings.Join(r.Entrypoints, ","); got != "websecure,web" {
		t.Errorf("entrypoints = %q", got)
	}
	// A chain's order decides which gate a request meets first, so the references keep both
	// their order and their `@provider` suffix exactly as written.
	if got := strings.Join(r.Middlewares, ","); got != "authentik@docker,compress@file" {
		t.Errorf("middlewares = %q", got)
	}
	if !r.TLS || r.CertResolver != "cloudflare" {
		t.Errorf("tls = %v, certResolver = %q", r.TLS, r.CertResolver)
	}
	if r.ServicePort != "3000" {
		t.Errorf("servicePort = %q, want 3000 resolved through the named service", r.ServicePort)
	}
}

// A rule is read for the names it can match and no further. HostRegexp and HostSNI are
// different matchers that happen to start with the same four letters, and a router whose
// regexp got read as a hostname would put a regular expression in the hostname index (§9).
func TestTraefikRuleMatchersAreWholeWords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  string
		hosts string
		paths string
	}{
		{name: "one host", rule: "Host(`one.example.com`)", hosts: "one.example.com"},
		{name: "alternation", rule: "Host(`a.example.com`) || Host(`b.example.com`)",
			hosts: "a.example.com,b.example.com"},
		{name: "lower case spelling", rule: "host(`c.example.com`)", hosts: "c.example.com"},
		{name: "HostRegexp is not Host", rule: "HostRegexp(`^.+\\.example\\.com$`)"},
		{name: "HostSNI is not Host", rule: "HostSNI(`d.example.com`)"},
		{name: "regexp beside a host", rule: "HostRegexp(`^x.*`) || Host(`e.example.com`)",
			hosts: "e.example.com"},
		{name: "repeat collapses", rule: "Host(`f.example.com`) || Host(`f.example.com`)",
			hosts: "f.example.com"},
		{name: "prefixes", rule: "Host(`g.example.com`) && (PathPrefix(`/a`) || PathPrefix(`/b`))",
			hosts: "g.example.com", paths: "/a,/b"},
		{name: "single quotes and none", rule: "Host('h.example.com') && PathPrefix(/plain)",
			hosts: "h.example.com", paths: "/plain"},
		{name: "no matcher at all", rule: "ClientIP(`192.0.2.0/24`)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, _ := Traefik(map[string]string{
				"traefik.http.routers.r.rule": tc.rule,
			}, "traefik")
			if len(routes) != 1 {
				t.Fatalf("routes = %d", len(routes))
			}
			if got := strings.Join(routes[0].Hosts, ","); got != tc.hosts {
				t.Errorf("hosts = %q, want %q", got, tc.hosts)
			}
			if got := strings.Join(routes[0].PathPrefixes, ","); got != tc.paths {
				t.Errorf("pathPrefixes = %q, want %q", got, tc.paths)
			}
			if routes[0].Rule != tc.rule {
				t.Errorf("rule = %q, want it kept verbatim", routes[0].Rule)
			}
		})
	}
}

func TestTraefikTLS(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]string
		want   bool
	}{
		{name: "absent", fields: map[string]string{}, want: false},
		{name: "bare true", fields: map[string]string{"tls": "true"}, want: true},
		{name: "explicit false is decisive",
			fields: map[string]string{"tls": "false", "tls.certresolver": "le"}, want: false},
		{name: "a resolver alone means TLS",
			fields: map[string]string{"tls.certresolver": "le"}, want: true},
		{name: "an options set alone means TLS",
			fields: map[string]string{"tls.options": "modern@file"}, want: true},
		{name: "unrecognised falls through to the sub-settings",
			fields: map[string]string{"tls": "maybe", "tls.certresolver": "le"}, want: true},
		{name: "unrecognised with nothing else is not TLS",
			fields: map[string]string{"tls": "maybe"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routerTLS(tc.fields); got != tc.want {
				t.Errorf("routerTLS(%v) = %v, want %v", tc.fields, got, tc.want)
			}
		})
	}
}

func TestTraefikEnableFalseWithholdsRouters(t *testing.T) {
	routes, notes := Traefik(map[string]string{
		"traefik.enable":              "false",
		"traefik.http.routers.a.rule": "Host(`a.example.com`)",
		"traefik.http.routers.b.rule": "Host(`b.example.com`)",
		"traefik.http.routers.b.tls":  "true",
	}, "traefik")
	if len(routes) != 0 {
		t.Fatalf("routes = %+v, want none: the proxy serves nothing here", routes)
	}
	// The labels are still in the compose file, so a reader who greps for them needs to be
	// told why they produced no route.
	if len(notes) != 1 || !strings.Contains(notes[0], "2 routers") ||
		!strings.Contains(notes[0], "traefik.enable") {
		t.Fatalf("notes = %q", notes)
	}
}

func TestTraefikEnableFalseWithNoRoutersIsSilent(t *testing.T) {
	routes, notes := Traefik(map[string]string{"traefik.enable": "false"}, "traefik")
	if len(routes) != 0 || len(notes) != 0 {
		t.Fatalf("routes = %+v, notes = %q, want nothing to report", routes, notes)
	}
}

func TestTraefikUnrecognisedEnableKeepsRouters(t *testing.T) {
	routes, notes := Traefik(map[string]string{
		"traefik.enable":              "maybe",
		"traefik.http.routers.a.rule": "Host(`a.example.com`)",
	}, "traefik")
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want the router reported as declared", len(routes))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "neither true nor false") {
		t.Fatalf("notes = %q", notes)
	}
}

func TestTraefikServicePortResolution(t *testing.T) {
	for _, tc := range []struct {
		name string
		lbls map[string]string
		want string
	}{
		{name: "the one declared port belongs to the one router", want: "8080", lbls: map[string]string{
			"traefik.http.routers.only.rule":                               "Host(`a.example.com`)",
			"traefik.http.services.somethingelse.loadbalancer.server.port": "8080",
		}},
		{name: "a service name matching the router", want: "9000", lbls: map[string]string{
			"traefik.http.routers.app.rule":                        "Host(`a.example.com`)",
			"traefik.http.routers.app.service":                     "app",
			"traefik.http.services.app.loadbalancer.server.port":   "9000",
			"traefik.http.services.other.loadbalancer.server.port": "1234",
		}},
		{name: "the reference's provider suffix is stripped", want: "7000", lbls: map[string]string{
			"traefik.http.routers.app.rule":                          "Host(`a.example.com`)",
			"traefik.http.routers.app.service":                       "backend@docker",
			"traefik.http.services.backend.loadbalancer.server.port": "7000",
			"traefik.http.services.decoy.loadbalancer.server.port":   "1234",
		}},
		{name: "two ports and nothing naming one leaves it unstated", want: "", lbls: map[string]string{
			"traefik.http.routers.app.rule":                      "Host(`a.example.com`)",
			"traefik.http.services.one.loadbalancer.server.port": "1",
			"traefik.http.services.two.loadbalancer.server.port": "2",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, _ := Traefik(tc.lbls, "traefik")
			if len(routes) != 1 {
				t.Fatalf("routes = %d", len(routes))
			}
			if routes[0].ServicePort != tc.want {
				t.Errorf("servicePort = %q, want %q", routes[0].ServicePort, tc.want)
			}
		})
	}
}

// Routers come out sorted by name so that two runs over one compose file produce the same
// bytes (I7). Compose hands labels over as a mapping, so there is no document order to keep.
func TestTraefikRoutersAreSortedByName(t *testing.T) {
	routes, _ := Traefik(map[string]string{
		"traefik.http.routers.zulu.rule":  "Host(`z.example.com`)",
		"traefik.http.routers.alpha.rule": "Host(`a.example.com`)",
		"traefik.http.routers.mike.rule":  "Host(`m.example.com`)",
	}, "traefik")
	var got []string
	for _, r := range routes {
		got = append(got, r.Router)
	}
	if strings.Join(got, ",") != "alpha,mike,zulu" {
		t.Errorf("routers = %q", got)
	}
}

// A router with no rule is still a router: reporting it is how a reader finds the labels that
// were meant to publish something and do not. §4.1 is what withholds the `traefik` ingress
// kind from it, not this reader.
func TestTraefikRouterWithoutRuleIsStillReported(t *testing.T) {
	routes, notes := Traefik(map[string]string{
		"traefik.http.routers.broken.entrypoints": "websecure",
	}, "traefik")
	if len(routes) != 1 || routes[0].Router != "broken" {
		t.Fatalf("routes = %+v", routes)
	}
	if len(routes[0].Hosts) != 0 || routes[0].Rule != "" {
		t.Errorf("route invented ingress evidence: %+v", routes[0])
	}
	if len(notes) != 0 {
		t.Errorf("notes = %q", notes)
	}
}

// Only the HTTP router vocabulary is read. A TCP router is a different section of Traefik's
// configuration and §4.1's evidence for a `traefik` ingress is an HTTP route.
func TestTraefikIgnoresNonHTTPAndForeignPrefixes(t *testing.T) {
	routes, notes := Traefik(map[string]string{
		"traefik.tcp.routers.db.rule":     "HostSNI(`*`)",
		"traefik.udp.routers.dns.service": "dns",
		"traefikish.http.routers.x.rule":  "Host(`x.example.com`)",
		"dockflare.hostname":              "y.example.com",
	}, "traefik")
	if len(routes) != 0 || len(notes) != 0 {
		t.Fatalf("routes = %+v, notes = %q, want nothing", routes, notes)
	}
}

// Both tools read their own labels case-insensitively, so a compose file spelling them in
// camel case declares the same routers. Router *names* keep their case; they are identifiers.
func TestTraefikKeysAreCaseInsensitive(t *testing.T) {
	routes, _ := Traefik(map[string]string{
		"Traefik.HTTP.Routers.Web.Rule":        "Host(`a.example.com`)",
		"Traefik.HTTP.Routers.Web.EntryPoints": "websecure",
		"Traefik.HTTP.Routers.Web.TLS":         "true",
	}, "traefik")
	if len(routes) != 1 {
		t.Fatalf("routes = %d", len(routes))
	}
	if routes[0].Router != "Web" {
		t.Errorf("router = %q, want the name's case kept", routes[0].Router)
	}
	if len(routes[0].Hosts) != 1 || !routes[0].TLS || len(routes[0].Entrypoints) != 1 {
		t.Errorf("route = %+v, want every field read", routes[0])
	}
}
