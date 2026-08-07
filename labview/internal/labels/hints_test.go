package labels

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// The two traps of §7, stated as tests.
//
// Both are substring matches that a naive reader makes and that would each attach the wrong
// provider to a real mechanism. They are the reason hints match at token boundaries.
func TestHintsDoNotMatchSubstrings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hints  []string
		target string
		want   string // the hint that must match, or "" for no match
	}{
		{name: "trap: auth inside oauth", hints: []string{"auth", "authentik"},
			target: "https://oauth.bigcorp.example.com/realms/main"},
		{name: "trap: auth inside an oauth2-proxy endpoint", hints: []string{"auth", "authentik"},
			target: "http://gatekeeper:4180/oauth2/auth"},
		{name: "trap: server inside another server's address", hints: []string{"authentik-server"},
			target: "ldap://ldap-server.internal:389"},
		{name: "the real thing still matches", hints: []string{"authentik"},
			target: "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
			want:   "authentik"},
		{name: "a two-token hint matches contiguously", hints: []string{"authentik-server"},
			target: "ldap://authentik-server.example.com:389", want: "authentik-server"},
		{name: "a two-token hint does not match out of order",
			hints: []string{"authentik-server"}, target: "http://server.authentik.example.com/"},
		{name: "the endpoint mark matches its own path segment",
			hints:  []string{"goauthentik.io"},
			target: "http://sso:9000/outpost.goauthentik.io/auth/traefik", want: "goauthentik.io"},
		{name: "a hostname hint matches a hostname", hints: []string{"sso.example.com"},
			target: "https://sso.example.com/application/o/authorize/", want: "sso.example.com"},
		{name: "a hostname hint does not match a different host",
			hints: []string{"sso.example.com"}, target: "https://sso.example.org/"},
		{name: "the longest matching hint is the one reported",
			hints:  []string{"authentik", "authentik-server"},
			target: "http://authentik-server:9000/", want: "authentik-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, matched := NewHints(tc.hints).Match(tc.target)
			if tc.want == "" {
				if matched {
					t.Fatalf("hint %q matched %q; a bare substring must never match", got, tc.target)
				}
				return
			}
			if !matched || got != tc.want {
				t.Fatalf("Match(%q) = %q, %v; want %q", tc.target, got, matched, tc.want)
			}
		})
	}
}

// A hint must be specific enough that matching it says something. `server` and `worker` are
// what upstream Authentik calls its own compose services, and they appear in half the
// addresses in a fleet — admitting either would make every directory look like Authentik.
func TestSpecificRejectsWeakHints(t *testing.T) {
	for hint, want := range map[string]bool{
		"authentik":        true,
		"authentik-server": true,
		"goauthentik.io":   true,
		"sso.example.com":  true,
		"idp.example.com":  true,
		"ak-outpost":       true,

		"server":     false,
		"worker":     false,
		"auth":       false,
		"sso":        false,
		"idp":        false,
		"app":        false,
		"localhost":  false,
		"127.0.0.1":  false,
		"192.0.2.10": false,
		"":           false,
		"   ":        false,
	} {
		if got := Specific(hint); got != want {
			t.Errorf("Specific(%q) = %v, want %v", hint, got, want)
		}
	}
}

func TestNewHintsFiltersDedupsAndOrders(t *testing.T) {
	h := NewHints(
		[]string{"authentik", "server", "authentik", ""},
		[]string{"goauthentik.io", "worker", "sso.example.com"},
	)
	if got := strings.Join(h.Values(), ","); got != "authentik,goauthentik.io,sso.example.com" {
		t.Errorf("values = %q", got)
	}
	if h.Empty() {
		t.Error("Empty reported true with three hints")
	}
	if !NewHints([]string{"server", "worker"}).Empty() {
		t.Error("a set of nothing but rejected hints must be empty")
	}
}

func TestTokens(t *testing.T) {
	for in, want := range map[string]string{
		"http://authentik-server:9000/outpost.goauthentik.io/auth": "http,authentik,server,9000,outpost,goauthentik,io,auth",
		"oauth.bigcorp.example.com":                                "oauth,bigcorp,example,com",
		"http://gatekeeper:4180/oauth2/auth":                       "http,gatekeeper,4180,oauth2,auth",
		"AUTHENTIK_HOST":                                           "authentik,host",
		"":                                                         "",
	} {
		if got := strings.Join(Tokens(in), ","); got != want {
			t.Errorf("Tokens(%q) = %q, want %q", in, got, want)
		}
	}
}

// Discover finds a provider or reports none. It cannot invent one: a fleet with no Authentik
// yields no hints, and then every gate in it is reported by mechanism alone (§7, I3).
func TestDiscoverCannotInventAProvider(t *testing.T) {
	fleet := []payload.AppStack{{ID: "other", Services: []payload.Service{{
		Name:          "gatekeeper",
		ContainerName: "oauth2-proxy",
		Image:         "quay.io/oauth2-proxy/oauth2-proxy:v7",
		Labels: map[string]string{
			"traefik.http.middlewares.oauth2.forwardauth.address": "http://gatekeeper:4180/oauth2/auth",
		},
		Traefik: []payload.TraefikRoute{{Router: "sso", Hosts: []string{"sso.bigcorp.example.com"}}},
	}}}}
	got := Discover(fleet, NewRegistry(fleet, "traefik"))
	if len(got) != 0 {
		t.Fatalf("hints = %q, want none: nothing in this fleet is Authentik", got)
	}
}

func TestDiscoverFromImageAndAddress(t *testing.T) {
	fleet := []payload.AppStack{
		{ID: "idp", Services: []payload.Service{{
			// Upstream calls this service `server`; the container name is the identifier a
			// hint can be built from, and the compose service name is never used.
			Name:          "server",
			ContainerName: "authentik-server",
			Image:         "ghcr.io/goauthentik/server:2024.10",
			Traefik: []payload.TraefikRoute{{
				Router: "authentik",
				Hosts:  []string{"sso.example.com", "authentik.example.com"},
			}},
			Cloudflare: []payload.CloudflareRoute{{Hostname: "login.example.com"}},
		}}},
		{ID: "outpost", Services: []payload.Service{{
			// Identifiably Authentik through the outpost endpoint its labels define, with
			// nothing saying `authentik` in an image pulled from a private mirror.
			Name:          "proxy",
			ContainerName: "ak-outpost",
			Image:         "registry.example.com/mirror/ak-proxy:2024.10",
			Labels: map[string]string{
				"traefik.http.middlewares.gate.forwardauth.address": "http://ak-outpost:9000/outpost.goauthentik.io/auth/traefik",
			},
		}}},
		{ID: "media", Services: []payload.Service{{
			Name: "jellyfin", ContainerName: "jellyfin", Image: "jellyfin/jellyfin:10.9",
			Traefik: []payload.TraefikRoute{{Router: "jellyfin", Hosts: []string{"media.example.com"}}},
		}}},
	}
	got := NewHints(Discover(fleet, NewRegistry(fleet, "traefik"))).Values()
	want := "ak-outpost,authentik-server,authentik.example.com,login.example.com,sso.example.com"
	if strings.Join(got, ",") != want {
		t.Fatalf("hints = %q, want %q", got, want)
	}
	// `server` was the compose service name of the Authentik service and must not be a hint;
	// nothing belonging to the unrelated media service may be either.
	for _, forbidden := range []string{"server", "jellyfin", "media.example.com"} {
		for _, h := range got {
			if h == forbidden {
				t.Errorf("hint %q was adopted", forbidden)
			}
		}
	}
}

// Discovery is fleet-wide and order-independent: the same tree scanned twice yields the same
// hints (I7).
func TestDiscoverIsStable(t *testing.T) {
	fleet := []payload.AppStack{
		{ID: "b", Services: []payload.Service{{Name: "worker", ContainerName: "authentik-worker",
			Image: "ghcr.io/goauthentik/server:2024.10"}}},
		{ID: "a", Services: []payload.Service{{Name: "server", ContainerName: "authentik-server",
			Image: "ghcr.io/goauthentik/server:2024.10"}}},
	}
	first := strings.Join(NewHints(Discover(fleet, NewRegistry(fleet, "traefik"))).Values(), ",")
	second := strings.Join(NewHints(Discover(fleet, NewRegistry(fleet, "traefik"))).Values(), ",")
	if first != second || first != "authentik-server,authentik-worker" {
		t.Errorf("hints = %q then %q", first, second)
	}
}
