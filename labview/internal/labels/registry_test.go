package labels

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// stacks is a fleet of one service per stack, built from label maps, for the registry tests.
func stacks(t *testing.T, entries ...[3]string) []payload.AppStack {
	t.Helper()
	var out []payload.AppStack
	for _, e := range entries {
		lbls := map[string]string{}
		for _, line := range strings.Split(e[2], "\n") {
			if line = strings.TrimSpace(line); line != "" {
				k, v, _ := strings.Cut(line, "=")
				lbls[k] = v
			}
		}
		out = append(out, payload.AppStack{
			ID:       e[0],
			Services: []payload.Service{{Name: e[1], Labels: lbls}},
		})
	}
	return out
}

func TestRegistryReadsDefinitions(t *testing.T) {
	reg := NewRegistry(stacks(t, [3]string{"idp", "server", `
		traefik.http.middlewares.authentik.forwardauth.address=http://authentik-server:9000/outpost.goauthentik.io/auth/traefik
		traefik.http.middlewares.authentik.forwardauth.trustForwardHeader=true
		traefik.http.middlewares.dash.basicauth.users=admin:$2y$05$notarealhashatall
		traefik.http.middlewares.secured.chain.middlewares=compress@file,authentik@docker
		traefik.http.middlewares.compress.compress=true
	`}), "traefik")

	if reg.Len() != 4 {
		t.Fatalf("registry holds %d definitions (%q), want 4", reg.Len(), reg.Names())
	}
	def, ok := reg.Lookup("authentik@docker")
	if !ok {
		t.Fatal("authentik@docker did not resolve; a reference's provider suffix must be stripped")
	}
	if def.Type != "forwardauth" {
		t.Errorf("type = %q", def.Type)
	}
	if def.Fields["address"] == "" || def.Fields["trustforwardheader"] != "true" {
		t.Errorf("fields = %v, want the sub-keys lower-cased", def.Fields)
	}
	if def.Where() != "idp/server" {
		t.Errorf("where = %q, want the location evidence needs", def.Where())
	}
	// A middleware whose whole definition is one value — `…middlewares.compress.compress=true`
	// — has still been found, which is what keeps it off the name-guessing path.
	if def, ok := reg.Lookup("compress"); !ok || def.Type != "compress" {
		t.Errorf("compress = %+v, %v; a field-less definition must still count as found", def, ok)
	}
	if got := strings.Join(reg.Names(), ","); got != "authentik,compress,dash,secured" {
		t.Errorf("names = %q, want them sorted", got)
	}
}

// An auth type wins a cross-stack name collision in either scan order. The failure this
// prevents is silent and one-directional: a `headers` middleware shadowing a `forwardauth`
// of the same name would remove a gate from the report and leave a service looking open.
func TestRegistryAuthTypeWinsCollision(t *testing.T) {
	gate := [3]string{"idp", "server",
		"traefik.http.middlewares.gate.forwardauth.address=http://authentik-server:9000/outpost.goauthentik.io/auth"}
	headers := [3]string{"apps", "web",
		"traefik.http.middlewares.gate.headers.customrequestheaders.x-forwarded-proto=https"}

	for _, tc := range []struct {
		name  string
		fleet []payload.AppStack
	}{
		{name: "gate defined first", fleet: stacks(t, gate, headers)},
		{name: "headers defined first", fleet: stacks(t, headers, gate)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			def, ok := NewRegistry(tc.fleet, "traefik").Lookup("gate@file")
			if !ok {
				t.Fatal("gate did not resolve")
			}
			if def.Type != "forwardauth" || def.Where() != "idp/server" {
				t.Errorf("def = %+v, want the forwardauth from idp/server", def)
			}
		})
	}
}

// Between two definitions of a kind the first in scan order stands, so the registry two runs
// over one tree build is the same registry (I7).
func TestRegistryFirstOfAKindStands(t *testing.T) {
	fleet := stacks(t,
		[3]string{"a", "one", "traefik.http.middlewares.gate.forwardauth.address=http://first:9000/auth"},
		[3]string{"b", "two", "traefik.http.middlewares.gate.forwardauth.address=http://second:9000/auth"},
	)
	def, _ := NewRegistry(fleet, "traefik").Lookup("gate")
	if !strings.Contains(def.Fields["address"], "first") {
		t.Errorf("address = %q, want the first definition in scan order", def.Fields["address"])
	}
}

// The registry is fleet-wide because a reference names a middleware another stack defines.
// Scoping it per stack would push every cross-stack gate onto the name-guessing path.
func TestRegistryIsFleetWide(t *testing.T) {
	fleet := stacks(t,
		[3]string{"idp", "server",
			"traefik.http.middlewares.authentik.forwardauth.address=http://authentik-server:9000/outpost.goauthentik.io/auth"},
		[3]string{"media", "jellyfin", "traefik.http.routers.jellyfin.middlewares=authentik@docker"},
	)
	if _, ok := NewRegistry(fleet, "traefik").Lookup("authentik@docker"); !ok {
		t.Error("a middleware defined in another stack must resolve")
	}
}

func TestRegistryServicesDefiningAddress(t *testing.T) {
	fleet := stacks(t,
		[3]string{"idp", "server",
			"traefik.http.middlewares.ak.forwardauth.address=http://authentik-server:9000/outpost.goauthentik.io/auth/traefik"},
		[3]string{"other", "gatekeeper",
			"traefik.http.middlewares.oauth2.forwardauth.address=http://gatekeeper:4180/oauth2/auth"},
	)
	got := NewRegistry(fleet, "traefik").ServicesDefiningAddress("goauthentik.io")
	if len(got) != 1 || !got["idp/server"] {
		t.Errorf("services = %v, want only idp/server", got)
	}
}

func TestBareName(t *testing.T) {
	for in, want := range map[string]string{
		"authentik@docker": "authentik",
		"authentik@file":   "authentik",
		"authentik":        "authentik",
		" spaced@file ":    "spaced",
		"@file":            "",
		"":                 "",
	} {
		if got := BareName(in); got != want {
			t.Errorf("BareName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsAuthType(t *testing.T) {
	for kind, want := range map[string]bool{
		"forwardauth": true, "basicauth": true, "digestauth": true, "ForwardAuth": true,
		"headers": false, "compress": false, "chain": false, "ratelimit": false,
		"redirectscheme": false, "stripprefix": false, "": false,
	} {
		if got := isAuthType(kind); got != want {
			t.Errorf("isAuthType(%q) = %v, want %v", kind, got, want)
		}
	}
}
