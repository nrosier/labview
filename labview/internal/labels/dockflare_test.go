package labels

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

func TestCloudflareFlatRoute(t *testing.T) {
	routes, notes := Cloudflare(map[string]string{
		"dockflare.enable":         "true",
		"dockflare.hostname":       "media.example.com",
		"dockflare.service":        "http://192.0.2.10:8096",
		"dockflare.path":           "/watch",
		"dockflare.access.policy":  "authenticate",
		"dockflare.access.group":   "media-users",
		"dockflare.access.emails":  "one@example.com, two@example.com",
		"dockflare.no_tls_verify":  "false",
		"dockflare.http2_origin":   "true",
		"unrelated.label":          "ignored",
		"dockflarelookalike.thing": "ignored",
	}, "dockflare")

	if len(notes) != 0 {
		t.Fatalf("notes = %q, want none", notes)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	r := routes[0]
	if r.Hostname != "media.example.com" || r.Service != "http://192.0.2.10:8096" || r.Path != "/watch" {
		t.Errorf("route = %+v", r)
	}
	if r.Access == nil || r.Access.Policy != "authenticate" || r.Access.Group != "media-users" {
		t.Fatalf("access = %+v", r.Access)
	}
	if got := r.Access.Emails; len(got) != 2 || got[0] != "one@example.com" || got[1] != "two@example.com" {
		t.Errorf("emails = %q", got)
	}
	if r.NoTLSVerify == nil || *r.NoTLSVerify {
		t.Errorf("noTlsVerify = %v, want a pointer to false", r.NoTLSVerify)
	}
	// Every dockflare label is retained, including the two this reader has no field for —
	// that is what keeps `http2_origin` answerable without inventing a payload field.
	if len(r.Raw) != 9 {
		t.Errorf("raw = %d entries, want 9: %v", len(r.Raw), r.Raw)
	}
	if r.Raw["dockflare.http2_origin"] != "true" {
		t.Errorf("raw dropped http2_origin: %v", r.Raw)
	}
	if _, unexpected := r.Raw["unrelated.label"]; unexpected {
		t.Errorf("raw took a label from another vocabulary: %v", r.Raw)
	}
}

func TestCloudflareEnableFlag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		enable string
		want   int
		note   string
	}{
		{name: "false suppresses the staged route", enable: "false", want: 0},
		{name: "off suppresses too", enable: "off", want: 0},
		{name: "capitalised truthy is enabled", enable: "TRUE", want: 1},
		{name: "one is enabled", enable: "1", want: 1},
		{name: "unrecognised keeps the route and says so", enable: "maybe", want: 1,
			note: "neither true nor false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, notes := Cloudflare(map[string]string{
				"dockflare.enable":   tc.enable,
				"dockflare.hostname": "staged.example.com",
				"dockflare.service":  "http://app:8080",
			}, "dockflare")
			if len(routes) != tc.want {
				t.Fatalf("routes = %d, want %d", len(routes), tc.want)
			}
			switch {
			case tc.note == "" && len(notes) != 0:
				t.Fatalf("notes = %q, want none", notes)
			case tc.note != "" && (len(notes) != 1 || !strings.Contains(notes[0], tc.note)):
				t.Fatalf("notes = %q, want one containing %q", notes, tc.note)
			}
		})
	}
}

func TestCloudflareIndexedRoutes(t *testing.T) {
	routes, notes := Cloudflare(map[string]string{
		// A top-level flag governs every indexed route that carries none of its own.
		"dockflare.enable":     "true",
		"dockflare.0.hostname": "first.example.com",
		"dockflare.0.service":  "http://app:8080",
		"dockflare.1.hostname": "second.example.com",
		"dockflare.1.enable":   "false",
		"dockflare.2.hostname": "third.example.com",
		"dockflare.10.service": "http://app:8080",
	}, "dockflare")

	var got []string
	for _, r := range routes {
		got = append(got, r.Hostname)
	}
	want := []string{"first.example.com", "third.example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("hostnames = %q, want %q", got, want)
	}
	// The flat group holds nothing but the governing flag, so it is not a route with a
	// missing hostname. Index 10 is.
	if len(notes) != 1 || !strings.Contains(notes[0], "at index 10") ||
		!strings.Contains(notes[0], "no hostname") {
		t.Fatalf("notes = %q, want one about index 10 having no hostname", notes)
	}
}

func TestCloudflareNoHostnameIsNoRoute(t *testing.T) {
	routes, notes := Cloudflare(map[string]string{
		"dockflare.enable":  "true",
		"dockflare.service": "http://app:8080",
	}, "dockflare")
	if len(routes) != 0 {
		t.Fatalf("routes = %+v, want none", routes)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "no hostname") {
		t.Fatalf("notes = %q", notes)
	}
}

func TestCloudflareRenamedPrefix(t *testing.T) {
	routes, _ := Cloudflare(map[string]string{
		"tunnel.enable":   "true",
		"tunnel.hostname": "renamed.example.com",
	}, "tunnel")
	if len(routes) != 1 || routes[0].Hostname != "renamed.example.com" {
		t.Fatalf("routes = %+v", routes)
	}
}

func TestCloudflareNoLabelsNoRoutes(t *testing.T) {
	routes, notes := Cloudflare(map[string]string{"traefik.enable": "true"}, "dockflare")
	if routes != nil || notes != nil {
		t.Fatalf("routes = %+v, notes = %q, want nothing", routes, notes)
	}
}

// A route with no access labels carries no access object at all, because absence is the fact
// (§16): an empty policy object would read as a policy that permits everyone.
func TestCloudflareAccessAbsentRatherThanEmpty(t *testing.T) {
	routes, _ := Cloudflare(map[string]string{
		"dockflare.enable":   "true",
		"dockflare.hostname": "open.example.com",
	}, "dockflare")
	if len(routes) != 1 {
		t.Fatalf("routes = %d", len(routes))
	}
	if routes[0].Access != nil {
		t.Errorf("access = %+v, want nil", routes[0].Access)
	}
	if routes[0].NoTLSVerify != nil {
		t.Errorf("noTlsVerify = %v, want nil", *routes[0].NoTLSVerify)
	}
}

func TestCloudflareRoutesAreValidPayload(t *testing.T) {
	routes, _ := Cloudflare(map[string]string{
		"dockflare.enable":   "true",
		"dockflare.hostname": "one.example.com",
	}, "dockflare")
	svc := payload.Service{Cloudflare: routes}
	payload.Normalize(&svc)
	if svc.Cloudflare[0].Raw == nil {
		t.Error("raw must never be null in the payload")
	}
}
