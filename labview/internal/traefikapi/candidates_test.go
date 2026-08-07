package traefikapi

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// candidateFleet holds one service per discovery signal, plus one identified by nothing.
func candidateFleet() []payload.AppStack {
	return []payload.AppStack{{
		ID: "apps", Name: "apps",
		Services: []payload.Service{
			{
				// Signal 1: the operator's own statement that this container serves the API.
				Name: "edge", ContainerName: "traefik", Image: "traefik:v3.1",
				Ports: []payload.PortMapping{{Published: "80", Target: "80"}, {Published: "443", Target: "443"}},
				Traefik: []payload.TraefikRoute{
					{Router: "dashboard", Service: internalAPIService, Hosts: []string{"edge.example.com"}},
					{Router: "grafana", Hosts: []string{"grafana.example.com"}},
				},
			},
			{
				// Signal 2: something else's tunnel origin resolved here. Observed without
				// consulting any image or name (§9).
				Name: "gateway", ContainerName: "gateway",
				Cloudflare: []payload.CloudflareRoute{{Hostname: "gw.example.com", Service: "http://gateway:80"}},
			},
			{
				// Signal 3: the vendor's own name for the software.
				Name: "proxy2", ContainerName: "proxy2", Image: "docker.io/library/traefik:v3.0",
				Ports: []payload.PortMapping{{Published: "8081", Target: "9000"}},
			},
			{Name: "wiki-web", ContainerName: "wiki-web", Image: "wiki:1"},
		},
	}}
}

// urls is the candidate addresses in the order discovery would try them.
func urls(in []Candidate) []string {
	var out []string
	for _, c := range in {
		out = append(out, c.URL)
	}
	return out
}

func candidateAt(t *testing.T, in []Candidate, url string) Candidate {
	t.Helper()
	for _, c := range in {
		if c.URL == url {
			return c
		}
	}
	t.Fatalf("no candidate for %q; got %#v", url, urls(in))
	return Candidate{}
}

// ---------------------------------------------------------------------------
// The ownership rule
// ---------------------------------------------------------------------------

// TestOnlyAServiceWhoseOwnLabelsDeclareTheAPIMayBeOfferedACredential is §12's hardest constraint on
// discovery.
//
// An address that merely *looks* like a proxy — because something's tunnel origin resolved to it, or
// because it runs the image — must never receive a credential. Both of those are inferences about
// somebody else's container, and a basic-auth header sent to one would hand the operator's proxy
// password to whatever is actually listening there.
func TestOnlyAServiceWhoseOwnLabelsDeclareTheAPIMayBeOfferedACredential(t *testing.T) {
	got := Candidates(candidateFleet(), map[string]bool{"apps/gateway": true})

	for _, tc := range []struct {
		url       string
		wantOwned bool
		wantWhy   string
	}{
		{"http://traefik:80", true, "declares a router whose service is `api@internal`"},
		{"https://edge.example.com", true, "declares a router whose service is `api@internal`"},
		{"http://gateway:8080", false, "is where another service's tunnel origin resolved"},
		{"http://proxy2:9000", false, "runs the image `docker.io/library/traefik:v3.0`"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			c := candidateAt(t, got, tc.url)
			if c.Owned != tc.wantOwned {
				t.Fatalf("Owned = %v, want %v: a credential may go only where ownership was proved (§12)",
					c.Owned, tc.wantOwned)
			}
			if !strings.Contains(c.Why, tc.wantWhy) {
				t.Fatalf("Why = %q, want it to contain %q", c.Why, tc.wantWhy)
			}
			if c.Key == "" {
				t.Fatal("a candidate with no service key cannot make the endpoint that answered attributable")
			}
		})
	}

	t.Run("a service no signal identifies is not a candidate", func(t *testing.T) {
		for _, c := range got {
			if c.Key == "apps/wiki-web" {
				t.Fatalf("wiki-web became a candidate: %#v", c)
			}
		}
	})
}

// TestTheStrongestSignalWins pins the order of the three signals.
//
// A service can carry all three at once. Only the declared `api@internal` router is the operator
// stating the fact, so it has to survive the presence of the two weaker ones — a service that also
// runs the image must not lose the credential it is entitled to.
func TestTheStrongestSignalWins(t *testing.T) {
	owned, why := signal("apps/edge", payload.Service{
		Name: "edge", Image: "traefik:v3.1",
		Traefik: []payload.TraefikRoute{{Router: "dashboard", Service: "API@Internal"}},
	}, map[string]bool{"apps/edge": true})

	if !owned {
		t.Fatal("a service declaring api@internal lost ownership to a weaker signal")
	}
	if !strings.Contains(why, internalAPIService) {
		t.Fatalf("Why = %q, want the declaration named", why)
	}
}

// TestAnOwnedServiceOffersOnlyTheAPIsOwnHostnames narrows where a credential may follow.
//
// Another router on the same container answers some application, and a credential sent to that
// hostname would go to whatever that application is. So for an owned service the public candidates
// are the `api@internal` router's own hosts and nothing else.
func TestAnOwnedServiceOffersOnlyTheAPIsOwnHostnames(t *testing.T) {
	got := Candidates(candidateFleet(), nil)
	for _, c := range got {
		if c.URL == "https://grafana.example.com" {
			t.Fatal("a hostname served by a different router on the same container was offered as the API")
		}
	}
	if c := candidateAt(t, got, "https://edge.example.com"); !c.Owned {
		t.Fatal("the api@internal router's own hostname is the one address ownership extends to")
	}
}

// ---------------------------------------------------------------------------
// Order and bounds
// ---------------------------------------------------------------------------

// TestInternalAddressesAreTriedBeforePublicHostnames is §11's precedent applied here: the public
// hostname of a proxy dashboard is normally behind the gate the proxy itself applies, so probing it
// first would report a reachable proxy as challenged.
func TestInternalAddressesAreTriedBeforePublicHostnames(t *testing.T) {
	got := Candidates(candidateFleet(), map[string]bool{"apps/gateway": true})

	seenPublic := false
	for _, c := range got {
		if !c.Internal {
			seenPublic = true
			continue
		}
		if seenPublic {
			t.Fatalf("internal address %q came after a public hostname:\n  %#v", c.URL, urls(got))
		}
	}
	if !seenPublic {
		t.Fatal("no public hostname was offered at all")
	}
}

// TestDeclaredPortsComeFirstAndTheAPIPortIsAppendedRatherThanSubstituted is mechanism from the
// vendor's documentation held apart from a guess about an operator (I2, I3).
//
// A declared target port is evidence about this container, so an operator who moved the API is
// followed first. 8080 is evidence about Traefik and is appended rather than substituted, because a
// proxy publishing only 80 and 443 — the ordinary arrangement — declares no port its API is on.
func TestDeclaredPortsComeFirstAndTheAPIPortIsAppendedRatherThanSubstituted(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  payload.Service
		want []string
	}{
		{"nothing declared", payload.Service{}, []string{apiPort}},
		{
			"the ordinary proxy, which declares nothing about its API",
			payload.Service{Ports: []payload.PortMapping{
				{Published: "80", Target: "80"}, {Published: "443", Target: "443"}}},
			[]string{"80", "443", apiPort},
		},
		{
			"an operator who moved the API says so first",
			payload.Service{Ports: []payload.PortMapping{{Published: "8081", Target: "9000"}}},
			[]string{"9000", apiPort},
		},
		{
			"the Engine's own publications count too",
			payload.Service{Docker: &payload.DockerState{
				PublishedPorts: []payload.PortMapping{{Published: "9999", Target: "9999"}}}},
			[]string{"9999", apiPort},
		},
		{
			"one service declaring many ports cannot fill the whole attempt list",
			payload.Service{Ports: []payload.PortMapping{
				{Target: "1"}, {Target: "2"}, {Target: "3"}, {Target: "4"}, {Target: "5"}}},
			[]string{"1", "2", "3"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiPorts(tc.svc); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("apiPorts() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestTheCandidateCapIsTheAttemptCap keeps one number in one place (I8).
//
// A reader who sees eight attempts and a scan that tried twelve addresses would be reading a list
// that is not the list, and the four missing ones are exactly the ones a diagnosis needs.
func TestTheCandidateCapIsTheAttemptCap(t *testing.T) {
	if MaxCandidates != transport.AttemptCap {
		t.Fatalf("MaxCandidates = %d, transport.AttemptCap = %d — the number a reader sees and the "+
			"number tried must be one number", MaxCandidates, transport.AttemptCap)
	}
}

// TestTheTraefikImageIsMatchedOnTheRepositorySegment keeps the weakest signal from firing on a name
// that merely contains the word.
//
// A tag such as `:traefik-v3` on an unrelated image is not a statement about what the image is, and
// matching the whole reference would read it as one — putting an ordinary application on the
// discovery list and probing it.
func TestTheTraefikImageIsMatchedOnTheRepositorySegment(t *testing.T) {
	for _, tc := range []struct {
		image string
		want  bool
	}{
		{"traefik", true},
		{"traefik:v3.1", true},
		{"docker.io/library/traefik:v3.0", true},
		{"ghcr.io/example/traefik@sha256:abc123", true},
		{"TRAEFIK:latest", true},
		{"myapp:traefik-v3", false},
		{"traefikish", false},
		{"registry.example.com/traefik-plugin:1", false},
		{"", false},
	} {
		t.Run(tc.image, func(t *testing.T) {
			if got := runsTraefikImage(payload.Service{Image: tc.image}); got != tc.want {
				t.Fatalf("runsTraefikImage(%q) = %v, want %v", tc.image, got, tc.want)
			}
		})
	}
}
