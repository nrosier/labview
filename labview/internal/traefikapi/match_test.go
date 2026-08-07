package traefikapi

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// The fleet the rules run against
// ---------------------------------------------------------------------------

// matchFleet is a scanned fleet with one of each case the three rules turn on:
//
//   - `edge` serves the proxy API itself,
//   - `wiki-web` holds a container IP **and** `grafana` publishes the host port that appears in
//     wiki-web's backend URL, which is the trap rule 1 must not fall into,
//   - `docs` is addressable by container name,
//   - `portal-a` and `portal-b` both declare `portal.example.com`, which is a tie no rule may break.
func matchFleet(withDocker bool) []payload.AppStack {
	wiki := payload.Service{
		Name: "wiki-web", ContainerName: "wiki-web",
		Traefik: []payload.TraefikRoute{{Router: "wiki-web", Hosts: []string{"wiki.example.com"}}},
	}
	if withDocker {
		wiki.Docker = &payload.DockerState{
			Name: "wiki-web", Running: true,
			IPAddresses: map[string]string{"proxy": "172.18.0.4"},
		}
	}

	return []payload.AppStack{{
		ID: "apps", Name: "apps",
		Services: []payload.Service{
			{
				Name: "edge", ContainerName: "traefik", Image: "traefik:v3.1",
				Ports: []payload.PortMapping{{Published: "80", Target: "80"}, {Published: "443", Target: "443"}},
				Traefik: []payload.TraefikRoute{{
					Router: "dashboard", Service: internalAPIService,
					Hosts: []string{"edge.example.com"},
				}},
			},
			wiki,
			{
				// The trap's other half: this service publishes host port 3000, which is the port in
				// wiki-web's container-address backend.
				Name: "grafana", ContainerName: "grafana",
				Ports: []payload.PortMapping{{Published: "3000", Target: "3000"}},
			},
			{Name: "docs", ContainerName: "docs",
				Traefik: []payload.TraefikRoute{{Router: "docs", Hosts: []string{"docs.example.com"}}}},
			{Name: "portal-a", ContainerName: "portal-a",
				Traefik: []payload.TraefikRoute{{Router: "portal", Hosts: []string{"portal.example.com"}}}},
			{Name: "portal-b", ContainerName: "portal-b",
				Cloudflare: []payload.CloudflareRoute{{Hostname: "portal.example.com", Service: "http://portal-b:80"}}},
		},
	}}
}

// oneRouter runs the match over a single live router and returns what it was tied to.
func oneRouter(t *testing.T, raw RawRouter, svc map[string]RawService, withDocker bool) (string, payload.UnmatchedRouter, Match) {
	t.Helper()

	if svc == nil {
		svc = map[string]RawService{}
	}
	snap := Snapshot{
		Routers:     []RawRouter{raw},
		Middlewares: map[string]RawMiddleware{},
		Services:    svc,
	}
	m := Apply(snap, fleet.NewIndex(matchFleet(withDocker)))

	for key, routers := range m.ByService {
		if len(routers) > 0 {
			return key, payload.UnmatchedRouter{}, m
		}
	}
	if len(m.Unmatched) != 1 {
		t.Fatalf("router %q was neither matched nor reported unmatched", raw.Name)
	}
	return "", m.Unmatched[0], m
}

// ---------------------------------------------------------------------------
// Rule 1: the backend the proxy holds
// ---------------------------------------------------------------------------

// TestAContainerAddressBackendIsResolvedThroughTheIPTableAndNowhereElse is the `wiki` fixture, and
// the sharpest trap in §12.
//
// A backend of `http://172.18.0.4:3000` is a container address. The generic lookup reads an IP
// literal's port as a *published host port* — right for a tunnel origin, wrong here — so resolving
// through it would land on whichever service publishes 3000 and would do it with full confidence.
// This fleet publishes 3000 on a different service precisely so that the wrong answer is available.
func TestAContainerAddressBackendIsResolvedThroughTheIPTableAndNowhereElse(t *testing.T) {
	// The router's name deliberately matches no label, so rule 1 is the only rule that can answer
	// and the subtests differ in the container-IP table alone.
	raw := RawRouter{Name: "wiki-backend@docker", Provider: "docker", Status: "enabled", Service: "wiki-web"}
	svc := map[string]RawService{
		"wiki-web@docker": {Servers: []payload.TraefikLiveServer{{URL: "http://172.18.0.4:3000"}}},
	}

	t.Run("with the Docker snapshot the IP identifies the container", func(t *testing.T) {
		key, _, m := oneRouter(t, raw, svc, true)
		if key != "apps/wiki-web" {
			t.Fatalf("matched %q, want apps/wiki-web", key)
		}
		evidence := m.ByService[key][0].Evidence
		if len(evidence) == 0 || !strings.Contains(evidence[len(evidence)-1], "172.18.0.4:3000") {
			t.Fatalf("evidence = %#v, want the backend address the proxy named", evidence)
		}
	})

	t.Run("with no Docker state the IP resolves through nothing", func(t *testing.T) {
		key, un, _ := oneRouter(t, raw, svc, false)
		if key == "apps/grafana" {
			t.Fatal("a container address's port was read as a published host port (§9, §12)")
		}
		if key != "" {
			t.Fatalf("matched %q, want no match at all", key)
		}
		if !strings.Contains(strings.Join(un.Considered, " "), "no Docker state") {
			t.Fatalf("considered = %#v, want it to say the container-IP table does not exist", un.Considered)
		}
	})
}

// TestABackendNamedByContainerNameIdentifiesItsService is rule 1's other address form.
//
// A DNS name in a backend URL is compose's own alias for the container, so resolving it is not an
// inference — and it needs no Docker state, which is why the two forms go through two tables.
func TestABackendNamedByContainerNameIdentifiesItsService(t *testing.T) {
	key, _, _ := oneRouter(t, RawRouter{
		Name: "anything@file", Provider: "file", Service: "docs-svc",
	}, map[string]RawService{
		"docs-svc": {Servers: []payload.TraefikLiveServer{{URL: "http://docs:80"}}},
	}, false)

	if key != "apps/docs" {
		t.Fatalf("matched %q, want apps/docs — rule 1 is the proxy naming its own target", key)
	}
}

// TestTwoBackendsResolvingToTwoServicesIsATieNothingBreaks pins that a rule requiring exactly one
// candidate means exactly one.
//
// Picking the first would attribute a router to whichever service the index happened to list first,
// with the same evidence line a correct match produces — a wrong answer that is indistinguishable
// from a right one.
func TestTwoBackendsResolvingToTwoServicesIsATieNothingBreaks(t *testing.T) {
	key, un, _ := oneRouter(t, RawRouter{
		Name: "mirror@file", Provider: "file", Service: "mirror",
	}, map[string]RawService{
		"mirror": {Servers: []payload.TraefikLiveServer{
			{URL: "http://docs:80"}, {URL: "http://grafana:3000"},
		}},
	}, false)

	if key != "" {
		t.Fatalf("matched %q, want no match: two backends resolved to two services", key)
	}
	if un.Reason != payload.UnmatchedAmbiguous {
		t.Fatalf("reason = %q, want %q", un.Reason, payload.UnmatchedAmbiguous)
	}
	if !strings.Contains(un.Detail, "apps/docs") || !strings.Contains(un.Detail, "apps/grafana") {
		t.Fatalf("detail = %q, want both candidates named", un.Detail)
	}
}

// ---------------------------------------------------------------------------
// Rule 2: the router's own name
// ---------------------------------------------------------------------------

// TestARouterNameIsEvidenceOnlyFromTheDockerProvider is the two `twin` fixtures.
//
// Traefik derives a docker-provider router's name from the labels of the very container it found them
// on, so an exact match there is that label round-tripping. A `@file` router's name was typed by hand
// in a file this scan cannot read, so its resembling a label is a coincidence with no evidentiary
// weight — and the two fixtures differ in the provider and nothing else.
func TestARouterNameIsEvidenceOnlyFromTheDockerProvider(t *testing.T) {
	t.Run("@docker, so the name is a label round-tripping", func(t *testing.T) {
		key, _, m := oneRouter(t, RawRouter{Name: "wiki-web@docker", Provider: "docker"}, nil, false)
		if key != "apps/wiki-web" {
			t.Fatalf("matched %q, want apps/wiki-web", key)
		}
		if ev := m.ByService[key][0].Evidence; len(ev) == 0 || !strings.Contains(ev[0], "declare the router") {
			t.Fatalf("evidence = %#v, want it to name the label that matched", ev)
		}
	})

	t.Run("@file, so the name is a coincidence", func(t *testing.T) {
		key, un, _ := oneRouter(t, RawRouter{Name: "wiki-web@file", Provider: "file"}, nil, false)
		if key != "" {
			t.Fatalf("matched %q on a hand-written router name, which carries no evidence (§12)", key)
		}
		considered := strings.Join(un.Considered, " ")
		if !strings.Contains(considered, "`file` provider") {
			t.Fatalf("considered = %#v, want the refusal explained by the provider", un.Considered)
		}
		if un.Reason != payload.UnmatchedNoCandidate {
			t.Fatalf("reason = %q, want %q — a refusal is not an ambiguity", un.Reason, payload.UnmatchedNoCandidate)
		}
	})
}

// ---------------------------------------------------------------------------
// Rule 3: the hosts in the rule
// ---------------------------------------------------------------------------

// TestAHostRuleResolvesThroughTheOneHostnameIndex is rule 3, and the reason §7 exports its rule
// parser.
//
// The hosts a live rule names and the hosts a labelled rule names have to be read the same way: a
// second parser here would be a second answer to "what does this rule match", and the answer is
// resolved through the very index the labels populated.
func TestAHostRuleResolvesThroughTheOneHostnameIndex(t *testing.T) {
	key, _, m := oneRouter(t, RawRouter{
		Name: "hand-written@file", Provider: "file", Rule: "Host(`docs.example.com`) && PathPrefix(`/`)",
	}, nil, false)

	if key != "apps/docs" {
		t.Fatalf("matched %q, want apps/docs", key)
	}
	if ev := m.ByService[key][0].Evidence; len(ev) == 0 || !strings.Contains(ev[0], "docs.example.com") {
		t.Fatalf("evidence = %#v, want the hostname that matched", ev)
	}
}

// TestAHostnameTwoServicesDeclareIsAmbiguous is the `twin` pair's second half.
//
// One hostname declared by a Traefik label on one service and a tunnel route on another is a tie the
// scan cannot see through, and §12 requires it reported as `ambiguous` with both candidates named
// rather than resolved by iteration order.
func TestAHostnameTwoServicesDeclareIsAmbiguous(t *testing.T) {
	key, un, _ := oneRouter(t, RawRouter{
		Name: "portal@file", Provider: "file", Rule: "Host(`portal.example.com`)",
	}, nil, false)

	if key != "" {
		t.Fatalf("matched %q, want no match", key)
	}
	if un.Reason != payload.UnmatchedAmbiguous {
		t.Fatalf("reason = %q, want %q", un.Reason, payload.UnmatchedAmbiguous)
	}
	if !strings.Contains(un.Detail, "apps/portal-a") || !strings.Contains(un.Detail, "apps/portal-b") {
		t.Fatalf("detail = %q, want both declaring services named", un.Detail)
	}
	if len(un.Considered) != 3 {
		t.Fatalf("considered = %#v, want one line per rule tried, in the order tried", un.Considered)
	}
}

// TestEveryRuleThatCouldNotRunStillSaysSo is §11's trace discipline applied here.
//
// A trace with a rule missing reads as a rule that passed, and a reader cannot tell which one was
// skipped. The unmatched router carries the whole live record too, so the reason is answerable
// against the router rather than only stated about it.
func TestEveryRuleThatCouldNotRunStillSaysSo(t *testing.T) {
	_, un, _ := oneRouter(t, RawRouter{Name: "bare@file", Provider: "file"}, nil, false)

	if len(un.Considered) != 3 {
		t.Fatalf("considered = %#v, want three lines: no backend, a non-docker provider, no host", un.Considered)
	}
	if un.Router.Router != "bare@file" {
		t.Fatalf("the unmatched record must carry the whole live router, got %#v", un.Router)
	}
	if un.Detail == "" {
		t.Fatal("an unmatched router with no detail is a reason a reader cannot act on (§22)")
	}
}

// ---------------------------------------------------------------------------
// A labelled router the proxy is not serving
// ---------------------------------------------------------------------------

// TestADeclaredRouterIsAbsentOnlyWhenNoRouterOfThatNameIsLive is the `twin-a` fixture's rule, and it
// is the reason the check runs against the whole snapshot.
//
// A router LabView could not attribute demonstrably *exists*. Comparing against the routers matched
// to this service would report a live route as missing — the one wording that would send an operator
// looking for a fault that is not there.
func TestADeclaredRouterIsAbsentOnlyWhenNoRouterOfThatNameIsLive(t *testing.T) {
	snap := Snapshot{
		Routers: []RawRouter{
			// Matched to nobody: the name is `@file` and the host is contested.
			{Name: "portal@file", Provider: "file", Rule: "Host(`portal.example.com`)"},
			{Name: "docs@docker", Provider: "docker", Rule: "Host(`docs.example.com`)"},
		},
		Middlewares: map[string]RawMiddleware{},
		Services:    map[string]RawService{},
	}
	m := Apply(snap, fleet.NewIndex(matchFleet(false)))

	for _, tc := range []struct {
		name string
		svc  payload.Service
		want []string
	}{
		{
			name: "a router that is live but attributed to nobody is not absent",
			svc: payload.Service{Name: "portal-a",
				Traefik: []payload.TraefikRoute{{Router: "portal"}}},
			want: nil,
		},
		{
			name: "a bare label matches a `name@provider` router",
			svc: payload.Service{Name: "docs",
				Traefik: []payload.TraefikRoute{{Router: "docs"}}},
			want: nil,
		},
		{
			name: "a router no name in the snapshot matches is absent",
			svc: payload.Service{Name: "blog",
				Traefik: []payload.TraefikRoute{{Router: "blog"}, {Router: "docs"}}},
			want: []string{"blog"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.Absent(tc.svc); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Absent() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Middlewares the fleet cannot see
// ---------------------------------------------------------------------------

// TestAMiddlewareNoStackDefinesIsNamedAsTheProxysOwn is one of the three things §12 exists to
// resolve.
//
// A middleware defined in a Traefik file provider has no definition anywhere in the compose tree, so
// label-only its type is unknowable and a gate could only ever be `inferred` from its name.
func TestAMiddlewareNoStackDefinesIsNamedAsTheProxysOwn(t *testing.T) {
	reg := labels.NewRegistry([]payload.AppStack{{
		ID: "apps",
		Services: []payload.Service{{
			Name: "edge",
			Labels: map[string]string{
				"traefik.http.middlewares.dashboard-auth.basicauth.users": "admin:$apr1$abc",
			},
		}},
	}}, "traefik")

	snap := Snapshot{Middlewares: map[string]RawMiddleware{
		"authentik@file":      {Name: "authentik@file", Type: "forwardAuth"},
		"dashboard-auth@file": {Name: "dashboard-auth@file", Type: "basicAuth"},
		"secured@file":        {Name: "secured@file", Type: "chain"},
	}}

	got := FileProviderMiddlewares(snap, reg)
	want := []string{"authentik@file", "secured@file"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FileProviderMiddlewares() = %#v, want %#v — `dashboard-auth` is defined by a label "+
			"and resolves through the registry regardless of the provider it is served through", got, want)
	}
}
