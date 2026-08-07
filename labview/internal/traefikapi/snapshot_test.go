package traefikapi

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// chainOf renders a resolved chain as `name:type` plus where the entry came from, which is the
// whole of what §12 concludes from one and is readable in a failure message.
func chainOf(r payload.TraefikLiveRouter) []string {
	var out []string
	for _, mw := range r.Middlewares {
		line := mw.Name + ":" + mw.Type
		if mw.ViaChain != "" {
			line += " via chain " + mw.ViaChain
		}
		if mw.ViaEntrypoint != nil && *mw.ViaEntrypoint {
			line += " via entrypoint"
		}
		if len(mw.Errors) > 0 {
			line += " [" + strings.Join(mw.Errors, "; ") + "]"
		}
		out = append(out, line)
	}
	return out
}

// docsSnapshot is the `docs` fixture's shape: a router whose only middleware is a file-provider
// chain, and the chain contains a real gate two levels down.
func docsSnapshot() Snapshot {
	return Snapshot{
		Version: "3.1.2",
		Routers: []RawRouter{{
			Name: "docs@docker", Provider: "docker", Status: "enabled",
			Rule: "Host(`docs.example.com`)", Service: "docs",
			EntryPoints: []string{"websecure"}, Middlewares: []string{"secured@file"}, TLS: true,
		}},
		Middlewares: map[string]RawMiddleware{
			"secured@file":   {Name: "secured@file", Type: "chain", Chain: []string{"ratelimit@file", "authentik@file"}},
			"ratelimit@file": {Name: "ratelimit@file", Type: "rateLimit"},
			"authentik@file": {Name: "authentik@file", Type: "forwardAuth",
				Address: "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik"},
		},
		Services: map[string]RawService{
			"docs@docker": {Servers: []payload.TraefikLiveServer{{URL: "http://docs:80", Status: "DOWN"}}},
		},
		Entrypoints:     map[string][]string{"websecure": nil},
		EntrypointsRead: true,
	}
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

// TestAChainMiddlewareIsExpandedIntoTheGateItContains is the `docs` fixture's rule.
//
// `secured@file` reads as no gate at all — it is a `chain` — and the forward-auth is two levels
// inside it. A reader of the router's own middleware list would conclude this service has no
// protection, which is the opposite of the truth, and every entry records the chain it came through
// so the gate can still be found in the proxy's configuration.
func TestAChainMiddlewareIsExpandedIntoTheGateItContains(t *testing.T) {
	live := docsSnapshot().Live()
	if len(live) != 1 {
		t.Fatalf("Live() returned %d routers, want 1", len(live))
	}

	want := []string{
		"secured@file:chain",
		"ratelimit@file:rateLimit via chain secured@file",
		"authentik@file:forwardAuth via chain secured@file",
	}
	if got := chainOf(live[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("chain =\n  %#v\nwant\n  %#v", got, want)
	}
	if addr := live[0].Middlewares[2].Address; addr == "" {
		t.Fatal("the forwardauth address is what resolves a gate back to a service (§12) and it was dropped")
	}
	if got := live[0].Hosts; !reflect.DeepEqual(got, []string{"docs.example.com"}) {
		t.Fatalf("hosts = %#v — a live rule and a labelled one must read through one parser", got)
	}
}

// TestAGateAtAnEntrypointIsInTheChainOnlyWhenTheEntrypointsWereRead is the `metrics` fixture beside
// the `dashboards` one, and the reason the read has a `partial` phase at all.
//
// A middleware attached at an entrypoint appears in no router's own list. Merging an entrypoint list
// that was never obtained would be an empty list standing in for an unknown one — and that reading
// is what would let §12's downgrade fire on a service whose gate this program simply had not looked
// for.
func TestAGateAtAnEntrypointIsInTheChainOnlyWhenTheEntrypointsWereRead(t *testing.T) {
	base := Snapshot{
		Routers: []RawRouter{{
			Name: "metrics@docker", Provider: "docker", Status: "enabled",
			Rule: "Host(`metrics.example.com`)", EntryPoints: []string{"WebSecure"},
		}},
		Middlewares: map[string]RawMiddleware{
			"authentik@file": {Name: "authentik@file", Type: "forwardAuth", Address: "http://authentik-server:9000/x"},
		},
		Services:    map[string]RawService{},
		Entrypoints: map[string][]string{"websecure": {"authentik@file"}},
	}

	t.Run("not read", func(t *testing.T) {
		got := chainOf(base.Live()[0])
		if len(got) != 0 {
			t.Fatalf("chain = %#v, want empty: an entrypoint list that was not read may not be merged", got)
		}
	})

	t.Run("read", func(t *testing.T) {
		snap := base
		snap.EntrypointsRead = true
		want := []string{"authentik@file:forwardAuth via entrypoint"}
		if got := chainOf(snap.Live()[0]); !reflect.DeepEqual(got, want) {
			t.Fatalf("chain =\n  %#v\nwant\n  %#v", got, want)
		}
	})
}

// TestAMiddlewareNamedTwiceIsOneMiddleware pins that the router's own list and its entrypoint's are
// one chain and not two.
//
// The same gate counted twice would put two `confirmed` accounts on one service, and §4.2's
// resolution would then report a fleet where every entrypoint-gated service has duplicate posture.
func TestAMiddlewareNamedTwiceIsOneMiddleware(t *testing.T) {
	snap := Snapshot{
		Routers: []RawRouter{{
			Name: "app@docker", Provider: "docker", Status: "enabled",
			EntryPoints: []string{"websecure"}, Middlewares: []string{"authentik@file"},
		}},
		Middlewares: map[string]RawMiddleware{
			"authentik@file": {Name: "authentik@file", Type: "forwardAuth", Address: "http://a:9000/x"},
		},
		Services:        map[string]RawService{},
		Entrypoints:     map[string][]string{"websecure": {"authentik@file"}},
		EntrypointsRead: true,
	}

	want := []string{"authentik@file:forwardAuth"}
	if got := chainOf(snap.Live()[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("chain =\n  %#v\nwant\n  %#v", got, want)
	}
}

// TestAMiddlewareTheProxyHoldsNoDefinitionForIsReportedRatherThanDropped is I4 in the chain.
//
// A reference the proxy cannot resolve is a router that will not serve, and a reader has to see that
// rather than infer it from an absence — a silently shortened chain reads exactly like a chain that
// never had a gate in it.
func TestAMiddlewareTheProxyHoldsNoDefinitionForIsReportedRatherThanDropped(t *testing.T) {
	snap := Snapshot{
		Routers: []RawRouter{{Name: "app@docker", Provider: "docker",
			Middlewares: []string{"gone@file", "authentik@file"}}},
		Middlewares: map[string]RawMiddleware{
			"authentik@file": {Name: "authentik@file", Type: "forwardAuth"},
		},
		Services: map[string]RawService{},
	}

	got := chainOf(snap.Live()[0])
	want := []string{
		"gone@file: [the proxy holds no definition for this middleware]",
		"authentik@file:forwardAuth",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chain =\n  %#v\nwant\n  %#v", got, want)
	}
}

// TestChainNestingDeeperThanTheLimitIsReportedRatherThanFollowed is I8 in a document this program
// did not write.
//
// The limit is the bound; the note is what keeps it from being a silent truncation. A chain that
// simply stopped at five levels would report a gate on the sixth as absent, which is the one
// direction §12's conclusions must never fail in.
func TestChainNestingDeeperThanTheLimitIsReportedRatherThanFollowed(t *testing.T) {
	mws := map[string]RawMiddleware{
		"gate@file": {Name: "gate@file", Type: "forwardAuth", Address: "http://a:9000/x"},
	}
	for i := 1; i <= 6; i++ {
		name := "c" + string(rune('0'+i)) + "@file"
		next := "c" + string(rune('0'+i+1)) + "@file"
		if i == 6 {
			next = "gate@file"
		}
		mws[name] = RawMiddleware{Name: name, Type: "chain", Chain: []string{next}}
	}
	snap := Snapshot{
		Routers:     []RawRouter{{Name: "app@docker", Provider: "docker", Middlewares: []string{"c1@file"}}},
		Middlewares: mws,
		Services:    map[string]RawService{},
	}

	got := chainOf(snap.Live()[0])
	if len(got) != chainDepth+1 {
		t.Fatalf("chain =\n  %#v\nwant %d entries: five resolved levels and one note", got, chainDepth+1)
	}
	last := got[len(got)-1]
	if !strings.Contains(last, "c6@file") || !strings.Contains(last, "deeper than 5") {
		t.Fatalf("the sixth level = %q, want it named with a note that it was not resolved", last)
	}
	for _, entry := range got {
		if strings.Contains(entry, "gate@file") {
			t.Fatal("the walk followed a chain past its limit (I8)")
		}
	}
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

// TestABackendWithNoObservedStatusIsNotHealthy is Appendix A's requirement that an absent status
// stays absent.
//
// `serverStatus` is keyed on the backend URL and a real Traefik omits entries it has not observed.
// Substituting `UP` would report a backend nobody has heard from as healthy, and the reachability
// view would then be a claim rather than a report.
func TestABackendWithNoObservedStatusIsNotHealthy(t *testing.T) {
	snap := Snapshot{
		Routers: []RawRouter{
			{Name: "docs@docker", Provider: "docker", Service: "docs"},
			{Name: "wiki@docker", Provider: "docker", Service: "wiki-web@docker"},
			{Name: "dashboard@docker", Provider: "docker", Service: "api@internal"},
			{Name: "nameless@docker", Provider: "docker"},
		},
		Middlewares: map[string]RawMiddleware{},
		Services: map[string]RawService{
			// A docker router names its service bare and the services section is keyed
			// `name@provider`. Both spellings are the same service and neither is a guess.
			"docs@docker": {Servers: []payload.TraefikLiveServer{{URL: "http://docs:80", Status: "DOWN"}}},
			"wiki-web@docker": {Servers: []payload.TraefikLiveServer{
				{URL: "http://172.18.0.4:3000"}, // observed by nothing
			}},
		},
	}

	live := snap.Live()
	for _, tc := range []struct {
		router string
		want   []payload.TraefikLiveServer
	}{
		{"docs@docker", []payload.TraefikLiveServer{{URL: "http://docs:80", Status: "DOWN"}}},
		{"wiki@docker", []payload.TraefikLiveServer{{URL: "http://172.18.0.4:3000"}}},
		// `api@internal` has no entry in the services section, which a real Traefik also omits.
		{"dashboard@docker", []payload.TraefikLiveServer{}},
		{"nameless@docker", []payload.TraefikLiveServer{}},
	} {
		t.Run(tc.router, func(t *testing.T) {
			for _, r := range live {
				if r.Router != tc.router {
					continue
				}
				if !reflect.DeepEqual(r.Servers, tc.want) {
					t.Fatalf("servers = %#v, want %#v", r.Servers, tc.want)
				}
				return
			}
			t.Fatalf("router %q is not in Live()", tc.router)
		})
	}
}

// ---------------------------------------------------------------------------
// What a router counts for
// ---------------------------------------------------------------------------

// TestADisabledOrErroredRouterIsNeitherIngressNorProtection is the `legacy` fixture's rule.
//
// `legacy` is a disabled router whose chain contains a real gate. Counting it would credit the
// service with a protection no request ever passes through — and counting it the other way, as a
// route, would draw ingress that does not exist.
//
// An empty status is working: §12 names two exclusions and silence is neither of them, so a build
// that does not populate the field must not lose every router it has.
func TestADisabledOrErroredRouterIsNeitherIngressNorProtection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		router payload.TraefikLiveRouter
		want   bool
	}{
		{"enabled", payload.TraefikLiveRouter{Status: "enabled"}, true},
		{"no status at all", payload.TraefikLiveRouter{}, true},
		{"padded and capitalised", payload.TraefikLiveRouter{Status: " Enabled "}, true},
		{"disabled", payload.TraefikLiveRouter{Status: "disabled"}, false},
		{"warning", payload.TraefikLiveRouter{Status: "warning"}, false},
		{"enabled but carrying an error", payload.TraefikLiveRouter{
			Status: "enabled", Errors: []string{"the service is unreachable"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Working(tc.router); got != tc.want {
				t.Fatalf("Working() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestABrokenRouterIsQuotedInTheProxysOwnWords is §12's wording requirement.
//
// The errors are the proxy's own statement about its own configuration and this program has no
// better ones — paraphrasing them would leave an operator unable to search for the message their
// proxy logged.
func TestABrokenRouterIsQuotedInTheProxysOwnWords(t *testing.T) {
	t.Run("a working router says nothing", func(t *testing.T) {
		if note := ErrorNote(payload.TraefikLiveRouter{Router: "app@docker", Status: "enabled"}); note != "" {
			t.Fatalf("ErrorNote() = %q, want empty", note)
		}
	})

	for _, tc := range []struct {
		name   string
		router payload.TraefikLiveRouter
		want   []string
	}{
		{
			name:   "disabled, with no error to quote",
			router: payload.TraefikLiveRouter{Router: "legacy@docker", Status: "disabled"},
			want:   []string{"`legacy@docker`", "`disabled`", "neither working ingress nor protection"},
		},
		{
			name: "an error and a status",
			router: payload.TraefikLiveRouter{Router: "broken@docker", Status: "warning",
				Errors: []string{"middleware \"gone@file\" does not exist"}},
			want: []string{"`broken@docker`", "`warning`", "error `middleware \"gone@file\" does not exist`"},
		},
		{
			name: "two errors",
			router: payload.TraefikLiveRouter{Router: "broken@docker",
				Errors: []string{"b happened", "a happened"}},
			want: []string{"errors `a happened` and `b happened`"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note := ErrorNote(tc.router)
			for _, want := range tc.want {
				if !strings.Contains(note, want) {
					t.Fatalf("ErrorNote() = %q, want it to contain %q", note, want)
				}
			}
		})
	}
}

// TestRoutersComeBackInOneOrder is I7 where the proxy's answer has no order at all.
//
// `/api/rawdata` is a map, and Go's map iteration is deliberately random. A payload whose router
// list differed between two identical reads would make §17's change note report a change to a fleet
// nothing happened to.
func TestRoutersComeBackInOneOrder(t *testing.T) {
	in := []RawRouter{
		{Name: "wiki-web@docker"}, {Name: "api@internal"}, {Name: "docs@docker"}, {Name: "blog@file"},
	}
	sortRouters(in)

	want := []string{"api@internal", "blog@file", "docs@docker", "wiki-web@docker"}
	var got []string
	for _, r := range in {
		got = append(got, r.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %#v, want %#v", got, want)
	}
}
