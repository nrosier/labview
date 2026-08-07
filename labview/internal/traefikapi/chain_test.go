package traefikapi

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
)

// The address the fixture fleet's outpost answers on, and the service key it resolves to.
const (
	outpostAddress = "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik"
	authentikKey   = "idp/authentik-server"
)

// postureIndex resolves the outpost address to exactly one scanned service, which is what turns a
// forward-auth into a named operator rather than an anonymous gate.
func postureIndex() *fleet.Index {
	return fleet.NewIndex([]payload.AppStack{{
		ID: "idp",
		Services: []payload.Service{
			{Name: "authentik-server", ContainerName: "authentik-server"},
			{Name: "authentik-worker", ContainerName: "authentik-worker"},
		},
	}})
}

// gate is a live forward-auth in a router's chain.
func gate(name, address string, viaEntrypoint bool) payload.TraefikLiveMiddleware {
	mw := payload.TraefikLiveMiddleware{Name: name, Type: "forwardAuth", Address: address, Errors: []string{}}
	if viaEntrypoint {
		yes := true
		mw.ViaEntrypoint = &yes
	}
	return mw
}

// router is one live router with a chain.
func router(name, status string, chain ...payload.TraefikLiveMiddleware) payload.TraefikLiveRouter {
	return payload.TraefikLiveRouter{
		Router: name, Provider: "docker", Status: status,
		Rule: "Host(`app.example.com`)", Hosts: []string{"app.example.com"},
		EntryPoints: []string{"websecure"}, Middlewares: chain,
		Errors: []string{}, Evidence: []string{},
	}
}

// claims is what §7 concluded from a label, which is the posture the live read may supersede.
func claims(detail string) []labels.Account {
	return []labels.Account{{
		Method:     payload.AuthForwardAuth,
		Detail:     detail,
		Confidence: payload.ConfidenceObserved,
		Evidence:   []string{"a label references " + quote(detail)},
	}}
}

func notesContain(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The live chain is the chain
// ---------------------------------------------------------------------------

// TestTheChainTheProxyBuiltIsConfirmedAndNamesItsOperator is why §12 exists at all.
//
// The proxy is reporting the chain it *built*, which is neither a label that might not have been
// served nor a name a rule inferred a meaning from — so the confidence is `confirmed`. And an address
// resolving to the service the identity-provider API answered on is not an inference either: that far
// end answered as an Authentik API, which no name match can establish.
func TestTheChainTheProxyBuiltIsConfirmedAndNamesItsOperator(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers:       []payload.TraefikLiveRouter{router("app@docker", "enabled", gate("authentik@file", outpostAddress, false))},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
	})

	if len(got.Accounts) != 1 {
		t.Fatalf("accounts = %#v, want exactly the one gate the chain contains", got.Accounts)
	}
	acct := got.Accounts[0]
	if acct.Confidence != payload.ConfidenceConfirmed {
		t.Fatalf("confidence = %q, want %q — the proxy reported the chain it built",
			acct.Confidence, payload.ConfidenceConfirmed)
	}
	if acct.Method != payload.AuthAuthentikForwardAuth {
		t.Fatalf("method = %q, want %q: the address resolves to the service that answered as the "+
			"Authentik API", acct.Method, payload.AuthAuthentikForwardAuth)
	}
	if acct.Address != outpostAddress {
		t.Fatalf("address = %q, want the forwardauth's own address", acct.Address)
	}
	if !notesContain(acct.Evidence, "answered as the Authentik API") {
		t.Fatalf("evidence = %#v, want the attribution stated", acct.Evidence)
	}
	if got.Suppress {
		t.Fatal("a chain that contains a gate must not suppress anything")
	}
}

// TestAGateWhoseAddressOnlyNamesTheProviderIsStillAttributed is the fallback of §7.
//
// The identity-provider API may not have answered at all. An address that *names* the provider this
// fleet runs is weaker evidence than one that resolves to it, and it is still the difference between
// "a forward-auth" and "the fleet's SSO" on a page.
func TestAGateWhoseAddressOnlyNamesTheProviderIsStillAttributed(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers: []payload.TraefikLiveRouter{router("app@docker", "enabled",
			gate("sso@file", "http://sso-authentik.example.internal/outpost.goauthentik.io/auth/traefik", false))},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
		Hints:         labels.NewHints([]string{"authentik"}),
	})

	if len(got.Accounts) != 1 || got.Accounts[0].Method != payload.AuthAuthentikForwardAuth {
		t.Fatalf("accounts = %#v, want one authentik-forward-auth", got.Accounts)
	}
	if !notesContain(got.Accounts[0].Evidence, "names") {
		t.Fatalf("evidence = %#v, want it to say the address names the provider", got.Accounts[0].Evidence)
	}
}

// TestAGateNobodyCanAttributeIsStillAGate keeps the weaker conclusion from being no conclusion.
//
// A forward-auth to something this scan cannot name is a real gate whose operator is unnamed, and
// reporting nothing would put the service in the exposure finding.
func TestAGateNobodyCanAttributeIsStillAGate(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers: []payload.TraefikLiveRouter{router("app@docker", "enabled",
			gate("gate@file", "http://some-unknown-thing:4180/verify", false))},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
	})

	if len(got.Accounts) != 1 || got.Accounts[0].Method != payload.AuthForwardAuth {
		t.Fatalf("accounts = %#v, want one plain forward-auth", got.Accounts)
	}
}

// TestABasicAuthChainIsAGateWithNoAddressToResolve is the `edge` fixture's own posture: the proxy
// dashboard behind a basicauth the proxy holds the definition for.
func TestABasicAuthChainIsAGateWithNoAddressToResolve(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers: []payload.TraefikLiveRouter{router("dashboard@docker", "enabled",
			payload.TraefikLiveMiddleware{Name: "dashboard-auth@file", Type: "basicAuth", Errors: []string{}})},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
	})

	if len(got.Accounts) != 1 {
		t.Fatalf("accounts = %#v, want one", got.Accounts)
	}
	if got.Accounts[0].Method != payload.AuthBasicAuth || got.Accounts[0].Address != "" {
		t.Fatalf("account = %#v, want a basic-auth with no address", got.Accounts[0])
	}
}

// ---------------------------------------------------------------------------
// The downgrade
// ---------------------------------------------------------------------------

// TestALabelledGateTheLiveChainDoesNotContainIsDowngraded is §12's sharpest conclusion, and the one
// direction in which this integration could mislead.
//
// The `dashboards` and `metrics` fixtures differ in nothing else: both declare a gate in a label and
// both have an empty router chain, and only the second one's *entrypoint* carries the gate. So the
// downgrade may only fire on a complete read, and the entrypoint half of the chain is what decides
// it — the live chain is what requests actually pass through.
func TestALabelledGateTheLiveChainDoesNotContainIsDowngraded(t *testing.T) {
	base := PostureInput{
		Reachable:     true,
		ChainComplete: true,
		LabelAccounts: claims("authentik@file"),
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
	}

	t.Run("dashboards: nothing in the chain, so the label is not reported", func(t *testing.T) {
		in := base
		in.Routers = []payload.TraefikLiveRouter{router("dashboards@docker", "enabled")}

		got := PostureOf(in)
		if !got.Suppress {
			t.Fatal("Suppress = false: a label claimed a gate the chain the proxy built does not contain")
		}
		if len(got.Accounts) != 0 {
			t.Fatalf("accounts = %#v, want none", got.Accounts)
		}
		if !notesContain(got.Notes, "authentik@file") ||
			!notesContain(got.Notes, "contains no authentication middleware") {
			t.Fatalf("notes = %#v, want the claim and the absence both stated", got.Notes)
		}
		if !notesContain(got.Notes, "including anything its entrypoints attach") {
			t.Fatalf("notes = %#v, want it clear that the entrypoints were looked at too", got.Notes)
		}
	})

	t.Run("metrics: the gate is on the entrypoint, so nothing is downgraded", func(t *testing.T) {
		in := base
		in.Routers = []payload.TraefikLiveRouter{
			router("metrics@docker", "enabled", gate("authentik@file", outpostAddress, true)),
		}

		got := PostureOf(in)
		if got.Suppress {
			t.Fatal("Suppress = true on a service whose entrypoint carries the gate (§12)")
		}
		if len(got.Accounts) != 1 {
			t.Fatalf("accounts = %#v, want the entrypoint's gate", got.Accounts)
		}
		if !notesContain(got.Accounts[0].Evidence, "attached at entrypoint") {
			t.Fatalf("evidence = %#v, want where the gate is attached recorded", got.Accounts[0].Evidence)
		}
	})

	t.Run("legacy: a disabled router's chain counts for nothing, and downgrades nothing", func(t *testing.T) {
		in := base
		in.Routers = []payload.TraefikLiveRouter{
			router("legacy@docker", "disabled", gate("authentik@file", outpostAddress, false)),
		}

		got := PostureOf(in)
		if got.Suppress {
			t.Fatal("a disabled router was treated as an assertion that no gate exists")
		}
		if len(got.Accounts) != 0 {
			t.Fatalf("accounts = %#v: a disabled router is neither ingress nor protection", got.Accounts)
		}
		if !notesContain(got.Notes, "`disabled`") {
			t.Fatalf("notes = %#v, want the proxy's own word for the router quoted", got.Notes)
		}
	})

	t.Run("blog: declared and not live, so the label posture stands", func(t *testing.T) {
		in := base
		in.Absent = []string{"blog"}

		got := PostureOf(in)
		if got.Suppress {
			t.Fatal("a label posture was discarded with no live counterpart to supersede it")
		}
		if !notesContain(got.Notes, "not among the routers the proxy is serving") {
			t.Fatalf("notes = %#v, want the declared-but-absent router reported", got.Notes)
		}
	})

	t.Run("a service whose labels claimed nothing has nothing to downgrade", func(t *testing.T) {
		in := base
		in.LabelAccounts = nil
		in.Routers = []payload.TraefikLiveRouter{router("open@docker", "enabled")}

		got := PostureOf(in)
		if got.Suppress {
			t.Fatal("Suppress = true where no label claimed a gate: there is nothing to suppress")
		}
		if len(got.Notes) != 0 {
			t.Fatalf("notes = %#v, want silence — an open service with no claim is not a finding here", got.Notes)
		}
	})
}

// A read that never happened says nothing about anybody's posture.
//
// This is the distinction between *the proxy reported no gate here* and *nobody asked the proxy*, and
// it is not a subtlety: the proxy read is off by default and off for six of §23's seven fixture roots,
// so if an unreachable read contributed notes then almost every service in almost every fleet would
// carry two sentences about what a proxy said — one claiming its router is not being served, one
// claiming its chain contains no authentication middleware — on the strength of an empty snapshot
// nobody fetched. Both would be false, and the second would read to an operator as a bypass.
//
// A partial read is a different case and is *not* covered by this: it answered, so it is reachable,
// and §12's rule for it is to report the gap and change nothing (the test below).
func TestAReadThatDidNotHappenSaysNothingAboutAnyPosture(t *testing.T) {
	// Everything that would produce a note if the read had answered: a labelled gate the chain does
	// not contain, a router the proxy is not serving, a live router carrying an error.
	in := PostureInput{
		Reachable:     false,
		ChainComplete: false,
		Routers:       []payload.TraefikLiveRouter{router("dashboards@docker", "disabled")},
		Absent:        []string{"dashboards"},
		LabelAccounts: claims("authentik@file"),
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
	}

	got := PostureOf(in)
	if len(got.Notes) != 0 {
		t.Fatalf("notes = %#v, want silence: the proxy was not read, so it reported nothing", got.Notes)
	}
	if len(got.Accounts) != 0 {
		t.Fatalf("accounts = %#v, want none from a read that did not happen", got.Accounts)
	}
	if got.Suppress {
		t.Fatal("Suppress = true from an unreachable read: an unasked question is not a denial")
	}
}

// TestAPartialReadReportsTheDifferenceAndChangesNoPosture is what the `partial` phase is for.
//
// The entrypoint list was not read, so an empty router chain is not evidence that no gate is
// attached. §12 requires the gap noted and no posture changed — and the wording has to be
// distinguishable from the downgrade's, because one is a report and the other is a conclusion.
func TestAPartialReadReportsTheDifferenceAndChangesNoPosture(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers:       []payload.TraefikLiveRouter{router("dashboards@docker", "enabled")},
		Reachable:     true,
		ChainComplete: false,
		LabelAccounts: claims("authentik@file"),
		Index:         postureIndex(),
	})

	if got.Suppress {
		t.Fatal("Suppress = true on an incomplete read: an unread entrypoint list is not an absent gate")
	}
	if len(got.Accounts) != 0 {
		t.Fatalf("accounts = %#v, want none — a partial read supersedes nothing", got.Accounts)
	}
	if !notesContain(got.Notes, "could not be read") {
		t.Fatalf("notes = %#v, want the gap itself stated", got.Notes)
	}
	if notesContain(got.Notes, "is not reported") {
		t.Fatalf("notes = %#v, want wording that reports rather than concludes", got.Notes)
	}
}

// ---------------------------------------------------------------------------
// The three-way cross-check
// ---------------------------------------------------------------------------

// carried is one matched Authentik application whose provider an outpost serves.
func carried(mode string) *payload.AuthentikMatch {
	return &payload.AuthentikMatch{
		Applications: []payload.AuthentikApplication{{
			Name: "CRM", Slug: "crm",
			Providers: []payload.AuthentikProvider{{
				Name: "crm-proxy", Kind: payload.ProviderProxy, RawKind: "proxy",
				Mode: mode, Outposts: []string{"authentik Embedded Outpost"},
			}},
		}},
	}
}

// TestTheCrossCheckFindsAnOutpostStandingBesideTheRequestPath is the `crm` fixture, and the reason
// §12 reads all three sources rather than two.
//
// Each source alone is unremarkable: no label to check, an empty chain like any other, and a provider
// that looks correctly configured. Held together they say somebody set up a gate and believes it is
// in force while nothing in the proxy forwards to it.
func TestTheCrossCheckFindsAnOutpostStandingBesideTheRequestPath(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers:       []payload.TraefikLiveRouter{router("crm@docker", "enabled")},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
		Applications:  carried("forward_single"),
	})

	if !notesContain(got.Notes, "without passing the outpost") {
		t.Fatalf("notes = %#v, want the bypass reported", got.Notes)
	}
	if !notesContain(got.Notes, "crm-proxy") {
		t.Fatalf("notes = %#v, want the provider named", got.Notes)
	}
}

// TestAProxyModeProviderIsTheBackendAndNotAMiddleware is the `shop` fixture, which differs from
// `crm` in the provider's `mode` and in nothing else.
//
// In proxy mode the outpost terminates the request and forwards upstream itself, so there is no
// middleware for it to be and an empty router chain is what a correct deployment looks like.
// Reporting a bypass there would invent a finding on a working setup.
func TestAProxyModeProviderIsTheBackendAndNotAMiddleware(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers:       []payload.TraefikLiveRouter{router("shop@docker", "enabled")},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
		Applications:  carried(proxyMode),
	})

	if notesContain(got.Notes, "without passing the outpost") {
		t.Fatalf("notes = %#v, want no finding: in proxy mode the outpost *is* the backend", got.Notes)
	}
	if len(got.Notes) != 0 {
		t.Fatalf("notes = %#v, want silence", got.Notes)
	}
}

// TestAProviderNoOutpostServesIsInNobodysRequestPath is the other half of the exemption set.
//
// A kind no outpost carries is not a forward-auth arrangement at all, and a provider assigned to no
// outpost has nothing deployed to stand in a request path — neither is a bypass.
func TestAProviderNoOutpostServesIsInNobodysRequestPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider payload.AuthentikProvider
	}{
		{"an OAuth2 provider, which needs no outpost", payload.AuthentikProvider{
			Name: "wiki-oauth", Kind: payload.ProviderOAuth2, RawKind: "oauth2",
			Outposts: []string{"authentik Embedded Outpost"}}},
		{"a proxy provider no outpost was assigned", payload.AuthentikProvider{
			Name: "wiki-proxy", Kind: payload.ProviderProxy, RawKind: "proxy", Mode: "forward_single"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PostureOf(PostureInput{
				Routers:       []payload.TraefikLiveRouter{router("wiki@docker", "enabled")},
				Reachable:     true,
				ChainComplete: true,
				Index:         postureIndex(),
				AuthentikKey:  authentikKey,
				Applications: &payload.AuthentikMatch{Applications: []payload.AuthentikApplication{{
					Slug: "wiki", Providers: []payload.AuthentikProvider{tc.provider},
				}}},
			})
			if len(got.Notes) != 0 {
				t.Fatalf("notes = %#v, want silence", got.Notes)
			}
		})
	}
}

// TestAllThreeSourcesAgreeingIsAlsoWorthSaying is the `wiki` fixture's third source.
//
// A reader deciding whether to trust the page needs the agreement stated as plainly as the
// disagreement — an integration that only ever speaks up to report a fault gives no way to tell a
// checked service from an unchecked one.
func TestAllThreeSourcesAgreeingIsAlsoWorthSaying(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers: []payload.TraefikLiveRouter{router("wiki-web@docker", "enabled",
			gate("authentik@file", outpostAddress, false))},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
		Applications:  carried("forward_single"),
	})

	if !notesContain(got.Notes, "agree") {
		t.Fatalf("notes = %#v, want the agreement of the three sources stated", got.Notes)
	}
}

// TestAGateWithNothingBehindItIsADifferentFindingFromAnAbsentGate keeps two unlike facts apart.
//
// The proxy forwards to the identity provider and the identity provider has nothing for this service:
// the gate is real, and what it will decide is not something Authentik was able to show.
func TestAGateWithNothingBehindItIsADifferentFindingFromAnAbsentGate(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers: []payload.TraefikLiveRouter{router("app@docker", "enabled",
			gate("authentik@file", outpostAddress, false))},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
		AuthentikKey:  authentikKey,
	})

	if !notesContain(got.Notes, "no application matched to this service") {
		t.Fatalf("notes = %#v, want the absent application reported", got.Notes)
	}
	if notesContain(got.Notes, "without passing the outpost") {
		t.Fatalf("notes = %#v, want no bypass claimed: the chain does forward to the provider", got.Notes)
	}
}

// TestNoCrossCheckRunsWithoutTheIdentityProvider pins that the third source has to be present for a
// three-way conclusion.
//
// With no Authentik read there is nothing to hold the other two against, and a note saying requests
// reach the service without passing an outpost would be a claim about a fleet this scan never looked
// at.
func TestNoCrossCheckRunsWithoutTheIdentityProvider(t *testing.T) {
	got := PostureOf(PostureInput{
		Routers: []payload.TraefikLiveRouter{router("app@docker", "enabled",
			gate("authentik@file", outpostAddress, false))},
		Reachable:     true,
		ChainComplete: true,
		Index:         postureIndex(),
	})

	if len(got.Notes) != 0 {
		t.Fatalf("notes = %#v, want silence with no identity-provider read to cross-check against", got.Notes)
	}
	if len(got.Accounts) != 1 {
		t.Fatalf("accounts = %#v — the gate itself is still reported", got.Accounts)
	}
}

// ---------------------------------------------------------------------------
// The proxy's own API
// ---------------------------------------------------------------------------

// TestAnAPIThatAnsweredWithNoCredentialIsReportedAsSuch is §12's requirement that this be a note
// rather than an implication of a summary field.
//
// An API that answered unauthenticated is a fact about how that API is exposed on the network it is
// on: anything that can reach the port can read the whole routing table.
func TestAnAPIThatAnsweredWithNoCredentialIsReportedAsSuch(t *testing.T) {
	for _, tc := range []struct {
		name string
		read Read
		want string
	}{
		{
			name: "answered with nothing sent",
			read: Read{
				Report:     payload.ConnectionReport{OK: true, Phase: payload.PhaseConnected},
				Endpoint:   "http://traefik:8080",
				Credential: payload.CredentialNone,
			},
			want: "read the whole routing table",
		},
		{
			name: "needed a credential, so there is nothing to report",
			read: Read{
				Report:     payload.ConnectionReport{OK: true, Phase: payload.PhaseConnected},
				Endpoint:   "http://traefik:8080",
				Credential: payload.CredentialBasic,
			},
			want: "",
		},
		{
			name: "never answered at all",
			read: Read{
				Report:     payload.ConnectionReport{Phase: payload.PhaseConnect},
				Credential: payload.CredentialNone,
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CredentialNote(tc.read)
			switch {
			case tc.want == "" && got != "":
				t.Fatalf("CredentialNote() = %q, want empty", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Fatalf("CredentialNote() = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
