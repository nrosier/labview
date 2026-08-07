package labels

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// testFleet is the middleware corpus the classification tests read: one Authentik forward-auth,
// one forward-auth to somebody else's gatekeeper, a basicauth, a chain, and two middlewares
// that do something other than gate.
func testFleet() []payload.AppStack {
	return []payload.AppStack{{ID: "idp", Services: []payload.Service{{
		Name: "server", ContainerName: "authentik-server", Image: "ghcr.io/goauthentik/server:2024.10",
		Labels: map[string]string{
			"traefik.http.middlewares.authentik.forwardauth.address":                     "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
			"traefik.http.middlewares.oauth2.forwardauth.address":                        "http://gatekeeper:4180/oauth2/auth",
			"traefik.http.middlewares.dash.basicauth.users":                              "admin:$2y$05$notarealhashatall",
			"traefik.http.middlewares.secured.chain.middlewares":                         "compress@file,sso-inner@file",
			"traefik.http.middlewares.deep.chain.middlewares":                            "secured@file",
			"traefik.http.middlewares.loop.chain.middlewares":                            "loop@file",
			"traefik.http.middlewares.compress.compress":                                 "true",
			"traefik.http.middlewares.oauth-headers.headers.customrequestheaders.x-auth": "1",
		},
	}}}}
}

// input is one service carrying one router with the given middleware chain.
func input(t *testing.T, refs ...string) Input {
	t.Helper()
	fleet := testFleet()
	reg := NewRegistry(fleet, "traefik")
	return Input{
		Service: payload.Service{
			Name:    "app",
			Traefik: []payload.TraefikRoute{{Router: "app", Hosts: []string{"app.example.com"}, Middlewares: refs}},
		},
		Registry: reg,
		Hints:    NewHints([]string{authentikMark, authentikEndpointMark}),
	}
}

func TestClassifyFromDefinition(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ref        string
		method     payload.AuthMethod
		confidence payload.AuthConfidence
		evidence   string // a substring one evidence line must contain
		notes      bool
	}{
		{name: "an Authentik forward-auth, named by its address",
			ref: "authentik@docker", method: payload.AuthAuthentikForwardAuth,
			confidence: payload.ConfidenceObserved, evidence: "goauthentik.io"},
		{name: "somebody else's forward-auth stays generic",
			ref: "oauth2@docker", method: payload.AuthForwardAuth,
			confidence: payload.ConfidenceObserved, evidence: providerNotIdentified},
		{name: "a basicauth",
			ref: "dash@file", method: payload.AuthBasicAuth,
			confidence: payload.ConfidenceObserved, evidence: "basicauth"},
		{name: "a chain reaches the gate inside it",
			ref: "secured@file", method: payload.AuthForwardAuth,
			confidence: payload.ConfidenceInferred, evidence: "reached through chain", notes: true},
		{name: "a nested chain still reaches it",
			ref: "deep@file", method: payload.AuthForwardAuth,
			confidence: payload.ConfidenceInferred, evidence: "reached through chain", notes: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accounts, notes := FromLabels(input(t, tc.ref))
			if len(accounts) != 1 {
				t.Fatalf("accounts = %+v, want 1", accounts)
			}
			a := accounts[0]
			if a.Method != tc.method || a.Confidence != tc.confidence {
				t.Errorf("method = %q (%q), want %q (%q)", a.Method, a.Confidence, tc.method, tc.confidence)
			}
			if !containsLine(a.Evidence, tc.evidence) {
				t.Errorf("evidence = %q, want a line containing %q", a.Evidence, tc.evidence)
			}
			// Evidence is what makes a conclusion answerable (I1): the router and the
			// middleware it applies are always named.
			if !containsLine(a.Evidence, "router `app` applies middleware") {
				t.Errorf("evidence = %q, want the router named", a.Evidence)
			}
			if got := len(notes) > 0; got != tc.notes {
				t.Errorf("notes = %q, want notes: %v", notes, tc.notes)
			}
		})
	}
}

// Everything Traefik can do to a request other than gate it leaves the request answerable by
// anyone. Reading one of these as a gate is the mistake that turns an open service into a
// protected-looking one — including `oauth-headers`, whose name says `auth` twice over.
func TestClassifyNonGatesAreNotGates(t *testing.T) {
	for _, ref := range []string{"compress@file", "oauth-headers@file"} {
		t.Run(ref, func(t *testing.T) {
			accounts, notes := FromLabels(input(t, ref))
			if len(accounts) != 0 {
				t.Errorf("accounts = %+v, want none", accounts)
			}
			if len(notes) != 0 {
				t.Errorf("notes = %q, want none", notes)
			}
		})
	}
}

// A definition beats a name even when the name is `authentik` and the address is not.
// This is I3 in one assertion.
func TestClassifyDefinitionBeatsName(t *testing.T) {
	fleet := []payload.AppStack{{ID: "apps", Services: []payload.Service{{
		Name: "web",
		Labels: map[string]string{
			// Named after the provider, pointing at somebody else entirely.
			"traefik.http.middlewares.authentik.forwardauth.address": "http://gatekeeper:4180/oauth2/auth",
		},
	}}}}
	in := Input{
		Service: payload.Service{Name: "app", Traefik: []payload.TraefikRoute{{
			Router: "app", Middlewares: []string{"authentik@docker"},
		}}},
		Registry: NewRegistry(fleet, "traefik"),
		Hints:    NewHints([]string{authentikMark, authentikEndpointMark}),
	}
	accounts, _ := FromLabels(in)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	if accounts[0].Method != payload.AuthForwardAuth {
		t.Errorf("method = %q, want the generic mechanism: the name is not the evidence",
			accounts[0].Method)
	}
	if !containsLine(accounts[0].Evidence, providerNotIdentified) {
		t.Errorf("evidence = %q", accounts[0].Evidence)
	}
}

// The name fallback runs only when no compose file defines the middleware anywhere, and then
// the tokens are matched by equality. These five cases are the whole rule: getting it wrong in
// the generous direction invents protection, which is worse than reporting none.
func TestClassifyFromNameWhenNothingDefinesIt(t *testing.T) {
	for _, tc := range []struct {
		ref    string
		method payload.AuthMethod // "" for not a gate
	}{
		{ref: "sso-gate@file", method: payload.AuthForwardAuth},
		{ref: "dashboard-auth@file", method: payload.AuthForwardAuth},
		{ref: "ak-authentik@file", method: payload.AuthAuthentikForwardAuth},
		{ref: "authentik-outpost@docker", method: payload.AuthAuthentikForwardAuth},
		{ref: "secured-elsewhere@file"},
		{ref: "oauth-only@file"},
		{ref: "compress-all@file"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			accounts, notes := FromLabels(input(t, tc.ref))
			if tc.method == "" {
				if len(accounts) != 0 {
					t.Fatalf("accounts = %+v, want none: %q does not name a gate", accounts, tc.ref)
				}
				if len(notes) != 0 {
					t.Fatalf("notes = %q, want none", notes)
				}
				return
			}
			if len(accounts) != 1 {
				t.Fatalf("accounts = %+v, want 1", accounts)
			}
			if accounts[0].Method != tc.method {
				t.Errorf("method = %q, want %q", accounts[0].Method, tc.method)
			}
			// A name-derived conclusion is `inferred` and says so in a service note, so a
			// reader can tell it from a reading of a definition.
			if accounts[0].Confidence != payload.ConfidenceInferred {
				t.Errorf("confidence = %q, want inferred", accounts[0].Confidence)
			}
			if len(notes) != 1 || !strings.Contains(notes[0], "not defined in any scanned compose file") {
				t.Errorf("notes = %q", notes)
			}
			if !containsLine(accounts[0].Evidence, "so its name is the evidence") {
				t.Errorf("evidence = %q", accounts[0].Evidence)
			}
		})
	}
}

// A chain that references itself is representable in labels. The walk refuses to follow it
// forever, and refusing is not the same as crashing (I8, I4).
func TestClassifySelfReferentialChainTerminates(t *testing.T) {
	accounts, _ := FromLabels(input(t, "loop@file"))
	if len(accounts) != 0 {
		t.Errorf("accounts = %+v, want none: a chain of itself gates nothing", accounts)
	}
}

// One middleware applied by two routers is one gate. Without collapsing, its evidence would
// repeat once per router, which reads as more corroboration than there is.
func TestFromLabelsCollapsesOneGateReachedTwice(t *testing.T) {
	in := input(t)
	in.Service.Traefik = []payload.TraefikRoute{
		{Router: "a", Middlewares: []string{"authentik@docker"}},
		{Router: "b", Middlewares: []string{"authentik@docker"}},
	}
	accounts, _ := FromLabels(in)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want 1", accounts)
	}
	var applied int
	for _, line := range accounts[0].Evidence {
		if strings.Contains(line, "applies middleware") {
			applied++
		}
	}
	if applied != 2 {
		t.Errorf("evidence names %d routers, want both kept: %q", applied, accounts[0].Evidence)
	}
}

// A Cloudflare Access policy is a gate Cloudflare enforces at its own edge, before the request
// reaches the fleet, and it needs no reverse proxy to be in force. The mechanism is
// `other-oauth`: an OIDC gate whose provider is named and not guessed.
func TestAccessPolicyIsAGate(t *testing.T) {
	in := input(t)
	in.Service.Cloudflare = []payload.CloudflareRoute{{
		Hostname: "media.example.com",
		Access: &payload.CloudflareAccess{
			Policy: "authenticate", Group: "media-users",
			Emails: []string{"one@example.com"},
		},
	}}
	accounts, _ := FromLabels(in)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want 1", accounts)
	}
	a := accounts[0]
	if a.Method != payload.AuthOtherOAuth || a.Confidence != payload.ConfidenceObserved {
		t.Errorf("account = %+v, want other-oauth observed", a)
	}
	if a.Detail != "Cloudflare Access" {
		t.Errorf("detail = %q", a.Detail)
	}
	if !containsLine(a.Evidence, "Cloudflare Access policy") || !containsLine(a.Evidence, "1 address") {
		t.Errorf("evidence = %q", a.Evidence)
	}
}

func TestAccessAbsentIsNoGate(t *testing.T) {
	in := input(t)
	in.Service.Cloudflare = []payload.CloudflareRoute{{Hostname: "open.example.com"}}
	if accounts, _ := FromLabels(in); len(accounts) != 0 {
		t.Errorf("accounts = %+v, want none", accounts)
	}
}

func TestFromEnv(t *testing.T) {
	ldapHints := []string{"LDAP_HOST", "LDAP_URI", "LDAP_SERVER", "AUTHENTIK_LDAP_HOST"}
	oauthHints := []string{"OIDC", "OAUTH", "ISSUER", "CLIENT_ID", "CLIENT_SECRET"}

	for _, tc := range []struct {
		name     string
		env      map[string]string
		method   payload.AuthMethod // "" for no account at all
		detail   string
		evidence string
	}{
		{name: "an LDAP host naming the provider", method: payload.AuthAuthentikLDAP,
			detail: "LDAP_HOST", evidence: "`authentik`",
			env: map[string]string{"LDAP_HOST": "ldap://authentik-server:389"}},
		{name: "trap: another directory is not the provider", method: payload.AuthLDAP,
			detail: "LDAP_HOST", evidence: providerNotIdentified,
			env: map[string]string{"LDAP_HOST": "ldap://ldap-server.internal:389"}},
		{name: "an issuer naming the provider's host", method: payload.AuthAuthentikOAuth,
			detail: "OIDC_ISSUER", evidence: "`sso.example.com`",
			env: map[string]string{"OIDC_ISSUER": "https://sso.example.com/application/o/app/"}},
		{name: "trap: another provider's issuer stays generic", method: payload.AuthOtherOAuth,
			detail: "OIDC_ISSUER", evidence: providerNotIdentified,
			env: map[string]string{"OIDC_ISSUER": "https://oauth.bigcorp.example.com/realms/main"}},
		{name: "a key matched as a fragment", method: payload.AuthOtherOAuth,
			detail: "APP_OAUTH_CLIENT_ID",
			env:    map[string]string{"APP_OAUTH_CLIENT_ID": "abc123"}},
		{name: "an LDAP key is matched by equality, not containment",
			env: map[string]string{"LDAP_BIND_PASSWORD": "ldap://authentik-server:389"}},
		{name: "a variable set to nothing configures nothing",
			env: map[string]string{"LDAP_HOST": ""}},
		{name: "a switch turned off configures nothing",
			env: map[string]string{"OIDC_ENABLED": "false"}},
		{name: "nothing at all",
			env: map[string]string{"TZ": "Etc/UTC", "PUID": "1000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := input(t)
			in.Service.Env = envOf(tc.env)
			in.LDAPEnvHints, in.OAuthEnvHints = ldapHints, oauthHints
			in.Hints = NewHints([]string{authentikMark, "sso.example.com"})

			accounts, _ := FromLabels(in)
			if tc.method == "" {
				if len(accounts) != 0 {
					t.Fatalf("accounts = %+v, want none", accounts)
				}
				return
			}
			if len(accounts) != 1 {
				t.Fatalf("accounts = %+v, want 1", accounts)
			}
			a := accounts[0]
			if a.Method != tc.method || a.Detail != tc.detail {
				t.Errorf("account = %+v, want %q from %q", a, tc.method, tc.detail)
			}
			// An environment key is a claim the operator wrote and the application acts on,
			// which is why it is observed rather than inferred.
			if a.Confidence != payload.ConfidenceObserved {
				t.Errorf("confidence = %q, want observed", a.Confidence)
			}
			if tc.evidence != "" && !containsLine(a.Evidence, tc.evidence) {
				t.Errorf("evidence = %q, want a line containing %q", a.Evidence, tc.evidence)
			}
		})
	}
}

// No environment value ever reaches an evidence line (I6).
//
// The hint lists are operator-configurable, and `CLIENT_SECRET` is a default OAuth hint — so
// the reader that quotes a matched value is one configuration line away from putting a secret
// in the payload. Only keys and matched hints are quoted; the value is read and discarded.
func TestEvidenceNeverCarriesAnEnvironmentValue(t *testing.T) {
	const secret = "s3cret-value-that-must-not-appear"
	in := input(t)
	in.Service.Env = envOf(map[string]string{
		"OIDC_CLIENT_SECRET": secret,
		"LDAP_HOST":          "ldap://authentik-server:389?bindpw=" + secret,
	})
	// An operator who adds a password variable to the hint list gets a matched account, and
	// still no leak.
	in.LDAPEnvHints = []string{"LDAP_HOST", "LDAP_BIND_PASSWORD"}
	in.OAuthEnvHints = []string{"OIDC", "CLIENT_SECRET"}

	accounts, notes := FromLabels(in)
	if len(accounts) != 2 {
		t.Fatalf("accounts = %+v, want both mechanisms read", accounts)
	}
	posture := Resolve(accounts)
	for _, line := range append(append([]string{}, posture.Evidence...), notes...) {
		if strings.Contains(line, secret) {
			t.Fatalf("evidence line leaked an environment value: %q", line)
		}
	}
	if posture.Detail == secret {
		t.Fatal("detail leaked an environment value")
	}
}

// A basicauth definition's `users` field holds password hashes, and an evidence line is part
// of the payload (I6).
func TestEvidenceNeverCarriesABasicAuthHash(t *testing.T) {
	accounts, _ := FromLabels(input(t, "dash@file"))
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	for _, line := range accounts[0].Evidence {
		if strings.Contains(line, "$2y$") || strings.Contains(line, "notarealhash") {
			t.Fatalf("evidence line leaked a password hash: %q", line)
		}
	}
}

// A forward-auth address can carry credentials. It is redacted before it becomes evidence.
func TestEvidenceRedactsCredentialsInAnAddress(t *testing.T) {
	fleet := []payload.AppStack{{ID: "idp", Services: []payload.Service{{
		Name: "server",
		Labels: map[string]string{
			"traefik.http.middlewares.gate.forwardauth.address": "http://user:hunter2@authentik-server:9000/outpost.goauthentik.io/auth",
		},
	}}}}
	in := Input{
		Service:  payload.Service{Traefik: []payload.TraefikRoute{{Router: "app", Middlewares: []string{"gate@file"}}}},
		Registry: NewRegistry(fleet, "traefik"),
		Hints:    NewHints([]string{authentikMark, authentikEndpointMark}),
	}
	accounts, _ := FromLabels(in)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	for _, line := range accounts[0].Evidence {
		if strings.Contains(line, "hunter2") {
			t.Fatalf("evidence line leaked a credential: %q", line)
		}
	}
	if !containsLine(accounts[0].Evidence, "authentik-server:9000") {
		t.Errorf("evidence = %q, want the address still readable", accounts[0].Evidence)
	}
}

// §4.2: the strongest confidence is reported, a tie goes to AuthMethod precedence, and the
// account that lost stays as evidence — because a label naming a gate the proxy is not
// applying reads very differently from no label at all.
func TestResolvePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		accounts   []Account
		method     payload.AuthMethod
		detail     string
		confidence payload.AuthConfidence
		evidence   string
	}{
		{name: "nothing named a gate", method: payload.AuthNone,
			confidence: payload.ConfidenceObserved, evidence: noGateNamed},
		{name: "confidence outranks method",
			accounts: []Account{
				{Method: payload.AuthAuthentikForwardAuth, Detail: "authentik@docker", Confidence: payload.ConfidenceInferred},
				{Method: payload.AuthBasicAuth, Detail: "dash@file", Confidence: payload.ConfidenceObserved},
			},
			method: payload.AuthBasicAuth, detail: "dash@file", confidence: payload.ConfidenceObserved,
			evidence: "also authentik-forward-auth (inferred) from authentik@docker"},
		{name: "a confirmed reading wins outright",
			accounts: []Account{
				{Method: payload.AuthBasicAuth, Detail: "dash@file", Confidence: payload.ConfidenceObserved},
				{Method: payload.AuthAuthentikForwardAuth, Detail: "live chain", Confidence: payload.ConfidenceConfirmed},
			},
			method: payload.AuthAuthentikForwardAuth, detail: "live chain",
			confidence: payload.ConfidenceConfirmed,
			evidence:   "also basic-auth (observed) from dash@file"},
		{name: "within a confidence, method precedence decides",
			accounts: []Account{
				{Method: payload.AuthOtherOAuth, Detail: "Cloudflare Access", Confidence: payload.ConfidenceObserved},
				{Method: payload.AuthAuthentikForwardAuth, Detail: "authentik@docker", Confidence: payload.ConfidenceObserved},
			},
			method: payload.AuthAuthentikForwardAuth, detail: "authentik@docker",
			confidence: payload.ConfidenceObserved,
			evidence:   "also other-oauth (observed) from Cloudflare Access"},
		{name: "forward-auth outranks a self-configured OIDC",
			accounts: []Account{
				{Method: payload.AuthOtherOAuth, Detail: "OIDC_ISSUER", Confidence: payload.ConfidenceObserved},
				{Method: payload.AuthForwardAuth, Detail: "gate@file", Confidence: payload.ConfidenceObserved},
			},
			method: payload.AuthForwardAuth, detail: "gate@file",
			confidence: payload.ConfidenceObserved,
			evidence:   "also other-oauth (observed) from OIDC_ISSUER"},
		{name: "one account is reported without an also line",
			accounts: []Account{
				{Method: payload.AuthLDAP, Detail: "LDAP_HOST", Confidence: payload.ConfidenceObserved,
					Evidence: []string{"environment `LDAP_HOST` configures an LDAP directory"}},
			},
			method: payload.AuthLDAP, detail: "LDAP_HOST", confidence: payload.ConfidenceObserved,
			evidence: "environment `LDAP_HOST` configures an LDAP directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.accounts)
			if got.Method != tc.method || got.Detail != tc.detail || got.Confidence != tc.confidence {
				t.Errorf("posture = %+v, want %q/%q (%q)", got, tc.method, tc.detail, tc.confidence)
			}
			if !containsLine(got.Evidence, tc.evidence) {
				t.Errorf("evidence = %q, want a line containing %q", got.Evidence, tc.evidence)
			}
			if got.ExposedWithoutAuth {
				t.Error("Resolve set exposedWithoutAuth; that is §14's boolean, not this one's")
			}
		})
	}
}

// A posture is never left with the strongest finding in the report resting on an empty list.
func TestResolveAlwaysCarriesEvidence(t *testing.T) {
	for _, accounts := range [][]Account{
		nil,
		{},
		{{Method: "", Detail: "dropped"}},
		{{Method: payload.AuthNone, Confidence: payload.ConfidenceObserved}},
	} {
		if got := Resolve(accounts); len(got.Evidence) == 0 {
			t.Errorf("Resolve(%+v) produced a posture with no evidence", accounts)
		}
	}
}

// Resolve takes groups so the label reading and a live reading can be handed to one rule
// (§4.2). The groups are one pool; where an account came from decides nothing.
func TestResolveGroupsAreOnePool(t *testing.T) {
	fromLabels := []Account{{Method: payload.AuthForwardAuth, Detail: "gate@file", Confidence: payload.ConfidenceInferred}}
	fromLive := []Account{{Method: payload.AuthAuthentikForwardAuth, Detail: "live chain", Confidence: payload.ConfidenceConfirmed}}
	got := Resolve(fromLabels, fromLive)
	if got.Method != payload.AuthAuthentikForwardAuth || got.Confidence != payload.ConfidenceConfirmed {
		t.Errorf("posture = %+v, want the confirmed live reading", got)
	}
	if !containsLine(got.Evidence, "also forward-auth (inferred) from gate@file") {
		t.Errorf("evidence = %q, want the label reading kept", got.Evidence)
	}
}

// An account that survives to the payload is one the UI can render: a method from the
// vocabulary, a confidence from the vocabulary, and evidence.
func TestResolveProducesVocabularyValues(t *testing.T) {
	in := input(t, "authentik@docker", "dash@file")
	in.Service.Cloudflare = []payload.CloudflareRoute{{
		Hostname: "app.example.com",
		Access:   &payload.CloudflareAccess{Policy: "authenticate"},
	}}
	accounts, _ := FromLabels(in)
	got := Resolve(accounts)
	if !payload.ValidAuthMethod(string(got.Method)) {
		t.Errorf("method %q is not in the vocabulary", got.Method)
	}
	if !payload.ValidAuthConfidence(string(got.Confidence)) {
		t.Errorf("confidence %q is not in the vocabulary", got.Confidence)
	}
	if got.Method != payload.AuthAuthentikForwardAuth {
		t.Errorf("method = %q, want the strongest of three readings", got.Method)
	}
	// All three readings are still in the report; two of them as `also` lines.
	for _, want := range []string{"also basic-auth", "also other-oauth"} {
		if !containsLine(got.Evidence, want) {
			t.Errorf("evidence = %q, want a line containing %q", got.Evidence, want)
		}
	}
}

func envOf(m map[string]string) []payload.EnvVar {
	out := make([]payload.EnvVar, 0, len(m))
	for _, k := range sortedKeys(m) {
		v := m[k]
		out = append(out, payload.EnvVar{Key: k, Value: &v, Source: payload.EnvFromEnvironment})
	}
	return out
}

func containsLine(lines []string, want string) bool {
	if want == "" {
		return true
	}
	for _, line := range lines {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}
