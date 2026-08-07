package payload

import (
	"reflect"
	"testing"
)

// §4's vocabularies are closed, and their order is load-bearing: AuthMethods is a
// precedence order the posture roll-up resolves ties by, ProbeGates is the order the
// reason sentence branches in, IngressKinds is the order every ingress set is written in.
// Each is transcribed here as a literal, so reordering a constant fails rather than
// quietly changing a verdict.
func TestClosedSetMembership(t *testing.T) {
	t.Run("IngressKind", func(t *testing.T) {
		want := []IngressKind{"public", "traefik", "lan", "internal", "none"}
		if !reflect.DeepEqual(IngressKinds, want) {
			t.Errorf("got %v, want %v", IngressKinds, want)
		}
		if !ValidIngressKind("lan") || ValidIngressKind("Lan") || ValidIngressKind("") {
			t.Error("ValidIngressKind accepts only exact members")
		}
	})

	t.Run("AuthMethod", func(t *testing.T) {
		want := []AuthMethod{"authentik-forward-auth", "authentik-oauth", "authentik-ldap",
			"forward-auth", "other-oauth", "ldap", "basic-auth", "none"}
		if !reflect.DeepEqual(AuthMethods, want) {
			t.Errorf("got %v, want %v", AuthMethods, want)
		}
		if !ValidAuthMethod("basic-auth") || ValidAuthMethod("basic") {
			t.Error("ValidAuthMethod accepts only exact members")
		}
	})

	t.Run("AuthConfidence", func(t *testing.T) {
		want := []AuthConfidence{"confirmed", "observed", "inferred"}
		if !reflect.DeepEqual(AuthConfidences, want) {
			t.Errorf("got %v, want %v", AuthConfidences, want)
		}
	})

	t.Run("ConnectionPhase", func(t *testing.T) {
		want := []ConnectionPhase{"disabled", "not-configured", "not-found", "credential",
			"resolve", "connect", "tls", "timeout",
			"authenticate", "authorize", "path", "status", "protocol",
			"partial", "connected"}
		if !reflect.DeepEqual(ConnectionPhases, want) {
			t.Errorf("got %v, want %v", ConnectionPhases, want)
		}
		if !ValidConnectionPhase("tls") || ValidConnectionPhase("TLS") {
			t.Error("ValidConnectionPhase accepts only exact members")
		}
	})

	t.Run("ProbeGate", func(t *testing.T) {
		want := []ProbeGate{"challenge", "redirect-origin", "redirect-login",
			"meta-refresh-login", "sso-form", "password-form", "credential-form",
			"state-challenge"}
		if !reflect.DeepEqual(ProbeGates, want) {
			t.Errorf("got %v, want %v", ProbeGates, want)
		}
	})

	t.Run("ProbeVantage", func(t *testing.T) {
		want := []ProbeVantage{"public", "traefik", "lan"}
		if !reflect.DeepEqual(ProbeVantages, want) {
			t.Errorf("got %v, want %v", ProbeVantages, want)
		}
	})

	t.Run("DeclaredAuthMechanism", func(t *testing.T) {
		want := []DeclaredAuthMechanism{"app-local-accounts", "app-ldap", "app-oidc",
			"app-saml", "app-token", "mtls", "network-restricted", "external-proxy", "other"}
		if !reflect.DeepEqual(DeclaredAuthMechanisms, want) {
			t.Errorf("got %v, want %v", DeclaredAuthMechanisms, want)
		}
		if !ValidDeclaredAuthMechanism("mtls") || ValidDeclaredAuthMechanism("app-basic") {
			t.Error("ValidDeclaredAuthMechanism accepts only exact members")
		}
	})

	t.Run("LoginFailureReason", func(t *testing.T) {
		want := []LoginFailureReason{"credentials", "throttled", "method-unavailable",
			"session-expired", "oidc-state", "oidc-provider", "oidc-token", "oidc-identity"}
		if !reflect.DeepEqual(LoginFailureReasons, want) {
			t.Errorf("got %v, want %v", LoginFailureReasons, want)
		}
		// A login redirect carrying anything else must be rejected, not displayed (§4.7).
		if ValidLoginFailureReason("nope") || ValidLoginFailureReason("") {
			t.Error("ValidLoginFailureReason accepts only exact members")
		}
	})

	t.Run("AuthentikProviderKind", func(t *testing.T) {
		want := []AuthentikProviderKind{"proxy", "oauth2", "ldap", "saml", "radius", "scim", "other"}
		if !reflect.DeepEqual(AuthentikProviderKinds, want) {
			t.Errorf("got %v, want %v", AuthentikProviderKinds, want)
		}
	})

	t.Run("LoginMethod", func(t *testing.T) {
		want := []LoginMethod{"passwd", "oidc"}
		if !reflect.DeepEqual(LoginMethods, want) {
			t.Errorf("got %v, want %v", LoginMethods, want)
		}
	})
}

// The external ingress kinds are their own question over their own three members, so that
// the exposure finding and the stale-acceptance check provably ask the same thing (§4.1).
func TestIngressExternalGrouping(t *testing.T) {
	want := []IngressKind{IngressPublic, IngressTraefik, IngressLan}
	if !reflect.DeepEqual(ExternalIngressKinds, want) {
		t.Errorf("got %v, want %v", ExternalIngressKinds, want)
	}
	for _, k := range IngressKinds {
		wantExternal := k == IngressPublic || k == IngressTraefik || k == IngressLan
		if k.IsExternal() != wantExternal {
			t.Errorf("%s.IsExternal() = %v", k, k.IsExternal())
		}
	}
	if IngressKind("nonsense").IsExternal() {
		t.Error("an unknown kind must not count as external")
	}
}

// Rank is what resolves two accounts of one service disagreeing (§4.2). An unknown member
// must rank last, so a member added by a future payload version cannot outrank a real gate.
func TestRankOrdering(t *testing.T) {
	for i := 1; i < len(AuthMethods); i++ {
		if AuthMethods[i-1].Rank() >= AuthMethods[i].Rank() {
			t.Errorf("%s does not outrank %s", AuthMethods[i-1], AuthMethods[i])
		}
	}
	if AuthMethod("from-the-future").Rank() <= AuthNone.Rank() {
		t.Error("an unknown method must rank after every known one")
	}
	for i := 1; i < len(AuthConfidences); i++ {
		if AuthConfidences[i-1].Rank() >= AuthConfidences[i].Rank() {
			t.Errorf("%s does not outrank %s", AuthConfidences[i-1], AuthConfidences[i])
		}
	}
	if AuthConfidence("").Rank() <= ConfidenceInferred.Rank() {
		t.Error("an unknown confidence must rank after every known one")
	}
}

// Detected is the single place "is there a gate" is decided, so eligibility for the probe
// and the exposure verdict cannot come apart (§13.1).
func TestAuthMethodDetected(t *testing.T) {
	for _, m := range AuthMethods {
		if got, want := m.Detected(), m != AuthNone; got != want {
			t.Errorf("%s.Detected() = %v, want %v", m, got, want)
		}
	}
	if AuthMethod("").Detected() {
		t.Error("an empty method is not a detected gate")
	}
}

// The first four phases stop before the network, which is what the banner rule of §15
// tests: a banner for partial, and for any failure that is not disabled or not-configured.
func TestPhaseBeforeTheNetwork(t *testing.T) {
	before := map[ConnectionPhase]bool{PhaseDisabled: true, PhaseNotConfigured: true}
	for _, p := range ConnectionPhases {
		if got := p.BeforeTheNetwork(); got != before[p] {
			t.Errorf("%s.BeforeTheNetwork() = %v, want %v", p, got, before[p])
		}
	}
}
