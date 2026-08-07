package probe

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

func routed() payload.Service {
	return payload.Service{Traefik: []payload.TraefikRoute{router("app", "app.lan", true)}}
}

func TestNotAskedAndNoAddressAreDifferentFacts(t *testing.T) {
	// The address test runs first. Asking about detected authentication first would count every database
	// and every queue as skipped, and the skipped figure would stop meaning *withheld* and start meaning
	// *not an HTTP service* (§13.1).
	database := payload.Service{Ports: []payload.PortMapping{port("5432:5432", "5432")}}
	database.Auth.Method = payload.AuthNone

	got := Eligible(database, "nas.lan")
	if got.Skipped {
		t.Fatal("a service with no HTTP address was never a candidate, so it is not skipped")
	}
	if got.Candidate() {
		t.Fatal("and it is not a candidate either")
	}
}

func TestACandidateWhoseAuthenticationWasAlreadyDetectedIsWithheld(t *testing.T) {
	s := routed()
	s.Auth.Method = payload.AuthAuthentikForwardAuth

	got := Eligible(s, "")
	if !got.Skipped {
		t.Fatal("asking could tell nobody anything, so the request is withheld")
	}
	if len(got.Targets) != 0 {
		t.Fatalf("and nothing is asked; got %+v", got.Targets)
	}
	if !got.Candidate() {
		t.Fatal("it was a candidate, which is what makes it countable as skipped")
	}
}

func TestAnInferredPostureCountsAsDetected(t *testing.T) {
	// §13.1 says so in as many words. An inferred posture is still a posture, and probing behind one
	// would spend a request to learn what is already recorded.
	s := routed()
	s.Auth.Method = payload.AuthForwardAuth

	if !Eligible(s, "").Skipped {
		t.Fatal("a forward-auth posture is detected authentication")
	}
}

func TestDetectedAuthenticationIsTheExposureVerdictsOwnExpression(t *testing.T) {
	// §13.1 requires the *same* expression, evaluated once and shared, so eligibility and the notes
	// explaining the outcome cannot come apart.
	for _, method := range payload.AuthMethods {
		s := routed()
		s.Auth.Method = method

		if got, want := DetectedAuth(s), s.ConfiguredEdgeAuth(); got != want {
			t.Fatalf("DetectedAuth and Service.ConfiguredEdgeAuth disagree for %q: %v vs %v",
				method, got, want)
		}
	}
}

func TestNeitherAProbeResultNorADeclarationCountsAsDetected(t *testing.T) {
	// The first would make the probe a function of itself; the second would let operator input silence a
	// measurement (I3, §14).
	probed := routed()
	probed.Auth.Method = payload.AuthNone
	probed.Probe = &payload.ServiceProbe{Gate: payload.GatePasswordForm}

	if DetectedAuth(probed) {
		t.Fatal("a probe gate is not detected authentication")
	}

	declared := routed()
	declared.Auth.Method = payload.AuthNone
	declared.Declared = &payload.ServiceDeclaration{
		Auth: []payload.DeclaredAuth{{Mechanism: payload.MechanismAppLocalAccounts}},
	}

	if DetectedAuth(declared) {
		t.Fatal("a declaration is not detected authentication")
	}
}

func TestWithholdingARequestCanOnlyLeaveAServiceInTheExposedCount(t *testing.T) {
	// The exposure verdict is `configuredEdgeAuth || probeGate`, and withholding a probe only ever
	// removes the second term. So the two facts stay written as two even though they are disjoint.
	open := routed()
	open.Auth.Method = payload.AuthNone

	if open.HasEdgeAuth() {
		t.Fatal("with no posture and no probe result, the service is exposed")
	}
	if Eligible(open, "").Skipped {
		t.Fatal("and it is asked, because asking is the only thing that could change that")
	}
}
