package declare

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// walk runs §14's walk over one service and returns it as the walk left it. The service is addressed
// through the slice Apply mutates, which is also the contract: Apply writes into the fleet it was
// handed rather than returning a copy for a caller to merge.
func walk(t *testing.T, svc payload.Service, refused ...fleet.Refusal) payload.Service {
	t.Helper()
	stacks := []payload.AppStack{{ID: "s", ProjectName: "s", Services: []payload.Service{svc}}}
	Apply(Input{Stacks: stacks, Refused: refused})
	return stacks[0].Services[0]
}

// exposed is a service reachable from outside with no detected gate: `lan` because a published port
// is the plainest form of it, and `none` for the method because nothing was detected.
func exposed(declared *payload.ServiceDeclaration) payload.Service {
	return payload.Service{
		Name:     "app",
		Ingress:  []payload.IngressKind{payload.IngressLan},
		Auth:     payload.AuthPosture{Method: payload.AuthNone},
		Declared: declared,
	}
}

// sidecar is a declaration naming its file, with whatever the case under test adds.
func sidecar() *payload.ServiceDeclaration {
	return &payload.ServiceDeclaration{Declaration: payload.Declaration{File: "s/.labview"}}
}

func hasEntry(entries []string, fragment string) bool {
	for _, e := range entries {
		if strings.Contains(e, fragment) {
			return true
		}
	}
	return false
}

// TestTheFourDriftChecks is §14's drift list, one case per check plus the negative that shows the
// check is a comparison rather than a presence test.
func TestTheFourDriftChecks(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  payload.Service
		// refused is drift check 3's input, which comes from dependency resolution rather than
		// being recomputed here.
		refused []fleet.Refusal
		// want is a fragment the drift entry must contain; empty means no drift at all.
		want string
	}{
		{
			// 1. An acceptance for an exposure that no longer exists. The service is internal now,
			// so there is nothing left to accept and the sentence in the file is stale.
			name: "stale acceptance",
			svc: func() payload.Service {
				d := sidecar()
				d.UnauthenticatedAccepted = &payload.AcceptedExposure{Reason: "read-only status page"}
				svc := exposed(d)
				svc.Ingress = []payload.IngressKind{payload.IngressInternal}
				return svc
			}(),
			want: "is stale: this service is no longer externally reachable",
		},
		{
			// The same acceptance on a service reachable only on the LAN. `lan` is external by
			// §4.1's own grouping, so the acceptance still stands — this is the case a "public or
			// traefik" reading of reachability would wrongly call stale.
			name: "acceptance on a LAN-only service still stands",
			svc: func() payload.Service {
				d := sidecar()
				d.UnauthenticatedAccepted = &payload.AcceptedExposure{Reason: "read-only status page"}
				return exposed(d)
			}(),
		},
		{
			// 2. A conflicting mechanism. The detected gate means the service is not exposed, so
			// rule 1 does not fire and the comparison reaches rule 3.
			name: "conflicting mechanism",
			svc: func() payload.Service {
				d := sidecar()
				d.Auth = []payload.DeclaredAuth{{Mechanism: payload.MechanismAppLDAP}}
				svc := exposed(d)
				svc.Auth = payload.AuthPosture{Method: payload.AuthAuthentikOAuth}
				return svc
			}(),
			want: "different mechanisms in the same layer",
		},
		{
			// 3. A declared dependency that no longer names exactly one service, carrying what was
			// weighed so the entry is answerable.
			name: "refused declared dependency",
			svc:  exposed(sidecar()),
			refused: []fleet.Refusal{{
				From: "s/app", Ref: "probe", File: "s/.labview",
				Reason:     "names more than one service and no service of that name in this stack",
				Considered: []string{"a/probe", "b/probe"},
			}},
			want: "the declared dependency `probe` in `s/.labview` names more than one service",
		},
		{
			// 4. Expected ingress, both directions in one entry. One direction alone would hide a
			// service that picked up an exposure nobody expected.
			name: "expected ingress mismatch in both directions",
			svc: func() payload.Service {
				d := sidecar()
				d.ExpectedIngress = []payload.IngressKind{payload.IngressInternal}
				svc := exposed(d)
				svc.Ingress = []payload.IngressKind{payload.IngressTraefik}
				return svc
			}(),
			want: "missing: internal; unexpected: traefik",
		},
		{
			name: "expected ingress that matches",
			svc: func() payload.Service {
				d := sidecar()
				d.ExpectedIngress = []payload.IngressKind{payload.IngressLan}
				return exposed(d)
			}(),
		},
		{
			// No expectation written is not an expectation of nothing. A file that says nothing
			// about ingress cannot be wrong about it.
			name: "no expected ingress declared",
			svc:  exposed(sidecar()),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := walk(t, tc.svc, tc.refused...).Declared.Drift

			switch {
			case tc.want == "" && len(got) != 0:
				t.Errorf("drift = %v, want none", got)
			case tc.want != "" && !hasEntry(got, tc.want):
				t.Errorf("drift = %v, want an entry saying %q", got, tc.want)
			}
		})
	}
}

// TestExpectedIngressIsOneEntryPerDirection is the shape of drift check 4's sentence: a direction
// with nothing in it is left out rather than written empty, and the mismatch is one entry either
// way — the declaration is wrong once, not twice.
func TestExpectedIngressIsOneEntryPerDirection(t *testing.T) {
	for _, tc := range []struct {
		name             string
		expected         []payload.IngressKind
		detected         []payload.IngressKind
		want, mustNotSay string
	}{
		{
			name:     "missing only",
			expected: []payload.IngressKind{payload.IngressTraefik, payload.IngressLan},
			detected: []payload.IngressKind{payload.IngressLan},
			want:     "missing: traefik", mustNotSay: "unexpected",
		},
		{
			name:     "unexpected only",
			expected: []payload.IngressKind{payload.IngressLan},
			detected: []payload.IngressKind{payload.IngressPublic, payload.IngressLan},
			want:     "unexpected: public", mustNotSay: "missing",
		},
		{
			// Both directions, and the kinds within each are in the canonical order of §4.1 rather
			// than in whichever order the file happened to list them.
			name:     "canonical order inside each direction",
			expected: []payload.IngressKind{payload.IngressInternal, payload.IngressTraefik},
			detected: []payload.IngressKind{payload.IngressLan, payload.IngressPublic},
			want:     "missing: traefik, internal; unexpected: public, lan",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := sidecar()
			d.ExpectedIngress = tc.expected
			svc := exposed(d)
			svc.Ingress = tc.detected

			drift := walk(t, svc).Declared.Drift
			if len(drift) != 1 {
				t.Fatalf("drift = %v, want exactly one entry", drift)
			}
			if !strings.Contains(drift[0], tc.want) {
				t.Errorf("drift = %q, want it to say %q", drift[0], tc.want)
			}
			if tc.mustNotSay != "" && strings.Contains(drift[0], tc.mustNotSay) {
				t.Errorf("drift = %q, want no %q direction: there is nothing in it",
					drift[0], tc.mustNotSay)
			}
		})
	}
}

// TestOneWalkFillsBothListsAndNeverTheSameFact is why §14 is one walk with two selectors. Drift and
// unconfirmed are two readings of the same comparison — drift is a declaration the scan
// contradicts, unconfirmed is one it could not corroborate — and a fact must land in exactly one.
//
// This service produces one of each at once: a conflicting `app-ldap` in the detected layer, and an
// `external-proxy` in the layer nothing was detected in.
func TestOneWalkFillsBothListsAndNeverTheSameFact(t *testing.T) {
	d := sidecar()
	d.Auth = []payload.DeclaredAuth{
		{Mechanism: payload.MechanismAppLDAP},
		{Mechanism: payload.MechanismExternalProxy},
	}
	svc := exposed(d)
	svc.Auth = payload.AuthPosture{Method: payload.AuthAuthentikOAuth}

	got := walk(t, svc).Declared
	if len(got.Drift) != 1 || !strings.Contains(got.Drift[0], "same layer") {
		t.Errorf("drift = %v, want the one conflict", got.Drift)
	}
	if len(got.Unconfirmed) != 1 || !strings.Contains(got.Unconfirmed[0], "`external-proxy`") {
		t.Errorf("unconfirmed = %v, want the one uncorroborated mechanism", got.Unconfirmed)
	}
	// Neither list may repeat the other's fact. Merging them would tell an operator that something
	// the scan simply could not see is something the scan disagrees with.
	if hasEntry(got.Unconfirmed, "same layer") {
		t.Errorf("the conflict is also in unconfirmed: %v", got.Unconfirmed)
	}
	if hasEntry(got.Drift, "could not be corroborated") {
		t.Errorf("the uncorroborated mechanism is also in drift: %v", got.Drift)
	}
}

// TestUnconfirmedSentenceCountsWhatItLists is the grammar the fifth collection is written in — one
// mechanism describes a layer, several describe layers — because an entry a reader is meant to act
// on is read as a sentence.
func TestUnconfirmedSentenceCountsWhatItLists(t *testing.T) {
	for _, tc := range []struct {
		mechanisms []payload.DeclaredAuthMechanism
		want       string
	}{
		{[]payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
			"`app-oidc` declared in `s/.labview` could not be corroborated"},
		{[]payload.DeclaredAuthMechanism{payload.MechanismAppOIDC}, "the layer it describes"},
		{[]payload.DeclaredAuthMechanism{payload.MechanismAppOIDC, payload.MechanismAppLDAP},
			"`app-oidc` and `app-ldap`"},
		{[]payload.DeclaredAuthMechanism{payload.MechanismAppOIDC, payload.MechanismAppLDAP},
			"the layer they describe"},
	} {
		d := sidecar()
		for _, m := range tc.mechanisms {
			d.Auth = append(d.Auth, payload.DeclaredAuth{Mechanism: m})
		}
		svc := exposed(d)
		// A detected gate in the other layer, so rule 1 does not fire and the app layer is the
		// unmeasured one.
		svc.Auth = payload.AuthPosture{Method: payload.AuthAuthentikForwardAuth}

		got := walk(t, svc).Declared.Unconfirmed
		if !hasEntry(got, tc.want) {
			t.Errorf("unconfirmed = %v, want an entry saying %q", got, tc.want)
		}
	}
}

// TestSuppliesAndSupplementsAreStatedInTheOpen is rule 2's disclosure requirement. `supplies` is
// the one verdict a declaration moves, so the service says so in a note naming the mechanism and
// the file; `supplements` is noted for the same reason and is not drift. `redundant` says nothing,
// and `conflicts` is a drift entry rather than a note — a finding, not a remark.
func TestSuppliesAndSupplementsAreStatedInTheOpen(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detected  payload.AuthMethod
		mechanism payload.DeclaredAuthMechanism
		agreement payload.DeclaredAuthAgreement
		note      string
	}{
		{
			name: "supplies", detected: payload.AuthNone, mechanism: payload.MechanismAppOIDC,
			agreement: payload.AgreementSupplies, note: "is the only account of a gate",
		},
		{
			name: "supplements", detected: payload.AuthAuthentikForwardAuth,
			mechanism: payload.MechanismAppOIDC,
			agreement: payload.AgreementSupplements, note: "both can be true at once",
		},
		{
			name: "redundant", detected: payload.AuthAuthentikOAuth,
			mechanism: payload.MechanismAppOIDC, agreement: payload.AgreementRedundant,
		},
		{
			name: "conflicts", detected: payload.AuthAuthentikOAuth,
			mechanism: payload.MechanismAppLDAP, agreement: payload.AgreementConflicts,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := sidecar()
			d.Auth = []payload.DeclaredAuth{{Mechanism: tc.mechanism}}
			svc := exposed(d)
			svc.Auth = payload.AuthPosture{Method: tc.detected}

			got := walk(t, svc)
			if got.Declared.AuthAgreement != tc.agreement {
				t.Fatalf("agreement = %q, want %q", got.Declared.AuthAgreement, tc.agreement)
			}
			switch {
			case tc.note == "" && len(got.Notes) != 0:
				t.Errorf("notes = %v, want none for %q", got.Notes, tc.agreement)
			case tc.note != "" && !hasEntry(got.Notes, tc.note):
				t.Errorf("notes = %v, want one saying %q", got.Notes, tc.note)
			}
			// A conflict is a finding and belongs in drift; it is never softened into a note.
			if tc.agreement == payload.AgreementConflicts && len(got.Declared.Drift) != 1 {
				t.Errorf("drift = %v, want the conflict as an entry", got.Declared.Drift)
			}
		})
	}
}

// TestADeclarationClearsTheFindingAndNothingElse is rule 2 exactly: the declaration moves the
// exposure finding and leaves the detected method alone. A file that also changed the method would
// let anyone turn an unprotected service into a protected one by typing a line.
func TestADeclarationClearsTheFindingAndNothingElse(t *testing.T) {
	// Reachable, nothing detected, nothing declared: the finding stands.
	bare := walk(t, exposed(nil))
	if !bare.Auth.ExposedWithoutAuth {
		t.Error("a reachable service with no gate and no declaration is not flagged")
	}

	d := sidecar()
	d.Auth = []payload.DeclaredAuth{{Mechanism: payload.MechanismAppOIDC}}
	declared := walk(t, exposed(d))

	if declared.Auth.ExposedWithoutAuth {
		t.Error("the declaration did not clear the exposure finding")
	}
	if declared.Auth.Method != payload.AuthNone {
		t.Errorf("method = %q, want it left at `none`: a declaration is not evidence of a gate",
			declared.Auth.Method)
	}
	if declared.Auth.Confidence != "" || len(declared.Auth.Evidence) != 0 {
		t.Errorf("the declaration wrote confidence %q and evidence %v onto a detection",
			declared.Auth.Confidence, declared.Auth.Evidence)
	}
}

// TestAnAcceptedExposureIsStillAnExposure is rule 3. An acceptance is an operator saying the
// exposure is intended, which is not the same as saying there is a gate: the finding stands, and
// §14's own counter is where the acceptance is reported.
func TestAnAcceptedExposureIsStillAnExposure(t *testing.T) {
	d := sidecar()
	d.UnauthenticatedAccepted = &payload.AcceptedExposure{Reason: "read-only status page"}
	got := walk(t, exposed(d))

	if !got.Auth.ExposedWithoutAuth {
		t.Error("an accepted exposure cleared the finding; acceptance is not a gate")
	}
	if len(got.Declared.Drift) != 0 {
		t.Errorf("drift = %v, want none: the acceptance is current", got.Declared.Drift)
	}
}

// TestTheVerdictIsWrittenWhetherOrNotThereIsAFile is the ordering inside the walk: the exposure
// verdict is set for every service, and only the declaration-derived lists are skipped when there
// is no sidecar. A service with no file is the common case and must still be counted.
func TestTheVerdictIsWrittenWhetherOrNotThereIsAFile(t *testing.T) {
	if !walk(t, exposed(nil)).Auth.ExposedWithoutAuth {
		t.Error("a service with no sidecar was skipped before the verdict was written")
	}
	// And an internal service is not flagged, so the verdict is a reading rather than a constant.
	internal := exposed(nil)
	internal.Ingress = []payload.IngressKind{payload.IngressInternal}
	if walk(t, internal).Auth.ExposedWithoutAuth {
		t.Error("an internal service was flagged as exposed")
	}
}

// TestADetectedGateLeavesNothingToSupply is why `supplies` cannot be reported on a protected
// service: the walk computes `reachable AND NOT hasEdgeAuth` once and shares it, so a detected gate
// removes the exposure, the finding and the outcome together.
func TestADetectedGateLeavesNothingToSupply(t *testing.T) {
	d := sidecar()
	d.Auth = []payload.DeclaredAuth{{Mechanism: payload.MechanismAppOIDC}}
	svc := exposed(d)
	svc.Auth = payload.AuthPosture{Method: payload.AuthAuthentikOAuth}

	got := walk(t, svc)
	if got.Declared.AuthAgreement == payload.AgreementSupplies {
		t.Error("a service with a detected gate was reported as having its gate supplied by a file")
	}
	if got.Auth.ExposedWithoutAuth {
		t.Error("a service with a detected gate is flagged as exposed")
	}
}

// TestAProbeGateAlsoRemovesTheExposure is the second term of the shared expression, which matters
// because it is the one a withheld probe can remove: a gate the probe read protects the service
// even though the detected method stays `none`.
func TestAProbeGateAlsoRemovesTheExposure(t *testing.T) {
	svc := exposed(nil)
	svc.Probe = &payload.ServiceProbe{
		Endpoint: "http://192.0.2.10:8080/", Gate: payload.GateRedirectLogin,
	}

	if walk(t, svc).Auth.ExposedWithoutAuth {
		t.Error("a probe-read gate did not remove the exposure finding")
	}
	// And with the probe withheld the same service is flagged, which is the direction §13.1 allows:
	// withholding a probe can only leave a service in the exposed count, never take one out.
	svc.Probe = nil
	if !walk(t, svc).Auth.ExposedWithoutAuth {
		t.Error("the same service with no probe is not flagged")
	}
}

// TestProbeWithNoLoginPageIsUnconfirmedNeverDrift is the last entry §14 collects, and the one whose
// classification matters most. The probe cannot see an application's own login form, so a probe that
// reached the service and read nothing contradicts the declaration in no way at all — it is a note
// about what was not confirmed.
func TestProbeWithNoLoginPageIsUnconfirmedNeverDrift(t *testing.T) {
	status := 200
	build := func(probe *payload.ServiceProbe) payload.Service {
		d := sidecar()
		d.Auth = []payload.DeclaredAuth{{Mechanism: payload.MechanismAppOIDC}}
		svc := exposed(d)
		svc.Probe = probe
		return svc
	}

	answered := walk(t, build(&payload.ServiceProbe{
		Endpoint: "http://192.0.2.10:8080/", Status: &status,
	}))
	if !hasEntry(answered.Declared.Unconfirmed, "read no login page") {
		t.Errorf("unconfirmed = %v, want the probe entry", answered.Declared.Unconfirmed)
	}
	if hasEntry(answered.Declared.Drift, "read no login page") {
		t.Errorf("drift = %v, want the probe entry nowhere in it: the probe contradicts nothing",
			answered.Declared.Drift)
	}
	// It quotes the endpoint it reached, so the note is checkable rather than an assertion.
	if !hasEntry(answered.Declared.Unconfirmed, "`http://192.0.2.10:8080/`") {
		t.Errorf("unconfirmed = %v, want the endpoint quoted", answered.Declared.Unconfirmed)
	}

	// A probe that never got a response says nothing either way, and I4 requires a failed request
	// to produce no finding.
	silent := walk(t, build(&payload.ServiceProbe{Endpoint: "http://192.0.2.10:8080/"}))
	if hasEntry(silent.Declared.Unconfirmed, "read no login page") {
		t.Errorf("unconfirmed = %v, want nothing from a request that failed",
			silent.Declared.Unconfirmed)
	}
	// And a service never probed at all.
	unasked := walk(t, build(nil))
	if hasEntry(unasked.Declared.Unconfirmed, "read no login page") {
		t.Errorf("unconfirmed = %v, want nothing from a probe that never ran",
			unasked.Declared.Unconfirmed)
	}
}

// TestRefusalsLandOnTheServiceThatWroteThem is what the grouping in drift check 3 is for: a
// reference is drift for the file that wrote it, and putting it on the service it failed to name
// would make an operator edit the wrong file.
func TestRefusalsLandOnTheServiceThatWroteThem(t *testing.T) {
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s",
		Services: []payload.Service{
			{Name: "caller", Declared: sidecar()},
			{Name: "other", Declared: sidecar()},
		},
	}}
	Apply(Input{
		Stacks: stacks,
		Refused: []fleet.Refusal{
			{From: "s/caller", Ref: "gone", File: "s/.labview", Reason: "names no scanned service"},
			{From: "s/caller", Ref: "also-gone", File: "s/.labview", Reason: "names no scanned service"},
		},
	})

	if got := stacks[0].Services[0].Declared.Drift; len(got) != 2 {
		t.Errorf("caller's drift = %v, want both refusals: one entry per reference", got)
	}
	if got := stacks[0].Services[1].Declared.Drift; len(got) != 0 {
		t.Errorf("other's drift = %v, want none", got)
	}
}

// TestAmbiguousRefusalCarriesItsCandidates is the answerability of drift check 3: a reference naming
// two services is only actionable if the entry says which two.
func TestAmbiguousRefusalCarriesItsCandidates(t *testing.T) {
	got := walk(t, exposed(sidecar()), fleet.Refusal{
		From: "s/app", Ref: "probe", File: "s/.labview",
		Reason:     "names more than one service",
		Considered: []string{"a/probe", "b/probe"},
	}).Declared.Drift

	if len(got) != 1 {
		t.Fatalf("drift = %v, want one entry", got)
	}
	if !strings.Contains(got[0], "candidates: `a/probe`, `b/probe`") {
		t.Errorf("drift = %q, want the candidates named", got[0])
	}

	// A refusal with nothing to weigh writes no empty candidate list.
	plain := walk(t, exposed(sidecar()), fleet.Refusal{
		From: "s/app", Ref: "gone", File: "s/.labview", Reason: "names no scanned service",
	}).Declared.Drift
	if strings.Contains(plain[0], "candidates") {
		t.Errorf("drift = %q, want no candidate list: there were none", plain[0])
	}
}

// TestBothListsAreRebuiltFromNothing is why Apply clears before it collects. Drift and unconfirmed
// are conclusions about *this* scan, so a stale entry from a previous one — or from a sidecar file
// that wrote the field itself — must not survive into the payload.
func TestBothListsAreRebuiltFromNothing(t *testing.T) {
	d := sidecar()
	d.Drift = []string{"a finding from a previous scan"}
	d.Unconfirmed = []string{"and a remark from one"}
	d.AuthAgreement = payload.AgreementConflicts

	got := walk(t, exposed(d)).Declared
	if len(got.Drift) != 0 {
		t.Errorf("drift = %v, want the stale entry gone", got.Drift)
	}
	if len(got.Unconfirmed) != 0 {
		t.Errorf("unconfirmed = %v, want the stale entry gone", got.Unconfirmed)
	}
	// The agreement is a conclusion too, and this service declares no mechanism at all.
	if got.AuthAgreement != "" {
		t.Errorf("authAgreement = %q, want it recomputed to nothing", got.AuthAgreement)
	}
}

// TestApplyIsDeterministic is I7 over the walk: two runs over one fleet produce the same entries in
// the same order, including the order of the drift list, which is the order §14 states its checks in.
func TestApplyIsDeterministic(t *testing.T) {
	build := func() []payload.AppStack {
		d := sidecar()
		d.Auth = []payload.DeclaredAuth{{Mechanism: payload.MechanismAppLDAP}}
		d.ExpectedIngress = []payload.IngressKind{payload.IngressInternal}
		svc := exposed(d)
		svc.Auth = payload.AuthPosture{Method: payload.AuthAuthentikOAuth}
		return []payload.AppStack{{ID: "s", ProjectName: "s", Services: []payload.Service{svc}}}
	}
	refused := []fleet.Refusal{
		{From: "s/app", Ref: "gone", File: "s/.labview", Reason: "names no scanned service"},
	}

	first, second := build(), build()
	Apply(Input{Stacks: first, Refused: refused})
	Apply(Input{Stacks: second, Refused: refused})

	a, b := first[0].Services[0].Declared.Drift, second[0].Services[0].Declared.Drift
	if len(a) != 3 {
		t.Fatalf("drift = %v, want all three entries: the conflict, the refusal and the mismatch", a)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("entry %d differs between runs:\n  %q\n  %q", i, a[i], b[i])
		}
	}
	// And the order is the order the checks are stated in: the conflict (2), the refusal (3), then
	// the ingress mismatch (4). Check 1 does not apply here.
	for i, want := range []string{"same layer", "the declared dependency", "expected ingress"} {
		if !strings.Contains(a[i], want) {
			t.Errorf("entry %d = %q, want check %d's sentence (%q)", i, a[i], i+2, want)
		}
	}
}

// TestApplyIsIdempotent is the same property across repeated runs over one object, which is what
// the cache does when it rebuilds a payload in place: the lists do not grow.
func TestApplyIsIdempotent(t *testing.T) {
	d := sidecar()
	d.Auth = []payload.DeclaredAuth{{Mechanism: payload.MechanismAppOIDC}}
	stacks := []payload.AppStack{{
		ID: "s", ProjectName: "s", Services: []payload.Service{exposed(d)},
	}}

	Apply(Input{Stacks: stacks})
	first := stacks[0].Services[0].Declared

	Apply(Input{Stacks: stacks})
	second := stacks[0].Services[0].Declared

	if len(second.Unconfirmed) != len(first.Unconfirmed) {
		t.Errorf("unconfirmed grew from %d to %d over two runs",
			len(first.Unconfirmed), len(second.Unconfirmed))
	}
	if len(second.Drift) != len(first.Drift) {
		t.Errorf("drift grew from %d to %d over two runs", len(first.Drift), len(second.Drift))
	}
	// Notes are not covered by this property and cannot be: they carry findings from every stage
	// before this one, so the walk has nothing of its own to rebuild them from. The walk is
	// therefore run once per scan, which is what the pipeline does (§15).
}
