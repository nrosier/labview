package declare

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// declaring builds one service that declares the given mechanisms and detected the given method.
// The sidecar file is always named, because a declaration with no file is not evidence of anything
// and every sentence §14 writes has to say where it was read from (I1).
func declaring(detected payload.AuthMethod, mechanisms ...payload.DeclaredAuthMechanism) payload.Service {
	var auth []payload.DeclaredAuth
	for _, m := range mechanisms {
		auth = append(auth, payload.DeclaredAuth{Mechanism: m})
	}
	return payload.Service{
		Name: "app",
		Auth: payload.AuthPosture{Method: detected},
		Declared: &payload.ServiceDeclaration{
			Declaration: payload.Declaration{File: "s/.labview"},
			Auth:        auth,
		},
	}
}

// TestAgreementsAreTestedInOrder is §14's four outcomes in the order it states them. The order is
// the whole content of the rule: `supplies` is asked before any family is consulted, `redundant`
// before `conflicts`, and `conflicts` before `supplements`. Reordering any pair changes verdicts.
func TestAgreementsAreTestedInOrder(t *testing.T) {
	for _, tc := range []struct {
		name           string
		detected       payload.AuthMethod
		declared       []payload.DeclaredAuthMechanism
		wouldBeExposed bool
		agreement      payload.DeclaredAuthAgreement
		mechanism      payload.DeclaredAuthMechanism
		// sentence is a fragment the outcome must say; empty means it must say nothing at all.
		sentence string
	}{
		{
			// 1. The service would be exposed and the declaration is the only account of a gate.
			// Asked first and without reference to any family, which is why the caller's
			// `reachable AND NOT hasEdgeAuth` makes the detected method `none` here by construction.
			name: "supplies", detected: payload.AuthNone,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC}, wouldBeExposed: true,
			agreement: payload.AgreementSupplies, mechanism: payload.MechanismAppOIDC,
			sentence: "the only account of a gate on this service",
		},
		{
			// 2. Same family. Rendered nowhere, so it carries no sentence: declared and detected
			// agreeing is not news.
			name: "redundant", detected: payload.AuthAuthentikOAuth,
			declared:  []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
			agreement: payload.AgreementRedundant, mechanism: payload.MechanismAppOIDC,
		},
		{
			// `other-oauth` is a different member of the same family, and a family is what the
			// comparison is between — not a member.
			name: "redundant across the family", detected: payload.AuthOtherOAuth,
			declared:  []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
			agreement: payload.AgreementRedundant, mechanism: payload.MechanismAppOIDC,
		},
		{
			// 3. Same layer, different family: the application cannot be authenticating its own
			// users by LDAP and by OIDC-from-Authentik at once without one of the two statements
			// being out of date.
			name: "conflicts", detected: payload.AuthAuthentikOAuth,
			declared:  []payload.DeclaredAuthMechanism{payload.MechanismAppLDAP},
			agreement: payload.AgreementConflicts, mechanism: payload.MechanismAppLDAP,
			sentence: "different mechanisms in the same layer",
		},
		{
			// 4. Different layers. Both statements can be true at once, so this is noted and never
			// drifted.
			name: "supplements", detected: payload.AuthAuthentikForwardAuth,
			declared:  []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
			agreement: payload.AgreementSupplements, mechanism: payload.MechanismAppOIDC,
			sentence: "both can be true at once",
		},
		{
			// And the other direction across the same split: a declared gate beside a detected
			// application login.
			name: "supplements the other way", detected: payload.AuthAuthentikOAuth,
			declared:  []payload.DeclaredAuthMechanism{payload.MechanismExternalProxy},
			agreement: payload.AgreementSupplements, mechanism: payload.MechanismExternalProxy,
			sentence: "both can be true at once",
		},
		{
			// A detected method no declared mechanism describes. `basic-auth` is a real gate with
			// no family, so it corroborates and contradicts nothing.
			name: "detected method outside every family", detected: payload.AuthBasicAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
		},
		{
			// A declared mechanism this scan has no instrument for, beside a detected gate.
			name: "declared mechanism outside every family", detected: payload.AuthAuthentikOAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismMTLS},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmp := Compare(declaring(tc.detected, tc.declared...), tc.wouldBeExposed)

			if cmp.Agreement != tc.agreement {
				t.Errorf("agreement = %q, want %q", cmp.Agreement, tc.agreement)
			}
			if cmp.Mechanism != tc.mechanism {
				t.Errorf("mechanism = %q, want %q", cmp.Mechanism, tc.mechanism)
			}
			// The detected method travels with every non-empty outcome, because every sentence
			// naming a conflict has to name both sides of it.
			if cmp.Detected != tc.detected {
				t.Errorf("detected = %q, want %q", cmp.Detected, tc.detected)
			}
			switch {
			case tc.sentence == "" && cmp.Sentence != "":
				t.Errorf("sentence = %q, want none", cmp.Sentence)
			case tc.sentence != "" && !strings.Contains(cmp.Sentence, tc.sentence):
				t.Errorf("sentence = %q, want it to say %q", cmp.Sentence, tc.sentence)
			}
		})
	}
}

// TestSuppliesIsAskedBeforeAnyFamily is the ordering of rules 1 and 2 as its own test, because the
// two can both apply and only the order decides. A service reachable with no detected gate whose
// file declares `app-oidc` is `supplies`; if the family test ran first there would be nothing to
// compare against — the detected method is `none` — and the outcome would silently be empty.
func TestSuppliesIsAskedBeforeAnyFamily(t *testing.T) {
	svc := declaring(payload.AuthNone, payload.MechanismAppOIDC)

	if got := Compare(svc, true).Agreement; got != payload.AgreementSupplies {
		t.Errorf("exposed: agreement = %q, want %q", got, payload.AgreementSupplies)
	}
	// The same service unreachable: nothing would be exposed, so there is no gate to supply and
	// no family to compare — and the outcome is empty rather than an invented agreement.
	if got := Compare(svc, false).Agreement; got != "" {
		t.Errorf("not exposed: agreement = %q, want none", got)
	}
}

// TestSuppliesNamesTheFirstMechanismInTheFile is the tie-break §14 states for rule 1: the file's own
// order carries the outcome. Every mechanism is still in the payload beside it, which is what the
// drawer lists — this decides only which one the sentence is about.
func TestSuppliesNamesTheFirstMechanismInTheFile(t *testing.T) {
	svc := declaring(payload.AuthNone, payload.MechanismAppToken, payload.MechanismAppOIDC)
	cmp := Compare(svc, true)

	if cmp.Mechanism != payload.MechanismAppToken {
		t.Errorf("mechanism = %q, want the first one written", cmp.Mechanism)
	}
	if !strings.Contains(cmp.Sentence, "`app-token`") {
		t.Errorf("sentence = %q, want it to name app-token", cmp.Sentence)
	}
	// And it says the method is unchanged, in the open. Rule 1 is the one verdict a declaration may
	// move, so the sentence has to admit that nothing was detected.
	if !strings.Contains(cmp.Sentence, "the method stays `none` because nothing was detected") {
		t.Errorf("sentence = %q, want it to say the method is unchanged", cmp.Sentence)
	}
	if !strings.Contains(cmp.Sentence, "`s/.labview`") {
		t.Errorf("sentence = %q, want it to name the file it was read from", cmp.Sentence)
	}
}

// TestRedundantBeatsConflictsWithinOneFile is the ordering of rules 2 and 3. A file declaring both
// `app-oidc` and `app-ldap` beside a detected `authentik-oauth` has one mechanism that agrees and
// one that does not, and the agreement wins regardless of which was written first: a file that
// mentions the arrangement in place is not drifting because it also mentions another.
func TestRedundantBeatsConflictsWithinOneFile(t *testing.T) {
	for _, order := range [][]payload.DeclaredAuthMechanism{
		{payload.MechanismAppOIDC, payload.MechanismAppLDAP},
		{payload.MechanismAppLDAP, payload.MechanismAppOIDC},
	} {
		cmp := Compare(declaring(payload.AuthAuthentikOAuth, order...), false)
		if cmp.Agreement != payload.AgreementRedundant {
			t.Errorf("%v: agreement = %q, want %q", order, cmp.Agreement, payload.AgreementRedundant)
		}
		if cmp.Mechanism != payload.MechanismAppOIDC {
			t.Errorf("%v: mechanism = %q, want the one that agrees", order, cmp.Mechanism)
		}
	}
}

// TestConflictsBeatsSupplementsWithinOneFile is the ordering of rules 3 and 4, the same way: a file
// declaring a contradiction and a supplement reports the contradiction, because that is the entry
// an operator has something to do about.
func TestConflictsBeatsSupplementsWithinOneFile(t *testing.T) {
	// Detected `authentik-oauth` is the application layer. `external-proxy` supplements it and
	// `app-ldap` contradicts it.
	cmp := Compare(declaring(payload.AuthAuthentikOAuth,
		payload.MechanismExternalProxy, payload.MechanismAppLDAP), false)

	if cmp.Agreement != payload.AgreementConflicts {
		t.Errorf("agreement = %q, want %q", cmp.Agreement, payload.AgreementConflicts)
	}
	if cmp.Mechanism != payload.MechanismAppLDAP {
		t.Errorf("mechanism = %q, want the contradicting one", cmp.Mechanism)
	}
}

// TestConflictSentenceNamesTheLayer is the answerability of a drift entry: *different mechanisms in
// the same layer* is only actionable if the reader is told which layer, in words rather than as the
// internal member name.
func TestConflictSentenceNamesTheLayer(t *testing.T) {
	for _, tc := range []struct {
		detected payload.AuthMethod
		declared payload.DeclaredAuthMechanism
		phrase   string
	}{
		{payload.AuthAuthentikOAuth, payload.MechanismAppLDAP, "the application authenticating its own users"},
		{payload.AuthAuthentikLDAP, payload.MechanismAppOIDC, "the application authenticating its own users"},
	} {
		cmp := Compare(declaring(tc.detected, tc.declared), false)
		if !strings.Contains(cmp.Sentence, tc.phrase) {
			t.Errorf("%q vs %q: sentence = %q, want the phrase %q",
				tc.detected, tc.declared, cmp.Sentence, tc.phrase)
		}
		// And both sides, so a reader does not have to look up what was detected.
		if !strings.Contains(cmp.Sentence, string(tc.detected)) ||
			!strings.Contains(cmp.Sentence, string(tc.declared)) {
			t.Errorf("sentence = %q, want it to name both mechanisms", cmp.Sentence)
		}
	}
}

// TestBothMappingsArePartial is the property that keeps §14 from over-claiming, checked over every
// member of both closed sets rather than on the two examples the prose gives.
//
// A mechanism with no family can never produce `conflicts`. That is the whole reason the maps are
// partial: `mtls` describes an arrangement this scan has no instrument for, and reporting it as a
// contradiction of a detected gate would be a finding manufactured out of a missing instrument.
func TestBothMappingsArePartial(t *testing.T) {
	unmappedDeclared := []payload.DeclaredAuthMechanism{
		payload.MechanismAppLocalAccounts,
		payload.MechanismAppSAML,
		payload.MechanismAppToken,
		payload.MechanismMTLS,
		payload.MechanismNetworkRestricted,
		payload.MechanismOther,
	}
	for _, m := range unmappedDeclared {
		for _, detected := range payload.AuthMethods {
			cmp := Compare(declaring(detected, m), false)
			if cmp.Agreement == payload.AgreementConflicts {
				t.Errorf("declared %q vs detected %q = conflicts; an unmapped mechanism "+
					"describes nothing this scan measures and cannot contradict it", m, detected)
			}
		}
	}

	// The two mapped mechanisms that *can* conflict, so the sweep above is not vacuous.
	for _, m := range []payload.DeclaredAuthMechanism{
		payload.MechanismAppOIDC, payload.MechanismAppLDAP,
	} {
		var conflicted bool
		for _, detected := range payload.AuthMethods {
			if Compare(declaring(detected, m), false).Agreement == payload.AgreementConflicts {
				conflicted = true
			}
		}
		if !conflicted {
			t.Errorf("%q never conflicts with any detected method; it has lost its family", m)
		}
	}

	// And `external-proxy` cannot conflict with anything, which is a consequence of the two-layer
	// split rather than of the partial mapping: a conflict needs two families in one layer, and the
	// gate layer holds exactly one. Every disagreement §14 can report is therefore a disagreement
	// about how the application authenticates its own users.
	for _, detected := range payload.AuthMethods {
		if got := Compare(declaring(detected, payload.MechanismExternalProxy), false).Agreement; got == payload.AgreementConflicts {
			t.Errorf("external-proxy vs %q = conflicts; the gate layer has no second family "+
				"to disagree with", detected)
		}
	}

	// And the detected side: `basic-auth` is a gate with no family, and `none` is no gate at all.
	// Neither can be an agreement of any kind.
	for _, detected := range []payload.AuthMethod{payload.AuthBasicAuth, payload.AuthNone} {
		for _, m := range payload.DeclaredAuthMechanisms {
			if got := Compare(declaring(detected, m), false).Agreement; got != "" {
				t.Errorf("detected %q vs declared %q = %q, want no agreement", detected, m, got)
			}
		}
	}
}

// TestNoDeclarationIsTheEmptyComparison is the boundary: nothing declared means nothing to compare,
// and the outcome carries no detected method either — an empty comparison is the absence of a
// reading rather than a reading that came out empty.
func TestNoDeclarationIsTheEmptyComparison(t *testing.T) {
	for _, name := range []string{"no file", "file with no auth"} {
		svc := payload.Service{Name: "app", Auth: payload.AuthPosture{Method: payload.AuthAuthentikOAuth}}
		if name == "file with no auth" {
			svc.Declared = &payload.ServiceDeclaration{
				Declaration: payload.Declaration{File: "s/.labview", Owner: "someone"},
			}
		}
		if got := (Compare(svc, true)); got != (Comparison{}) {
			t.Errorf("%s: comparison = %+v, want the empty one", name, got)
		}
	}
}

// TestUnconfirmedMechanisms is §14's fifth collection: a declared mechanism in a layer where the
// scan detected nothing. It is not drift — the scan did not contradict it, it had no instrument
// pointed at it.
func TestUnconfirmedMechanisms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		detected payload.AuthMethod
		declared []payload.DeclaredAuthMechanism
		want     []payload.DeclaredAuthMechanism
	}{
		{
			name: "nothing detected at all", detected: payload.AuthNone,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
			want:     []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
		},
		{
			// Detected in the same layer: corroborated, so not listed.
			name: "same layer", detected: payload.AuthAuthentikOAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC},
		},
		{
			// Detected in the same layer but a different family. That is a conflict, which the
			// comparison already reports; it is not also unconfirmed.
			name: "same layer, contradicted", detected: payload.AuthAuthentikOAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppLDAP},
		},
		{
			name: "other layer", detected: payload.AuthAuthentikOAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismExternalProxy},
			want:     []payload.DeclaredAuthMechanism{payload.MechanismExternalProxy},
		},
		{
			// A detected gate with no family leaves both layers unmeasured, so a mapped
			// mechanism in either of them is unconfirmed.
			name: "detected method outside every family", detected: payload.AuthBasicAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC, payload.MechanismExternalProxy},
			want:     []payload.DeclaredAuthMechanism{payload.MechanismAppOIDC, payload.MechanismExternalProxy},
		},
		{
			name: "the file's own order is kept", detected: payload.AuthAuthentikForwardAuth,
			declared: []payload.DeclaredAuthMechanism{payload.MechanismAppLDAP, payload.MechanismAppOIDC},
			want:     []payload.DeclaredAuthMechanism{payload.MechanismAppLDAP, payload.MechanismAppOIDC},
		},
		{
			// Mixed: only the mechanism in the unmeasured layer is listed, and the unmapped one
			// is never listed at all.
			name: "mixed", detected: payload.AuthAuthentikOAuth,
			declared: []payload.DeclaredAuthMechanism{
				payload.MechanismAppOIDC, payload.MechanismMTLS, payload.MechanismExternalProxy,
			},
			want: []payload.DeclaredAuthMechanism{payload.MechanismExternalProxy},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnconfirmedMechanisms(declaring(tc.detected, tc.declared...))
			if len(got) != len(tc.want) {
				t.Fatalf("unconfirmed = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("unconfirmed = %v, want %v", got, tc.want)
					break
				}
			}
		})
	}
}

// TestUnmappedMechanismIsNeverUnconfirmed states the omission on its own, because it is the one a
// future change is most likely to undo by "completing" the mapping. `mtls` and `network-restricted`
// describe arrangements this scan has no instrument for. Listing them as unconfirmed would read as
// a check that failed rather than one that was never possible.
func TestUnmappedMechanismIsNeverUnconfirmed(t *testing.T) {
	for _, m := range []payload.DeclaredAuthMechanism{
		payload.MechanismAppLocalAccounts, payload.MechanismAppSAML, payload.MechanismAppToken,
		payload.MechanismMTLS, payload.MechanismNetworkRestricted, payload.MechanismOther,
	} {
		for _, detected := range payload.AuthMethods {
			if got := UnconfirmedMechanisms(declaring(detected, m)); len(got) != 0 {
				t.Errorf("declared %q with detected %q: unconfirmed = %v, want nothing",
					m, detected, got)
			}
		}
	}
	if got := UnconfirmedMechanisms(payload.Service{Name: "app"}); got != nil {
		t.Errorf("a service with no declaration: unconfirmed = %v, want nil", got)
	}
}

// TestSentencesNameTheFileOrSayWhichFile is the one thing every §14 sentence has in common: it says
// where it was read from. A declaration with no recorded path is a bug elsewhere, and the sentence
// degrades to plain words rather than showing a reader an empty pair of backticks.
func TestSentencesNameTheFileOrSayWhichFile(t *testing.T) {
	svc := declaring(payload.AuthNone, payload.MechanismAppOIDC)
	svc.Declared.File = "  "

	got := Compare(svc, true).Sentence
	if !strings.Contains(got, "the sidecar file") {
		t.Errorf("sentence = %q, want the words `the sidecar file`", got)
	}
	if strings.Contains(got, "``") {
		t.Errorf("sentence = %q, want no empty pair of backticks", got)
	}
}
