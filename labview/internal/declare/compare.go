// Package declare is §14: what may be done with a sidecar file.
//
// Three rules govern the whole package. A declaration never changes a detection — it writes notes,
// drift and agreement only. It can change exactly one verdict, in the open: the exposure finding,
// because a service authenticating its own users is not an exposure. And an accepted exposure is
// still an exposure, counted in its own statistic and never subtracted from the exposed count.
//
// The file is operator input and explicitly not evidence. Nothing anyone typed makes an undetected
// gate detected.
package declare

import (
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// family is a group of mechanisms that mean the same thing. Comparison happens between families
// rather than between members, because `authentik-oauth` and `app-oidc` are one arrangement
// described from two sides.
type family string

const (
	familyOIDC  family = "oidc"
	familyLDAP  family = "ldap"
	familyProxy family = "proxy"
)

// layer is which of the two things a family describes. The layers exist so that a forward-auth
// gate and an application's own OIDC — both true at once — are never compared (§14).
type layer string

const (
	// layerApp is the application authenticating its own users.
	layerApp layer = "app"
	// layerGate is a gate in front of it.
	layerGate layer = "gate"
)

// layerOf is the two-layer split. Every family belongs to exactly one.
var layerOf = map[family]layer{
	familyOIDC:  layerApp,
	familyLDAP:  layerApp,
	familyProxy: layerGate,
}

// layerPhrase is how a layer is written in a sentence a reader sees.
var layerPhrase = map[layer]string{
	layerApp:  "the application authenticating its own users",
	layerGate: "a gate in front of it",
}

// detectedFamily maps a detected method to its family. It is **partial** on purpose: `basic-auth`
// is a real gate that no declared mechanism describes, so it has no family and cannot conflict
// with anything (§14).
var detectedFamily = map[payload.AuthMethod]family{
	payload.AuthAuthentikOAuth:       familyOIDC,
	payload.AuthOtherOAuth:           familyOIDC,
	payload.AuthAuthentikLDAP:        familyLDAP,
	payload.AuthLDAP:                 familyLDAP,
	payload.AuthAuthentikForwardAuth: familyProxy,
	payload.AuthForwardAuth:          familyProxy,
}

// declaredFamily maps a declared mechanism to its family, and is partial for the same reason:
// `app-local-accounts`, `app-saml`, `app-token`, `mtls`, `network-restricted` and `other` describe
// arrangements this scan detects nothing about, so they can neither corroborate nor contradict.
var declaredFamily = map[payload.DeclaredAuthMechanism]family{
	payload.MechanismAppOIDC:       familyOIDC,
	payload.MechanismAppLDAP:       familyLDAP,
	payload.MechanismExternalProxy: familyProxy,
}

// Comparison is what §14's comparison concluded about one service.
//
// Sentence is empty for `redundant`, which is rendered nowhere — declared and detected agreeing is
// not news — and for the empty agreement.
type Comparison struct {
	Agreement payload.DeclaredAuthAgreement
	// Mechanism is the declared mechanism the outcome turns on, when one did.
	Mechanism payload.DeclaredAuthMechanism
	// Detected is the method it was compared against, for the sentence.
	Detected payload.AuthMethod
	Sentence string
}

// Compare is the four outcomes of §14, tested in the order it states them.
//
// wouldBeExposed is `reachable AND NOT hasEdgeAuth` — deliberately *would be* rather than
// reachable, which is what makes `supplies` imply the method is `none` and impossible to report on
// a service that has a detected gate.
func Compare(svc payload.Service, wouldBeExposed bool) Comparison {
	declared := svc.DeclaredAuthMechanisms()
	if len(declared) == 0 {
		return Comparison{}
	}
	file := ""
	if svc.Declared != nil {
		file = svc.Declared.File
	}
	detected := svc.Auth.Method

	// 1. supplies — the service would be exposed and a declaration is the only protection. The
	// first mechanism in the file's order carries the outcome; every one of them is still listed
	// beside it in the drawer.
	if wouldBeExposed {
		m := declared[0].Mechanism
		return Comparison{
			Agreement: payload.AgreementSupplies,
			Mechanism: m,
			Detected:  detected,
			Sentence: "`" + string(m) + "` declared in " + quote(file) +
				" is the only account of a gate on this service; the method stays `none` " +
				"because nothing was detected",
		}
	}

	fam, hasFamily := detectedFamily[detected]

	// 2. redundant — declared and detected in the same family. Silent.
	if hasFamily {
		for _, d := range declared {
			if declaredFamily[d.Mechanism] == fam {
				return Comparison{
					Agreement: payload.AgreementRedundant,
					Mechanism: d.Mechanism,
					Detected:  detected,
				}
			}
		}
	}

	// 3. conflicts — same layer, different family.
	if hasFamily {
		for _, d := range declared {
			df, ok := declaredFamily[d.Mechanism]
			if !ok || df == fam {
				continue
			}
			if layerOf[df] == layerOf[fam] {
				return Comparison{
					Agreement: payload.AgreementConflicts,
					Mechanism: d.Mechanism,
					Detected:  detected,
					Sentence: "declared `" + string(d.Mechanism) + "` and detected `" +
						string(detected) + "` are different mechanisms in the same layer (" +
						layerPhrase[layerOf[fam]] + ")",
				}
			}
		}
	}

	// 4. supplements — declared in a layer with nothing detected in it, while the other layer has
	// a gate. Noted, not drift: both statements can be true at once.
	if hasFamily {
		for _, d := range declared {
			df, ok := declaredFamily[d.Mechanism]
			if !ok || layerOf[df] == layerOf[fam] {
				continue
			}
			return Comparison{
				Agreement: payload.AgreementSupplements,
				Mechanism: d.Mechanism,
				Detected:  detected,
				Sentence: "declared `" + string(d.Mechanism) + "` describes " +
					layerPhrase[layerOf[df]] + ", while the detected `" + string(detected) +
					"` is " + layerPhrase[layerOf[fam]] + "; both can be true at once",
			}
		}
	}

	// Nothing to say: an unmapped mechanism, or a detected method no declared mechanism describes.
	return Comparison{Detected: detected}
}

// UnconfirmedMechanisms are the declared mechanisms the scan neither contradicts nor corroborates:
// a mechanism in a layer where nothing was detected (§14, the fifth collection).
//
// An unmapped mechanism is not listed. `mtls` and `network-restricted` describe arrangements this
// scan has no instrument for, and calling them unconfirmed would suggest a failed check rather
// than a check that was never possible.
func UnconfirmedMechanisms(svc payload.Service) []payload.DeclaredAuthMechanism {
	declared := svc.DeclaredAuthMechanisms()
	if len(declared) == 0 {
		return nil
	}
	detectedLayer, detectedInAnyLayer := layerOf[detectedFamily[svc.Auth.Method]]

	var out []payload.DeclaredAuthMechanism
	for _, d := range declared {
		df, ok := declaredFamily[d.Mechanism]
		if !ok {
			continue
		}
		if !detectedInAnyLayer || layerOf[df] != detectedLayer {
			out = append(out, d.Mechanism)
		}
	}
	return out
}

// quote wraps a value in backticks for a sentence a reader sees, leaving an empty value as plain
// words rather than an empty pair of quotes.
func quote(s string) string {
	if strings.TrimSpace(s) == "" {
		return "the sidecar file"
	}
	return "`" + s + "`"
}

// joinMechanisms lists mechanisms in a sentence.
func joinMechanisms(ms []payload.DeclaredAuthMechanism) string {
	out := ""
	for i, m := range ms {
		switch {
		case i == 0:
		case i == len(ms)-1:
			out += " and "
		default:
			out += ", "
		}
		out += "`" + string(m) + "`"
	}
	return out
}

// joinKinds lists ingress kinds in a sentence, comma separated as §14 writes them.
func joinKinds(ks []payload.IngressKind) string {
	out := ""
	for i, k := range ks {
		if i > 0 {
			out += ", "
		}
		out += string(k)
	}
	return out
}
