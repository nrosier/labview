package declare

import (
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// Input is what §14's walk reads. Refused comes from dependency resolution rather than being
// recomputed here: whether a reference named exactly one service was decided once, where the fleet
// index was, and drift check 3 reports that decision rather than repeating it.
type Input struct {
	Stacks  []payload.AppStack
	Refused []fleet.Refusal
}

// Apply is §14 in one walk over the fleet: the exposure verdict, the agreement, and drift and
// unconfirmed collected together.
//
// **One walk with two selectors.** Drift and unconfirmed are two readings of the same comparison —
// drift is a declaration the scan contradicts, unconfirmed is one it could not corroborate — and
// collecting them in one pass is what makes it impossible for a service to end up in one list and
// not the other by accident. Two walks would be two chances to disagree.
//
// Both lists are conclusions about this scan and not about the file, so each is rebuilt from
// nothing here rather than appended to whatever a previous scan left.
func Apply(in Input) {
	refusals := refusalsByService(in.Refused)

	for si := range in.Stacks {
		stack := &in.Stacks[si]
		for vi := range stack.Services {
			svc := &stack.Services[vi]
			key := fleet.Key(stack.ID, svc.Name)

			// The external-reachability rule, asked once and used by both the verdict and the
			// stale-acceptance check, so `lan`-only counting as reachable cannot mean one thing
			// here and another there (§4.1).
			reachable := fleet.External(svc.Ingress)
			wouldBeExposed := reachable && !svc.HasEdgeAuth()
			cmp := Compare(*svc, wouldBeExposed)

			// Rule 2's one boolean, stored rather than derived so that the finding a reader sees
			// and the number the counter reports cannot come apart. A declaration clears the
			// finding and nothing else: the method stays whatever was detected.
			svc.Auth.ExposedWithoutAuth = wouldBeExposed && len(svc.DeclaredAuthMechanisms()) == 0

			d := svc.Declared
			if d == nil {
				continue
			}
			d.AuthAgreement = cmp.Agreement
			d.Drift, d.Unconfirmed = nil, nil

			// The two selectors. Everything below chooses one of them and never both for the
			// same fact.
			drift := func(sentence string) { d.Drift = append(d.Drift, sentence) }
			unconfirmed := func(sentence string) { d.Unconfirmed = append(d.Unconfirmed, sentence) }

			// Rule 2 requires the supplies outcome to be stated in the open, naming which
			// mechanism and which file said so; supplements is noted rather than drifted.
			switch cmp.Agreement {
			case payload.AgreementSupplies, payload.AgreementSupplements:
				svc.Notes = append(svc.Notes, cmp.Sentence)
			}

			// Drift 1 — a stale acceptance. Tested with the external-reachability rule, so a
			// service reachable only on the LAN still counts as reachable and its acceptance
			// still stands.
			if d.UnauthenticatedAccepted != nil && !reachable {
				drift("the accepted exposure in " + quote(d.File) +
					" is stale: this service is no longer externally reachable, so there is no " +
					"longer an exposure to accept")
			}

			// Drift 2 — a conflicting mechanism.
			if cmp.Agreement == payload.AgreementConflicts {
				drift(cmp.Sentence)
			}

			// Drift 3 — a declared dependency that no longer names exactly one service.
			for _, r := range refusals[key] {
				drift(refusalSentence(r))
			}

			// Drift 4 — an expected-ingress mismatch, in both directions. One direction alone
			// would hide a service that picked up an exposure nobody expected.
			if len(d.ExpectedIngress) > 0 {
				missing, unexpected := fleet.MissingAndUnexpected(d.ExpectedIngress, svc.Ingress)
				if len(missing) > 0 || len(unexpected) > 0 {
					drift("the expected ingress declared in " + quote(d.File) +
						" does not match what was detected — " + mismatch(missing, unexpected))
				}
			}

			// The fifth collection, which is not drift: a declared mechanism in a layer where
			// the scan detected nothing.
			if ms := UnconfirmedMechanisms(*svc); len(ms) > 0 {
				unconfirmed(joinMechanisms(ms) + " declared in " + quote(d.File) +
					" could not be corroborated: the scan detected nothing in the layer " +
					plural(len(ms), "it describes", "they describe"))
			}

			// And a probe that answered with no login page on a service whose only protection is
			// declared. The probe contradicts nothing — it cannot see an application's own login
			// — so this is a note about what was not confirmed, never a finding.
			if cmp.Agreement == payload.AgreementSupplies && svc.Probe != nil &&
				svc.Probe.Status != nil && svc.Probe.Gate == "" {
				unconfirmed("the probe reached " + quote(svc.Probe.Endpoint) +
					" and read no login page, while the only account of a gate here is the " +
					"declaration in " + quote(d.File))
			}
		}
	}
}

// refusalsByService groups refused references by the service that wrote them, keeping their
// resolution order.
func refusalsByService(refusals []fleet.Refusal) map[string][]fleet.Refusal {
	out := map[string][]fleet.Refusal{}
	for _, r := range refusals {
		out[r.From] = append(out[r.From], r)
	}
	return out
}

// refusalSentence writes one refused reference as a drift entry, carrying what was weighed so an
// ambiguous reference is answerable rather than merely reported.
func refusalSentence(r fleet.Refusal) string {
	out := "the declared dependency `" + r.Ref + "` in " + quote(r.File) + " " + r.Reason
	if len(r.Considered) > 0 {
		out += " (candidates: " + joinKeys(r.Considered) + ")"
	}
	return out
}

// mismatch is the both-directions sentence of §14, in the shape it writes: *missing: lan;
// unexpected: traefik*. A direction with nothing in it is left out rather than written empty.
func mismatch(missing, unexpected []payload.IngressKind) string {
	out := ""
	if len(missing) > 0 {
		out = "missing: " + joinKinds(missing)
	}
	if len(unexpected) > 0 {
		if out != "" {
			out += "; "
		}
		out += "unexpected: " + joinKinds(unexpected)
	}
	return out
}

func joinKeys(keys []string) string {
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += "`" + k + "`"
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
