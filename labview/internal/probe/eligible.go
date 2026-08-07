package probe

import "github.com/nrosier/labview/internal/payload"

// ---------------------------------------------------------------------------
// Two separate questions
// ---------------------------------------------------------------------------

// DetectedAuth is §13.1's detected-authentication test, and it is **the same expression the exposure
// verdict uses** — `payload.Service.ConfiguredEdgeAuth`, evaluated once and shared, so that
// eligibility and the notes explaining the outcome cannot come apart.
//
// A method other than `none` from labels or the live Traefik chain, a Cloudflare Access policy on the
// tunnel route, or an Authentik provider the API reports as enforced. An `inferred` posture counts as
// detected. **Neither a probe result nor a declaration counts** — the first would make the probe a
// function of itself, the second would let operator input silence a measurement.
func DetectedAuth(s payload.Service) bool { return s.ConfiguredEdgeAuth() }

// Eligibility is what §13.1 concluded about one service, in the two facts it insists are different.
//
// **Not asked and no address are different facts.** A service with no HTTP address was never a
// candidate; a candidate whose authentication was already detected was withheld. Only the second is
// Skipped, and only the second is counted as such.
type Eligibility struct {
	// Targets is where the probe may ask, in walk order. Empty when nothing may be asked, for either
	// reason.
	Targets []Target

	// Skipped is a withheld candidate: there were addresses, and authentication was already detected.
	Skipped bool
}

// Candidate is whether there was an HTTP address at all, whatever was decided about asking.
func (e Eligibility) Candidate() bool { return len(e.Targets) > 0 || e.Skipped }

// Eligible answers both questions, **address first**.
//
// The order is the requirement, not an implementation detail: asking about detected authentication
// first would count every database and every queue as skipped, and the skipped figure would stop
// meaning *withheld* and start meaning *not an HTTP service* — which is the one thing §13.1's two
// facts exist to keep apart.
//
// Withholding a request can only ever leave a service *in* the exposed count, because the exposure
// verdict is `configuredEdgeAuth || probeGate` and this only ever removes the second term.
func Eligible(s payload.Service, lanHost string) Eligibility {
	targets := Addresses(s, lanHost)
	if len(targets) == 0 {
		return Eligibility{} // never a candidate
	}
	if DetectedAuth(s) {
		return Eligibility{Skipped: true} // a candidate, withheld
	}
	return Eligibility{Targets: targets}
}
