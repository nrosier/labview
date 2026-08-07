package probe

import (
	"fmt"
	"strings"

	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// Both findings are findings
// ---------------------------------------------------------------------------

// Verdict is the three outcomes of §13.6, and all three are findings — except the third, which is
// deliberately *not* a measurement.
type Verdict string

const (
	// VerdictGated is a login page answering: the service leaves the exposure count, is counted as
	// probe-gated, and its no-auth reason becomes `probed-gate` with the method untouched at `none`.
	VerdictGated Verdict = "gated"

	// VerdictOpen is an answer with no login page: the exposure note gains a clause saying LabView
	// requested the address and was served the application. The finding stands.
	VerdictOpen Verdict = "open"

	// VerdictNoAnswer is neither. Counted in neither statistic, claiming no measurement.
	VerdictNoAnswer Verdict = "no-answer"
)

// VerdictOf reads one probe record.
func VerdictOf(p payload.ServiceProbe) Verdict {
	switch {
	case !conn.OK(p.Phase):
		return VerdictNoAnswer
	case p.Gate != "":
		return VerdictGated
	default:
		return VerdictOpen
	}
}

// Label is the words a reader is shown. *No answer* and *No login page* are kept apart because they
// are different claims: one says the application served everybody, the other says nothing was
// measured. §13.5 pins the middle one — **the verdict label stays *No login page*** even when the
// anonymous reading had a great deal to say.
func Label(v Verdict) string {
	switch v {
	case VerdictGated:
		return "Login page"
	case VerdictOpen:
		return "No login page"
	default:
		return "No answer"
	}
}

// ---------------------------------------------------------------------------
// The reason sentence
// ---------------------------------------------------------------------------

// Reason is the sentence beside the verdict: pure, and branching in the signals' own precedence order.
//
// For a gate, the fact that fired. For a negative verdict, **the clause that came closest and what it
// lacked** — which is the part that makes the record arguable. A reader told only "no gate observed"
// has nothing to check; a reader told "answered 401 but named no scheme" knows exactly which line of
// §13.3 to disagree with.
func Reason(p payload.ServiceProbe) string {
	if !conn.OK(p.Phase) {
		return noAnswerClause(p)
	}
	if p.Gate != "" {
		return gateClause(p)
	}

	clauses := []string{closestClause(p)}
	if extra := anonClause(p); extra != "" {
		clauses = append(clauses, extra)
	}
	return strings.Join(clauses, " ")
}

func noAnswerClause(p payload.ServiceProbe) string {
	if p.Detail != "" {
		return fmt.Sprintf("No answer from %s — %s.", p.Endpoint, p.Detail)
	}
	return fmt.Sprintf("No answer from %s.", p.Endpoint)
}

// ---------------------------------------------------------------------------
// One sentence per signal
// ---------------------------------------------------------------------------

// gateClause is the wording for the signal that fired, one branch per gate in precedence order.
//
// **The mapping MUST be exhaustive**, and the init below is what enforces it: a gate added to
// `payload.ProbeGates` without a branch here panics before anything runs, so no build in which the two
// have drifted survives its own start-up. Go cannot check a string switch at compile time, so the
// check is placed where it fails earliest and loudest instead.
func gateClause(p payload.ServiceProbe) string {
	switch p.Gate {
	case payload.GateChallenge:
		return fmt.Sprintf("The address answered %s and named an authentication scheme.", statusOf(p))

	case payload.GateRedirectOrigin:
		return fmt.Sprintf("The address answered %s and redirected off its own origin, to %s — something else answers for it.",
			statusOf(p), targetOf(p.Redirect))

	case payload.GateRedirectLogin:
		return fmt.Sprintf("The address answered %s and redirected to %s, a login path on its own origin.",
			statusOf(p), targetOf(p.Redirect))

	case payload.GateMetaRefreshLogin:
		return fmt.Sprintf("The page's own markup refreshed to %s, which is a login destination.", targetOf(p.Refresh))

	case payload.GateSSOForm:
		return "The page carried a hidden SAML field — a federation hand-off already in progress."

	case payload.GatePasswordForm:
		return "The page carried a password input."

	case payload.GateCredentialForm:
		return "One form asked for an identifier with a submit control and no password field — " +
			credentialIntent(p.Form) + "."

	case payload.GateStateChallenge:
		return fmt.Sprintf("No form was in the page at all, and the page's own client was refused at %s with %s, naming an authentication scheme.",
			refusedAt(p.State), stateStatus(p.State))
	}
	return ""
}

// The exhaustiveness §13.6 requires, in the earliest form Go can hold it: adding a signal without its
// wording fails every build's own start-up, and therefore every test.
func init() {
	for _, gate := range payload.ProbeGates {
		if gateClause(payload.ServiceProbe{Gate: gate}) == "" {
			panic("probe: §13.6 requires one sentence per signal, and there is none for " + string(gate))
		}
	}
}

// credentialIntent names which of the two intent markers `credential-form` rested on, because they
// mean different things to a reader: an action is a route, a one-time-code field is a whole
// authentication style.
func credentialIntent(f *payload.LoginFormShape) string {
	switch {
	case f == nil:
		return "passwordless sign-in"
	case f.OTP:
		return "a one-time code field, which is passwordless sign-in"
	case f.Action != "":
		return "posting to " + f.Action + ", which is passwordless sign-in"
	default:
		return "passwordless sign-in"
	}
}

// ---------------------------------------------------------------------------
// What came closest, and what it lacked
// ---------------------------------------------------------------------------

// closestClause is the negative verdict's substance: the clause of §13.3 that came nearest to firing,
// and the fact it was missing.
//
// The branches are in the signals' own precedence order, so the clause a reader is shown is the
// strongest one that nearly held rather than the last one checked.
func closestClause(p payload.ServiceProbe) string {
	status := 0
	if p.Status != nil {
		status = *p.Status
	}

	switch {
	// 1. A refusal that named nothing. This is the near-miss worth naming above all others: it is one
	// header away from a gate, and that header's absence is exactly why genuinely open applications
	// stay in the count.
	case status == 401 || status == 407:
		return fmt.Sprintf("The address answered %d but named no authentication scheme, so this is not a challenge — an application serving everybody answers the same way.", status)

	case status == 403:
		return "The address answered 403, which is refusal without a challenge — a directory with no index answers the same way."

	// 2/3. A redirect that went nowhere useful.
	case p.Redirect != nil:
		return fmt.Sprintf("The address answered %d and redirected to %s, which stayed on its own origin and is not a login path.",
			status, targetOf(p.Redirect))

	case status >= 300 && status < 400:
		return fmt.Sprintf("The address answered %d with no target that resolves, so where it points is unknown.", status)

	// 4. A meta refresh that was not a gate.
	case p.Refresh != nil:
		return fmt.Sprintf("The page refreshed to %s, which neither left the origin nor landed on a login path.", targetOf(p.Refresh))

	// 5/6/7. A page was read and the form clauses did not hold.
	case p.Form != nil:
		return "The page carried a form, " + formShortfall(*p.Form) + truncatedNote(p.Truncated)

	// 8. §13.4 ran, which is the only way a page with no form at all gets this far.
	case p.State != nil:
		return stateShortfall(p.State)

	// A 200 that was not a page.
	case status == 200 && p.MediaType != "" && !HTML(p.MediaType):
		return fmt.Sprintf("The address answered 200 with content type %s, which is not a page, so no body was read as one.", p.MediaType)

	case status == 200:
		return "The address answered 200 with no content type naming a page, so no body was read as one."

	default:
		return fmt.Sprintf("The address answered %d, which is not any of the eight signals.", status)
	}
}

// formShortfall is what a form lacked, named field by field. A form that says nothing still gets a
// sentence: §13.3 attaches the shape whenever a form was found, including when nothing was concluded
// from it, and a shape with no sentence would be a fact nobody can read.
func formShortfall(f payload.LoginFormShape) string {
	var has, lacks []string

	for _, part := range []struct {
		got  bool
		name string
	}{
		{f.Username, "an identifier field"},
		{f.Submit, "a submit control"},
		{f.OTP, "a one-time code field"},
		{f.Action != "", "an action on a login path"},
	} {
		if part.got {
			has = append(has, part.name)
		} else {
			lacks = append(lacks, part.name)
		}
	}

	switch {
	case len(has) == 0:
		return "with none of the fields a login form has: no " + list(lacks) + "."
	case len(lacks) == 0:
		// Every part present with no password field is `credential-form`, so this is unreachable from
		// a negative verdict. It is written anyway: a sentence that depends on a signal staying wrong
		// is a sentence that breaks silently when the signal is fixed.
		return "with " + list(has) + " — and no password field."
	default:
		return "with " + list(has) + ", lacking " + list(lacks) + "."
	}
}

func truncatedNote(truncated *bool) string {
	if truncated != nil && *truncated {
		return " The body reached the read cap, so a form below it would not have been seen."
	}
	return ""
}

// stateShortfall is §13.4's own negative wording. A bare refusal is **recorded and named as a place to
// look, in the same sentence that says the finding stands** — which is why both halves are here rather
// than in two sentences a reader could see one of.
func stateShortfall(s *payload.ProbeState) string {
	if BareRefusal(s) {
		return fmt.Sprintf("No form was in the page at all, and the page's own client was refused at %s with %s but no scheme was named — worth a look, though the finding stands.",
			refusedAt(s), stateStatus(s))
	}
	if s.Asked == 0 {
		return "No form was in the page at all, and there was no current-user address to ask."
	}
	return fmt.Sprintf("No form was in the page at all, and %s served without a credential.", askedCount(s.Asked))
}

func askedCount(asked int) string {
	if asked == 1 {
		return "the one current-user address asked was"
	}
	return fmt.Sprintf("all %d current-user addresses asked were", asked)
}

// ---------------------------------------------------------------------------
// The anonymous reading's own sentence
// ---------------------------------------------------------------------------

// anonClause is §13.5's three-row table, reached **only after the §13.4 shortfall** — the record
// travels with every HTML 200, gate or no gate, but the sentence is an addition to a negative verdict
// and nothing else.
//
// Note what the middle row does: a sign-in offer with no content served says **nothing**. A login
// screen a bundle drew has exactly that shape, and describing it would be describing the page §13.4
// already failed to settle.
func anonClause(p payload.ServiceProbe) string {
	if p.Anon == nil {
		return ""
	}
	a := *p.Anon
	served, offered := ContentServed(a), SignInOffered(a)

	switch {
	case served && offered:
		return fmt.Sprintf("It served %s and offered a way in%s.", volume(a), offer(a))
	case served:
		return fmt.Sprintf("It served %s — the application's own content, not a shell.", volume(a))
	default:
		return ""
	}
}

func volume(a payload.ProbeAnon) string {
	links := fmt.Sprintf("%d links", a.Links)
	switch a.Links {
	case 0:
		links = "no links"
	case 1:
		links = "1 link"
	}
	return fmt.Sprintf("%d characters of visible text across %s", a.TextChars, links)
}

// offer names the link or the control **in the words the page used**, which is the point of keeping a
// label at all. When the label was too long to keep (I6) the path stands in for it, and when there is
// neither the offer is named without either.
func offer(a payload.ProbeAnon) string {
	switch {
	case a.LoginLabel != "" && a.LoginHref != "":
		return fmt.Sprintf(" — %q, to %s", a.LoginLabel, a.LoginHref)
	case a.LoginLabel != "":
		return fmt.Sprintf(" — %q", a.LoginLabel)
	case a.LoginHref != "":
		return " — a link to " + a.LoginHref
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Small shared wordings
// ---------------------------------------------------------------------------

func statusOf(p payload.ServiceProbe) string {
	if p.Status == nil {
		return "no status"
	}
	return fmt.Sprintf("%d", *p.Status)
}

func targetOf(r *payload.ProbeRedirect) string {
	if r == nil || r.To == "" {
		return "an address it did not name"
	}
	return r.To
}

func refusedAt(s *payload.ProbeState) string {
	if s == nil || s.RefusedAt == "" {
		return "one of its own addresses"
	}
	return s.RefusedAt
}

func stateStatus(s *payload.ProbeState) string {
	if s == nil || s.Status == nil {
		return "a refusal"
	}
	return fmt.Sprintf("%d", *s.Status)
}

// list is an English enumeration, for the field names a form lacked.
func list(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}
