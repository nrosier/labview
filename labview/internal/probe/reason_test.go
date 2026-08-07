package probe

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// status and yes exist so the tables below can be written as literals.
func status(n int) *int { return &n }
func yes() *bool        { t := true; return &t }
func to(url string) *payload.ProbeRedirect {
	return &payload.ProbeRedirect{To: url}
}

// answered is a probe record that got an HTTP answer, which is what every wording branch below is
// reached through.
func answered(p payload.ServiceProbe) payload.ServiceProbe {
	p.Endpoint, p.Phase = base, payload.PhaseConnected
	if p.Status == nil {
		p.Status = status(200)
	}
	return p
}

func TestEverySignalHasItsOwnSentence(t *testing.T) {
	// The init in reason.go already panics on a gate with no wording, which means this assertion can
	// never fail on its own — the package would not load. It is written out anyway, because the
	// requirement is §13.6's and a reader looking for it should find it stated as a test rather than as
	// a side effect of the package loading.
	seen := map[string]bool{}
	for _, gate := range payload.ProbeGates {
		got := gateClause(payload.ServiceProbe{Gate: gate})
		if got == "" {
			t.Fatalf("no sentence for gate %q", gate)
		}
		if !strings.HasSuffix(got, ".") {
			t.Fatalf("the sentence for %q is not a sentence: %q", gate, got)
		}
		if seen[got] {
			t.Fatalf("two gates share one sentence, so a reader cannot tell them apart: %q", got)
		}
		seen[got] = true
	}
	if len(payload.ProbeGates) != 8 {
		t.Fatalf("§13.3 and §13.4 name eight signals; the vocabulary has %d", len(payload.ProbeGates))
	}
}

func TestAGateSentenceNamesTheFactThatFired(t *testing.T) {
	cases := []struct {
		name  string
		probe payload.ServiceProbe
		want  []string
	}{
		{
			name:  "a challenge names its status",
			probe: answered(payload.ServiceProbe{Gate: payload.GateChallenge, Status: status(401)}),
			want:  []string{"401", "authentication scheme"},
		},
		{
			name: "an off-origin redirect names where it went",
			probe: answered(payload.ServiceProbe{Gate: payload.GateRedirectOrigin, Status: status(302),
				Redirect: to("https://auth.example.com/outpost/start")}),
			want: []string{"302", "https://auth.example.com/outpost/start", "something else answers for it"},
		},
		{
			name: "a login redirect says it stayed home",
			probe: answered(payload.ServiceProbe{Gate: payload.GateRedirectLogin, Status: status(302),
				Redirect: to("/users/sign_in")}),
			want: []string{"302", "/users/sign_in", "its own origin"},
		},
		{
			name: "a meta refresh says it was the page's own markup",
			probe: answered(payload.ServiceProbe{Gate: payload.GateMetaRefreshLogin,
				Refresh: to("/login")}),
			want: []string{"own markup", "/login"},
		},
		{
			name:  "an SSO form says a hand-off is already in progress",
			probe: answered(payload.ServiceProbe{Gate: payload.GateSSOForm}),
			want:  []string{"SAML", "hand-off"},
		},
		{
			name:  "a password form says what it carried",
			probe: answered(payload.ServiceProbe{Gate: payload.GatePasswordForm}),
			want:  []string{"password input"},
		},
		{
			name: "a credential form names which intent marker it rested on",
			probe: answered(payload.ServiceProbe{Gate: payload.GateCredentialForm,
				Form: &payload.LoginFormShape{Username: true, Submit: true, Action: "/login"}}),
			want: []string{"no password field", "posting to /login", "passwordless"},
		},
		{
			name: "a one-time code is named as a style, not a route",
			probe: answered(payload.ServiceProbe{Gate: payload.GateCredentialForm,
				Form: &payload.LoginFormShape{Username: true, Submit: true, OTP: true}}),
			want: []string{"one-time code field", "passwordless"},
		},
		{
			name: "a state challenge names the address that refused",
			probe: answered(payload.ServiceProbe{Gate: payload.GateStateChallenge,
				State: &payload.ProbeState{Asked: 2, RefusedAt: "https://app.example.com/api/me",
					Status: status(401), Challenge: yes()}}),
			want: []string{"No form was in the page at all", "https://app.example.com/api/me", "401",
				"naming an authentication scheme"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Reason(c.probe)
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Fatalf("%s\n want %q in the sentence\n  got %q", c.name, want, got)
				}
			}
		})
	}
}

func TestANegativeVerdictNamesWhatCameClosestAndWhatItLacked(t *testing.T) {
	// This is the part that makes the record arguable. A reader told only *no gate observed* has nothing
	// to check; a reader told *answered 401 but named no scheme* knows which line of §13.3 to disagree
	// with.
	cases := []struct {
		name  string
		probe payload.ServiceProbe
		want  []string
	}{
		{
			name:  "a bare refusal is the near-miss named above all others",
			probe: answered(payload.ServiceProbe{Status: status(401)}),
			want:  []string{"401", "named no authentication scheme", "serving everybody answers the same way"},
		},
		{
			name:  "a 403 is refusal without a challenge",
			probe: answered(payload.ServiceProbe{Status: status(403)}),
			want:  []string{"403", "directory with no index"},
		},
		{
			name: "a same-origin redirect that is not a login path",
			probe: answered(payload.ServiceProbe{Status: status(302),
				Redirect: to("/dashboard")}),
			want: []string{"302", "/dashboard", "stayed on its own origin", "not a login path"},
		},
		{
			name:  "a redirect that named no target that resolves",
			probe: answered(payload.ServiceProbe{Status: status(302)}),
			want:  []string{"302", "no target that resolves"},
		},
		{
			name:  "a refresh that was neither",
			probe: answered(payload.ServiceProbe{Refresh: to("/home")}),
			want:  []string{"/home", "neither left the origin nor landed on a login path"},
		},
		{
			name: "a form that lacked things",
			probe: answered(payload.ServiceProbe{
				Form: &payload.LoginFormShape{Username: true, Submit: true}}),
			want: []string{"carried a form", "an identifier field and a submit control",
				"lacking a one-time code field and an action on a login path"},
		},
		{
			name: "a form that said nothing at all still gets a sentence",
			probe: answered(payload.ServiceProbe{
				Form: &payload.LoginFormShape{}}),
			want: []string{"none of the fields a login form has"},
		},
		{
			name: "a truncated body says a form below the cap would not have been seen",
			probe: answered(payload.ServiceProbe{
				Form: &payload.LoginFormShape{Username: true}, Truncated: yes()}),
			want: []string{"read cap", "a form below it would not have been seen"},
		},
		{
			name: "the state walk served everybody",
			probe: answered(payload.ServiceProbe{
				State: &payload.ProbeState{Asked: 4}}),
			want: []string{"No form was in the page at all", "all 4 current-user addresses asked were",
				"served without a credential"},
		},
		{
			name: "the state walk found a bare refusal",
			probe: answered(payload.ServiceProbe{
				State: &payload.ProbeState{Asked: 1, RefusedAt: "https://app.example.com/api/",
					Status: status(401)}}),
			want: []string{"no scheme was named", "worth a look", "the finding stands"},
		},
		{
			name:  "a 200 that was not a page names its content type",
			probe: answered(payload.ServiceProbe{Status: status(200), MediaType: "application/json"}),
			want:  []string{"200", "application/json", "not a page"},
		},
		{
			name:  "a 200 with no content type at all",
			probe: answered(payload.ServiceProbe{Status: status(200)}),
			want:  []string{"200", "no content type naming a page"},
		},
		{
			name:  "anything else says which of the eight it was not",
			probe: answered(payload.ServiceProbe{Status: status(500)}),
			want:  []string{"500", "not any of the eight signals"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if VerdictOf(c.probe) != VerdictOpen {
				t.Fatalf("the fixture must be a negative verdict to reach the clause; got %q",
					VerdictOf(c.probe))
			}
			got := Reason(c.probe)
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Fatalf("%s\n want %q in the sentence\n  got %q", c.name, want, got)
				}
			}
		})
	}
}

func TestTheSingularStateSentenceReadsAsEnglish(t *testing.T) {
	got := Reason(answered(payload.ServiceProbe{State: &payload.ProbeState{Asked: 1}}))

	if !strings.Contains(got, "the one current-user address asked was served") {
		t.Fatalf("one address is singular; got %q", got)
	}
}

func TestTheAnonymousReadingsThreeRows(t *testing.T) {
	// §13.5's table. Note what the middle row does: an offer with no content served says **nothing**,
	// because a login screen a bundle drew has exactly that shape and describing it would be describing
	// the page §13.4 already failed to settle.
	cases := []struct {
		name string
		anon payload.ProbeAnon
		want []string
		none bool
	}{
		{
			name: "content served and a way in",
			anon: payload.ProbeAnon{TextChars: 4210, Links: 37, LoginHref: "/login", LoginLabel: "Sign in"},
			want: []string{"4210 characters of visible text", "37 links", "offered a way in",
				`"Sign in"`, "/login"},
		},
		{
			name: "content served and no way in",
			anon: payload.ProbeAnon{TextChars: 4210, Links: 37},
			want: []string{"4210 characters", "the application's own content, not a shell"},
		},
		{
			name: "a way in and no content served",
			anon: payload.ProbeAnon{TextChars: 12, Links: 1, LoginHref: "/login", LoginLabel: "Sign in"},
			none: true,
		},
		{
			name: "neither",
			anon: payload.ProbeAnon{},
			none: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := anonClause(payload.ServiceProbe{Anon: &c.anon})
			if c.none {
				if got != "" {
					t.Fatalf("%s must add nothing; got %q", c.name, got)
				}
				return
			}
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Fatalf("%s\n want %q\n  got %q", c.name, want, got)
				}
			}
		})
	}
}

func TestAnOfferWhoseLabelWasDroppedIsStillNamed(t *testing.T) {
	// I6 dropped the label; the path stands in for it rather than the offer going unmentioned.
	got := anonClause(payload.ServiceProbe{Anon: &payload.ProbeAnon{
		TextChars: 900, Links: 12, LoginHref: "/accounts/login"}})

	if !strings.Contains(got, "a link to /accounts/login") {
		t.Fatalf("want the path standing in for the label; got %q", got)
	}
}

func TestAnOfferWithNoPathIsNamedByItsWords(t *testing.T) {
	// The control case: a button, which has a label and no href.
	got := anonClause(payload.ServiceProbe{Anon: &payload.ProbeAnon{
		TextChars: 900, Links: 12, LoginLabel: "Sign in"}})

	if !strings.Contains(got, `offered a way in — "Sign in".`) {
		t.Fatalf("want the words and no path; got %q", got)
	}
}

func TestTheAnonymousSentenceIsAnAdditionToANegativeVerdictAndNothingElse(t *testing.T) {
	// The record travels with every HTML 200, gate or no gate. The sentence does not.
	anon := &payload.ProbeAnon{TextChars: 4210, Links: 37}

	gated := Reason(answered(payload.ServiceProbe{Gate: payload.GatePasswordForm, Anon: anon}))
	if strings.Contains(gated, "characters of visible text") {
		t.Fatalf("a gate's sentence is the fact that fired, and nothing else; got %q", gated)
	}

	open := Reason(answered(payload.ServiceProbe{Form: &payload.LoginFormShape{}, Anon: anon}))
	if !strings.Contains(open, "characters of visible text") {
		t.Fatalf("a negative verdict's sentence gains the clause; got %q", open)
	}
}

func TestNoAnswerIsNotAMeasurementAndSaysSo(t *testing.T) {
	got := payload.ServiceProbe{Endpoint: "https://app.lan/", Phase: payload.PhaseConnect,
		Detail: "connection refused"}

	if VerdictOf(got) != VerdictNoAnswer {
		t.Fatalf("a phase that is not ok is no answer; got %q", VerdictOf(got))
	}
	if Label(VerdictOf(got)) != "No answer" {
		t.Fatalf("and it is labelled apart from *No login page*; got %q", Label(VerdictOf(got)))
	}

	reason := Reason(got)
	for _, want := range []string{"No answer from https://app.lan/", "connection refused"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("want %q in %q", want, reason)
		}
	}
}

func TestAPartialAnswerIsStillAnAnswer(t *testing.T) {
	// conn.OK is true for partial, and a service that answered on one of two addresses was measured.
	got := payload.ServiceProbe{Endpoint: base, Phase: payload.PhasePartial, Status: status(200),
		Form: &payload.LoginFormShape{}}

	if VerdictOf(got) != VerdictOpen {
		t.Fatalf("partial is ok, so this is a reading; got %q", VerdictOf(got))
	}
}

func TestTheVerdictLabelStaysNoLoginPageHoweverMuchTheAnonymousReadingSaid(t *testing.T) {
	// §13.5 pins this. The extra sentence is an addition to the reason, never a change of verdict.
	got := answered(payload.ServiceProbe{Form: &payload.LoginFormShape{},
		Anon: &payload.ProbeAnon{TextChars: 9000, Links: 120, LoginHref: "/login", LoginLabel: "Sign in"}})

	if Label(VerdictOf(got)) != "No login page" {
		t.Fatalf("the verdict label is unchanged; got %q", Label(VerdictOf(got)))
	}
}

func TestTheThreeLabelsAreThreeDifferentClaims(t *testing.T) {
	for verdict, want := range map[Verdict]string{
		VerdictGated:    "Login page",
		VerdictOpen:     "No login page",
		VerdictNoAnswer: "No answer",
	} {
		if got := Label(verdict); got != want {
			t.Fatalf("Label(%q) = %q, want %q", verdict, got, want)
		}
	}
}

func TestOnePageGivesOneSentenceAndGivesItTwice(t *testing.T) {
	// I7, at the wording layer: a form's shortfall walks fixed field order, not a map.
	p := answered(payload.ServiceProbe{Form: &payload.LoginFormShape{Username: true, OTP: true}})

	first := Reason(p)
	for i := 0; i < 20; i++ {
		if again := Reason(p); again != first {
			t.Fatalf("the same record gave\n%q\nthen\n%q", first, again)
		}
	}
}
