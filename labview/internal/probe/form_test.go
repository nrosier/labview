package probe

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// shape reads one form out of served markup, the way the reading does.
func shape(body string) payload.LoginFormShape {
	all := forms(drawn(body))
	if len(all) != 1 {
		panic("the fixture must carry exactly one form")
	}
	return shapeOf(base, all[0])
}

func TestTheFiveFieldsAreReadFromWhatSection13SaysTheyAreReadFrom(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		check func(payload.LoginFormShape) bool
		want  string
	}{
		{"type=password", `<form><input type="password"></form>`,
			func(s payload.LoginFormShape) bool { return s.Password }, "password"},
		{"autocomplete=current-password", `<form><input autocomplete="current-password"></form>`,
			func(s payload.LoginFormShape) bool { return s.Password }, "password"},
		{"autocomplete=new-password", `<form><input autocomplete="new-password"></form>`,
			func(s payload.LoginFormShape) bool { return !s.Password }, "no password"},

		{"type=email needs no name", `<form><input type="email"></form>`,
			func(s payload.LoginFormShape) bool { return s.Username }, "username"},
		{"a text input named user", `<form><input type="text" name="user"></form>`,
			func(s payload.LoginFormShape) bool { return s.Username }, "username"},
		{"an input with no type at all", `<form><input name="username"></form>`,
			func(s payload.LoginFormShape) bool { return s.Username }, "username"},
		{"a tel input named identifier", `<form><input type="tel" name="identifier"></form>`,
			func(s payload.LoginFormShape) bool { return s.Username }, "username"},
		{"an autocomplete naming it", `<form><input type="text" autocomplete="username"></form>`,
			func(s payload.LoginFormShape) bool { return s.Username }, "username"},
		{"a search box", `<form><input type="text" name="q"></form>`,
			func(s payload.LoginFormShape) bool { return !s.Username }, "no username"},
		{"a query box", `<form><input type="text" name="query"></form>`,
			func(s payload.LoginFormShape) bool { return !s.Username }, "no username"},
		{"a checkbox named remember_user", `<form><input type="checkbox" name="remember_user"></form>`,
			func(s payload.LoginFormShape) bool { return !s.Username }, "no username"},

		{"input type=submit", `<form><input type="submit"></form>`,
			func(s payload.LoginFormShape) bool { return s.Submit }, "submit"},
		{"input type=image", `<form><input type="image" src="/go.png"></form>`,
			func(s payload.LoginFormShape) bool { return s.Submit }, "submit"},
		{"a button with type=submit", `<form><button type="submit">Go</button></form>`,
			func(s payload.LoginFormShape) bool { return s.Submit }, "submit"},
		{"a button with no type", `<form><button>Go</button></form>`,
			func(s payload.LoginFormShape) bool { return s.Submit }, "submit"},
		{"a button with type=button", `<form><button type="button">Go</button></form>`,
			func(s payload.LoginFormShape) bool { return !s.Submit }, "no submit"},

		{"one-time-code", `<form><input autocomplete="one-time-code"></form>`,
			func(s payload.LoginFormShape) bool { return s.OTP }, "otp"},

		{"an action on a login path", `<form action="/users/sign_in"></form>`,
			func(s payload.LoginFormShape) bool { return s.Action == "/users/sign_in" }, "the action"},
		{"an action off a login path", `<form action="/subscribe"></form>`,
			func(s payload.LoginFormShape) bool { return s.Action == "" }, "no action"},
		{"a cross-origin action", `<form action="https://hosted.example.net/login"></form>`,
			func(s payload.LoginFormShape) bool { return s.Action == "" }, "no action"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shape(c.body)
			if !c.check(got) {
				t.Fatalf("%s must read as %s; got %+v", c.name, c.want, got)
			}
		})
	}
}

func TestACrossOriginActionIsRejectedRatherThanReadAsAHandOff(t *testing.T) {
	// A hosted newsletter signup has the identical shape and the opposite meaning. Rejecting it costs a
	// gate on a real SSO hand-off — which is why `sso-form` exists and reads the SAML field instead.
	got := shape(`<form action="https://hosted.example.net/login"><input type="email" name="email"><button>Go</button></form>`)

	if got.Action != "" {
		t.Fatalf("a cross-origin action records nothing; got %q", got.Action)
	}
	if CredentialForm(got) {
		t.Fatal("with no login intent left, this is not a credential-form")
	}
}

func TestCredentialFormNeedsAllThreePartsOnOneForm(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"identifier, submit and an action on a login path",
			`<form action="/login"><input type="email"><button>Go</button></form>`, true},
		{"identifier, submit and a one-time code",
			`<form action="/verify"><input name="user"><input autocomplete="one-time-code"><input type="submit"></form>`, true},
		{"no submit control",
			`<form action="/login"><input type="email"></form>`, false},
		{"no identifier",
			`<form action="/login"><button>Continue</button></form>`, false},
		{"no login intent",
			`<form action="/subscribe"><input type="email"><button>Go</button></form>`, false},
		{"a password field disqualifies it",
			`<form action="/login"><input type="email"><input type="password"><button>Go</button></form>`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CredentialForm(shape(c.body)); got != c.want {
				t.Fatalf("CredentialForm for %s = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestLoginIntentIsOnlyTheTwoThingsAShapeCanState(t *testing.T) {
	// Everything else on a form — a name, a placeholder, a heading above it — is text, and §13.3 forbids
	// concluding a gate from text.
	if LoginIntent(payload.LoginFormShape{Username: true, Submit: true}) {
		t.Fatal("an identifier and a submit control state no intent on their own")
	}
	if !LoginIntent(payload.LoginFormShape{Action: "/login"}) {
		t.Fatal("an action on a login path is intent")
	}
	if !LoginIntent(payload.LoginFormShape{OTP: true}) {
		t.Fatal("a one-time-code field is intent")
	}
}

func TestWhenSeveralFormsQualifyTheStrongestWins(t *testing.T) {
	all := forms(drawn(
		`<form action="/search"><input name="q"><button>Search</button></form>` +
			`<form action="/login"><input name="user"><input type="password"><button>Go</button></form>` +
			`<form action="/subscribe"><input type="email"><button>Join</button></form>`))

	got := strongestForm(base, all)
	if got == nil || !got.Password {
		t.Fatalf("the password form outranks the other two; got %+v", got)
	}
}

func TestTheFirstOfEqualsWins(t *testing.T) {
	// So one page yields one answer and yields it twice (I7).
	all := forms(drawn(
		`<form action="/login"><input name="alpha"><input type="submit"></form>` +
			`<form action="/signin"><input name="beta"><input type="submit"></form>`))

	first := strongestForm(base, all)
	if first == nil || first.Action != "/login" {
		t.Fatalf("the first of two equally strong forms decides; got %+v", first)
	}
	if again := strongestForm(base, all); again.Action != first.Action {
		t.Fatalf("the same page gave %q then %q", first.Action, again.Action)
	}
}

func TestNoFormAtAllIsADifferentFactFromAFormThatSaidNothing(t *testing.T) {
	// The distinction is §13.4's entry condition.
	if got := strongestForm(base, forms(drawn(`<div id="root"></div>`))); got != nil {
		t.Fatalf("no form means nil, which is what §13.4 turns on; got %+v", got)
	}
	if got := strongestForm(base, forms(drawn(`<form></form>`))); got == nil {
		t.Fatal("an empty form is still a form, and its shape is still attached")
	}
}

func TestCompositionIsNeverReadAcrossForms(t *testing.T) {
	// A password input in one form and a username input in another do not make a login form. Reading
	// them together is how a site with a search box and a newsletter signup becomes a login page.
	all := forms(drawn(
		`<form action="/subscribe"><input type="email" name="email"><button>Join</button></form>` +
			`<form action="/settings"><input type="password" name="pw"></form>`))

	for _, f := range all {
		got := shapeOf(base, f)
		if got.Password && got.Username {
			t.Fatalf("two forms were read as one: %+v", got)
		}
	}
}
