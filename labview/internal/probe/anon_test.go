package probe

import (
	"strings"
	"testing"
)

// view runs §13.5 over served markup the way the reading does: drawn markup, not served markup.
func view(body string) (textChars, links int, href, label string) {
	got := anonymousView(base, drawn(body))
	return got.TextChars, got.Links, got.LoginHref, got.LoginLabel
}

func TestBlogIndexIsNotASignInOffer(t *testing.T) {
	// The word-boundary detail, pinned by the corpus. Without `\b`, `log[\s_-]?in` matches `Blog index`
	// and a blog's own index link becomes a login affordance.
	_, _, href, label := view(`<a href="/blog">Blog index</a>`)

	if href != "" || label != "" {
		t.Fatalf("`Blog index` must not read as a sign-in offer; got href %q label %q", href, label)
	}
}

func TestContinueWithIsDeliberatelyNotALoginLabel(t *testing.T) {
	// It is a login label only when a provider name follows it, so §13.5 leaves it out of the
	// vocabulary entirely. The cost is a missed label; the alternative is reading a reading app's own
	// button as a sign-in control.
	_, _, href, label := view(`<a href="/read/next">Continue with reading</a>`)

	if href != "" || label != "" {
		t.Fatalf("`Continue with reading` must offer nothing; got href %q label %q", href, label)
	}
}

func TestSignInSlashSignUpStillReadsAsASignInOffer(t *testing.T) {
	// Sign-up is deliberately absent from the veto, so a page whose one affordance is spelled this way
	// is not vetoed by its own second half.
	_, _, href, label := view(`<a href="/login">Sign in / Sign up</a>`)

	if href != "/login" || label != "Sign in / Sign up" {
		t.Fatalf("want the offer kept; got href %q label %q", href, label)
	}
}

func TestALogoutLinkIsSkippedBeforeItsPathIsRead(t *testing.T) {
	// This is the case the requirement is written in those terms for: the label says nothing, and the
	// path is a login path *by prefix*. A page carrying it is a page somebody is already signed in to.
	_, _, href, label := view(`<a href="/oauth2/sign_out">Exit</a>`)

	if href != "" || label != "" {
		t.Fatalf("a logout path must be skipped before it is read as a login path; got href %q label %q",
			href, label)
	}
}

func TestALogoutLabelIsSkippedToo(t *testing.T) {
	for _, markup := range []string{
		`<a href="/x">Log out</a>`,
		`<a href="/x">Sign out</a>`,
		`<a href="/x">Abmelden</a>`,
		`<a href="/x">Déconnexion</a>`,
		`<a href="/x">ログアウト</a>`,
	} {
		if _, _, href, label := view(markup); href != "" || label != "" {
			t.Fatalf("%s offers a way out, not in; got href %q label %q", markup, href, label)
		}
	}
}

func TestTheVocabularyIsMultiLanguageBecauseOnlyTheLabelGetsTranslated(t *testing.T) {
	// A path stays `/login` in every locale. A single-language list would read every non-English
	// homepage as offering nothing.
	cases := []string{
		"Log in", "Login", "Sign in", "Anmelden", "Einloggen", "Connexion", "Se connecter",
		"Iniciar sesión", "Accedi", "Inloggen", "Logga in", "Kirjaudu", "Zaloguj", "Войти",
		"登录", "ログイン", "로그인",
	}
	for _, label := range cases {
		if !loginWords(label) {
			t.Fatalf("%q is a sign-in label in some locale and must be read as one", label)
		}
		if notLogin(label) {
			t.Fatalf("%q must not be vetoed", label)
		}
	}
}

func TestTheFirstOfferOnThePageWins(t *testing.T) {
	// One page yields one reading and yields it twice (I7).
	body := `<a href="/signin">Sign in</a><a href="/login">Log in</a>`

	_, _, href, label := view(body)
	if href != "/signin" || label != "Sign in" {
		t.Fatalf("the first offer decides; got href %q label %q", href, label)
	}
	if _, _, again, _ := view(body); again != href {
		t.Fatalf("the same page gave %q then %q", href, again)
	}
}

func TestALoginPathIsAnOfferWhateverTheLinkWasCalled(t *testing.T) {
	_, _, href, label := view(`<a href="/users/sign_in"><svg viewBox="0 0 1 1"/></a>`)

	if href != "/users/sign_in" {
		t.Fatalf("the path alone is enough; got href %q", href)
	}
	if label != "" {
		t.Fatalf("an icon link has no words to quote; got label %q", label)
	}
}

func TestALabelTooLongToBeALabelIsNotKept(t *testing.T) {
	// I6: a short label is the page's own words for its affordance; a long one is prose, and prose from
	// somebody else's page has no business in a payload.
	long := "Click here to sign in to your account"
	if len([]rune(long)) < LabelCap {
		t.Fatalf("the fixture must exceed the %d-character cap to test it", LabelCap)
	}

	_, _, href, label := view(`<a href="/login">` + long + `</a>`)
	if href != "/login" {
		t.Fatalf("the offer still stands; got href %q", href)
	}
	if label != "" {
		t.Fatalf("a label past the cap is dropped, not truncated; got %q", label)
	}
}

func TestASignInControlCountsWhenNoLinkOfferedOne(t *testing.T) {
	// §13.5 asks for the link **or the control**: a page can post its login form from JavaScript, or
	// open a hosted flow from a button.
	cases := []struct{ markup, want string }{
		{`<div id="root"></div><button class="primary">Sign in</button>`, "Sign in"},
		{`<input type="submit" value="Anmelden">`, "Anmelden"},
		{`<button type="button">ログイン</button>`, "ログイン"},
	}
	for _, c := range cases {
		if _, _, href, label := view(c.markup); label != c.want || href != "" {
			t.Fatalf("%s must offer %q with no path; got href %q label %q", c.markup, c.want, href, label)
		}
	}
}

func TestAControlInsideATemplateIsNotSomethingAnyoneWasShown(t *testing.T) {
	// Drawn markup, not served markup. A button a bundle may or may not render is not an affordance the
	// reading may describe, and missing it falls to §13.4 — the safe direction.
	if _, _, _, label := view(`<template><button>Sign in</button></template><p>hi</p>`); label != "" {
		t.Fatalf("a control inside a <template> was never drawn; got label %q", label)
	}
}

func TestContentServedNeedsBothHalves(t *testing.T) {
	// A login page can carry 200 characters of boilerplate, and a page of nothing but navigation can
	// carry ten links. Both MUST hold.
	text := strings.Repeat("word ", 60) // comfortably past 200 characters

	cases := []struct {
		name string
		body string
		want bool
	}{
		{"text and links", `<p>` + text + `</p><a href="/a">A</a><a href="/b">B</a>`, true},
		{"text and one link", `<p>` + text + `</p><a href="/a">A</a>`, false},
		{"text and no links", `<p>` + text + `</p>`, false},
		{"links and no text", `<a href="/a">A</a><a href="/b">B</a>`, false},
		{"neither", `<div id="root"></div>`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := anonymousView(base, drawn(c.body))
			if ContentServed(*got) != c.want {
				t.Fatalf("ContentServed for %s = %v, want %v (%d chars, %d links)",
					c.name, !c.want, c.want, got.TextChars, got.Links)
			}
		})
	}
}

func TestTheNumbersComeFromDrawnMarkup(t *testing.T) {
	// A page of nothing but a script tag has no visible text, however many bytes it carries.
	chars, links, _, _ := view(`<script>` + strings.Repeat("x=1;", 200) + `</script>`)

	if chars != 0 || links != 0 {
		t.Fatalf("a page of script is a page of nothing; got %d chars and %d links", chars, links)
	}
}

func TestASignInOfferWithNoContentServedIsRecordedAndSaysNothing(t *testing.T) {
	// The middle row of §13.5's table: a login screen a bundle drew has exactly this shape, and the
	// reading is left to §13.4 rather than described.
	got := anonymousView(base, drawn(`<div id="root"></div><a href="/login">Sign in</a>`))

	if !SignInOffered(*got) {
		t.Fatal("the offer is recorded")
	}
	if ContentServed(*got) {
		t.Fatal("one link and no text is not content served")
	}
}
