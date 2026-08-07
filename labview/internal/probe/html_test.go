package probe

import (
	"strings"
	"testing"
)

func TestMarkupNobodySeesIsRemovedBeforeAnythingIsCounted(t *testing.T) {
	cases := []struct {
		name string
		body string
		gone string
	}{
		{"a comment", `<p>hello</p><!-- <input type="password"> -->`, "password"},
		{"a script", `<p>hi</p><script>var p = '<input type="password">'</script>`, "password"},
		{"a style", `<style>.x{content:"<input type=password>"}</style><p>hi</p>`, "password"},
		{"a template", `<template><input type="password"></template><p>hi</p>`, "password"},
		{"a noscript", `<noscript><input type="password"></noscript><p>hi</p>`, "password"},
		{"an svg", `<svg><desc><input type="password"></desc></svg><p>hi</p>`, "password"},
		{"an unterminated script", `<p>hi</p><script>var p = '<input type="password">'`, "password"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := drawn(c.body); contains(got, c.gone) {
				t.Fatalf("§13.5 requires %s removed before any number is read, and %q survived it: %q",
					c.name, c.gone, got)
			}
		})
	}
}

func TestASelfClosingSVGDoesNotSwallowThePageAfterIt(t *testing.T) {
	// SVG is the one place in HTML where `/>` really closes an element. A paired pattern applied first
	// would run from this `<svg/>` to the *next* `</svg>` and take the login form with it.
	body := `<svg viewBox="0 0 4 4"/><input type="password"><svg><path/></svg>`

	if got := drawn(body); !contains(got, `type="password"`) {
		t.Fatalf("§13.5 drops a self-closing <svg/> before either arm; the password input between the "+
			"two svgs was swallowed instead: %q", got)
	}
}

func TestVisibleTextIsCountedInCharactersAndNotBytes(t *testing.T) {
	// Three runes, nine bytes. A byte count would make a 200-character threshold mean 67 characters in
	// Japanese and 200 in English, so the wording thresholds would say different things per language.
	if got := textChars(`<p>日本語</p>`); got != 3 {
		t.Fatalf("visible text is counted in runes: want 3 for three CJK characters, got %d", got)
	}
}

func TestEntitiesAndWhitespaceDoNotInflateTheTextCount(t *testing.T) {
	if got := textChars("<p>a&nbsp;b</p>\n\n\t   <p>c</p>"); got != 5 {
		t.Fatalf(`want 5 characters for "a b c", got %d`, got)
	}
}

func TestAnHrefLessLinkStillCountsAsALink(t *testing.T) {
	// A framework binds a handler to a bare <a>. It is a link on the page whether or not it carries a
	// path, so it counts toward the total and simply offers no path to read (§13.5).
	got := anchors(`<a>Menu</a><a href="/docs">Docs</a>`)
	if len(got) != 2 {
		t.Fatalf("want 2 links, got %d: %+v", len(got), got)
	}
	if got[0].href != "" || got[0].label != "Menu" {
		t.Fatalf("an href-less link keeps its label and offers no path, got %+v", got[0])
	}
}

func TestALinkLabelIsTheWordsAndNotTheMarkup(t *testing.T) {
	got := anchors(`<a href="/login"><span class="icon"></span> Sign&nbsp;in </a>`)
	if len(got) != 1 || got[0].label != "Sign in" {
		t.Fatalf(`want the label "Sign in" with the icon markup and the entity resolved, got %+v`, got)
	}
}

func TestEachFormIsReadOnItsOwn(t *testing.T) {
	// A password input in one form and a username input in another do not make a login form (§13.3).
	all := forms(`<form action="/search"><input name="q"></form>` +
		`<form action="/subscribe"><input type="email" name="email"><button>Go</button></form>`)

	if len(all) != 2 {
		t.Fatalf("want 2 forms read separately, got %d", len(all))
	}
	if contains(all[0].inner, "email") {
		t.Fatalf("the first form's contents leaked into it from the second: %q", all[0].inner)
	}
}

func TestAFormTheBodyWasCutInTheMiddleOfIsStillRead(t *testing.T) {
	// The 64 KiB cap lands wherever it lands. A form whose close tag never arrived is read, and the
	// record says the body was truncated (§13.6).
	all := forms(`<form action="/login"><input type="password" name="pw"`)

	if len(all) != 1 {
		t.Fatalf("want the truncated tail form read, got %d forms", len(all))
	}
	if !contains(all[0].inner, "password") {
		t.Fatalf("the tail form kept nothing: %+v", all[0])
	}
}

func TestAnAttributeIsReadInAllThreeSpellingsHTMLPermits(t *testing.T) {
	cases := []struct{ element, want string }{
		{`<input type="password">`, "password"},
		{`<input type='password'>`, "password"},
		{`<input type=password>`, "password"},
		{`<input  type = "password" >`, "password"},
		{`<input name="pw">`, ""},
	}
	for _, c := range cases {
		if got := attr(c.element, "type"); got != c.want {
			t.Fatalf("attr(%q, type) = %q, want %q", c.element, got, c.want)
		}
	}
}

func TestADuplicatedAttributeKeepsTheFirstSpelling(t *testing.T) {
	// Invalid HTML, and browsers keep the first. Reading the same thing a reader's browser did is what
	// keeps the reading reproducible (I7).
	if got := attr(`<input type="text" type="password">`, "type"); got != "text" {
		t.Fatalf("the first spelling wins; got %q", got)
	}
}

func TestAnAttributePresentWithNoValueIsStillAbsentAsAValue(t *testing.T) {
	// `<button type>` is nonsense, but `attrPresent` and `attr` have to disagree about it: a <button>
	// with no `type` at all is a submit control, and that absence is the fact §13.3 reads.
	if attrPresent(`<button>Go</button>`, "type") {
		t.Fatal("a button with no type attribute must read as absent")
	}
	if !attrPresent(`<button type="button">Go</button>`, "type") {
		t.Fatal("a button with a type attribute must read as present")
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
