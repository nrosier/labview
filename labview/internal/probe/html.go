// Package probe is §13: the active probe.
//
// Every other source in this program says what a service is *configured* to do. This one says what
// it **answers**, for one blind spot — an application with its own login page carries no label, no
// environment key and no entry in anybody's API.
//
// The split is stricter here than anywhere else in the program, because §13 requires it in as many
// words: **every rule is pure and independently testable, with none of it in the code that
// fetches.** `Do` walks addresses and holds the only `transport.Client`; `Signals` takes an Answer —
// a status, a header set and at most 64 KiB of body — and returns a Reading. So the eight signals,
// the form composition, the anonymous view and the reason sentences are all assertable as tables of
// literals, which is the only way a rule that decides whether a service is exposed can be reviewed
// at all.
//
// The asymmetry that governs the whole section: a signal here can only ever take a service **out**
// of the exposed count. A missing rule costs a gate; it can never invent one. Every judgement call
// below resolves in that direction.
package probe

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Drawn markup, not served markup
// ---------------------------------------------------------------------------

// The elements a reader never sees. §13.5 requires every number it reports to come from a body with
// these removed, and the form rules read the same reduced body: a login form inside a `<template>`
// is markup a JavaScript bundle may or may not render, and reading it as a served form would be the
// one direction §13.3 forbids — a gate concluded from something nobody was shown.
//
// Missing it costs nothing, because a page whose only form is in a template is exactly the shape
// §13.4 asks its second question about.
var hiddenElements = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<script\b[^>]*>.*?</\s*script\s*>`),
	regexp.MustCompile(`(?is)<style\b[^>]*>.*?</\s*style\s*>`),
	regexp.MustCompile(`(?is)<template\b[^>]*>.*?</\s*template\s*>`),
	regexp.MustCompile(`(?is)<noscript\b[^>]*>.*?</\s*noscript\s*>`),
	regexp.MustCompile(`(?is)<svg\b[^>]*>.*?</\s*svg\s*>`),
}

var (
	reComment = regexp.MustCompile(`(?s)<!--.*?-->`)

	// A self-closing `<svg/>`, dropped before either arm above. SVG is the one place in HTML where
	// `/>` really closes an element, so a paired pattern would run past it to the *next* `</svg>`
	// and swallow the whole page between them (§13.5).
	reSelfClosing = regexp.MustCompile(`(?is)<svg\b[^>]*/>`)

	// An element the body was cut in the middle of. The 64 KiB cap lands wherever it lands, and a
	// half-arrived `<script>` whose close tag never came would otherwise leave a page of JavaScript
	// being counted as visible text.
	reUnterminated = regexp.MustCompile(`(?is)<(?:script|style|template|noscript|svg)\b[^>]*>.*$`)

	reTag    = regexp.MustCompile(`(?s)<[^>]*>`)
	reSpaces = regexp.MustCompile(`\s+`)
)

// drawn is the body with everything a reader never sees removed, in the order §13.5 fixes.
func drawn(body string) string {
	body = reComment.ReplaceAllString(body, " ")
	body = reSelfClosing.ReplaceAllString(body, " ")
	for _, re := range hiddenElements {
		body = re.ReplaceAllString(body, " ")
	}
	return reUnterminated.ReplaceAllString(body, " ")
}

// ---------------------------------------------------------------------------
// Reading the reduced markup
// ---------------------------------------------------------------------------

// entities is the handful an unescape has to know to count text honestly. It is deliberately short:
// this is a length, not a rendering, and a page whose text is mostly named entities is not a case
// any threshold here turns on.
var entities = strings.NewReplacer(
	"&nbsp;", " ", "&#160;", " ",
	"&amp;", "&", "&lt;", "<", "&gt;", ">",
	"&quot;", `"`, "&#39;", "'", "&apos;", "'",
)

// textChars is the visible text length: tags removed, entities unescaped, whitespace collapsed.
//
// Runes rather than bytes. A page of Japanese would otherwise clear a 200-character threshold on a
// third of the words, which would make the wording thresholds mean different things in different
// languages.
func textChars(reduced string) int {
	text := reTag.ReplaceAllString(reduced, " ")
	text = entities.Replace(text)
	text = strings.TrimSpace(reSpaces.ReplaceAllString(text, " "))
	return len([]rune(text))
}

// anchor is one link as the page wrote it: where it points and what it was called.
type anchor struct {
	href  string
	label string
}

var reAnchor = regexp.MustCompile(`(?is)<a\b([^>]*)>(.*?)</\s*a\s*>`)

// anchors is every link in the reduced markup, in document order.
//
// An anchor with no `href` is still a link on the page — a button a framework binds a handler to —
// so it counts toward the link total and simply offers no path to read.
func anchors(reduced string) []anchor {
	var out []anchor
	for _, m := range reAnchor.FindAllStringSubmatch(reduced, -1) {
		out = append(out, anchor{
			href:  attr(m[1], "href"),
			label: textOf(m[2]),
		})
	}
	return out
}

// textOf is one element's own visible text, for a link label.
func textOf(inner string) string {
	text := reTag.ReplaceAllString(inner, " ")
	text = entities.Replace(text)
	return strings.TrimSpace(reSpaces.ReplaceAllString(text, " "))
}

var reForm = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</\s*form\s*>`)

// A form the body was cut in the middle of. It is read rather than discarded, and the record says
// the body was truncated — which is exactly the fact §13.6 keeps a field for.
var reFormTail = regexp.MustCompile(`(?is)<form\b([^>]*)>((?:.|\n)*)$`)

// form is one `<form>` element: its own attributes and its own contents. Composition is read per
// element and never page-wide, because a password input in one form and a username input in another
// do not make a login form (§13.3).
type form struct {
	attrs string
	inner string
}

// forms is every form in the reduced markup, in document order.
func forms(reduced string) []form {
	var out []form
	rest := reduced
	for {
		m := reForm.FindStringSubmatchIndex(rest)
		if m == nil {
			break
		}
		out = append(out, form{
			attrs: rest[m[2]:m[3]],
			inner: rest[m[4]:m[5]],
		})
		rest = rest[m[1]:]
	}
	// Whatever is left can still hold a form whose close tag never arrived.
	if m := reFormTail.FindStringSubmatch(rest); m != nil {
		out = append(out, form{attrs: m[1], inner: m[2]})
	}
	return out
}

var reInput = regexp.MustCompile(`(?is)<input\b[^>]*>`)

// inputs is every input element in a fragment, as written.
func inputs(fragment string) []string { return reInput.FindAllString(fragment, -1) }

var reButton = regexp.MustCompile(`(?is)<button\b([^>]*)>`)

// buttons is the attribute text of every button in a fragment.
func buttons(fragment string) []string {
	var out []string
	for _, m := range reButton.FindAllStringSubmatch(fragment, -1) {
		out = append(out, m[1])
	}
	return out
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

// reAttr reads one attribute in all three spellings HTML permits: double-quoted, single-quoted and
// bare. The bare arm is what makes `<input type=password>` — which every browser accepts — read the
// same as the quoted form, and the quoting is why the value is taken from whichever group matched
// rather than by trimming quotes afterwards.
var reAttr = regexp.MustCompile(`(?is)\b([a-z0-9_:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>` + "`" + `]+))`)

// attr is one attribute's value from an element's attribute text, lower-cased and trimmed, and
// empty when the attribute is absent.
//
// The first spelling wins. A duplicated attribute is invalid HTML and browsers keep the first, so
// this reads the same thing a reader's browser did (I7).
func attr(attrs, name string) string {
	for _, m := range reAttr.FindAllStringSubmatch(attrs, -1) {
		if !strings.EqualFold(m[1], name) {
			continue
		}
		for _, group := range m[2:] {
			if group != "" {
				return strings.TrimSpace(group)
			}
		}
		return ""
	}
	return ""
}

// hasAttrValue is whether an attribute is present and its value equals one of the wanted ones,
// compared case-insensitively.
func hasAttrValue(attrs, name string, want ...string) bool {
	got := strings.ToLower(attr(attrs, name))
	for _, v := range want {
		if got == v {
			return true
		}
	}
	return false
}

// attrPresent is whether an attribute appears at all, whatever it carries. `<button>` with no
// `type` is a submit control, so its absence is the fact that matters (§13.3).
func attrPresent(attrs, name string) bool {
	for _, m := range reAttr.FindAllStringSubmatch(attrs, -1) {
		if strings.EqualFold(m[1], name) {
			return true
		}
	}
	return false
}
