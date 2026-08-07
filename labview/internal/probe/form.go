package probe

import (
	"regexp"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// The three patterns §13.3 gives verbatim
// ---------------------------------------------------------------------------

// These are the spellings the specification fixes, transcribed unchanged. They use only RE2
// constructs, so they are the same expressions in any engine that reimplements this section — which
// is the point of pinning them rather than describing them.
//
// Each is applied both page-wide and to one form's own markup, so "is there a password input" has
// one definition and not two.
var (
	reMetaTag = regexp.MustCompile(`(?i)<meta\b[^>]*>`)

	reSAMLField = regexp.MustCompile(`(?i)<input\b[^>]*\bname\s*=\s*["']?saml(?:request|response)\b`)

	// The `\b` after `current-password` is what keeps `new-password` out: a registration form's
	// second field is not evidence that this page gates anything.
	rePasswordInput = regexp.MustCompile(`(?i)<input\b[^>]*(?:\btype\s*=\s*["']?password\b|\bautocomplete\s*=\s*["']?current-password\b)`)
)

// ---------------------------------------------------------------------------
// Username
// ---------------------------------------------------------------------------

// usernameMarkers are the substrings a text or tel input's `name`, `id` or `autocomplete` may carry
// for it to be an identifier field.
//
// The match is loose, and that is affordable **only** because it is never sufficient alone: a
// username field with no password, no submit control and no login intent concludes nothing. `q`,
// `search` and `query` are absent on purpose — they are the shape of every site search box on the
// internet, and including them would read a homepage with a search field as a login page.
var usernameMarkers = []string{
	"username", "user", "uname", "userid", "uid", "login", "email", "e-mail", "identifier", "account",
}

// usernameInput is whether one input element is an identifier field.
//
// `type="email"` needs no name at all: the type *is* the statement. Otherwise the input must be text
// or tel — a checkbox called `remember_user` is not an identifier field — and one of its three
// naming attributes must carry a marker.
func usernameInput(element string) bool {
	kind := strings.ToLower(attr(element, "type"))
	if kind == "email" {
		return true
	}
	if kind != "" && kind != "text" && kind != "tel" {
		return false
	}
	if kind == "" && !looksTextual(element) {
		return false
	}
	for _, name := range []string{"name", "id", "autocomplete"} {
		value := strings.ToLower(attr(element, name))
		if value == "" {
			continue
		}
		for _, marker := range usernameMarkers {
			if strings.Contains(value, marker) {
				return true
			}
		}
	}
	return false
}

// looksTextual is for `<input>` with no `type`, which HTML defines as `text`. It is spelled out
// rather than defaulted silently, because the same absence on a `<button>` means the opposite thing
// two rules down and a reader comparing them should see both stated.
func looksTextual(element string) bool { return !attrPresent(element, "type") }

// submitControl is whether an input or button submits the form.
//
// `type="image"` is a submit control that renders as a picture, which is how a good many older login
// forms spell their button. A `<button>` with no `type` is `submit` by HTML's own default, and that
// default is load-bearing: framework templates almost never write it.
func submitControl(inputs, buttons []string) bool {
	for _, element := range inputs {
		if hasAttrValue(element, "type", "submit", "image") {
			return true
		}
	}
	for _, attrs := range buttons {
		if !attrPresent(attrs, "type") || hasAttrValue(attrs, "type", "submit") {
			return true
		}
	}
	return false
}

// otpInput is a one-time-code field, by the attribute a password manager reads.
func otpInput(elements []string) bool {
	for _, element := range elements {
		if hasAttrValue(element, "autocomplete", "one-time-code") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// One form's shape
// ---------------------------------------------------------------------------

// shapeOf reads one form. Composition is per element and never page-wide: a password input in one
// form and a username input in another do not make a login form, and reading them together is how a
// site with a search box and a newsletter signup becomes a login page (§13.3).
//
// The action is recorded **only** when it stays on this origin and prefix-matches a login path. A
// cross-origin action MUST be rejected rather than read as a hand-off to an identity provider: a
// hosted newsletter signup has the identical shape and the opposite meaning.
func shapeOf(base string, f form) payload.LoginFormShape {
	elements := inputs(f.inner)

	out := payload.LoginFormShape{
		Password: rePasswordInput.MatchString(f.inner),
		Submit:   submitControl(elements, buttons(f.inner)),
		OTP:      otpInput(elements),
	}
	for _, element := range elements {
		if usernameInput(element) {
			out.Username = true
			break
		}
	}

	if target, ok := Point(base, attr(f.attrs, "action")); ok && !target.CrossOrigin {
		if path := Path(target); LoginPath(path) {
			out.Action = path
		}
	}
	return out
}

// LoginIntent is the marker `credential-form` needs beside a username field and a submit control.
//
// There are exactly two things in a shape that state intent: an action that resolves to one of the
// ten login paths on this origin, and a one-time-code field. Everything else on a form — a name, a
// placeholder, a heading above it — is text, and §13.3 forbids concluding a gate from text.
func LoginIntent(s payload.LoginFormShape) bool { return s.Action != "" || s.OTP }

// CredentialForm is §13.3's one clause that holds several facts together, and holds them
// deliberately: passwordless sign-in has no single marker, so without this every magic-link and
// passkey login reads as reachable without authentication.
//
// All three parts MUST be present on **one** form, and a password field disqualifies it — that form
// is a `password-form`, which is a stronger signal read page-wide.
func CredentialForm(s payload.LoginFormShape) bool {
	return !s.Password && s.Username && s.Submit && LoginIntent(s)
}

// rank is how much one form says, for choosing which shape to attach when a page has several.
//
// The strongest wins and the first of equals, so one page yields one answer and yields it twice
// (I7). A form that says nothing still ranks 0 and is still attached: §13.3 requires the shape
// attached whenever a form was found, **including when nothing was concluded from it**, because a
// reader who is told "no gate" needs to see what was actually on the page.
func rank(s payload.LoginFormShape) int {
	switch {
	case s.Password:
		return 4
	case CredentialForm(s):
		return 3
	case s.Username && s.Submit:
		return 2
	case s.Username || s.Submit || s.OTP || s.Action != "":
		return 1
	default:
		return 0
	}
}

// strongestForm is the shape attached to the record, and nil when the page carried no form at all.
//
// The distinction between no form and an empty form is what §13.4 turns on: "no `<form>` anywhere in
// the body" is its entry condition, and a nil here is that condition.
func strongestForm(base string, all []form) *payload.LoginFormShape {
	if len(all) == 0 {
		return nil
	}
	best := shapeOf(base, all[0])
	for _, f := range all[1:] {
		if got := shapeOf(base, f); rank(got) > rank(best) {
			best = got
		}
	}
	return &best
}
