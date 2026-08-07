package probe

import (
	"regexp"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// What an anonymous caller was shown
// ---------------------------------------------------------------------------

// LabelCap is the longest link label kept (I6). A short label is the words a page used for its own
// sign-in affordance, which is what a sentence has to quote; a long one is prose, and prose from
// somebody else's page is content this program has no business copying into a payload.
const LabelCap = 24

// The wording thresholds of §13.5. **Both** must hold for content to count as served: a login page
// can carry 200 characters of boilerplate, and a page of nothing but navigation can carry ten links.
//
// These are wording thresholds and not verdict thresholds. Nothing below decides whether a service
// is exposed — the worst a mistake here can do is put a wrong sentence on a service that stays in
// the exposed count either way.
const (
	MinTextChars = 200
	MinLinks     = 2
)

// anonymousView is §13.5: one pure function over the body already fetched, and no second request
// (I8).
//
// **It is structurally incapable of gating.** The gate rule takes an Answer; this takes reduced
// markup and a base address, so there is no response for it to influence — and `Read` computes it
// *after* the signal switch has already resolved, so no gate can be a function of it even by
// accident.
//
// It keeps no header, no cookie and no attribute value except one resolved path and a label shorter
// than LabelCap.
func anonymousView(base, reduced string) *payload.ProbeAnon {
	links := anchors(reduced)
	out := payload.ProbeAnon{
		TextChars: textChars(reduced),
		Links:     len(links),
	}

	if href, label, ok := loginOffer(base, links); ok {
		out.LoginHref, out.LoginLabel = href, label
		return &out
	}
	// No link offered one, but a page can put its sign-in behind a button — a form posted by
	// JavaScript, or a control that opens a hosted flow. §13.5 asks for the link **or the control**.
	if label, ok := loginControl(reduced); ok {
		out.LoginLabel = label
	}
	return &out
}

// loginOffer is the first link on the page that offers a way in, by its path or by its words.
//
// A logout link is skipped **before its path is read**, which §13.5 requires in those terms: login
// paths match by prefix, so `/auth/logout`, `/oauth2/sign_out` and `/sso/logout` are login paths *by
// name*, and a page carrying one is a page somebody is already signed in to.
func loginOffer(base string, links []anchor) (href, label string, ok bool) {
	for _, a := range links {
		if notLogin(a.label) {
			continue
		}

		var path string
		if target, resolved := Point(base, a.href); resolved {
			path = Path(target)
			if LogoutPath(path) {
				continue
			}
		}

		if path != "" && LoginPath(path) {
			return path, keepLabel(a.label), true
		}
		if loginWords(a.label) {
			return path, keepLabel(a.label), true
		}
	}
	return "", "", false
}

var (
	reControlButton = regexp.MustCompile(`(?is)<button\b[^>]*>(.*?)</\s*button\s*>`)
	reControlInput  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
)

// loginControl is a sign-in affordance that is a control rather than a link: a button's own words, or
// a submit input's `value`.
func loginControl(reduced string) (string, bool) {
	for _, m := range reControlButton.FindAllStringSubmatch(reduced, -1) {
		if label := textOf(m[1]); loginWords(label) && !notLogin(label) {
			return keepLabel(label), true
		}
	}
	for _, element := range reControlInput.FindAllString(reduced, -1) {
		if !hasAttrValue(element, "type", "submit", "button", "image") {
			continue
		}
		if label := attr(element, "value"); loginWords(label) && !notLogin(label) {
			return keepLabel(label), true
		}
	}
	return "", false
}

// keepLabel is the label reduced to what may be recorded: the page's own words when they are short
// enough to be a label, and nothing when they are prose (I6).
func keepLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" || len([]rune(label)) >= LabelCap {
		return ""
	}
	return label
}

// ---------------------------------------------------------------------------
// The two vocabularies
// ---------------------------------------------------------------------------

// The vocabularies are private and multi-language, for one reason: a path stays `/login` in every
// locale, and the label is the part that gets translated. A single-language list would read every
// non-English homepage as offering nothing.
//
// Three details are pinned by the corpus:
//
//   - **Word boundaries.** Without them `log[\s_-]?in` matches `Blog index`, and a blog's own index
//     link becomes a sign-in offer.
//   - ***Continue with* is deliberately absent.** It is a login label only when a provider name
//     follows it, and *Continue with reading* is not one.
//   - **Sign-up is deliberately absent from the veto**, so that a page offering *Sign in / Sign up*
//     still reads as a login affordance rather than being vetoed by its second half.
var loginWordPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\blog[\s_-]?in\b`),
	regexp.MustCompile(`(?i)\bsign[\s_-]?in\b`),
	regexp.MustCompile(`(?i)\bsigned[\s_-]?out\b`), // "You have been signed out" offers the way back
	regexp.MustCompile(`(?i)\bauthenticate\b`),
	regexp.MustCompile(`(?i)\bsso\b`),
	regexp.MustCompile(`(?i)\banmelden\b`),
	regexp.MustCompile(`(?i)\beinloggen\b`),
	regexp.MustCompile(`(?i)\bconnexion\b`),
	regexp.MustCompile(`(?i)\bse connecter\b`),
	regexp.MustCompile(`(?i)\biniciar sesi`), // sesión / sesion, both spellings
	regexp.MustCompile(`(?i)\bacceder\b`),
	regexp.MustCompile(`(?i)\baccedi\b`),
	regexp.MustCompile(`(?i)\bentrar\b`),
	regexp.MustCompile(`(?i)\binloggen\b`),
	regexp.MustCompile(`(?i)\blogga in\b`),
	regexp.MustCompile(`(?i)\blogg inn\b`),
	regexp.MustCompile(`(?i)\bkirjaudu\b`),
	regexp.MustCompile(`(?i)\bzaloguj\b`),
}

// loginWordsCJK and the veto's own list are matched as substrings rather than with `\b`, because Go's
// word boundary is an ASCII notion: in `ログイン` every position is a boundary and none of them mean
// anything, so a boundary assertion there is noise dressed as rigour.
var loginWordsCJK = []string{"войти", "вход", "登录", "登入", "ログイン", "로그인"}

var notLoginWordPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\blog[\s_-]?out\b`),
	regexp.MustCompile(`(?i)\bsign[\s_-]?out\b`),
	regexp.MustCompile(`(?i)\babmelden\b`),
	regexp.MustCompile(`(?i)\bd[eé]connexion\b`),
	regexp.MustCompile(`(?i)\bse d[eé]connecter\b`),
	regexp.MustCompile(`(?i)\bcerrar sesi`),
	regexp.MustCompile(`(?i)\buitloggen\b`),
	regexp.MustCompile(`(?i)\blogga ut\b`),
	regexp.MustCompile(`(?i)\bwyloguj\b`),
}

var notLoginWordsCJK = []string{"выйти", "登出", "注销", "ログアウト", "로그아웃"}

// loginWords is whether a label offers a way in.
func loginWords(label string) bool {
	if label == "" {
		return false
	}
	for _, re := range loginWordPatterns {
		if re.MatchString(label) {
			return true
		}
	}
	return containsAny(label, loginWordsCJK)
}

// notLogin is the veto: a label that offers a way *out*. It is checked first everywhere, because
// `Sign out` contains `sign` and `out` contains nothing that would stop the login list on its own.
func notLogin(label string) bool {
	if label == "" {
		return false
	}
	for _, re := range notLoginWordPatterns {
		if re.MatchString(label) {
			return true
		}
	}
	return containsAny(label, notLoginWordsCJK)
}

func containsAny(haystack string, needles []string) bool {
	lower := strings.ToLower(haystack)
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// What the reading amounts to
// ---------------------------------------------------------------------------

// ContentServed is §13.5's threshold, and both halves must hold.
func ContentServed(a payload.ProbeAnon) bool {
	return a.TextChars >= MinTextChars && a.Links >= MinLinks
}

// SignInOffered is whether the page put a way in on the screen, by link or by control.
func SignInOffered(a payload.ProbeAnon) bool { return a.LoginHref != "" || a.LoginLabel != "" }
