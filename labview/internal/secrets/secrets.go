// Package secrets is §20: the mask, and the redaction of credentials embedded in URIs.
//
// It is deliberately tiny and has no dependencies. Both operations happen before
// serialisation and never at render time (I6), so every caller is on the producing side of
// the payload; keeping them in one package is what makes "one masking rule" checkable.
package secrets

import "strings"

// Mask is what a withheld value is replaced with. It preserves shape — something was set,
// and it is not shown — and nothing of the content, not even its length: a mask that
// matched the length of a password would publish the length of every password in the fleet
// (§20).
const Mask = "********"

// MaskValue withholds a value.
//
// The empty string is returned unchanged, and that is not an oversight. An environment
// variable named like a secret and set to nothing is a finding — `POSTGRES_PASSWORD=` is
// the absence of a password, not a password — and replacing it with a mask would report a
// credential where the fleet has none, which is the opposite of the truth (I1).
func MaskValue(v string) string {
	if v == "" {
		return ""
	}
	return Mask
}

// RedactURIs replaces the password half of every `scheme://user:password@host` it finds.
//
// It is anchored on `://` rather than on `@` alone, because an unanchored reader mangles
// every email address and every `user@host` it meets. Userinfo with no colon is left
// alone: `smtp://notify@mail.example.com` names an account, and there is nothing there to
// withhold — inventing a mask for it would hide evidence about how a service is
// configured while protecting nothing.
//
// The username is kept for the same reason. It says which account a service connects as,
// which an operator reading the payload needs, and it is not the secret.
func RedactURIs(s string) string {
	if !strings.Contains(s, "://") {
		return s // the overwhelmingly common case, and no allocation
	}

	var b strings.Builder
	for i := 0; i < len(s); {
		mark := strings.Index(s[i:], "://")
		if mark < 0 {
			b.WriteString(s[i:])
			break
		}
		authority := i + mark + len("://")
		b.WriteString(s[i:authority])

		// The authority ends at the first delimiter, so an `@` further along — in a path
		// segment, in a query — is not userinfo and must not be touched.
		end := authority + strings.IndexFunc(s[authority:], endsAuthority)
		if end < authority {
			end = len(s)
		}
		at := strings.LastIndex(s[authority:end], "@")
		if at < 0 {
			b.WriteString(s[authority:end])
			i = end
			continue
		}
		userinfo := s[authority : authority+at]
		user, _, hasPassword := strings.Cut(userinfo, ":")
		if !hasPassword {
			b.WriteString(s[authority:end])
			i = end
			continue
		}
		b.WriteString(user)
		b.WriteByte(':')
		b.WriteString(Mask)
		b.WriteString(s[authority+at : end])
		i = end
	}
	return b.String()
}

// endsAuthority reports the characters that terminate a URI's authority component. Space
// and quote are included because these strings are environment values and label text, not
// parsed URIs, and a URI in prose ends where the prose resumes.
func endsAuthority(r rune) bool {
	switch r {
	case '/', '?', '#', ' ', '\t', '\n', '"', '\'', ',', ')', '>':
		return true
	}
	return false
}
