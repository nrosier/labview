package access

import "strings"

// UsernamePattern is §16's rule, stated once: *A username anywhere in the payload or a log line
// satisfies `^[A-Za-z0-9._@-]{1,64}$`, with `?` as the fallback.*
//
// It is written as a predicate rather than a regexp because it is checked on every login attempt and
// on every log line, and because a character class this small reads more plainly as a switch than as
// a pattern.
const UsernamePattern = `^[A-Za-z0-9._@-]{1,64}$`

// MaxUsername is the pattern's length bound.
const MaxUsername = 64

// UnknownUsername is what a name outside the pattern is reported as.
//
// It is a single character on purpose: it cannot itself be mistaken for a name, and it cannot carry a
// newline, an ANSI escape or a quotation mark into a log line. §19 requires exactly this — *a
// username is sanitised to `?` when it falls outside the username pattern, so a hostile username
// cannot forge a log line*.
const UnknownUsername = "?"

// ValidUsername reports whether s satisfies the pattern exactly.
func ValidUsername(s string) bool {
	if len(s) == 0 || len(s) > MaxUsername {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !usernameByte(s[i]) {
			return false
		}
	}
	return true
}

// Username is s if it satisfies the pattern, and `?` otherwise.
//
// Every path that puts a name into a log line or into a payload goes through here. A name that came
// off the wire is attacker-controlled: without this, a login attempt as
// `admin\n2026-03-14 signed in: root` would write two lines into the log and the second would be a
// lie about somebody else.
func Username(s string) string {
	if ValidUsername(s) {
		return s
	}
	return UnknownUsername
}

// ThrottleKey is the case-folded sanitised name the throttle counts against (§19).
//
// Case-folded because `Admin` and `admin` are the same attempt against the same account as far as a
// lock is concerned, and an attacker who could reset the counter by changing the case would have no
// lock to defeat. Sanitised first, so the 4096-key table cannot be filled with arbitrary strings.
func ThrottleKey(s string) string {
	return strings.ToLower(Username(s))
}

// usernameByte is the character class, written out.
func usernameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '@', b == '-':
		return true
	default:
		return false
	}
}
