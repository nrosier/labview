package scan

import (
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// maxInterpDepth is §6's bound on nested substitution. It counts brace nesting, not the
// length of a chain of values, because a substituted value is never re-scanned — Compose
// expands `${A:-${B:-c}}` and stops, and a value that happens to contain `${X}` after
// substitution is text.
const maxInterpDepth = 32

// varSource records what supplied a substituted value's text. It is a set: one value can
// take part of its text from the stack's .env and part from a default.
type varSource uint8

const (
	// fromEnvFile — a variable that the stack's .env set.
	fromEnvFile varSource = 1 << iota
	// fromDefault — text written into the expression as a default, which no file pins.
	fromDefault
	// fromShell — nothing supplied it. Compose would take it from the shell it is
	// started in; this scan cannot see that shell, so the reference is left as written.
	fromShell
)

// interpolator is a stack's substitution environment (§6).
//
// It holds the stack's .env file and **nothing else**. Reading LabView's own process
// environment here would be wrong twice over: it is not the environment the stack was
// started in, so the values would be fiction; and it would copy LabView's own variables —
// including the four credentials of §3.3 — into a payload describing somebody else's
// service (I6). The cost is that a variable only the shell sets reads as unresolved, which
// is both true and the note it produces.
type interpolator struct {
	// vars holds only names with a value. A name declared with no value is a name the
	// shell supplies, so it is absent here and `${NAME:-x}` takes its default.
	vars map[string]string
}

// expand substitutes one scalar's text. where names the field for any note it produces —
// `image`, `environment.LDAP_HOST`, `labels[3]` — because a note that says a variable is
// unset without saying where is a note an operator cannot act on.
func (in interpolator) expand(s, where string) (out string, src varSource, notes []string) {
	if !strings.ContainsRune(s, '$') {
		return s, 0, nil // the overwhelmingly common case, and no allocation
	}
	return in.expandAt(s, where, 0)
}

func (in interpolator) expandAt(s, where string, depth int) (string, varSource, []string) {
	if depth > maxInterpDepth {
		return s, fromShell, []string{where + ": nested substitution goes deeper than " +
			itoa(maxInterpDepth) + " levels; left as written"}
	}

	var (
		b     strings.Builder
		src   varSource
		notes []string
	)
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// `$$` is an escaped dollar and never the start of a reference.
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			end, ok := matchBrace(s, i+1)
			if !ok {
				// Left as written, and not as a value any file pins: an expression this
				// scan could not finish must not read as text the environment block set.
				notes = append(notes, where+`: "`+s[i:]+`" has no closing brace; left as written`)
				b.WriteString(s[i:])
				src |= fromShell
				break
			}
			t, esrc, en := in.evalBraced(s[i+2:end], s[i:end+1], where, depth)
			b.WriteString(t)
			src |= esrc
			notes = append(notes, en...)
			i = end + 1
			continue
		}
		// The braceless form. Compose accepts it, so a fleet using it must read the same
		// way here as it does at up time.
		if name := scanName(s[i+1:]); name != "" {
			t, esrc, en := in.lookup(name, "$"+name, where)
			b.WriteString(t)
			src |= esrc
			notes = append(notes, en...)
			i += 1 + len(name)
			continue
		}
		// A `$` that begins nothing is a dollar sign.
		b.WriteByte('$')
		i++
	}
	return b.String(), src, notes
}

// evalBraced evaluates one `${...}` expression. expr is the text between the braces and
// raw is the expression as written, which is what a refusal leaves in place.
func (in interpolator) evalBraced(expr, raw, where string, depth int) (string, varSource, []string) {
	name := scanName(expr)
	op, arg, ok := splitOperator(expr[len(name):])
	if name == "" || !ok {
		// `${1BAD}`, `${}`, or one of the forms §6 does not list — `${VAR:+alt}`,
		// `${VAR/a/b}`. Guessing at an unlisted form is how a scanner reports a value
		// the fleet never had, so the expression stays as written and says so.
		return raw, fromShell, []string{where + `: "` + raw + `" is not a variable reference; left as written`}
	}

	value, set := in.vars[name]
	// The two spellings differ on the empty string: `:-` and `:?` treat set-but-empty as
	// missing, the bare forms treat it as a value.
	missing := !set || (value == "" && strings.HasPrefix(op, ":"))

	switch op {
	case "":
		return in.lookup(name, raw, where)

	case ":-", "-":
		if !missing {
			return value, fromEnvFile, nil
		}
		// The default is only evaluated when it is reached: `${SET:-${MUST_NOT_BE_READ}}`
		// must not produce a note about the branch it never took.
		text, src, notes := in.expandAt(arg, where, depth+1)
		if !singleRef(arg) {
			// Some of this text was written into the expression rather than supplied by
			// a file, so no file pins the value.
			src |= fromDefault
		}
		return text, src, notes

	case ":?", "?":
		if !missing {
			return value, fromEnvFile, nil
		}
		// Compose refuses to start the stack here. LabView reports it and carries on: a
		// whole fleet is not withheld over one stack's missing variable (I4).
		note := where + ": ${" + name + "} is required and not set"
		if msg := strings.TrimSpace(arg); msg != "" {
			note += ": " + msg
		}
		return raw, fromShell, []string{note + "; left as written"}
	}
	return raw, fromShell, nil
}

// lookup is the plain `${NAME}` and `$NAME` forms.
func (in interpolator) lookup(name, raw, where string) (string, varSource, []string) {
	if value, ok := in.vars[name]; ok {
		return value, fromEnvFile, nil
	}
	return raw, fromShell, []string{where + ": ${" + name +
		"} is not set in this stack's .env; left as written"}
}

// splitOperator splits the tail of an expression into one of §6's five forms. It reports
// false for anything else, including trailing text after a bare name.
func splitOperator(rest string) (op, arg string, ok bool) {
	switch {
	case rest == "":
		return "", "", true
	case strings.HasPrefix(rest, ":-"):
		return ":-", rest[2:], true
	case strings.HasPrefix(rest, ":?"):
		return ":?", rest[2:], true
	case strings.HasPrefix(rest, "-"):
		return "-", rest[1:], true
	case strings.HasPrefix(rest, "?"):
		return "?", rest[1:], true
	}
	return "", "", false
}

// scanName returns the leading run of s matching §6's name rule,
// `^[A-Za-z_][A-Za-z0-9_]*`, and "" when s does not begin with one.
func scanName(s string) string {
	if s == "" || !(isAlpha(s[0]) || s[0] == '_') {
		return ""
	}
	i := 1
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '_') {
		i++
	}
	return s[:i]
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// matchBrace returns the index of the `}` closing the `{` at open. Counting rather than
// searching is the whole point: `${A:-${B}}` closes at the second brace, and a scanner
// that stops at the first leaves `}` in the output.
func matchBrace(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// singleRef reports whether s is exactly one variable reference and nothing else, which
// is what decides whether a default contributed text of its own. `${A:-${B}}` takes B's
// source, because B supplied every character; `${A:-port-${B}}` does not, because
// "port-" came from the expression.
func singleRef(s string) bool {
	if strings.HasPrefix(s, "${") {
		end, ok := matchBrace(s, 1)
		return ok && end == len(s)-1
	}
	if strings.HasPrefix(s, "$") {
		return len(s) > 1 && scanName(s[1:]) == s[1:]
	}
	return false
}

// sourceOf answers §4.8's question about one environment entry: where did this value come
// from? declaredIn is the key it was written under — the `environment:` block or an
// `env_file:` — and is the answer when no substitution took place.
//
// A value assembled from more than one source takes the weakest, because the question the
// field answers is whether the files pin the value. A default or an unresolved reference
// means they do not, whatever else contributed.
func sourceOf(src varSource, declaredIn payload.EnvVarSource) payload.EnvVarSource {
	switch {
	case src&(fromDefault|fromShell) != 0:
		return payload.EnvFromShellDefault
	case src&fromEnvFile != 0:
		return payload.EnvFromEnvFile
	default:
		return declaredIn
	}
}

// itoa avoids pulling strconv in for the two numbers this package formats.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
