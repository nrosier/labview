package scan

import "strings"

// maxEnvFileBytes bounds one environment file.
//
// §6 caps the sidecar and not this, but an unbounded read of a file named by a file is the
// same hazard by a different door (I8) — and no legitimate environment file is a megabyte.
// Over the limit the file is not read, with a note, rather than truncated: half an
// environment file is a set of values the stack never had.
const maxEnvFileBytes = 1 << 20

// envEntry is one declaration from an environment file, in file order.
//
// Value is nil for a line that names a variable and gives it nothing — `TZ` on its own.
// Compose takes that from the shell it is started in, so it is a different fact from
// `TZ=`, which sets it to the empty string, and the payload keeps them apart (§4.8).
type envEntry struct {
	Key   string
	Value *string
}

// parseEnvFile reads the `KEY=VALUE` format Compose's `env_file` and `.env` share.
//
// Deliberately literal: nothing in an environment file is substituted. Compose does not
// interpolate `env_file` values, and doing it here would invent values the stack never
// had. Quoting is honoured because it is the only way to write a value with a `#` or a
// newline in it, and a PEM key in an environment file is an ordinary thing to find.
func parseEnvFile(data []byte) []envEntry {
	lines := strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n")

	var out []envEntry
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")

		key, rest, hasValue := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if key == "" || strings.ContainsAny(key, " \t") {
			continue // not a declaration: a stray word, or a line this format cannot mean
		}
		if !hasValue {
			out = append(out, envEntry{Key: key})
			continue
		}

		value, consumed := envValue(strings.TrimLeft(rest, " \t"), lines[i+1:])
		i += consumed
		out = append(out, envEntry{Key: key, Value: &value})
	}
	return out
}

// envValue reads one value, continuing onto following lines while a quote is still open.
// It returns the value and how many extra lines it consumed.
func envValue(rest string, following []string) (string, int) {
	for _, q := range []byte{'"', '\''} {
		if len(rest) == 0 || rest[0] != q {
			continue
		}
		body, used, closed := quoted(rest[1:], following, q)
		if !closed {
			// An unterminated quote. The file is malformed and there is no quoted value to
			// read, so the line's text is taken exactly as written — opening quote and all.
			// Stripping the quote would report a value the file does not contain.
			break
		}
		if q == '"' {
			body = unescape(body)
		}
		return body, used
	}
	return strings.TrimRight(stripComment(rest), " \t"), 0
}

// quoted collects a quoted body up to the closing quote, spanning lines if it has to.
func quoted(rest string, following []string, q byte) (body string, used int, closed bool) {
	var b strings.Builder
	for {
		if end := closingQuote(rest, q); end >= 0 {
			b.WriteString(rest[:end])
			return b.String(), used, true
		}
		b.WriteString(rest)
		if used >= len(following) {
			return "", 0, false
		}
		b.WriteByte('\n')
		rest = strings.TrimRight(following[used], "\r")
		used++
	}
}

// closingQuote finds the terminating quote, skipping one escaped by a backslash.
func closingQuote(s string, q byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == q {
			return i
		}
	}
	return -1
}

// unescape handles the escapes a double-quoted value may carry.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\', '"', '\'':
			b.WriteByte(s[i])
		default:
			// Not an escape this format defines, so both characters are text.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// stripComment removes a trailing comment from an unquoted value. The `#` has to be
// preceded by whitespace, or a value that legitimately contains one — a URL fragment, a
// colour — would lose its tail.
func stripComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
			return s[:i]
		}
	}
	return s
}

// envMap folds entries into a substitution environment, last declaration winning. A key
// declared with no value is left out: the shell would supply it, and this scan cannot see
// the shell, so `${KEY:-default}` must reach its default (§6).
func envMap(entries []envEntry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.Value == nil {
			delete(m, e.Key)
			continue
		}
		m[e.Key] = *e.Value
	}
	return m
}
