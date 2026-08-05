// Package labels is §7: the two label vocabularies, the fleet's middleware registry, the
// provider hints, and the authentication posture the three of them together support.
//
// Nothing here reads a file or opens a socket. It is handed label maps and environment
// entries that §6 already resolved, and it returns conclusions plus the evidence for them.
//
// Three rules from §7 shape all of it.
//
// A middleware is classified from its **definition** first, and from its name only when no
// stack defines it anywhere — and a name-derived conclusion is `inferred` and says so in a
// service note. A middleware called `authentik` that forwards somewhere else is not
// Authentik (I3).
//
// Hints match at **token boundaries**, never as bare substrings: `auth` must not match
// `oauth.bigcorp.example.com`, and `server` — which is what upstream Authentik calls one of
// its own services — must never become a hint at all.
//
// A mechanism whose provider could not be named is reported as the mechanism, with the
// evidence line saying the provider was not identified. The generic answer is the honest
// one; a guess would be worse than nothing, because a reader cannot tell a guess from a
// reading.
package labels

import (
	"sort"
	"strconv"
	"strings"
)

// itoa is strconv.Itoa under a name short enough to sit inside a note being assembled.
func itoa(n int) string { return strconv.Itoa(n) }

// afterPrefix returns what follows `<prefix>.` in a label key.
//
// The prefix comparison is case-insensitive. Both label vocabularies are read
// case-insensitively by the tools that own them, so `Traefik.HTTP.Routers…` in a compose
// file is the same router as the lower-case spelling, and a reader that only accepted one
// would silently drop the other's routes.
func afterPrefix(key, prefix string) (string, bool) {
	if prefix == "" || len(key) <= len(prefix)+1 {
		return "", false
	}
	if !strings.EqualFold(key[:len(prefix)], prefix) || key[len(prefix)] != '.' {
		return "", false
	}
	return key[len(prefix)+1:], true
}

// truthy and falsy are the two halves of an `enable` flag. Anything that is neither is
// unrecognised, and the caller decides — for both label vocabularies the decision is to
// keep the route and say so, because refusing to read a hostname over a misspelled flag
// would hide a live route (I4).
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func falsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return true
	}
	return false
}

// splitList reads a comma-separated label value in the order it was written. Order is kept
// because a middleware chain is ordered, and duplicates are kept because the value is
// evidence: what the operator wrote is what the proxy was told.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sortedKeys is the only order a label map has.
//
// Compose hands labels over as a mapping, so the document order of a `labels:` block is
// gone by the time it reaches here. Sorting the keys is what makes two runs over the same
// file produce byte-identical output (I7) — for anything where the operator's own order
// matters, the order has to be inside a single value, as it is for a middleware chain.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lowerJoin lowercases the field half of a label key, leaving the caller's own segments
// alone. `entryPoints` and `tls.certResolver` are the same settings as their lower-case
// spellings; a router *name* is not, and never passes through here.
func lowerJoin(segments []string) string {
	return strings.ToLower(strings.Join(segments, "."))
}

// quote sets a value apart from the sentence of a note that carries it. Label values are
// prose often enough — a middleware name, a misspelled flag — that an unquoted one reads as
// part of the note rather than as the evidence for it.
func quote(v string) string { return "`" + v + "`" }
