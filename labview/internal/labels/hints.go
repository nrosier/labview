package labels

import (
	"net"
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// minBareHintLen is how long a single-token hint has to be before it may be believed.
//
// Upstream Authentik's own compose file calls its services `server` and `worker`. Adopting
// either verbatim would make every `OIDC_ISSUER=https://server.example.com` in the fleet
// read as Authentik, so a bare word has to be long enough to be a name rather than a role.
// `authentik` (nine) passes; `server` and `worker` (six) do not.
const minBareHintLen = 8

// maxChainDepth bounds middleware chain expansion. A chain that references itself is
// representable in labels, and this walk is what has to refuse to follow it forever (I8).
const maxChainDepth = 8

// Hints is the set of strings that identify the SSO provider (§7), either configured or
// discovered, matched against forward-auth addresses, issuer URLs and LDAP hosts.
//
// A hint is held as its token sequence rather than as text, because that is how it is
// matched: `authentik-server` matches `http://authentik-server:9000/…` and does not match
// `ldap://ldap-server.internal:389`, where a substring reader would find `server` and
// attribute somebody else's directory to Authentik.
type Hints struct {
	raw  []string
	toks [][]string
}

// NewHints keeps the specific hints among values, deduplicated and in a fixed order.
func NewHints(values ...[]string) Hints {
	var h Hints
	seen := map[string]bool{}
	for _, group := range values {
		for _, v := range group {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" || seen[v] || !Specific(v) {
				continue
			}
			seen[v] = true
			h.raw = append(h.raw, v)
		}
	}
	sort.Strings(h.raw)
	for _, v := range h.raw {
		h.toks = append(h.toks, Tokens(v))
	}
	return h
}

// Values is the hint set as text, for the diagnostics view.
func (h Hints) Values() []string { return h.raw }

// Empty reports that nothing identifies a provider. Every issuer then stays generic, which
// is what makes a fleet with no Authentik report honestly (§7).
func (h Hints) Empty() bool { return len(h.raw) == 0 }

// Match reports which hint the target names, if any.
//
// The match is a contiguous run of whole tokens, so a hint has to name the thing rather
// than merely occur inside a longer word. The longest hint that matches is returned, so an
// address naming `authentik-server` is credited to that hint rather than to `authentik`.
func (h Hints) Match(target string) (string, bool) {
	if target == "" {
		return "", false
	}
	tt := Tokens(target)
	best, bestLen := "", 0
	for i, hint := range h.raw {
		if contiguous(tt, h.toks[i]) && len(hint) > bestLen {
			best, bestLen = hint, len(hint)
		}
	}
	return best, best != ""
}

// Specific rejects a hint that would match half the fleet (§7).
//
// An address, an empty string and `localhost` identify nobody. Everything else has to be
// either a compound name — two or more tokens, which is what a hostname and a container
// name both are — or a single word long enough not to be a role.
func Specific(hint string) bool {
	h := strings.ToLower(strings.TrimSpace(hint))
	if h == "" || h == "localhost" {
		return false
	}
	if net.ParseIP(h) != nil {
		return false
	}
	t := Tokens(h)
	switch {
	case len(t) == 0:
		return false
	case len(t) >= 2:
		return true
	default:
		return len(t[0]) >= minBareHintLen
	}
}

// Tokens splits a value into the lower-case alphanumeric runs a hint is matched against.
//
// Every delimiter a host, a URL, a container name or an environment value can hold is a
// boundary: `http://authentik-server:9000/outpost.goauthentik.io/auth/traefik` becomes
// `http authentik server 9000 outpost goauthentik io auth traefik`. `oauth2` stays one
// token, which is precisely why the hint `auth` cannot match it.
func Tokens(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		switch {
		case alnum && start < 0:
			start = i
		case !alnum && start >= 0:
			out = append(out, strings.ToLower(s[start:i]))
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, strings.ToLower(s[start:]))
	}
	return out
}

// contiguous reports whether needle appears in haystack as consecutive whole tokens.
func contiguous(haystack, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j, n := range needle {
			if haystack[i+j] != n {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Discover is stage 9's provider discovery (§7): it walks the parsed fleet for a service
// that is identifiably Authentik and adopts what that service is called.
//
// Two things identify one — its image mentions `authentik`, or it defines a forward-auth
// address containing `goauthentik.io`, which is the outpost's own endpoint path and is not
// a naming convention about anybody's host. What is adopted is the service's container name
// and every hostname it answers on; its *compose service name* is deliberately not adopted,
// because upstream calls those `server` and `worker`.
//
// It cannot invent a provider. No such service means an empty return, every issuer stays
// generic, and a fleet with no Authentik says so.
func Discover(stacks []payload.AppStack, reg Registry) []string {
	var out []string
	eachAuthentik(stacks, reg, func(_ payload.AppStack, svc payload.Service, _ string) {
		out = append(out, svc.ContainerName)
		for _, r := range svc.Cloudflare {
			out = append(out, r.Hostname)
		}
		for _, r := range svc.Traefik {
			out = append(out, r.Hosts...)
		}
	})
	return out
}

// IsAuthentik is the one definition of "this is Authentik" (§11), which §7's provider discovery
// and §11's endpoint discovery are both required to share. Two definitions of it would mean a
// fleet where the hint list adopted a service the identity-provider read would not talk to.
//
// Both halves are things Authentik publishes about itself — the vendor's name in an image
// reference, and the outpost's own endpoint domain in a forward-auth address — and neither is an
// assumption about how the operator named anything (I2). The caller supplies the second half
// because finding it needs the middleware registry, which is a fleet-wide reading.
func IsAuthentik(svc payload.Service, definesOutpostAddress bool) bool {
	return definesOutpostAddress || strings.Contains(strings.ToLower(svc.Image), authentikMark)
}

// AuthentikServices is every service the definition matches, as `stack/service` keys in scan
// order (I7). It is what §11 builds its endpoint candidates from.
func AuthentikServices(stacks []payload.AppStack, reg Registry) []string {
	var out []string
	eachAuthentik(stacks, reg, func(_ payload.AppStack, _ payload.Service, key string) {
		out = append(out, key)
	})
	return out
}

func eachAuthentik(stacks []payload.AppStack, reg Registry, fn func(payload.AppStack, payload.Service, string)) {
	defining := reg.ServicesDefiningAddress(authentikEndpointMark)
	for _, stack := range stacks {
		for _, svc := range stack.Services {
			key := stack.ID + "/" + svc.Name
			if IsAuthentik(svc, defining[key]) {
				fn(stack, svc, key)
			}
		}
	}
}

const (
	// authentikMark is the vendor's name as it appears in an image reference.
	authentikMark = "authentik"
	// authentikEndpointMark is the outpost's endpoint domain, which appears in every
	// forward-auth address pointing at it.
	authentikEndpointMark = "goauthentik.io"
)
