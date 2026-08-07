package labels

import (
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// Traefik reads the routers one service's labels declare (§7).
//
// A router is reported whether or not it looks complete, because a labelled router that the
// proxy will not serve is exactly the kind of thing a reader needs to see. What it is *not*
// is ingress: §4.1 requires hosts or a rule for that, so a router with neither is listed
// here and produces no `traefik` kind.
//
// `traefik.enable=false` withholds every router, the same way the tunnel's flag does and for
// the same reason — the proxy will not serve them, so reporting them as routes would invent
// exposure. A note names how many were withheld, because the labels are still there and a
// reader who greps the compose file will find them.
func Traefik(lbls map[string]string, prefix string) ([]payload.TraefikRoute, []string) {
	routers := map[string]map[string]string{}
	ports := map[string]string{}
	var names []string
	enable, hasEnable := "", false

	for _, key := range sortedKeys(lbls) {
		rest, ok := afterPrefix(key, prefix)
		if !ok {
			continue
		}
		value := lbls[key]
		segments := strings.Split(rest, ".")

		if len(segments) == 1 && strings.EqualFold(segments[0], "enable") {
			enable, hasEnable = value, true
			continue
		}
		// Only the HTTP router vocabulary is read. A TCP or UDP router is a different
		// section of Traefik's own configuration, and §4.1's evidence for `traefik` is an
		// HTTP route's hosts or rule.
		if len(segments) < 4 || !strings.EqualFold(segments[0], "http") {
			continue
		}
		name, field := segments[2], lowerJoin(segments[3:])

		switch strings.ToLower(segments[1]) {
		case "routers":
			r := routers[name]
			if r == nil {
				r = map[string]string{}
				routers[name] = r
				names = append(names, name)
			}
			if field != "" {
				r[field] = value
			}
		case "services":
			// The one service field that says anything about reachability: which port of the
			// container the proxy forwards to.
			if field == "loadbalancer.server.port" {
				ports[name] = strings.TrimSpace(value)
			}
		}
	}

	sort.Strings(names)
	var notes []string
	if hasEnable && falsy(enable) {
		if len(names) > 0 {
			notes = append(notes, "Traefik labels declare "+plural(len(names), "router", "routers")+
				" but traefik.enable is "+quote(enable)+", so the proxy serves none of them")
		}
		return nil, notes
	}
	if hasEnable && !truthy(enable) {
		notes = append(notes, "Traefik label traefik.enable is "+quote(enable)+
			", which is neither true nor false; the routers are reported as declared")
	}

	// A single declared backend port with nothing naming it belongs to the container's one
	// router. Traefik reaches the same conclusion from the same evidence.
	only := ""
	if len(ports) == 1 {
		for _, p := range ports {
			only = p
		}
	}

	routes := make([]payload.TraefikRoute, 0, len(names))
	for _, name := range names {
		f := routers[name]
		rule := strings.TrimSpace(f["rule"])
		route := payload.TraefikRoute{
			Router:       name,
			Rule:         rule,
			Hosts:        matcherArgs(rule, "host"),
			PathPrefixes: matcherArgs(rule, "pathprefix"),
			Entrypoints:  splitList(f["entrypoints"]),
			CertResolver: strings.TrimSpace(f["tls.certresolver"]),
			Middlewares:  splitList(f["middlewares"]),
			Service:      strings.TrimSpace(f["service"]),
		}
		route.TLS = routerTLS(f)
		switch {
		case route.Service != "" && ports[BareName(route.Service)] != "":
			route.ServicePort = ports[BareName(route.Service)]
		case ports[name] != "":
			route.ServicePort = ports[name]
		default:
			route.ServicePort = only
		}
		routes = append(routes, route)
	}
	return routes, notes
}

// routerTLS reads the TLS flag the way Traefik does.
//
// An explicit `tls=false` is decisive. Otherwise any `tls.…` sub-setting turns it on: a
// certificate resolver, a TLS option set or a domain list has no meaning on a plain-HTTP
// router, so declaring one is declaring TLS. Reading only the bare `tls` key would report
// every `tls.certresolver`-only router — the common spelling — as unencrypted.
func routerTLS(fields map[string]string) bool {
	if v, ok := fields["tls"]; ok {
		if falsy(v) {
			return false
		}
		if truthy(v) {
			return true
		}
		// Neither: fall through to the sub-settings, which are the stronger evidence.
	}
	for k := range fields {
		if strings.HasPrefix(k, "tls.") {
			return true
		}
	}
	return false
}

// RuleHosts is the hostnames a Traefik rule can match, in the order the rule names them.
//
// It exists so that §12's live routers and §7's labelled ones read a rule through the same
// parser. A second implementation over there would be a second answer to "what hosts does this
// rule match" — and rule 3 of the live matcher resolves its result through the same hostname
// index the labels populated, so the two spellings have to agree exactly.
func RuleHosts(rule string) []string { return matcherArgs(rule, "host") }

// RulePathPrefixes is the same for path prefixes.
func RulePathPrefixes(rule string) []string { return matcherArgs(rule, "pathprefix") }

// matcherArgs pulls the quoted arguments of one Traefik rule matcher out of a rule.
//
// The rule is parsed no further than this. A rule is a small expression language with `&&`,
// `||` and parentheses, and evaluating it is the proxy's job — what this needs is the names
// the rule can match, which are the matcher's arguments. Every occurrence is read, so
// “Host(`a`) || Host(`b`)“ yields both.
func matcherArgs(rule, matcher string) []string {
	var out []string
	lower := strings.ToLower(rule)
	for i := 0; i < len(lower); {
		at := strings.Index(lower[i:], matcher+"(")
		if at < 0 {
			break
		}
		start := i + at
		// A matcher name is a whole word: `HostRegexp(` and `HostSNI(` are different
		// matchers, and the character before must not be a name character either.
		if start > 0 && isNameByte(lower[start-1]) {
			i = start + len(matcher) + 1
			continue
		}
		open := start + len(matcher) + 1
		end := strings.IndexByte(lower[open:], ')')
		if end < 0 {
			break
		}
		for _, arg := range strings.Split(rule[open:open+end], ",") {
			if a := strings.Trim(strings.TrimSpace(arg), "`'\""); a != "" {
				out = append(out, a)
			}
		}
		i = open + end + 1
	}
	return dedupe(out)
}

func isNameByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// dedupe keeps the first occurrence of each value. Two identical hosts in one rule are one
// host, and reporting the repeat would count one route twice in the hostname index (§9).
func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}
