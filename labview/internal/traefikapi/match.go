package traefikapi

import (
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
)

// Match is the whole match stage: which live routers each service was tied to, and why the rest
// were not.
type Match struct {
	// ByService is keyed on the fleet service key, each list in `name@provider` order (I7).
	ByService map[string][]payload.TraefikLiveRouter

	// Unmatched is every live router no service could be tied to, in the order they were read.
	Unmatched []payload.UnmatchedRouter

	// liveNames is the bare router names the snapshot holds, matched or not.
	//
	// It is the whole snapshot on purpose. §12 requires the declared-but-absent check to run
	// against every router the proxy is serving, because a router LabView could not attribute
	// demonstrably *exists* — reporting it as missing from the service whose label declares it
	// would be a route that is live being called absent. `twin-a` is exactly that case.
	liveNames map[string]bool
}

// Apply is §12's matching: three rules in descending strength, each requiring exactly one
// candidate.
//
// It does no network work. Everything it needs is the snapshot and the fleet index, which is what
// makes the rules assertable as a table — the alternative is a test that needs a live proxy to
// discover that rule 2 declines a `@file` router.
func Apply(snap Snapshot, ix *fleet.Index) Match {
	m := Match{
		ByService: map[string][]payload.TraefikLiveRouter{},
		liveNames: map[string]bool{},
	}
	routers := newRouterNames(ix)
	ips := hasContainerIPs(ix)

	for _, live := range snap.Live() {
		m.liveNames[strings.ToLower(bareRouter(live.Router))] = true

		key, evidence, trace := match(live, ix, routers, ips)
		if key == "" {
			m.Unmatched = append(m.Unmatched, unmatched(live, trace))
			continue
		}
		live.Evidence = append(live.Evidence, evidence)
		m.ByService[key] = append(m.ByService[key], live)
	}
	return m
}

// MatchedServices is the count the summary reports.
func (m Match) MatchedServices() int { return len(m.ByService) }

// Absent is the routers a service's labels declare that the proxy is not serving, in label order.
//
// The comparison is on the bare name, because a label declares `blog` and the proxy reports
// `blog@docker` — and it is against every router in the snapshot rather than against the ones
// matched to this service, for the reason `liveNames` documents.
func (m Match) Absent(svc payload.Service) []string {
	var out []string
	for _, r := range svc.Traefik {
		name := strings.TrimSpace(r.Router)
		if name == "" || m.liveNames[strings.ToLower(name)] {
			continue
		}
		out = appendOnce(out, name)
	}
	return out
}

// ---------------------------------------------------------------------------
// The trace
// ---------------------------------------------------------------------------

// outcome is what one rule did.
//
// There is no `blocked` member, and its absence is deliberate. Rule 2's refusal applies to every
// non-docker router, so a fleet with any file-provider routing would report *blocked* on all of
// them — and promoting that to the headline reason would displace the answer a reader needs, which
// is whichever rule found nothing or found too much (§12).
type outcome uint8

const (
	outcomeNoEvidence  outcome = iota // the rule could not run at all
	outcomeNoCandidate                // it ran and found nobody
	outcomeContested                  // it found more than one, so it must discard
	outcomeMatched
)

// step is one line of the trace: which rule ran, what happened, and what it says.
type step struct {
	outcome outcome
	line    string
}

// ---------------------------------------------------------------------------
// The three rules
// ---------------------------------------------------------------------------

// match runs the three rules in order and returns the first that found exactly one service.
//
// A rule that could not run still produces a trace line, for the same reason as §11: a trace with
// a rule missing reads as a rule that passed, and a reader cannot tell which.
func match(live payload.TraefikLiveRouter, ix *fleet.Index, routers routerNames, ips bool) (key, evidence string, trace []step) {
	for _, rule := range []func(payload.TraefikLiveRouter, *fleet.Index, routerNames, bool) (string, string, step){
		ruleBackend,
		ruleRouterName,
		ruleHostRule,
	} {
		gotKey, gotEvidence, gotStep := rule(live, ix, routers, ips)
		trace = append(trace, gotStep)
		if gotKey != "" {
			return gotKey, gotEvidence, trace
		}
	}
	return "", "", trace
}

// ruleBackend is rule 1: the load-balancer server URLs, the proxy naming its own target. It is the
// strongest rule there is because it is not an inference at all.
//
// The two address forms are resolved through two different tables and never through the generic
// lookup. That lookup reads an IP literal's port as a *published host port*, which is right for a
// tunnel origin and wrong here: a backend of `http://172.18.0.4:3000` is a container address, and
// reading 3000 as a host port would land on whichever service publishes 3000 — with full
// confidence and the wrong answer. The `wiki` fixture is that exact pair.
func ruleBackend(live payload.TraefikLiveRouter, ix *fleet.Index, _ routerNames, ips bool) (string, string, step) {
	if len(live.Servers) == 0 {
		return "", "", step{outcomeNoEvidence,
			"The proxy holds no backend address for this router's service, so there is no target " +
				"to resolve."}
	}

	var found, skipped []string
	var matched string
	for _, server := range live.Servers {
		a := fleet.ParseAddress(server.URL)
		if a.Host == "" {
			continue
		}

		var got []string
		switch {
		case a.IsIP():
			if !ips {
				// No Docker state, so there is no container-IP table to resolve through. Skipped
				// rather than guessed: the generic lookup would answer, and answer wrongly.
				skipped = appendOnce(skipped, a.Host)
				continue
			}
			got = ix.ByIP(a.Host)
		default:
			got = ix.ByName(a.Host)
		}

		if len(got) > 0 {
			found = appendKeys(found, got)
			if matched == "" {
				matched = server.URL
			}
		}
	}

	switch {
	case len(found) == 1:
		return found[0], "the proxy forwards this router to " + quote(matched), step{outcomeMatched, ""}
	case len(found) > 1:
		return "", "", step{outcomeContested,
			"This router's backend addresses resolve to " + list(found) + "."}
	case len(skipped) > 0:
		return "", "", step{outcomeNoCandidate,
			"This router's backend is the container address " + quote(skipped[0]) +
				", and with no Docker state there is no container-IP table to resolve it through."}
	default:
		return "", "", step{outcomeNoCandidate,
			"No backend address the proxy holds for this router addresses a scanned container."}
	}
}

// ruleRouterName is rule 2: an exact match against a label-derived router name, and **only** for a
// `@docker` router.
//
// Traefik derives a docker-provider router's name from the labels of the very container it found
// them on, so an exact match there is that label round-tripping. A `@file` router's name was typed
// by hand in a file this scan cannot read, so its resembling a label is a coincidence with no
// evidentiary weight — which is what the two `twin` fixtures pin.
func ruleRouterName(live payload.TraefikLiveRouter, _ *fleet.Index, routers routerNames, _ bool) (string, string, step) {
	if !strings.EqualFold(strings.TrimSpace(live.Provider), "docker") {
		return "", "", step{outcomeNoEvidence,
			"Router " + quote(live.Router) + " comes from the " + quote(live.Provider) +
				" provider, so its name was not derived from any container's labels and matching " +
				"on it would carry no evidence."}
	}

	name := bareRouter(live.Router)
	found := routers.lookup(name)
	switch {
	case len(found) == 1:
		return found[0], "this service's labels declare the router " + quote(name), step{outcomeMatched, ""}
	case len(found) > 1:
		return "", "", step{outcomeContested,
			"The router name " + quote(name) + " is declared by " + list(found) + "."}
	default:
		return "", "", step{outcomeNoCandidate,
			"No scanned service declares a router called " + quote(name) + "."}
	}
}

// ruleHostRule is rule 3: the hosts in the router's rule, through the same hostname index the
// Authentik matcher uses.
//
// The index deduplicates by service key, so one service naming one hostname in both a tunnel route
// and a Traefik rule is one candidate rather than a contested pair.
func ruleHostRule(live payload.TraefikLiveRouter, ix *fleet.Index, _ routerNames, _ bool) (string, string, step) {
	if len(live.Hosts) == 0 {
		return "", "", step{outcomeNoEvidence,
			"This router's rule names no host, so there is no declared hostname to match."}
	}

	var found []string
	var matched string
	for _, host := range live.Hosts {
		if got := ix.ByHostname(host); len(got) > 0 {
			found = appendKeys(found, got)
			if matched == "" {
				matched = host
			}
		}
	}
	switch {
	case len(found) == 1:
		return found[0], "this service declares the hostname " + quote(matched), step{outcomeMatched, ""}
	case len(found) > 1:
		return "", "", step{outcomeContested,
			"The hostname " + quote(live.Hosts[0]) + " is declared by " + list(found) + "."}
	default:
		return "", "", step{outcomeNoCandidate,
			"No service declares " + quote(live.Hosts[0]) + " in a Cloudflare or Traefik label."}
	}
}

// bareRouter is the name half of a `name@provider` reference.
func bareRouter(ref string) string {
	ref = strings.TrimSpace(ref)
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		return ref[:at]
	}
	return ref
}

// ---------------------------------------------------------------------------
// The router-name index
// ---------------------------------------------------------------------------

// routerNames maps a label-declared router name to the services declaring it.
type routerNames struct{ byName map[string][]string }

func newRouterNames(ix *fleet.Index) routerNames {
	n := routerNames{byName: map[string][]string{}}
	if ix == nil {
		return n
	}
	for _, key := range ix.Keys() {
		svc := ix.Service(key)
		if svc == nil {
			continue
		}
		for _, r := range svc.Traefik {
			name := strings.ToLower(strings.TrimSpace(r.Router))
			if name == "" {
				continue
			}
			n.byName[name] = appendOnce(n.byName[name], key)
		}
	}
	return n
}

func (n routerNames) lookup(name string) []string {
	return n.byName[strings.ToLower(strings.TrimSpace(name))]
}

// hasContainerIPs reports whether this scan has any Docker state at all.
//
// It is the condition rule 1 skips an IP-form backend under. Asking the index for one IP would not
// answer it: an unknown IP and an index with no IPs in it both come back empty, and only the
// second one means *the table does not exist*.
func hasContainerIPs(ix *fleet.Index) bool {
	if ix == nil {
		return false
	}
	for _, key := range ix.Keys() {
		svc := ix.Service(key)
		if svc != nil && svc.Docker != nil && len(svc.Docker.IPAddresses) > 0 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Why it was not matched
// ---------------------------------------------------------------------------

// unmatched turns a trace into the mirror of §11's unmatched application: the whole live router,
// a reason, a one-line detail and the trace with one line per rule tried in the order tried.
//
// The reason is `ambiguous` exactly when something was contested. There is no blocked case to
// weigh, so the detail is the first contested line and otherwise a generic fallback.
func unmatched(live payload.TraefikLiveRouter, trace []step) payload.UnmatchedRouter {
	out := payload.UnmatchedRouter{
		Router:     live,
		Reason:     payload.UnmatchedNoCandidate,
		Considered: []string{},
	}

	var contested string
	for _, s := range trace {
		if s.line != "" {
			out.Considered = append(out.Considered, s.line)
		}
		if s.outcome == outcomeContested && contested == "" {
			contested = s.line
			out.Reason = payload.UnmatchedAmbiguous
		}
	}

	if contested != "" {
		out.Detail = contested
		return out
	}
	out.Detail = "Nothing this router carries identifies exactly one scanned service."
	return out
}

// ---------------------------------------------------------------------------
// Middleware definitions the fleet cannot see
// ---------------------------------------------------------------------------

// FileProviderMiddlewares is the middlewares the proxy holds that no scanned stack defines, in
// name order.
//
// This is one of the three things §12 exists to resolve. A middleware defined in a Traefik file
// provider has no definition anywhere in the compose tree, so label-only its type is unknowable
// and a gate could only ever be `inferred` from its name — `docs`, whose `secured@file` is a
// `chain` that does not read as auth at all, is the case that makes it matter.
func FileProviderMiddlewares(snap Snapshot, reg labels.Registry) []string {
	var out []string
	for _, name := range sortedNames(snap.Middlewares) {
		if name == "" {
			continue
		}
		if _, defined := reg.Lookup(name); defined {
			continue
		}
		out = appendOnce(out, name)
	}
	sort.Strings(out)
	return out
}
