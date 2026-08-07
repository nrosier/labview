// Package changes is §17's change note: what moved between two scans, and what to say about it.
//
// Two structures, kept apart. The **configuration diff** compares the parsed compose tree; the
// **integration diff** compares what the two API reads came back with. §17 requires the second not
// be folded into the first, because *no config changes; authentik +1 application, -3 withheld* is a
// sentence a reader can act on and *3 changes* is not — one of those two facts means somebody edited
// a file and the other means somebody clicked something in Authentik.
//
// Everything here is a pure function of two payloads. Nothing reads a clock, a file or a network,
// and nothing logs: the note is a value, and the caller decides whether this build's cadence says to
// print it (§17, I7).
package changes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
)

// The two presentation caps §17 states. They are presentation, so they live here and never in the
// analysis: a capped line is still answerable from the payload (§16).
const (
	// MaxStackLines caps the per-stack lines in the configuration diff.
	MaxStackLines = 12

	// MaxNames caps the names on **one** line, which is not the same cap. A fleet with forty
	// applications puts forty names into one line's worth of text with the remainder stated,
	// rather than spilling into forty lines.
	MaxNames = 12
)

// Note is one build's account of what moved.
type Note struct {
	// Baseline is the first build's statement of what it found. Empty on every later build,
	// because there is nothing to compare a first scan against and *0 changes* would be a lie
	// about a fleet nobody had looked at yet.
	Baseline string

	// Config is the parsed-configuration diff: somebody edited a file.
	Config []string

	// Integration is the API-read diff: somebody changed something in Authentik or Traefik, or a
	// target started or stopped answering. A separate list, never merged into Config (§17).
	Integration []string
}

// Quiet reports whether this note says nothing happened.
//
// It is what decides the cadence §17 states: a change always speaks, a **forced** rescan answers
// even when quiet because somebody asked, and only a quiet **timer** rebuild stays silent. Quiet
// means **both** diffs — a fleet whose files did not move but whose provider gained an application
// is not quiet.
func (n Note) Quiet() bool {
	return n.Baseline == "" && len(n.Config) == 0 && len(n.Integration) == 0
}

// Lines renders the note.
//
// The `no config changes` clause appears only when the configuration is unchanged *and* something
// else is not, which is the case §17 writes out: a reader seeing only *authentik +1 application*
// would not know whether the files moved too.
func (n Note) Lines() []string {
	if n.Baseline != "" {
		return append([]string{n.Baseline}, n.Integration...)
	}
	if len(n.Config) == 0 && len(n.Integration) == 0 {
		return nil
	}

	out := make([]string, 0, len(n.Config)+len(n.Integration)+1)
	if len(n.Config) == 0 {
		out = append(out, "no config changes")
	}
	out = append(out, n.Config...)
	return append(out, n.Integration...)
}

// Describe compares two scans. A nil previous scan is the first build, which states a baseline
// rather than a diff.
func Describe(prev *payload.Overview, next payload.Overview) Note {
	if prev == nil {
		return Note{
			Baseline:    baseline(next),
			Integration: integration(nil, next),
		}
	}
	return Note{
		Config:      configuration(*prev, next),
		Integration: integration(prev, next),
	}
}

// baseline is the first build's sentence (§17).
func baseline(out payload.Overview) string {
	return "LabView read " + conn.Plural(out.Stats.Stacks, "stack", "stacks") +
		", " + conn.Plural(out.Stats.Services, "service", "services") +
		" from " + out.Meta.AppsRoot
}

// ---------------------------------------------------------------------------
// The configuration diff
// ---------------------------------------------------------------------------

// configuration compares the **parsed configuration** of two scans, through the canonical
// serialisation of §17 — never the enriched payload, because a container restarting is not somebody
// editing a file.
func configuration(prev, next payload.Overview) []string {
	before, after := fingerprints(prev), fingerprints(next)

	var added, removed, changed []string
	for _, id := range sortedKeys(after) {
		switch {
		case before[id] == "":
			added = append(added, id)
		case before[id] != after[id]:
			changed = append(changed, id)
		}
	}
	for _, id := range sortedKeys(before) {
		if after[id] == "" {
			removed = append(removed, id)
		}
	}

	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		return nil
	}

	// The headline first: the two counters a reader checks before reading anything else. Only the
	// ones that moved appear, so an edit that changed a label does not claim +0 stacks.
	var out []string
	if head := deltas([]delta{
		{now: next.Stats.Stacks, was: prev.Stats.Stacks, one: "stack", many: "stacks"},
		{now: next.Stats.Services, was: prev.Stats.Services, one: "service", many: "services"},
	}); head != "" {
		out = append(out, head)
	}

	// Then one line per stack that moved, in a fixed order (I7): added, removed, changed, each
	// already sorted by id.
	lines := make([]string, 0, len(added)+len(removed)+len(changed))
	for _, id := range added {
		lines = append(lines, "stack "+quote(id)+" added, "+
			conn.Plural(serviceCount(next, id), "service", "services"))
	}
	for _, id := range removed {
		lines = append(lines, "stack "+quote(id)+" removed, "+
			conn.Plural(serviceCount(prev, id), "service", "services"))
	}
	for _, id := range changed {
		lines = append(lines, "stack "+quote(id)+" changed"+servicesMoved(prev, next, id))
	}

	return append(out, capped(lines, MaxStackLines, "stack")...)
}

// servicesMoved names the service count's movement inside one changed stack, or says nothing when
// the change was to a service rather than to how many there are.
func servicesMoved(prev, next payload.Overview, id string) string {
	was, now := serviceCount(prev, id), serviceCount(next, id)
	if was == now {
		return ""
	}
	return ": " + deltas([]delta{{now: now, was: was, one: "service", many: "services"}})
}

func serviceCount(out payload.Overview, id string) int {
	for _, stack := range out.Stacks {
		if stack.ID == id {
			return len(stack.Services)
		}
	}
	return 0
}

// fingerprints is every stack's canonical configuration digest, by stack id.
func fingerprints(out payload.Overview) map[string]string {
	fps := make(map[string]string, len(out.Stacks))
	for _, stack := range out.Stacks {
		fps[stack.ID] = Fingerprint(stack)
	}
	return fps
}

// Fingerprint is one stack's parsed configuration, canonically serialised and digested.
//
// Canonical because it is the JSON of a Go struct: fields serialise in declaration order and map
// keys sorted, so two scans of one unchanged file produce one string (I7).
func Fingerprint(stack payload.AppStack) string {
	b, err := json.Marshal(strip(stack))
	if err != nil {
		// Nothing in AppStack can fail to marshal — there is no channel, function or NaN in it.
		// A digest of the error text is still stable for an unchanged stack, which is the only
		// property the comparison needs, and it degrades rather than panicking (I4).
		b = []byte(err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// strip removes what §17's volatile list names, and **only** that.
//
// It is a deny-list, so it zeroes named fields rather than copying wanted ones: a field added to
// Service tomorrow is compared by default, and a genuinely volatile one has to be named here. The
// other way round, a new field would silently stop being compared, and the diff would go quiet
// about real edits without anybody noticing.
func strip(stack payload.AppStack) payload.AppStack {
	out := stack
	out.Services = make([]payload.Service, len(stack.Services))

	for i, svc := range stack.Services {
		// Live container state — a restart is not an edit.
		svc.Docker = nil
		// The identity-provider match — somebody's Authentik, not this file.
		svc.Authentik = nil
		// Live proxy records — the running router table.
		svc.TraefikLive = nil
		// The two pass-2 conclusions. Both are derived from the fleet and from the reads, so
		// comparing them would report every provider change as a file change.
		svc.Ingress = nil
		svc.Auth = payload.AuthPosture{}
		// Notes: sentences the analysis wrote about this service, not content the file had.
		svc.Notes = nil
		// Tunnel-route state: the route is configuration, what its origin resolved to is not.
		svc.Cloudflare = withoutOrigins(svc.Cloudflare)
		// The probe result. §17's enumeration does not name it, but §17's governing sentence is
		// *compares the parsed configuration, not the enriched payload*, and a probe result is
		// enrichment by construction. Leaving it in would make every probing rescan of an
		// unedited fleet announce a configuration change, which is the exact noise the
		// canonical comparison exists to prevent.
		svc.Probe = nil
		// What the sidecar *declared* is configuration and stays. What §14 concluded about it is
		// derived from ingress, auth and the probe, all three of which are gone above.
		svc.Declared = withoutVerdicts(svc.Declared)

		out.Services[i] = svc
	}
	return out
}

// withoutOrigins drops each route's resolved origin and keeps the route.
func withoutOrigins(routes []payload.CloudflareRoute) []payload.CloudflareRoute {
	if routes == nil {
		return nil
	}
	out := make([]payload.CloudflareRoute, len(routes))
	for i, route := range routes {
		route.Origin = nil
		out[i] = route
	}
	return out
}

// withoutVerdicts drops §14's conclusions and keeps what the sidecar said.
func withoutVerdicts(decl *payload.ServiceDeclaration) *payload.ServiceDeclaration {
	if decl == nil {
		return nil
	}
	out := *decl
	out.Drift = nil
	out.Unconfirmed = nil
	out.AuthAgreement = ""
	return &out
}

// ---------------------------------------------------------------------------
// The integration diff
// ---------------------------------------------------------------------------

// integration compares what the two API reads came back with, and what happened to every outbound
// target's connection.
//
// A nil previous scan is the first build: §15 says the first scan logs every target regardless, so
// the reachability lines are stated rather than diffed.
func integration(prev *payload.Overview, next payload.Overview) []string {
	var out []string
	out = append(out, identity(prev, next)...)
	out = append(out, proxy(prev, next)...)
	return append(out, connections(prev, next)...)
}

// identity is the Authentik half.
func identity(prev *payload.Overview, next payload.Overview) []string {
	now := next.Meta.Authentik
	if now == nil {
		return nil
	}
	var was *payload.AuthentikSummary
	if prev != nil {
		was = prev.Meta.Authentik
	}

	// Reachability is decided before any count (§17). A target neither side read has nothing to
	// say, and a target that started or stopped answering has something that is not a number.
	switch reach(was != nil && was.Reachable, now.Reachable, prev == nil) {
	case reachNeither:
		return nil
	case reachStarted:
		return []string{"authentik started answering at " + now.Endpoint}
	case reachStopped:
		return []string{"authentik stopped answering" + because(now.Error)}
	}

	lines := []string{}
	if head := deltas([]delta{
		{now: now.Applications, was: was.Applications, one: "application", many: "applications"},
		// A count the API itself claimed, absent when it claimed none — so it is compared only
		// where **both** sides have one (§17).
		{now: value(now.ApplicationsConfigured), was: value(was.ApplicationsConfigured),
			absent: now.ApplicationsConfigured == nil || was.ApplicationsConfigured == nil,
			one:    "configured", many: "configured"},
		// A modifier, so it reads the same in both directions: `+1 withheld`, `-3 withheld`.
		{now: now.ApplicationsWithheld, was: was.ApplicationsWithheld,
			one: "withheld", many: "withheld"},
		{now: now.ApplicationsRecovered, was: was.ApplicationsRecovered,
			one: "recovered", many: "recovered"},
		{now: now.Providers, was: was.Providers, one: "provider", many: "providers"},
		{now: now.Outposts, was: was.Outposts, one: "outpost", many: "outposts"},
		{now: now.MatchedServices, was: was.MatchedServices,
			one: "matched service", many: "matched services"},
	}); head != "" {
		lines = append(lines, "authentik "+head)
	}

	// The named records, read back off the payload and sorted (I7). Two lines at most, which with
	// the count line above is §17's three per target.
	gained, lost := names(applications(*prev), applications(next))
	if len(gained) > 0 {
		lines = append(lines, "authentik gained "+list(gained, "application", "applications"))
	}
	if len(lost) > 0 {
		lines = append(lines, "authentik lost "+list(lost, "application", "applications"))
	}
	return lines
}

// proxy is the Traefik half.
func proxy(prev *payload.Overview, next payload.Overview) []string {
	now := next.Meta.Traefik
	if now == nil {
		return nil
	}
	var was *payload.TraefikSummary
	if prev != nil {
		was = prev.Meta.Traefik
	}

	switch reach(was != nil && was.Reachable, now.Reachable, prev == nil) {
	case reachNeither:
		return nil
	case reachStarted:
		return []string{"traefik started answering at " + now.Endpoint}
	case reachStopped:
		return []string{"traefik stopped answering" + because(now.Error)}
	}

	lines := []string{}
	if head := deltas([]delta{
		{now: now.Routers, was: was.Routers, one: "router", many: "routers"},
		{now: now.Middlewares, was: was.Middlewares, one: "middleware", many: "middlewares"},
		// **`live service`**, because `service` in this payload already means a compose service
		// and a reader seeing `+1 service` here would look for a new container (§17).
		{now: now.Services, was: was.Services, one: "live service", many: "live services"},
		{now: now.MatchedServices, was: was.MatchedServices,
			one: "matched service", many: "matched services"},
	}); head != "" {
		lines = append(lines, "traefik "+head)
	}

	gained, lost := names(routers(*prev), routers(next))
	if len(gained) > 0 {
		lines = append(lines, "traefik gained "+list(gained, "router", "routers"))
	}
	if len(lost) > 0 {
		lines = append(lines, "traefik lost "+list(lost, "router", "routers"))
	}
	return lines
}

// connections is every outbound target whose report moved, by §15's comparison: target, `ok`, phase
// and endpoint, and **never** `read`. Comparing `read` would re-announce a working Docker on every
// rescan, because the container count ticks.
func connections(prev *payload.Overview, next payload.Overview) []string {
	if prev == nil {
		return nil
	}
	before := map[string]payload.ConnectionReport{}
	for _, report := range prev.Meta.Connections {
		before[report.Target] = report
	}

	var out []string
	for _, now := range next.Meta.Connections {
		was, ok := before[now.Target]
		if !ok || conn.Same(was, now) {
			continue
		}
		out = append(out, now.Target+" is now "+string(now.Phase)+
			endpointClause(now.Endpoint)+because(now.Detail))
	}
	return out
}

func endpointClause(endpoint string) string {
	if strings.TrimSpace(endpoint) == "" {
		return ""
	}
	return " at " + endpoint
}

func because(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return ": " + detail
}

// ---------------------------------------------------------------------------
// Reachability, before any count
// ---------------------------------------------------------------------------

type reachability int

const (
	// reachBoth is the only one of the four that leads to a numeric comparison.
	reachBoth reachability = iota
	reachNeither
	reachStarted
	reachStopped
)

// reach is §17's rule that reachability is decided first. `started` and `stopped` are not numeric
// comparisons and MUST NOT be phrased as ones — a target that was not answering had no counts to
// be up or down from.
//
// On a first build there is no previous side at all: a target answering is a `started` statement,
// and one that is not says nothing, because §15's *the first scan logs all of them* is about the
// connection reports and those are printed from `meta.connections` in full.
func reach(was, now, first bool) reachability {
	switch {
	case first && now:
		return reachStarted
	case first:
		return reachNeither
	case !was && !now:
		return reachNeither
	case !was && now:
		return reachStarted
	case was && !now:
		return reachStopped
	default:
		return reachBoth
	}
}

// ---------------------------------------------------------------------------
// Deltas
// ---------------------------------------------------------------------------

// delta is one counter's movement. A modifier — `withheld`, `recovered` — sets one and many to the
// same word, so it reads identically in both directions (§17).
type delta struct {
	now, was  int
	one, many string

	// absent marks a count one side did not have. Counts are compared only where **both** sides
	// have a value, so an optional count appearing or vanishing is not a delta (§17).
	absent bool
}

// deltas renders the counters that moved, joined, or nothing.
func deltas(in []delta) string {
	var parts []string
	for _, d := range in {
		if d.absent || d.now == d.was {
			continue
		}
		parts = append(parts, signed(d.now-d.was, d.one, d.many))
	}
	return strings.Join(parts, ", ")
}

// signed is `+1 application` or `-3 withheld`: the sign, the magnitude, and the noun pluralised on
// the magnitude rather than on the direction.
func signed(by int, one, many string) string {
	magnitude := by
	sign := "+"
	if by < 0 {
		magnitude, sign = -by, "-"
	}
	return sign + conn.Plural(magnitude, one, many)
}

func value(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// ---------------------------------------------------------------------------
// Named records
// ---------------------------------------------------------------------------

// applications is every application the identity provider knows about, read back off the payload and
// sorted (I7).
//
// Both places it appears: the ones matched to a service, and the ones the summary listed as matching
// none. An application that merely moved from unmatched to matched is not gained or lost, which is
// the reason for reading both rather than only the summary's list.
func applications(out payload.Overview) []string {
	var names []string
	if s := out.Meta.Authentik; s != nil {
		for _, u := range s.UnmatchedApplications {
			names = append(names, record(u.Application.Slug, u.Application.Name))
		}
	}
	for _, stack := range out.Stacks {
		for _, svc := range stack.Services {
			if svc.Authentik == nil {
				continue
			}
			for _, app := range svc.Authentik.Applications {
				names = append(names, record(app.Slug, app.Name))
			}
		}
	}
	sort.Strings(names)
	return dedupe(names)
}

// routers is every live router the proxy read returned, matched or not, sorted (I7).
func routers(out payload.Overview) []string {
	var names []string
	if s := out.Meta.Traefik; s != nil {
		for _, u := range s.UnmatchedRouters {
			names = append(names, u.Router.Router)
		}
	}
	for _, stack := range out.Stacks {
		for _, svc := range stack.Services {
			for _, r := range svc.TraefikLive {
				names = append(names, r.Router)
			}
		}
	}
	sort.Strings(names)
	return dedupe(names)
}

// record prefers the stable identifier and falls back to the display name, so a record with no slug
// is still named rather than appearing as an empty string in a list.
func record(slug, name string) string {
	if strings.TrimSpace(slug) != "" {
		return slug
	}
	return name
}

// names is what one side has and the other does not, both sorted.
func names(was, now []string) (gained, lost []string) {
	before, after := set(was), set(now)
	for _, name := range now {
		if !before[name] {
			gained = append(gained, name)
		}
	}
	for _, name := range was {
		if !after[name] {
			lost = append(lost, name)
		}
	}
	return dedupe(gained), dedupe(lost)
}

func set(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s] = true
	}
	return out
}

// dedupe keeps sorted order and drops repeats, because two records can share a display name once
// `record` has fallen back to it.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for i, s := range in {
		if i > 0 && s == in[i-1] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// list is a count and its names, truncated at MaxNames **on the line** with the remainder stated
// rather than silently dropped (§17).
func list(names []string, one, many string) string {
	head := conn.Plural(len(names), one, many) + ": "
	if len(names) <= MaxNames {
		return head + strings.Join(names, ", ")
	}
	return head + strings.Join(names[:MaxNames], ", ") +
		" and " + strconv.Itoa(len(names)-MaxNames) + " more"
}

// capped truncates a set of lines and states what it dropped, which §17 and §22 both require of
// every capped list: a reader who is not told is a reader who thinks they saw everything.
func capped(lines []string, limit int, noun string) []string {
	if len(lines) <= limit {
		return lines
	}
	dropped := len(lines) - limit
	return append(lines[:limit],
		"and "+conn.Plural(dropped, noun+" not listed", noun+"s not listed"))
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func quote(s string) string { return `"` + s + `"` }
