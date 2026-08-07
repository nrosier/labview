package traefikapi

import "github.com/nrosier/labview/internal/payload"

// Summarize is the reverse-proxy panel of the payload (§12).
//
// It is a projection and holds no rule of its own: every number it reports is either already on the
// read or derived by the read's own method, so the count a card shows and the count the connection
// report's phase was decided from cannot come apart.
func Summarize(r Read, m Match) payload.TraefikSummary {
	out := payload.TraefikSummary{
		Enabled:    r.Enabled,
		Configured: r.Configured,
		Reachable:  r.Reachable(),

		Endpoint:       r.Report.Endpoint,
		EndpointSource: r.Report.Source,
		Credential:     r.Credential,
		Version:        r.Snapshot.Version,

		// Not `r.Reachable() && …`: this is the field a reader checks to find out why a live chain
		// did not supersede a label, and it has to be the fact itself rather than a conjunction
		// that hides which half was false. ChainComplete is the conjunction, and it is derived.
		EntrypointsRead: r.Snapshot.EntrypointsRead,

		Routers:         len(r.Snapshot.Routers),
		Middlewares:     len(sortedNames(r.Snapshot.Middlewares)),
		Services:        len(r.Snapshot.Services),
		MatchedServices: m.MatchedServices(),

		UnmatchedRouters: m.Unmatched,
	}
	if out.UnmatchedRouters == nil {
		out.UnmatchedRouters = []payload.UnmatchedRouter{}
	}

	// The error is the report's own detail, not a second wording of it. A read that came back
	// `partial` is reachable *and* has something to say — the entrypoints — so the detail is
	// carried either way and it is `reachable` that says whether anything was obtained.
	if !r.Report.OK || r.Report.Phase == payload.PhasePartial {
		out.Error = r.Report.Detail
	}
	return out
}
