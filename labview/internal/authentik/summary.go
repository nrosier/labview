package authentik

import "github.com/nrosier/labview/internal/payload"

// Summarize is the identity-provider panel of the payload (§11).
//
// It is a projection and holds no rule of its own: every number it reports is either already on the
// read or derived by the read's own method, so the count a card shows and the count the connection
// report's phase was decided from cannot come apart.
func Summarize(r Read, m Match) payload.AuthentikSummary {
	out := payload.AuthentikSummary{
		Enabled:    r.Enabled,
		Configured: r.Configured,
		Reachable:  r.Report.OK,

		Endpoint:       r.Report.Endpoint,
		EndpointSource: r.Report.Source,

		Applications:           len(r.Applications),
		ApplicationsConfigured: r.Total,
		ApplicationsWithheld:   r.Withheld(),
		ApplicationsRecovered:  r.Recovered,

		Providers:       r.Providers,
		Outposts:        r.Outposts,
		MatchedServices: m.MatchedServices(),

		UnmatchedApplications: m.Unmatched,
	}
	if out.UnmatchedApplications == nil {
		out.UnmatchedApplications = []payload.UnmatchedApplication{}
	}

	// The error is the report's own detail, not a second wording of it. A read that came back
	// `partial` is reachable *and* has something to say, so the detail is carried either way and it
	// is `reachable` that says whether anything was obtained.
	if !r.Report.OK || r.Report.Phase == payload.PhasePartial {
		out.Error = r.Report.Detail
	}
	return out
}
