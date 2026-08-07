package probe

import (
	"context"
	"net/url"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// The eighth signal
// ---------------------------------------------------------------------------

// StatePaths is §13.4's constant list, walked in this order. It is a constant list on purpose:
// **nothing is parsed out of the page**. Reading the bundle's own fetch calls would mean executing
// somebody else's JavaScript to find out where to send a request, which is a different program.
//
// These four are the addresses a single-page application asks for the current user, in the order they
// appear in the frameworks that generate them. `/api/` leads because a bare API root refuses
// unauthenticated callers in more of them than any single user endpoint does.
var StatePaths = []string{"/api/", "/api/me", "/api/v1/me", "/api/v1/user"}

// StateAddresses is where §13.4's second question is asked: the constant list resolved against **the
// origin that answered**, and nothing else about the endpoint kept.
//
// The origin and not the endpoint. A router that answered at `https://host/app/` is still one origin,
// and `/api/me` on it is `https://host/api/me` — resolving relative to the path would ask
// `/app/api/me`, which is a different address the spec does not name.
func StateAddresses(endpoint string) []string {
	base, err := url.Parse(endpoint)
	if err != nil || base.Host == "" {
		return nil
	}
	origin := url.URL{Scheme: base.Scheme, Host: base.Host}

	out := make([]string, 0, len(StatePaths))
	for _, path := range StatePaths {
		next := origin
		next.Path = path
		out = append(out, next.String())
	}
	return out
}

// Refusal is what counts as a refusal here, and it is the narrow reading: 401 or 407.
//
// **403 is excluded**, because nginx 403s a directory with no index — a static site with no API at
// all answers that way, and reading it as a refusal would take genuinely open applications out of the
// exposed count.
func Refusal(status int) bool { return status == 401 || status == 407 }

// StateAnswer is one answer to the second question, reduced to the two things §13.4 permits reading:
// a status, and whether the refusal named a scheme. Nothing else — no body, no other header.
type StateAnswer struct {
	Status int

	// Challenge is whether a `WWW-Authenticate` header was present. **The gate rests on this fact
	// alone.**
	Challenge bool
}

// StateAsker is one credential-free GET for the state walk. It returns false when the request did not
// produce an answer at all, which is not a refusal and not a permission — it is nothing, and the walk
// carries on to the next address.
type StateAsker func(ctx context.Context, address string) (StateAnswer, bool)

// AskState is §13.4's walk: sequential, stopping on the first refusal.
//
// **Sequential regardless of `probe.maxConcurrency`** — that budget is across *services*, and
// spending it inside one service would let a single unlucky page fan out four requests while the
// fleet-wide bound reads as respected.
//
// The result is the four numbers §13.4 permits: how many were asked, which refused, with what status,
// and whether that refusal named a scheme.
func AskState(ctx context.Context, endpoint string, ask StateAsker) *payload.ProbeState {
	addresses := StateAddresses(endpoint)
	if len(addresses) == 0 || ask == nil {
		return nil
	}

	out := payload.ProbeState{}
	for _, address := range addresses {
		if ctx.Err() != nil {
			break
		}
		out.Asked++

		answer, answered := ask(ctx, address)
		if !answered || !Refusal(answer.Status) {
			continue
		}

		status, challenge := answer.Status, answer.Challenge
		out.RefusedAt, out.Status, out.Challenge = address, &status, &challenge
		break
	}
	return &out
}

// StateGate is the pure rule §13.4 rests on, and it rests on one fact.
//
// A refusal carrying `WWW-Authenticate` is a `challenge` one address over, and that is a gate. A
// **bare** 401 is **not** — an anonymous-enabled Grafana and a world-readable Gitea both answer that
// way while serving everybody. The bare refusal is still recorded, and §13.6 names it as a place to
// look in the same sentence that says the finding stands.
func StateGate(s *payload.ProbeState) payload.ProbeGate {
	if s == nil || s.Challenge == nil || !*s.Challenge {
		return ""
	}
	return payload.GateStateChallenge
}

// BareRefusal is a refusal that named no scheme: recorded, not a gate, and worth a sentence. It is
// spelled out as its own predicate so that the wording in §13.6 and the non-gate in StateGate read
// off the same condition rather than two negations of each other.
func BareRefusal(s *payload.ProbeState) bool {
	return s != nil && s.Status != nil && (s.Challenge == nil || !*s.Challenge)
}
