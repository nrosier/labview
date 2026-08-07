package access

import (
	"net/http"
	"time"

	"github.com/nrosier/labview/internal/payload"
)

// The login decision (§19): the order in which a password attempt is judged.
//
// The order is the whole of it, so it is written once, here, rather than assembled by whichever route
// happens to call these pieces:
//
//  1. Is the method live? An attempt against a method that is not available is not a failed attempt.
//  2. Is this name locked? **Checked before the password, so a lock holds regardless of whether the
//     password was right** (§19). A lock that opened for the correct password would not be a lock.
//  3. Does the password verify? Against the table on the posture, with an unknown name compared to the
//     decoy hash.
//  4. On failure, count it. On success, clear the count and mint.
//
// Nothing here consults scanned data, and nothing here is reachable without going through the posture
// first (I8).

// Login is one password attempt's whole outcome. It carries both messages: what the client is told and
// what the log records (§19).
type Login struct {
	// Token is the minted session, empty unless OK.
	Token  string
	Claims Claims

	// OK is whether the attempt succeeded.
	OK bool

	// Status is what the client is told: 200, 401, 429 or 503.
	Status int

	// Reason is the code the client receives, one of §4.7's eight.
	Reason payload.LoginFailureReason

	// RetryAfter is set for a throttled attempt, for the header of the same name.
	RetryAfter time.Duration

	// Detail is for the log and is never served. It is the sentence that says which of the several
	// reasons behind one code applied.
	Detail string

	// Username is the sanitised name, for the log line about this attempt (§16).
	Username string
}

// Attempt judges a password login and mints a session when it succeeds.
//
// The posture is a parameter rather than read here, so that the decision is made against the same
// posture the route already reported to the client — a posture re-read mid-request could tell a browser
// the method is live and then refuse the attempt as unavailable.
func (g *Gate) Attempt(posture Posture, user, password string, now time.Time) Login {
	out := Login{Username: Username(user)}

	if !posture.Live(payload.MethodPasswd) {
		// 503 rather than 401: the credentials were not judged, and answering 401 would tell an
		// operator their password is wrong when the truth is that nothing was checked.
		out.Status, out.Reason = http.StatusServiceUnavailable, payload.FailMethodUnavailable
		out.Detail = "password sign-in is not available"
		return out
	}

	if verdict := g.throttle().Allow(user, now); verdict.Locked {
		out.Status, out.Reason = http.StatusTooManyRequests, payload.FailThrottled
		out.RetryAfter = verdict.RetryAfter
		out.Detail = "too many failed attempts for this name"
		return out
	}

	if !Verify(posture.Passwd, user, password) {
		verdict := g.throttle().Failed(user, now)
		out.Detail = "the password did not verify"

		if verdict.Locked {
			// The attempt that reached the limit is answered as throttled rather than as a bad
			// password. Both are true, and this one is the more useful: it carries the retry-after, so
			// the person who mistyped four times learns to wait rather than typing a fifth.
			out.Status, out.Reason = http.StatusTooManyRequests, payload.FailThrottled
			out.RetryAfter = verdict.RetryAfter
			return out
		}

		out.Status, out.Reason = http.StatusUnauthorized, payload.FailCredentials
		return out
	}

	token, claims, err := g.Signer.Mint(user, payload.MethodPasswd, now)
	if err != nil {
		// Minting fails only if the process cannot produce randomness. Reported as unavailable rather
		// than as bad credentials, because the credentials were right (I4: say what could not be done).
		out.Status, out.Reason = http.StatusServiceUnavailable, payload.FailMethodUnavailable
		out.Detail = "the session could not be signed: " + err.Error()
		return out
	}

	// **The reset is on success** (§19).
	g.throttle().Succeeded(user)

	out.OK, out.Status = true, http.StatusOK
	out.Token, out.Claims = token, claims
	out.Username = claims.U
	return out
}

// Accept mints a session for an identity that arrived some other way — today, a completed OIDC
// handshake.
//
// The throttle is not consulted and not reset. It counts password attempts, and a provider sign-in is
// not one: a name locked out at the passwd file has proved nothing to the provider, and a successful
// provider sign-in has proved nothing about the password.
func (g *Gate) Accept(posture Posture, user string, via payload.LoginMethod, now time.Time) Login {
	out := Login{Username: Username(user)}

	if !posture.Live(via) {
		out.Status, out.Reason = http.StatusServiceUnavailable, payload.FailMethodUnavailable
		out.Detail = string(via) + " sign-in is not available"
		return out
	}

	token, claims, err := g.Signer.Mint(user, via, now)
	if err != nil {
		out.Status, out.Reason = http.StatusServiceUnavailable, payload.FailMethodUnavailable
		out.Detail = "the session could not be signed: " + err.Error()
		return out
	}

	out.OK, out.Status = true, http.StatusOK
	out.Token, out.Claims = token, claims
	out.Username = claims.U
	return out
}

// Logout revokes whatever session the request carries and returns the clearing cookie.
//
// It succeeds whether or not there was a session to revoke. A logout that reported *you were not signed
// in* would be a way to ask whether a token is still valid, and the client's next step is the same
// either way.
func (g *Gate) Logout(r *http.Request) *http.Cookie {
	now := g.clock()()
	if token, err := g.Cookies.Token(r); err == nil {
		// Verified before revoking, so an unauthenticated caller cannot add arbitrary identifiers to
		// the revocation set and fill it — the cap would then evict real revocations, which is a
		// sign-out that silently un-signs-out.
		//
		// An already-expired session is not added: the expiry check refuses it earlier, so an entry for
		// it would be state held to answer a question already answered.
		if claims, kind, err := g.Signer.Verify(token, now); err == nil || kind == payload.RejectRevoked {
			g.Signer.Revoke(claims, now)
		}
	}
	return g.Cookies.Clear(r)
}

// SessionInfo is what `GET /api/session` answers with (§4.7, §18).
//
// It is built here rather than in the HTTP layer because it is the one place that holds both halves —
// the posture and the request's session — and because §19 requires the same posture that gates a request
// to be the one described to it.
func (g *Gate) SessionInfo(r *http.Request) payload.SessionInfo {
	posture := g.posture()

	out := payload.SessionInfo{AccessMode: posture.Mode, OIDCLabel: posture.OIDCLabel}
	if !posture.Live(payload.MethodOIDC) {
		// The label is dropped when the method is not live, so a UI rendering *a label exists, show the
		// button* cannot offer a sign-in that would fail.
		out.OIDCLabel = ""
	}

	// The viewer the guard already resolved, so a public route and a gated one agree about who is
	// calling. Falls back to resolving it, for a caller that reached here without the guard.
	viewer := From(r.Context())
	if viewer.User == nil && viewer.Kind == "" {
		viewer = g.resolve(r)
	}
	out.User = viewer.User

	// §16, through the same walk the Overview goes out with: `methods` and `notes` are required lists,
	// and Go writes `null` for a nil slice. A posture with nothing live has an empty method list, and
	// `null` there would make every consumer treat *no methods* as a case to handle separately from
	// *no methods yet* — the distinction Appendix A reserves for the fields it marks optional.
	payload.Normalize(&out)
	return out
}

// unthrottled is the throttle a gate that was configured without one uses. Its Max is zero, so every
// method on it returns immediately without touching its map — which is what makes sharing one safe.
//
// Shared rather than assigned into the gate on first use: a lazy assignment would be a write to a struct
// several goroutines are reading, which is a data race the race detector would find on the first
// concurrent login. A gate that throttles nothing is weaker, not broken (I4), and the server always
// configures one.
var unthrottled = &Throttle{}

func (g *Gate) throttle() *Throttle {
	if g.Throttle == nil {
		return unthrottled
	}
	return g.Throttle
}
