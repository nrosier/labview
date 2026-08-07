package httpapi

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/payload"
)

// The five gate routes (§19), which are the four public API paths plus the two OIDC redirects.
//
// Every decision here belongs to the access package: the posture, the judgement of an attempt, the
// minting and the cookie. What is left is HTTP — a status, a header, a body, a redirect — which is
// exactly the split §19 asks for, since the gate must be testable without a server and the server must
// not be able to reach a second opinion about who is signed in.

// session answers the posture and whoever is signed in (§4.7).
//
// Public, because the UI has to be able to ask whether it needs to show a login form before it has a
// session — a gated `/api/session` would mean the login form was only visible to people who were
// already past it.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.gate.SessionInfo(r))
}

// credentials is the body of `POST /api/login`.
//
// Two fields and no more. It is decoded into a struct rather than a map so an unrecognised field is
// ignored (I4) and neither value can arrive as a number, an object or an array — and it is `passwd`
// throughout, never `basic`, because a name is how this method gets mistaken for HTTP Basic (§4.7).
type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginReply is what `POST /api/login` answers with.
//
// On success the signed-in user, so the UI has the posture's answer without a second round trip. On
// failure the sentence and the code — the code, because §4.7 fixes eight of them and a client is
// entitled to tell *wrong password* from *locked out*; the sentence, because it says no more than the
// code already did.
type loginReply struct {
	OK     bool                       `json:"ok"`
	User   *payload.SessionUser       `json:"user,omitempty"`
	Error  string                     `json:"error,omitempty"`
	Reason payload.LoginFailureReason `json:"reason,omitempty"`
}

// login judges a password attempt (§19).
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		// The sentence names the body and not the credentials: an attempt that was never judged must not
		// be reported as one that failed.
		writeError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}

	var req credentials
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "the request body is not a JSON object")
		return
	}

	// The posture is read once and passed in, so the decision is made against the same posture the
	// client was told about (§19). Re-reading it inside the gate could tell a browser the method is live
	// and then refuse the attempt as unavailable.
	posture := s.gate.Postures.Current()
	out := s.gate.Attempt(posture, req.Username, req.Password, s.clock()())

	// The log gets the reason; the client gets the code. Note what is absent: the password is never a
	// field of an Event and never part of a Detail, so there is no formatting mistake that could put one
	// in a log line (I6).
	s.log(Event{
		What:     EventLogin,
		Username: out.Username,
		Via:      payload.MethodPasswd,
		OK:       out.OK,
		Status:   out.Status,
		Reason:   out.Reason,
		Detail:   out.Detail,
	})

	if !out.OK {
		if out.RetryAfter > 0 {
			// Rounded up, because a Retry-After that rounded down would invite the client back a
			// fraction of a second before the lock opens and be answered with another 429.
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(out.RetryAfter.Seconds()))))
		}
		writeJSON(w, out.Status, loginReply{Error: Sentence(out.Reason), Reason: out.Reason})
		return
	}

	http.SetCookie(w, s.gate.Cookies.Set(r, out.Token, s.gate.Signer.TTL()))

	user := out.Claims.User()
	writeJSON(w, http.StatusOK, loginReply{OK: true, User: &user})
}

// logout revokes the session and clears the cookie (§19).
//
// It answers 200 whether or not there was a session. A logout that reported *you were not signed in*
// would be a way to ask whether a token is still valid without holding one.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// Read before the revocation, because Logout's clearing cookie says nothing about who was signed in
	// and the log line should.
	name := viewerName(r)

	http.SetCookie(w, s.gate.Logout(r))

	s.log(Event{
		What:     EventLogout,
		Username: name,
		OK:       true,
		Status:   http.StatusOK,
		Detail:   "session cleared",
	})

	writeJSON(w, http.StatusOK, okReply{OK: true})
}

// ---------------------------------------------------------------------------
// The provider handshake
// ---------------------------------------------------------------------------

// oidcStart sends the browser to the provider (§18: 302 to the authorize URL).
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		s.unavailable(w, r, EventOIDCStart, "no provider is configured")
		return
	}

	target, cookie, err := s.oidc.Start(r.Context(), r)
	if err != nil {
		s.handshakeFailed(w, r, EventOIDCStart, err)
		return
	}

	http.SetCookie(w, cookie)

	s.log(Event{
		What:     EventOIDCStart,
		Username: access.UnknownUsername,
		Via:      payload.MethodOIDC,
		OK:       true,
		Status:   http.StatusFound,
		Detail:   "redirected to the provider",
	})

	// 302 and not 303: this is a GET redirected to a GET, and 302 is what every provider's own
	// documentation describes. The target is the provider's absolute authorize URL, which the access
	// package built and already refused unless it was HTTPS or loopback (§19).
	http.Redirect(w, r, target, http.StatusFound)
}

// oidcCallback completes the handshake: code → session cookie → 302 `/`, or 302 `/?login_error=<code>`
// (§18).
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		s.unavailable(w, r, EventOIDCCallback, "no provider is configured")
		return
	}

	// **Cleared whatever happens, and cleared first.** The handshake this cookie carries is spent the
	// moment the callback arrives: leaving it set would let a failed callback be retried against the
	// same state and nonce, and clearing it only on success would leave the browser holding a handshake
	// for a sign-in that already failed.
	http.SetCookie(w, s.oidc.ClearTransient(r))

	identity, err := s.oidc.Callback(r.Context(), r)
	if err != nil {
		s.handshakeFailed(w, r, EventOIDCCallback, err)
		return
	}

	posture := s.gate.Postures.Current()
	out := s.gate.Accept(posture, identity.Username, payload.MethodOIDC, s.clock()())

	s.log(Event{
		What:     EventOIDCCallback,
		Username: out.Username,
		Via:      payload.MethodOIDC,
		OK:       out.OK,
		Status:   http.StatusFound,
		Reason:   out.Reason,
		Detail:   out.Detail,
	})

	if !out.OK {
		// A verified identity that cannot be given a session — the method went away mid-handshake, or
		// the process cannot produce randomness. Reported as its code, because the browser's next step is
		// the same as for any other failure: back to the dashboard with something to render.
		http.Redirect(w, r, loginErrorURL(out.Reason), http.StatusFound)
		return
	}

	http.SetCookie(w, s.gate.Cookies.Set(r, out.Token, s.gate.Signer.TTL()))
	http.Redirect(w, r, "/", http.StatusFound)
}

// unavailable is the answer when the provider is not configured at all.
//
// A redirect rather than a 404, and `method-unavailable` rather than silence: the route stays
// registered when the method is switched off (§18), so a browser that still has a sign-in button
// gets a code it can render instead of the UI shell arriving where a redirect was expected.
func (s *Server) unavailable(w http.ResponseWriter, r *http.Request, what, detail string) {
	s.log(Event{
		What:     what,
		Username: access.UnknownUsername,
		Via:      payload.MethodOIDC,
		Status:   http.StatusFound,
		Reason:   payload.FailMethodUnavailable,
		Detail:   detail,
	})
	http.Redirect(w, r, loginErrorURL(payload.FailMethodUnavailable), http.StatusFound)
}

// handshakeFailed turns a handshake error into the redirect and the log line (§19).
func (s *Server) handshakeFailed(w http.ResponseWriter, r *http.Request, what string, err error) {
	failure, ok := err.(access.Failure)
	if !ok {
		// Every refusal the access package produces is a Failure. An error that is not one is a bug
		// rather than a handshake outcome, so it is reported as the code that means *the exchange with
		// the provider did not work* and its text goes to the log where the operator can read it.
		failure = access.Failure{Code: payload.FailOIDCProvider, Reason: err.Error()}
	}

	s.log(Event{
		What:     what,
		Username: access.UnknownUsername,
		Via:      payload.MethodOIDC,
		Status:   http.StatusFound,
		Reason:   failure.Code,
		Detail:   failure.Reason,
		Report:   failure.Report,
	})

	// Failure.Redirect escapes the code, so a value that reached it from somewhere unexpected cannot
	// break out of the query string (§19).
	http.Redirect(w, r, failure.Redirect(), http.StatusFound)
}

// loginErrorURL is where a failed sign-in sends the browser. It matches access.Failure.Redirect, and
// escapes for the same reason: the codes are a closed set and a value that arrived from outside it must
// not be able to add a query parameter of its own.
func loginErrorURL(reason payload.LoginFailureReason) string {
	return access.Failure{Code: reason}.Redirect()
}

// ---------------------------------------------------------------------------
// The eight sentences
// ---------------------------------------------------------------------------

// sentences is one rendering per failure code (§4.7).
//
// Written as data and total over the eight, so a code added to the vocabulary without a sentence is a
// missing map entry a test finds rather than an empty string a browser renders. Each says exactly what
// its code says and no more: *the username or password is wrong* rather than *no such user*, because a
// reply that distinguished them would enumerate accounts.
var sentences = map[payload.LoginFailureReason]string{
	payload.FailCredentials:       "the username or password is wrong",
	payload.FailThrottled:         "too many failed attempts for this name; try again shortly",
	payload.FailMethodUnavailable: "that sign-in method is not available",
	payload.FailSessionExpired:    "the session has expired",
	payload.FailOIDCState:         "the sign-in could not be completed; start again",
	payload.FailOIDCProvider:      "the identity provider could not be read",
	payload.FailOIDCToken:         "the identity provider's answer could not be verified",
	payload.FailOIDCIdentity:      "the identity provider supplied no usable username",
}

// Sentence renders a failure code for a client.
//
// An unknown code renders as the generic sentence rather than as itself: a code that reached here from
// outside the closed set is not a value to reflect back into a response body.
func Sentence(reason payload.LoginFailureReason) string {
	if s, ok := sentences[reason]; ok {
		return s
	}
	return "the sign-in did not succeed"
}
