package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Reading and writing, in one place so no handler decides these questions for itself.

// ContentTypeJSON is what every JSON reply carries. The charset is explicit because a browser that
// guessed would be guessing about strings that came from a scanned fleet.
const ContentTypeJSON = "application/json; charset=utf-8"

// MaxBodyBytes bounds any request body this server reads.
//
// Four kilobytes, because the two bodies that exist are `{"probe":true}` and a username with a
// password whose own cap is 1024 characters (§19). A larger bound would buy nothing and would let an
// unauthenticated caller — `/api/login` and `/api/rescan` are both public on an open dashboard —
// spend this process's memory a request at a time.
const MaxBodyBytes = 4 << 10

// errorReply is the one shape a failure takes: `{"error": "..."}`, matching the gate's own refusals
// byte for byte in structure so a client has one thing to parse.
type errorReply struct {
	Error string `json:"error"`

	// Reason is the served code on a login failure, one of §4.7's eight. Omitted everywhere else,
	// because no other refusal has a code a client is allowed to distinguish (§19).
	Reason string `json:"reason,omitempty"`
}

// okReply is what a route that did something and has nothing to return answers with. A body rather
// than a 204, because a client that got no body could not tell an answered request from a proxy's
// silence.
type okReply struct {
	OK bool `json:"ok"`
}

// writeJSON serialises v and writes it.
//
// **Marshalled into memory before anything is written.** A streaming encoder that failed halfway would
// have already sent a 200 and half a document, and a client cannot tell that from a truncated
// connection. The payload is one Overview — kilobytes, occasionally a megabyte — and holding it is
// cheaper than being ambiguous about whether it was complete.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Unreachable for the types this package serialises, all of which are plain structs. Handled
		// rather than ignored, because the alternative is a 200 with an empty body.
		w.Header().Set("Content-Type", ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"the payload could not be serialised"}`))
		return
	}

	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError is the refusal, with no detail in it beyond the sentence the caller chose. Everything a
// client is not told goes to the log instead (§19).
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorReply{Error: message})
}

// errBodyTooLarge is the one read failure a caller distinguishes: a body over the cap is refused
// rather than truncated, because truncated JSON parses as malformed and *that* is a different thing to
// tell an operator than *you sent too much*.
var errBodyTooLarge = errors.New("the request body is larger than this server reads")

// readBody reads a bounded body.
//
// One byte past the cap is read on purpose: it is how the difference between *exactly at the cap* and
// *over it* is known without trusting Content-Length, which a client chooses.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, errors.New("the request body could not be read")
	}
	if len(body) > MaxBodyBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}
