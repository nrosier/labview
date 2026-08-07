// Package conn is §15: every outbound target reports through one shape, and every phase in that
// shape is produced by one shared classification.
//
// The point of the package is negative. Nothing outside it may look at an error message to decide
// what went wrong: there is one mapping from a transport error to a phase, one from an HTTP status
// to a phase, and one JSON read that hands back the phase and the underlying code beside the error.
// A caller that re-derived a phase from a message string would be a second definition of `timeout`,
// and the two would disagree the first time a Go release reworded a `net` error.
//
// The package holds no I/O of its own. It is handed errors, statuses and bodies that somebody else
// obtained, which is what makes every rule here table-testable without a listener.
package conn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
)

// Target is an outbound target LabView reports on. The set is closed because §15 requires one
// action to take per (target, phase) pair, and an open set would mean a pair with no action.
type Target string

const (
	TargetDocker    Target = "docker"
	TargetAuthentik Target = "authentik"
	TargetTraefik   Target = "traefik"
	TargetProbe     Target = "probe"
	TargetOIDC      Target = "oidc"
)

// Targets is the order the Diagnostics view lists them in when phases tie (§22.2).
var Targets = []Target{TargetDocker, TargetAuthentik, TargetTraefik, TargetProbe, TargetOIDC}

// Label is how a target is named in a sentence a reader sees.
func (t Target) Label() string {
	switch t {
	case TargetDocker:
		return "Docker Engine"
	case TargetAuthentik:
		return "Authentik"
	case TargetTraefik:
		return "Traefik"
	case TargetProbe:
		return "the active probe"
	case TargetOIDC:
		return "the OIDC provider"
	default:
		return string(t)
	}
}

// ---------------------------------------------------------------------------
// The three shared classifiers
// ---------------------------------------------------------------------------

// FromError is the one mapping from a transport error to a phase.
//
// It is written against the error *types* the standard library defines rather than against their
// messages, except where no type exists — a TLS handshake failure and a connection reset both
// arrive as opaque errors, and there the string is all there is. Those two cases are the reason
// this function exists in one place: a second copy of them would rot independently.
//
// `elapsed` and `budget` are what make `timeout` honest. Many clients implement a request timeout
// by tearing the socket down, so a silent endpoint surfaces as a reset rather than as a deadline
// (§10). A teardown that reached the budget is a timeout; the same teardown at 200 ms is a reset,
// which is a different fault with a different fix.
func FromError(err error, elapsed, budget time.Duration) payload.ConnectionPhase {
	if err == nil {
		return payload.PhaseConnected
	}

	// A deadline the runtime itself recognised, whatever wrapped it.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return payload.PhaseTimeout
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return payload.PhaseTimeout
	}

	// DNS, before the dial error it is wrapped in: a resolve failure is also a *net.OpError with
	// Op "dial", so asking about the dial first would classify every unknown host as `connect`.
	var dnserr *net.DNSError
	if errors.As(err, &dnserr) {
		if dnserr.IsTimeout {
			return payload.PhaseTimeout
		}
		return payload.PhaseResolve
	}

	// A socket path that is not there. This is the shape a `tcp://` endpoint never produces and a
	// unix socket produces constantly, and it is `not-found` rather than `connect`: there is
	// nothing to refuse the connection.
	if errors.Is(err, fs.ErrNotExist) {
		return payload.PhaseNotFound
	}
	if errors.Is(err, fs.ErrPermission) {
		// Present and not ours. §10 is explicit that this is `authorize` and not `connect`: the
		// fix is a group membership, not a listener.
		return payload.PhaseAuthorize
	}

	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTDOWN) {
		return payload.PhaseConnect
	}

	// TLS, asked before the teardown below. `crypto/tls` exports no error type for a failed
	// handshake, so this is partly recognised by text — and a handshake that fails often *also*
	// tears the connection down, so whichever of the two is asked first wins. TLS wins: a
	// certificate that will not verify is the one failure an operator most needs told apart from a
	// network fault, and verification is never disabled here, so it is a real outcome (§21).
	if isTLS(err) {
		return payload.PhaseTLS
	}

	// A teardown. Whether it is a timeout depends on the clock and on nothing in the message.
	if isTeardown(err) {
		if budget > 0 && elapsed >= budget {
			return payload.PhaseTimeout
		}
		return payload.PhaseConnect
	}

	// A dial that failed for none of the above.
	var operr *net.OpError
	if errors.As(err, &operr) {
		return payload.PhaseConnect
	}

	// Unclassified, and the budget is the last thing worth asking about: a request that ran out of
	// time and failed for a reason nothing above recognised is still a timeout to a reader.
	if budget > 0 && elapsed >= budget {
		return payload.PhaseTimeout
	}
	return payload.PhaseConnect
}

// teardownText are the conditions that mean the connection went away mid-exchange. They are
// separated from TLS text because a teardown is the one class whose phase depends on the clock.
var teardownText = []string{
	"connection reset",
	"broken pipe",
	"unexpected eof",
	"use of closed network connection",
	"server closed idle connection",
	"http2: client connection lost",
	"connection closed",
}

func isTeardown(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	return matchesAny(err, teardownText)
}

// tlsText are handshake and verification failures. `crypto/tls` returns most of these as plain
// errors, and x509's own types are worth naming explicitly so a certificate problem is not read as
// a network one.
var tlsText = []string{
	"tls:",
	"x509:",
	"certificate",
	"handshake failure",
	"remote error: tls",
}

func isTLS(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	if errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) {
		return true
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return true
	}
	return matchesAny(err, tlsText)
}

// matchesAny is the case-folded substring test the two text lists share. It is one function so
// that "we had to read the message" is visible in exactly two places.
func matchesAny(err error, needles []string) bool {
	msg := message(err)
	if msg == "" {
		return false
	}
	for _, needle := range needles {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// message is err.Error() without the assumption that every error can be asked for its message.
// A malformed error value panics when asked: both *net.OpError and *fs.PathError dereference their
// wrapped error unconditionally, so either of them with a nil Err takes down whoever formats it.
//
// That is somebody else's bug, and I4's answer to somebody else's bug is a degraded reading rather
// than a crashed scan. This classifier runs on every outbound read of every target, so a panic here
// would end the scan instead of the one request — and the request had already failed anyway. An
// error whose message cannot be obtained falls through to the phase it would have had without any
// text, which is `connect`.
func message(err error) (msg string) {
	defer func() {
		if recover() != nil {
			msg = ""
		}
	}()
	return strings.ToLower(err.Error())
}

// FromStatus is the one mapping from an HTTP status to a phase.
//
// `authenticate` and `authorize` stay separate everywhere (§4.6): a wrong token and a token
// without permission need different fixes, and collapsing them into one "auth failed" would send
// an operator to reissue a credential that was already correct.
func FromStatus(status int) payload.ConnectionPhase {
	switch {
	case status >= 200 && status < 300:
		return payload.PhaseConnected
	case status == 401 || status == 407:
		return payload.PhaseAuthenticate
	case status == 403:
		return payload.PhaseAuthorize
	case status == 404 || status == 405:
		return payload.PhasePath
	default:
		return payload.PhaseStatus
	}
}

// ReadJSON is the one JSON read: it returns the phase and the underlying code **beside** the
// error, so no caller re-derives a phase from a message (§15).
//
// A body that is not JSON is `protocol` and not `status`: the host answered, and answered as
// something else. That distinction is the whole diagnosis when a reverse proxy in front of an API
// serves its own login page with a 200 — the status says success and the phase says the API was
// never reached.
//
// The read is bounded by whatever reader it is handed. It does not impose its own cap, because the
// 64 KiB cap of I8 is applied once, at the transport, and a second cap here would be a second
// number to keep in step.
func ReadJSON(r io.Reader, into any) (payload.ConnectionPhase, string, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		// The body stopped arriving. The clock is the caller's to supply, so this is classified
		// without one: a truncated read is a teardown, not a deadline.
		return FromError(err, 0, 0), "", err
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return payload.PhaseProtocol, "empty", errors.New("the response carried no body")
	}
	if err := json.Unmarshal(body, into); err != nil {
		return payload.PhaseProtocol, firstToken(trimmed), err
	}
	return payload.PhaseConnected, "", nil
}

// firstToken is what a `protocol` phase reports as its code: enough of the body to recognise what
// answered instead, and no more. It is a shape and never a value — a login page's HTML tag, not
// anything the page contained (I6).
func firstToken(body string) string {
	switch {
	case strings.HasPrefix(body, "<!DOCTYPE"), strings.HasPrefix(body, "<!doctype"):
		return "html"
	case strings.HasPrefix(body, "<html"), strings.HasPrefix(body, "<HTML"):
		return "html"
	case strings.HasPrefix(body, "<"):
		return "xml-or-html"
	default:
		return "not-json"
	}
}

// ExcerptCap is how much of an unexpected body a detail carries.
//
// It is a diagnostic and not a document: what tells an operator which program answered is in the
// first few hundred bytes — a proxy's status line, a login page's title, the opening bracket of a
// list that was cut — and a detail long enough to hold a whole page is one nobody finishes reading.
const ExcerptCap = 512

// Excerpt is the beginning of a body that was not what was asked for, rendered so that it can go in
// a `detail` — which is the field a reader sees and the one the log prints (§15, §16).
//
// It is the counterpart of the `protocol` code and not a replacement for it. The code names the
// *shape* that answered and must never say more than that (I6; ReadJSON has its own test holding it
// there). This says what the shape contained, because `not-json` alone leaves an operator with
// nowhere to go: a socket proxy answering on the Engine's path, a list cut at the body cap and a
// plain-text refusal all report those same three words.
//
// Four things happen to the bytes, and each is what makes printing them defensible:
//
//   - Credentials embedded in a URI are redacted (§20). A body is somebody else's output and may
//     carry a connection string; the rule that covers an environment value covers this too.
//   - Runs of whitespace become one space, because §15's format is one line per report plus one
//     indented line per candidate, and a body carrying newlines would forge those lines.
//   - It is quoted, so a control character is escaped rather than sent to a terminal, and so a
//     reader can see where the far end's own text begins and ends.
//   - The *rendered* text is cut at ExcerptCap, and the cut is stated rather than hidden.
//
// A body that is not text is described instead of shown. Bytes that are not valid UTF-8 are a gzip
// stream, a TLS record or a binary protocol, and *that* is the finding — pasting them into a log
// tells an operator nothing and corrupts the line they were reading.
func Excerpt(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return ""
	}
	if !utf8.Valid(trimmed) {
		return strconv.Itoa(len(body)) + " bytes that are not text"
	}

	// Fields splits on every kind of whitespace and drops the runs, which is both halves of the
	// one-line rule in one pass.
	flat := strings.Join(strings.Fields(secrets.RedactURIs(string(trimmed))), " ")

	// Rendered a rune at a time and spent against the cap, rather than cut and then quoted, because
	// quoting expands what it renders: one control character becomes four characters, so a body that
	// is largely control characters would produce a line four times the size this cap promises. What
	// has to be bounded is the text that reaches the log, not the bytes that produced it — and taking
	// whole runes is what keeps a replacement character out of a diagnostic, where it would only
	// invite the reader to wonder whether the far end sent it.
	var b strings.Builder
	b.WriteByte('"')
	cut := false
	for _, r := range flat {
		piece := quoteRune(r)
		// The closing quote is part of the cap, so its byte is reserved before the budget is spent.
		if b.Len()+len(piece) > ExcerptCap-1 {
			cut = true
			break
		}
		b.WriteString(piece)
	}
	b.WriteByte('"')
	if !cut {
		return b.String()
	}
	// The ellipsis goes outside the quotes: it is this function's word for *there was more*, not a
	// character the far end sent.
	return b.String() + "…"
}

// quoteRune renders one rune as it appears inside a double-quoted string.
//
// strconv.QuoteRune would be the obvious call and is the wrong one: it quotes for single quotes, so
// it escapes `'` and leaves `"` alone — and a `"` written unescaped into a quoted excerpt ends the
// quoting early, which is the one thing the quoting is there to prevent.
func quoteRune(r rune) string {
	q := strconv.Quote(string(r))
	return q[1 : len(q)-1]
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

// OK is the one definition of a target having worked. `partial` counts: a partial read is useful,
// and treating it as a failure would hide what was read (§15).
func OK(phase payload.ConnectionPhase) bool {
	return phase == payload.PhaseConnected || phase == payload.PhasePartial
}

// Report builds one connection report, filling in the derived fields so that no caller sets `ok`
// or `hint` by hand and disagrees with the next one.
//
// The endpoint must already be credential-free. Stripping it here would mean the caller had a
// credential-bearing string in hand and trusted this function to remove it; the transport formats
// endpoints without credentials in the first place (§15, I6).
func Report(target Target, phase payload.ConnectionPhase, endpoint string, source payload.EndpointSource, detail string) payload.ConnectionReport {
	return payload.ConnectionReport{
		Target:   string(target),
		OK:       OK(phase),
		Phase:    phase,
		Endpoint: endpoint,
		Source:   source,
		Detail:   detail,
		Hint:     Hint(target, phase),
		Attempts: []payload.ConnectionAttempt{},
	}
}

// Prose is one phase in the words a reader sees. Every member of the closed set has one, and
// ProseIsExhaustive is the test that keeps it that way.
func Prose(phase payload.ConnectionPhase) string {
	switch phase {
	case payload.PhaseDisabled:
		return "switched off in configuration"
	case payload.PhaseNotConfigured:
		return "nothing to talk to"
	case payload.PhaseNotFound:
		return "the thing to talk to does not exist"
	case payload.PhaseCredential:
		return "a credential was needed and was absent or blank"
	case payload.PhaseResolve:
		return "the name did not resolve"
	case payload.PhaseConnect:
		return "refused, unreachable, or no route"
	case payload.PhaseTLS:
		return "the TLS handshake failed"
	case payload.PhaseTimeout:
		return "no answer inside the budget"
	case payload.PhaseAuthenticate:
		return "answered 401 — the credential was not accepted"
	case payload.PhaseAuthorize:
		return "answered 403 — the credential lacks permission"
	case payload.PhasePath:
		return "answered, but not on that route"
	case payload.PhaseStatus:
		return "answered with an error status"
	case payload.PhaseProtocol:
		return "answered, but not as this API"
	case payload.PhasePartial:
		return "read enough to be useful, not all of it"
	case payload.PhaseConnected:
		return "read in full"
	default:
		// Unreachable for a member of the closed set, and honest for anything else: a phase with
		// no wording is reported as one rather than silently reading as connected.
		return "phase " + string(phase) + " has no wording"
	}
}

// Hint is the one action to take for a (target, phase) pair (§15).
//
// The pairs that differ by target are the ones worth having this function for. `credential` on
// Authentik means an API token; on Traefik it means a username and password that is explicitly
// *not* that token; and on Docker it cannot arise, because a socket has no credential. A single
// per-phase hint would tell an operator to set the wrong variable.
func Hint(target Target, phase payload.ConnectionPhase) string {
	// The phases that stop before the network say the same thing to everybody, because the fix is
	// in configuration and not at the far end.
	switch phase {
	case payload.PhaseDisabled:
		return "set " + enableKey(target) + " if you want this read"
	case payload.PhaseConnected:
		return ""
	}

	switch target {
	case TargetDocker:
		switch phase {
		case payload.PhaseNotConfigured:
			return "set LABVIEW_DOCKER_SOCKET or LABVIEW_DOCKER_HOST"
		case payload.PhaseNotFound:
			return "the socket path does not exist — check the bind mount; a missing host path " +
				"is silently created as an empty directory"
		case payload.PhaseAuthorize:
			// Both arrangements, because one action per (target, phase) pair means this string cannot
			// branch on the endpoint — and naming only the socket sends the larger half of operators to
			// the wrong fix. A `403` from a *TCP* endpoint is a socket proxy refusing a path it was
			// never configured to pass, where there is no uid and no socket to chmod; the body quoted
			// in the detail usually names the proxy outright.
			return "a socket proxy that was never given CONTAINERS=1, or — on a unix socket — a uid " +
				"outside the docker group; the quoted body beside this line says which refused"
		case payload.PhaseConnect:
			return "nothing is listening — check that the Engine is running and the path or " +
				"port is right"
		case payload.PhaseTimeout:
			return "the Engine did not answer in time — raise LABVIEW_DOCKER_TIMEOUT, or " +
				"lower LABVIEW_DOCKER_MAX_CONCURRENCY if the host is loaded"
		case payload.PhasePartial:
			return "some containers could not be inspected; their ports, networks and health " +
				"are missing from this scan"
		case payload.PhaseProtocol:
			return "something answered on that path that is not the Docker Engine"
		}
	case TargetAuthentik:
		switch phase {
		case payload.PhaseNotConfigured:
			return "set LABVIEW_AUTHENTIK_TOKEN, and LABVIEW_AUTHENTIK_URL if it cannot be found"
		case payload.PhaseCredential:
			return "LABVIEW_AUTHENTIK_TOKEN is present and empty"
		case payload.PhaseNotFound:
			return "no Authentik endpoint was found — set LABVIEW_AUTHENTIK_URL"
		case payload.PhaseAuthenticate:
			return "the token was not accepted — reissue it in Authentik"
		case payload.PhaseAuthorize:
			return "the token lacks permission — a superuser token reads the exact application " +
				"list; otherwise widen this token's permissions"
		case payload.PhasePartial:
			return "applications were withheld from this token — use a superuser token for the " +
				"exact list, or check this token's permissions"
		case payload.PhaseProtocol:
			return "something answered there that is not the Authentik API"
		case payload.PhasePath:
			return "check LABVIEW_AUTHENTIK_URL points at the API root, not at a sub-path"
		}
	case TargetTraefik:
		switch phase {
		case payload.PhaseNotConfigured:
			return "set LABVIEW_TRAEFIK_URL, or expose the API on a port this scan can see"
		case payload.PhaseCredential:
			return "set LABVIEW_TRAEFIK_USERNAME and LABVIEW_TRAEFIK_PASSWORD — an Authentik " +
				"API token is not a credential here"
		case payload.PhaseNotFound:
			return "no Traefik API was found — set LABVIEW_TRAEFIK_URL"
		case payload.PhaseAuthenticate:
			return "the API needs a credential — set LABVIEW_TRAEFIK_USERNAME and " +
				"LABVIEW_TRAEFIK_PASSWORD"
		case payload.PhaseAuthorize:
			return "the credential was accepted and lacks permission for the API"
		case payload.PhasePartial:
			return "the entrypoint list was not read, so a middleware attached at an entrypoint " +
				"is invisible and no posture was changed by this read"
		case payload.PhaseProtocol:
			return "something answered there that is not the Traefik API — the dashboard and the " +
				"API are different paths"
		case payload.PhasePath:
			return "the API is not on that path — Traefik serves it on its own entrypoint"
		}
	case TargetProbe:
		switch phase {
		case payload.PhaseNotFound:
			return "no service had an HTTP address to ask — a published port alone is not one"
		case payload.PhasePartial:
			return "part of the fleet did not answer; those services claim no measurement " +
				"either way"
		case payload.PhaseTimeout:
			return "raise LABVIEW_PROBE_TIMEOUT, or lower LABVIEW_PROBE_MAX_CONCURRENCY"
		case payload.PhaseNotConfigured:
			return "set LABVIEW_PROBE_LAN_HOST to reach services published on the host only"
		}
	case TargetOIDC:
		switch phase {
		case payload.PhaseNotConfigured:
			return "set LABVIEW_OIDC_ISSUER, LABVIEW_OIDC_CLIENT_ID and LABVIEW_OIDC_REDIRECT_URI"
		case payload.PhaseCredential:
			return "LABVIEW_OIDC_CLIENT_SECRET is present and empty — unset it for a public client"
		case payload.PhaseResolve, payload.PhaseConnect, payload.PhaseTimeout:
			return "LabView cannot reach the issuer, so nobody can sign in — check " +
				"LABVIEW_OIDC_ISSUER"
		case payload.PhaseTLS:
			return "the issuer's certificate did not verify; LabView will not skip verification"
		case payload.PhaseProtocol, payload.PhasePath:
			return "the discovery document was not served — check the issuer URL"
		case payload.PhasePartial:
			return "the discovery document was read and its key set was not, so sign-in would " +
				"fail when a token came back — check that jwks_uri is reachable"
		case payload.PhaseAuthenticate, payload.PhaseAuthorize:
			return "the issuer refused this client — check LABVIEW_OIDC_CLIENT_ID and, for a " +
				"confidential client, LABVIEW_OIDC_CLIENT_SECRET"
		}
	}

	// A pair with no specific action still gets the general one, which is to read what happened.
	// Returning the prose keeps every failing report actionable in the weak sense rather than
	// leaving a blank column in the Diagnostics view.
	if !OK(phase) {
		return Prose(phase) + " — see the detail beside this line"
	}
	return ""
}

// enableKey is the environment variable that switches a target on, for the `disabled` hint. The
// probe's is the one a reader can also override per rescan (§13.7).
func enableKey(target Target) string {
	switch target {
	case TargetDocker:
		return "LABVIEW_DOCKER_ENABLED=true"
	case TargetAuthentik:
		return "LABVIEW_AUTHENTIK_ENABLED=true"
	case TargetTraefik:
		return "LABVIEW_TRAEFIK_ENABLED=true"
	case TargetProbe:
		return "LABVIEW_PROBE_ENABLED=true, or tick the box beside Rescan for one scan"
	case TargetOIDC:
		return "LABVIEW_OIDC_ENABLED=true"
	default:
		return "the target's enabled flag"
	}
}

// ---------------------------------------------------------------------------
// Formatting, comparison, logging
// ---------------------------------------------------------------------------

// Format is §15's shape: one line for the report plus one indented line per rejected candidate.
// It is a pure function of the report, because the pipeline takes no logger and a caller is what
// prints (§5).
func Format(r payload.ConnectionReport) []string {
	head := r.Target + ": " + string(r.Phase)
	if r.Endpoint != "" {
		head += " " + r.Endpoint
		if r.Source != "" {
			head += " (" + string(r.Source) + ")"
		}
	}
	switch {
	case r.Read != "":
		head += " — " + r.Read
	case r.Detail != "":
		head += " — " + r.Detail
	}
	if r.Hint != "" && !OK(r.Phase) {
		head += " — " + r.Hint
	}

	lines := []string{head}
	for _, a := range r.Attempts {
		line := "  " + a.Endpoint + ": " + string(a.Phase)
		if a.Why != "" {
			line += " (candidate: " + a.Why + ")"
		}
		if a.Detail != "" {
			line += " — " + a.Detail
		}
		lines = append(lines, line)
	}
	return lines
}

// Same is the comparison of §15: two reports are the same when target, `ok`, phase and endpoint
// agree. `read` is deliberately **not** compared — a container count ticking up would otherwise
// re-announce a working target on every rescan, which is how a change feed becomes noise nobody
// reads.
func Same(a, b payload.ConnectionReport) bool {
	return a.Target == b.Target && a.OK == b.OK && a.Phase == b.Phase && a.Endpoint == b.Endpoint
}

// Banner reports whether this target deserves a banner in the UI: `partial`, or any failure whose
// phase is neither `disabled` nor `not-configured` (§15). Those two are choices rather than
// faults, and banners for choices train a reader to dismiss banners.
func Banner(r payload.ConnectionReport) bool {
	if r.Phase == payload.PhasePartial {
		return true
	}
	return !r.OK && !r.Phase.BeforeTheNetwork()
}

// Level is the log level for one report (§15): a working target at info, `partial` and failures at
// warn. The first scan logs all of them regardless, which is the caller's decision and not this
// function's — it has no way to know which scan it is looking at.
type Level string

const (
	LevelInfo Level = "info"
	LevelWarn Level = "warn"
)

func LevelOf(r payload.ConnectionReport) Level {
	if r.Phase == payload.PhasePartial || !r.OK {
		return LevelWarn
	}
	return LevelInfo
}

// ---------------------------------------------------------------------------
// Helpers shared by the readers
// ---------------------------------------------------------------------------

// Code renders an HTTP status as a report's `code`. It is a string in the payload because a code is
// sometimes a status and sometimes a syscall name, and one field with two spellings is easier to
// read than two fields one of which is always absent.
func Code(status int) string {
	if status == 0 {
		return ""
	}
	return strconv.Itoa(status)
}

// Plural is the wording helper every `read` sentence uses (*86 containers*, *1 container*). It
// lives here because the `read` strings are what §15 shows a reader, and building them the same way
// everywhere is what keeps the Diagnostics view readable.
func Plural(n int, one, many string) string {
	if n == 1 {
		return strconv.Itoa(n) + " " + one
	}
	return strconv.Itoa(n) + " " + many
}
