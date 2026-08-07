package conn

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
)

// wrapped is how these errors actually arrive: an `http.Client` returns a *url.Error around a
// *net.OpError around an *os.SyscallError around the errno. Every case below is tested through that
// wrapping rather than on the bare error, because a classifier that only works on the bare error
// works on nothing a real request produces.
func wrapped(err error) error {
	return &url.Error{
		Op:  "Get",
		URL: "http://example.invalid/api",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: err},
	}
}

func syscallErr(errno syscall.Errno) error {
	return &os.SyscallError{Syscall: "connect", Err: errno}
}

// TestFromErrorIsTheOneMappingFromATransportError is §15's first classifier over every shape a
// transport error takes. The wording of these errors is not LabView's to control, which is the whole
// reason there is one mapping: a Go release that rewords `net`'s errors has to be able to break this
// test rather than silently reclassify half the fleet.
func TestFromErrorIsTheOneMappingFromATransportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want payload.ConnectionPhase
		why  string
	}{
		{
			name: "no error at all", err: nil, want: payload.PhaseConnected,
			why: "a nil error is a completed exchange, not an unclassified one",
		},
		{
			name: "context deadline", err: wrapped(context.DeadlineExceeded),
			want: payload.PhaseTimeout,
			why:  "the per-request budget is imposed with a context, so this is the common timeout",
		},
		{
			name: "socket deadline", err: wrapped(os.ErrDeadlineExceeded),
			want: payload.PhaseTimeout,
			why:  "a read deadline reached on the socket rather than in the context",
		},
		{
			name: "unknown host", err: wrapped(&net.DNSError{Err: "no such host", Name: "authentik", IsNotFound: true}),
			want: payload.PhaseResolve,
			why:  "the name is the fault; nothing was dialled",
		},
		{
			name: "dns timeout", err: wrapped(&net.DNSError{Err: "i/o timeout", IsTimeout: true}),
			want: payload.PhaseTimeout,
			why:  "a resolver that did not answer is a timeout, not a resolve failure",
		},
		{
			name: "connection refused", err: wrapped(syscallErr(syscall.ECONNREFUSED)),
			want: payload.PhaseConnect,
			why:  "something is there to refuse; the port is the fault",
		},
		{
			name: "no route to host", err: wrapped(syscallErr(syscall.EHOSTUNREACH)),
			want: payload.PhaseConnect,
		},
		{
			name: "network unreachable", err: wrapped(syscallErr(syscall.ENETUNREACH)),
			want: payload.PhaseConnect,
		},
		{
			name: "socket path absent", err: &fs.PathError{Op: "stat", Path: "/var/run/docker.sock", Err: syscall.ENOENT},
			want: payload.PhaseNotFound,
			why:  "there is nothing to refuse the connection, so this is not `connect`",
		},
		{
			name: "socket not readable", err: &fs.PathError{Op: "open", Path: "/var/run/docker.sock", Err: syscall.EACCES},
			want: payload.PhaseAuthorize,
			why:  "the fix is a group membership, not a listener (§10)",
		},
		{
			name: "certificate will not verify", err: wrapped(x509.UnknownAuthorityError{}),
			want: payload.PhaseTLS,
		},
		{
			name: "handshake failure by text", err: wrapped(errors.New("remote error: tls: handshake failure")),
			want: payload.PhaseTLS,
			why:  "crypto/tls exports no type for this, so the message is all there is",
		},
		{
			name: "hostname mismatch by text",
			err:  wrapped(errors.New(`x509: certificate is valid for traefik, not authentik`)),
			want: payload.PhaseTLS,
		},
		{
			name: "unclassified dial", err: wrapped(errors.New("something nobody has seen")),
			want: payload.PhaseConnect,
			why:  "an unrecognised dial error is a connect failure rather than an invented phase",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromError(tc.err, 10*time.Millisecond, time.Second); got != tc.want {
				t.Errorf("phase = %q, want %q — %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestATeardownIsATimeoutOnlyWhenTheClockSaysSo is the rule §4.6 states as *established by the
// clock*. Many servers implement a timeout by tearing the socket down rather than by answering, so
// the same reset means two different things depending on when it arrived — and the message is
// identical in both cases. Deriving `timeout` from the message would therefore be a coin flip.
func TestATeardownIsATimeoutOnlyWhenTheClockSaysSo(t *testing.T) {
	for _, err := range []error{
		wrapped(syscallErr(syscall.ECONNRESET)),
		wrapped(io.ErrUnexpectedEOF),
		wrapped(errors.New("connection reset by peer")),
		wrapped(errors.New("http: server closed idle connection")),
		&url.Error{Op: "Get", URL: "http://x/", Err: io.EOF},
	} {
		budget := 2 * time.Second
		if got := FromError(err, budget, budget); got != payload.PhaseTimeout {
			t.Errorf("%v at the budget: phase = %q, want %q", err, got, payload.PhaseTimeout)
		}
		if got := FromError(err, 200*time.Millisecond, budget); got != payload.PhaseConnect {
			t.Errorf("%v well inside the budget: phase = %q, want %q", err, got, payload.PhaseConnect)
		}
	}

	// With no budget to compare against, a teardown is never a timeout: there is no clock, so there
	// is nothing to establish it with. This is the shape ReadJSON classifies under.
	if got := FromError(wrapped(io.ErrUnexpectedEOF), 0, 0); got != payload.PhaseConnect {
		t.Errorf("no budget: phase = %q, want %q", got, payload.PhaseConnect)
	}
}

// TestResolveIsAskedBeforeConnect is an ordering test rather than a mapping one. A DNS failure
// arrives wrapped in a *net.OpError whose Op is "dial", so asking "was this a dial error?" first
// would classify every unknown hostname as `connect` and send an operator to check a firewall for a
// typo in a name.
func TestResolveIsAskedBeforeConnect(t *testing.T) {
	err := wrapped(&net.DNSError{Err: "no such host", Name: "authentik.invalid", IsNotFound: true})

	// The premise: this really is an OpError, so the two rules really do both apply.
	var operr *net.OpError
	if !errors.As(err, &operr) {
		t.Fatal("the test's premise is wrong: a DNS failure no longer arrives inside a *net.OpError")
	}
	if got := FromError(err, 0, time.Second); got != payload.PhaseResolve {
		t.Errorf("phase = %q, want %q — the DNS test must be asked before the dial test", got, payload.PhaseResolve)
	}
}

// TestFromStatusKeepsAuthenticateAndAuthorizeApart is §4.6's insistence that the two never collapse.
// A token that was refused and a token that lacks a permission need different fixes: one is
// reissued, the other has its scope widened. "Auth failed" would send an operator to do the first
// when the second was needed.
func TestFromStatusKeepsAuthenticateAndAuthorizeApart(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   payload.ConnectionPhase
	}{
		{200, payload.PhaseConnected},
		{204, payload.PhaseConnected},
		{299, payload.PhaseConnected},
		{301, payload.PhaseStatus},
		{400, payload.PhaseStatus},
		{401, payload.PhaseAuthenticate},
		{403, payload.PhaseAuthorize},
		{404, payload.PhasePath},
		{405, payload.PhasePath},
		{407, payload.PhaseAuthenticate},
		{429, payload.PhaseStatus},
		{500, payload.PhaseStatus},
		{502, payload.PhaseStatus},
		{503, payload.PhaseStatus},
	} {
		if got := FromStatus(tc.status); got != tc.want {
			t.Errorf("status %d = %q, want %q", tc.status, got, tc.want)
		}
	}

	// And the property behind the table: no status maps 401 and 403 to one phase, at any status.
	if FromStatus(401) == FromStatus(403) {
		t.Error("401 and 403 produce one phase; a wrong credential and an unpermitted one are different fixes")
	}
	// A redirect is `status` and never `connected`: LabView's own reads never follow one, so a 302
	// on an API means the API was not read (§15).
	for _, status := range []int{301, 302, 303, 307, 308} {
		if OK(FromStatus(status)) {
			t.Errorf("status %d reads as ok; a redirect is not a read", status)
		}
	}
}

// TestReadJSONReturnsThePhaseBesideTheError is the third classifier and the reason it exists: the
// phase and the code come back **beside** the error, so no caller has to look at the message to
// decide what happened.
func TestReadJSONReturnsThePhaseBesideTheError(t *testing.T) {
	type doc struct {
		Version string `json:"version"`
	}

	for _, tc := range []struct {
		name  string
		body  string
		phase payload.ConnectionPhase
		code  string
		fails bool
		why   string
	}{
		{
			name: "an object", body: `{"version":"2024.2.1"}`,
			phase: payload.PhaseConnected,
		},
		{
			name: "whitespace around it", body: "\n  {\"version\":\"x\"}\n",
			phase: payload.PhaseConnected,
		},
		{
			name: "a login page", body: "<!DOCTYPE html>\n<html><body>Sign in</body></html>",
			phase: payload.PhaseProtocol, code: "html", fails: true,
			why: "a proxy answering 200 with its own page is the API not being reached",
		},
		{
			name: "an html page with no doctype", body: "<html><head></head></html>",
			phase: payload.PhaseProtocol, code: "html", fails: true,
		},
		{
			name: "some other markup", body: `<?xml version="1.0"?><error/>`,
			phase: payload.PhaseProtocol, code: "xml-or-html", fails: true,
		},
		{
			name: "prose", body: "Internal Server Error",
			phase: payload.PhaseProtocol, code: "not-json", fails: true,
		},
		{
			name: "nothing at all", body: "",
			phase: payload.PhaseProtocol, code: "empty", fails: true,
			why: "an empty body is `protocol` and not `connected`: there was nothing to read",
		},
		{
			name: "only whitespace", body: "   \n\t",
			phase: payload.PhaseProtocol, code: "empty", fails: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var into doc
			phase, code, err := ReadJSON(strings.NewReader(tc.body), &into)

			if phase != tc.phase {
				t.Errorf("phase = %q, want %q — %s", phase, tc.phase, tc.why)
			}
			if code != tc.code {
				t.Errorf("code = %q, want %q", code, tc.code)
			}
			if tc.fails != (err != nil) {
				t.Errorf("err = %v, want failure = %v", err, tc.fails)
			}
		})
	}
}

// TestReadJSONNeverPutsTheBodyInTheCode is I6 at the one place a response body is turned into
// something a reader sees. The `protocol` code says what shape answered and never what it
// contained: a login page's HTML is exactly the kind of body that carries a session cookie name, a
// CSRF token or an internal hostname.
func TestReadJSONNeverPutsTheBodyInTheCode(t *testing.T) {
	secret := "csrftoken=Nz9Kq3vExample"
	body := "<!DOCTYPE html><html><body><input name=\"" + secret + "\"></body></html>"

	var into map[string]any
	_, code, _ := ReadJSON(strings.NewReader(body), &into)

	if code != "html" {
		t.Errorf("code = %q, want the shape and nothing else", code)
	}
	if strings.Contains(code, "csrftoken") || strings.Contains(code, secret) {
		t.Errorf("code = %q, which carries the body it read", code)
	}
}

// TestExcerptIsOneQuotedLineWhateverArrived is the other half of the rule above. The code stays a
// shape; the *detail* is allowed to say what the shape contained, because `not-json` on its own
// leaves an operator with nowhere to go. What makes that defensible is that the rendering cannot
// hurt the log it lands in, whatever the far end sent — so each case here is a way a body could
// otherwise have broken §15's one-line-per-report format or the terminal reading it.
func TestExcerptIsOneQuotedLineWhateverArrived(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{{
		// §15's format is one line per report plus one indented line per candidate. A body carrying
		// newlines would forge those lines, so runs of whitespace collapse to one space.
		name: "a multi-line body becomes one line",
		body: "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\n  API\tforbidden\n",
		want: `"HTTP/1.1 403 Forbidden Server: nginx API forbidden"`,
	}, {
		// Quoting is what keeps an escape sequence from reaching the terminal *as* an escape
		// sequence: it survives into the line as the four printable characters that describe it,
		// where a reader can see what was sent, rather than clearing their screen.
		name: "control characters are escaped and not acted on",
		body: "\x1b[2J\x07oops",
		want: `"\x1b[2J\aoops"`,
	}, {
		name: "an empty body has nothing to say",
		body: "",
		want: "",
	}, {
		name: "a body of nothing but whitespace has nothing to say either",
		body: " \r\n\t ",
		want: "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Excerpt([]byte(tc.body)); got != tc.want {
				t.Errorf("Excerpt(%q) = %s, want %s", tc.body, got, tc.want)
			}
		})
	}
}

// TestExcerptRedactsACredentialItWasHanded is I6 reaching the one field that now carries somebody
// else's output. A body is not ours and may hold a connection string — a proxy echoing its upstream,
// an ORM printing the DSN it failed on — and the rule that covers an environment value covers this.
func TestExcerptRedactsACredentialItWasHanded(t *testing.T) {
	got := Excerpt([]byte(`{"error":"dial postgres://labview:hunter2@db.internal:5432/lab failed"}`))

	if strings.Contains(got, "hunter2") {
		t.Errorf("Excerpt = %s, which carries the password the body handed it", got)
	}
	if !strings.Contains(got, secrets.Mask) {
		t.Errorf("Excerpt = %s, want the password replaced by %q rather than dropped: an operator "+
			"needs to see that one was there", got, secrets.Mask)
	}
	// Redaction is not censorship of the finding. Everything that says *which* program answered has
	// to survive it, or the excerpt stops earning its place in the detail.
	for _, keep := range []string{"postgres://", "labview", "db.internal:5432"} {
		if !strings.Contains(got, keep) {
			t.Errorf("Excerpt = %s, want it to keep %q", got, keep)
		}
	}
}

// TestExcerptIsBoundedAndSaysWhereItStopped is I8's containment applied to a diagnostic: a detail
// long enough to hold a whole page is one nobody finishes reading, and a 64 KiB body pasted into a
// log is worse than no excerpt at all.
func TestExcerptIsBoundedAndSaysWhereItStopped(t *testing.T) {
	// The second body is the one that catches a cut made before quoting rather than after: escaped,
	// every byte of it renders as four, so a cap spent on the body instead of on the rendering
	// produces a line four times the length promised.
	for _, body := range []string{strings.Repeat("a", 4<<10), strings.Repeat("\x01", 4<<10)} {
		got := Excerpt([]byte(body))

		// The ellipsis is this function's own character and sits outside the cap; everything else,
		// quotes included, is spent from it.
		if len(got) > ExcerptCap+len("…") {
			t.Errorf("Excerpt of %d bytes of %q rendered to %d bytes, want no more than ExcerptCap "+
				"(%d) and the ellipsis", len(body), body[:1], len(got), ExcerptCap)
		}
		if !strings.HasSuffix(got, `"…`) {
			t.Errorf("Excerpt = %s, want the cut stated with an ellipsis outside the quotes: it is "+
				"this program's word for *there was more*, not a character the far end sent", got)
		}
	}
}

// TestExcerptNeverSplitsARune keeps a replacement character out of a diagnostic. One appearing in a
// detail invites the reader to wonder whether the far end sent it, which is an hour spent on this
// program instead of on their fleet.
func TestExcerptNeverSplitsARune(t *testing.T) {
	// Three bytes each, so the cap lands mid-rune however it divides.
	body := strings.Repeat("字", ExcerptCap)

	got := Excerpt([]byte(body))

	if strings.ContainsRune(got, utf8.RuneError) {
		t.Errorf("Excerpt = %s, which was cut through the middle of a rune", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("Excerpt = %q, which is not valid UTF-8", got)
	}
}

// TestExcerptDescribesBytesThatAreNotText is the case where showing the body helps nobody. A gzip
// stream, a TLS record or a binary protocol answering on the Engine's path is itself the finding —
// pasting it corrupts the line the operator was reading and tells them nothing.
func TestExcerptDescribesBytesThatAreNotText(t *testing.T) {
	// A TLS server hello: the far end is speaking HTTPS on a plaintext port, which is a real and
	// common misconfiguration and one an operator can act on the moment it is named.
	got := Excerpt([]byte{0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0xff})

	if !strings.Contains(got, "not text") {
		t.Errorf("Excerpt = %q, want the bytes described rather than shown", got)
	}
	if !strings.Contains(got, "10") {
		t.Errorf("Excerpt = %q, want the length said: it is the only thing left to report", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("Excerpt = %q, which put the bytes in the log after all", got)
	}
}

// failingReader stops mid-body, which is what a connection dropped during a read looks like.
type failingReader struct{ after int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.after <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, strings.Repeat("{", r.after))
	r.after = 0
	return n, nil
}

// TestReadJSONClassifiesATruncatedRead is the read that stopped rather than the body that was wrong.
// It is `connect` and not `protocol`: what arrived was not a different protocol, it was half an
// answer.
func TestReadJSONClassifiesATruncatedRead(t *testing.T) {
	var into map[string]any
	phase, code, err := ReadJSON(&failingReader{after: 4}, &into)

	if phase != payload.PhaseConnect {
		t.Errorf("phase = %q, want %q", phase, payload.PhaseConnect)
	}
	if code != "" {
		t.Errorf("code = %q, want none: a truncated read has no code to report", code)
	}
	if err == nil {
		t.Error("a truncated read returned no error")
	}
}

// TestOKIsConnectedAndPartialOnly is §15's definition of a target having worked. `partial` counting
// as working is the whole of I4 in one boolean: a read that got most of the way is reported as a
// read, with a banner saying what is missing, rather than as a failure that hides what was obtained.
func TestOKIsConnectedAndPartialOnly(t *testing.T) {
	for _, phase := range payload.ConnectionPhases {
		want := phase == payload.PhaseConnected || phase == payload.PhasePartial
		if got := OK(phase); got != want {
			t.Errorf("OK(%q) = %v, want %v", phase, got, want)
		}
	}
}

// TestEveryPhaseHasWording is the exhaustiveness §4.6's closed set buys. A phase with no wording
// would reach the Diagnostics view as a bare member name, which is the one place a reader has
// nothing else to go on.
func TestEveryPhaseHasWording(t *testing.T) {
	seen := map[string]payload.ConnectionPhase{}
	for _, phase := range payload.ConnectionPhases {
		got := Prose(phase)
		if got == "" {
			t.Errorf("%q has no wording", phase)
			continue
		}
		if strings.Contains(got, "has no wording") {
			t.Errorf("%q fell through to the default branch", phase)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("%q and %q share the wording %q; two phases a reader cannot tell apart",
				phase, other, got)
		}
		seen[got] = phase
	}
}

// TestEveryFailingPairHasAnAction is §15's promise that a failure says what to do. It is swept over
// the whole product of targets and phases rather than over the examples, because the pair an
// operator actually hits is the one nobody wrote an example for.
func TestEveryFailingPairHasAnAction(t *testing.T) {
	for _, target := range Targets {
		for _, phase := range payload.ConnectionPhases {
			hint := Hint(target, phase)
			switch {
			case phase == payload.PhaseConnected:
				if hint != "" {
					t.Errorf("%s/%s: hint = %q, want none — there is nothing to do", target, phase, hint)
				}
			case hint == "":
				t.Errorf("%s/%s: no action to take", target, phase)
			}
		}
	}
}

// TestTheActionDependsOnTheTarget is why Hint takes a target at all. `credential` on Authentik means
// an API token; on Traefik it means a username and password that is explicitly *not* that token.
// One per-phase hint would tell an operator to set the wrong variable — and §12 says operators do
// try the Authentik token here.
func TestTheActionDependsOnTheTarget(t *testing.T) {
	authentik := Hint(TargetAuthentik, payload.PhaseCredential)
	traefik := Hint(TargetTraefik, payload.PhaseCredential)

	if authentik == traefik {
		t.Fatalf("both targets give the same action for `credential`: %q", authentik)
	}
	if !strings.Contains(authentik, "LABVIEW_AUTHENTIK_TOKEN") {
		t.Errorf("authentik/credential = %q, want it to name the token variable", authentik)
	}
	for _, want := range []string{"LABVIEW_TRAEFIK_USERNAME", "LABVIEW_TRAEFIK_PASSWORD"} {
		if !strings.Contains(traefik, want) {
			t.Errorf("traefik/credential = %q, want it to name %s", traefik, want)
		}
	}
	// And it says which credential is *not* the one, because that is the mistake being corrected.
	if !strings.Contains(traefik, "Authentik API token is not a credential here") {
		t.Errorf("traefik/credential = %q, want it to rule out the Authentik token", traefik)
	}

	// The same shape for `authorize`: on Docker it is the endpoint's own permission, on Authentik a
	// token's scope. Nothing about them is interchangeable.
	//
	// Docker's names both of its arrangements, because the hint cannot branch on the endpoint and the
	// two have nothing in common: a `403` over TCP is a socket proxy refusing a path it was never
	// given, where there is no uid and no socket to chmod, and a `403` on a unix socket is a group
	// membership. A hint naming only one of them is wrong half the time it is read.
	docker := Hint(TargetDocker, payload.PhaseAuthorize)
	for _, want := range []string{"docker group", "CONTAINERS=1"} {
		if !strings.Contains(docker, want) {
			t.Errorf("docker/authorize = %q, want it to name %q", docker, want)
		}
	}
	if docker == Hint(TargetAuthentik, payload.PhaseAuthorize) {
		t.Error("docker and authentik give the same action for `authorize`")
	}
}

// TestDisabledSaysHowToEnableIt is the one hint that is not a diagnosis. `disabled` is a choice
// rather than a fault, and the only useful thing to say about a choice is how to make the other one.
func TestDisabledSaysHowToEnableIt(t *testing.T) {
	for _, target := range Targets {
		hint := Hint(target, payload.PhaseDisabled)
		if !strings.Contains(hint, "LABVIEW_") || !strings.Contains(hint, "=true") {
			t.Errorf("%s/disabled = %q, want it to name the variable that switches it on", target, hint)
		}
	}
	// The probe's is the one that can also be switched on for a single scan from the UI (§13.7), so
	// its hint says so rather than only naming a variable that needs a restart.
	if got := Hint(TargetProbe, payload.PhaseDisabled); !strings.Contains(got, "Rescan") {
		t.Errorf("probe/disabled = %q, want it to mention the box beside Rescan", got)
	}
}

// TestTheOIDCFailureSaysNobodyCanSignIn is §19's consequence stated where an operator will read it.
// The issuer goes through this same chokepoint as every other target, and a `connect` on it is not
// one degraded panel — it is the whole application being unreachable to its users.
func TestTheOIDCFailureSaysNobodyCanSignIn(t *testing.T) {
	for _, phase := range []payload.ConnectionPhase{
		payload.PhaseResolve, payload.PhaseConnect, payload.PhaseTimeout,
	} {
		if got := Hint(TargetOIDC, phase); !strings.Contains(got, "nobody can sign in") {
			t.Errorf("oidc/%s = %q, want it to say what the failure costs", phase, got)
		}
	}
	// And the certificate case says the verification will not be skipped, because that is the next
	// thing an operator will ask for (§21).
	if got := Hint(TargetOIDC, payload.PhaseTLS); !strings.Contains(got, "will not skip verification") {
		t.Errorf("oidc/tls = %q, want it to rule out disabling verification", got)
	}
}

// TestReportFillsInWhatNobodySetsByHand is why Report exists rather than a struct literal at each
// reader: `ok` and `hint` are derived, and a reader that set them itself could disagree with the
// next one about what `partial` means.
func TestReportFillsInWhatNobodySetsByHand(t *testing.T) {
	r := Report(TargetDocker, payload.PhasePartial, "unix:///var/run/docker.sock",
		payload.SourceDefault, "3 of 86 inspects were refused")

	if r.Target != "docker" {
		t.Errorf("target = %q", r.Target)
	}
	if !r.OK {
		t.Error("a partial read reported ok=false, which hides what was read")
	}
	if r.Hint == "" {
		t.Error("a partial read carries no action")
	}
	if r.Attempts == nil {
		t.Error("attempts is nil, so the payload would carry `null` where §16 requires a list")
	}
	// A working target has nothing to do about it, so the hint is empty rather than reassuring.
	if got := Report(TargetDocker, payload.PhaseConnected, "unix:///x", payload.SourceConfig, "86 containers"); got.Hint != "" {
		t.Errorf("a connected target carries the hint %q", got.Hint)
	}
}

// TestFormatIsOneLinePlusOnePerCandidate is §15's shape. The indented lines are what makes a
// discovery failure answerable: *nothing was found* is unactionable, and *these four addresses were
// tried and each of them said this* is the diagnosis.
func TestFormatIsOneLinePlusOnePerCandidate(t *testing.T) {
	r := Report(TargetTraefik, payload.PhaseNotFound, "", "", "no candidate answered")
	r.Attempts = []payload.ConnectionAttempt{
		{Endpoint: "http://traefik:8080", Why: "container name", Phase: payload.PhaseConnect, Detail: "connection refused"},
		{Endpoint: "http://192.0.2.10:8080", Why: "published port", Phase: payload.PhaseTimeout, Detail: "no answer in 3000ms"},
	}

	lines := Format(r)
	if len(lines) != 3 {
		t.Fatalf("Format produced %d lines, want 1 + 2 candidates:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if strings.HasPrefix(lines[0], " ") {
		t.Errorf("the report's own line is indented: %q", lines[0])
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("candidate line is not indented: %q", line)
		}
	}
	// Each candidate says its address, its phase and what made it a candidate — a reader cannot act
	// on an address without knowing why the scan thought it was one.
	for _, want := range []string{"http://traefik:8080", "connect", "container name", "connection refused"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("candidate line = %q, want it to say %q", lines[1], want)
		}
	}
	if !strings.Contains(lines[0], "traefik: not-found") {
		t.Errorf("head = %q, want the target and phase first", lines[0])
	}
	if !strings.Contains(lines[0], Hint(TargetTraefik, payload.PhaseNotFound)) {
		t.Errorf("head = %q, want the action on the failing line", lines[0])
	}
}

// TestFormatPrefersWhatWasReadOverTheDetail is the partial case as a reader sees it: the useful
// sentence is *86 containers, 3 refused*, not the internal detail behind it. A working line carries
// no action, so nothing is appended to it.
func TestFormatPrefersWhatWasReadOverTheDetail(t *testing.T) {
	r := Report(TargetDocker, payload.PhaseConnected, "unix:///var/run/docker.sock", payload.SourceDefault, "")
	r.Read = Plural(86, "container", "containers")

	line := Format(r)[0]
	if !strings.Contains(line, "86 containers") {
		t.Errorf("line = %q, want what was read", line)
	}
	if strings.Contains(line, Hint(TargetDocker, payload.PhaseTimeout)) {
		t.Errorf("line = %q, want no action on a working target", line)
	}
	if !strings.Contains(line, "(default)") {
		t.Errorf("line = %q, want the endpoint's source — a built-in path is not an operator's choice", line)
	}
}

// TestSameIgnoresWhatWasRead is §15's comparison and the reason the change feed is readable. A
// container count that ticks from 86 to 87 is not a change in the connection, and re-announcing a
// working target every rescan is how a feed becomes something nobody looks at.
func TestSameIgnoresWhatWasRead(t *testing.T) {
	base := Report(TargetDocker, payload.PhaseConnected, "unix:///var/run/docker.sock", payload.SourceDefault, "")
	base.Read = "86 containers"

	quieter := base
	quieter.Read = "87 containers"
	quieter.Detail = "one more than last time"
	quieter.Code = "200"
	if !Same(base, quieter) {
		t.Error("a changed read counted as a changed connection")
	}

	for _, tc := range []struct {
		name  string
		mutew func(*payload.ConnectionReport)
	}{
		{"target", func(r *payload.ConnectionReport) { r.Target = "traefik" }},
		{"ok", func(r *payload.ConnectionReport) { r.OK = false }},
		{"phase", func(r *payload.ConnectionReport) { r.Phase = payload.PhasePartial }},
		{"endpoint", func(r *payload.ConnectionReport) { r.Endpoint = "tcp://192.0.2.10:2375" }},
	} {
		other := base
		tc.mutew(&other)
		if Same(base, other) {
			t.Errorf("a changed %s counted as the same connection", tc.name)
		}
	}
}

// TestBannerIsForFaultsAndNotForChoices is §15's banner rule. `disabled` and `not-configured` are
// decisions an operator already made, and a banner about a decision teaches a reader to dismiss
// banners — which is what makes the next real one invisible.
func TestBannerIsForFaultsAndNotForChoices(t *testing.T) {
	for _, phase := range payload.ConnectionPhases {
		want := phase != payload.PhaseConnected && !phase.BeforeTheNetwork()
		got := Banner(Report(TargetAuthentik, phase, "http://authentik:9000", payload.SourceConfig, ""))
		if got != want {
			t.Errorf("Banner(%q) = %v, want %v", phase, got, want)
		}
	}

	// Said as the rule rather than as the sweep, because these three are the whole point of it: a
	// partial read banners even though it is ok, and the two pre-network phases do not even though
	// they are not.
	if !Banner(Report(TargetDocker, payload.PhasePartial, "unix:///x", payload.SourceDefault, "")) {
		t.Error("a partial read raises no banner, so a reader is not told what is missing")
	}
	for _, phase := range []payload.ConnectionPhase{payload.PhaseDisabled, payload.PhaseNotConfigured} {
		if Banner(Report(TargetDocker, phase, "", "", "")) {
			t.Errorf("%q raises a banner; it is a choice, not a fault", phase)
		}
	}
}

// TestLevelIsWarnForAnythingNotWorking is §15's logging rule. `partial` warns despite being ok,
// because the whole reason it is a separate phase is that something is missing from the payload.
func TestLevelIsWarnForAnythingNotWorking(t *testing.T) {
	for _, phase := range payload.ConnectionPhases {
		want := LevelWarn
		if phase == payload.PhaseConnected {
			want = LevelInfo
		}
		if got := LevelOf(Report(TargetProbe, phase, "", "", "")); got != want {
			t.Errorf("LevelOf(%q) = %q, want %q", phase, got, want)
		}
	}
	// Including the one that is ok: partial is a warning about a payload with a hole in it.
	partial := Report(TargetProbe, payload.PhasePartial, "", "", "")
	if !partial.OK || LevelOf(partial) != LevelWarn {
		t.Errorf("partial: ok = %v, level = %q; want ok with a warning", partial.OK, LevelOf(partial))
	}
}

// TestPluralAndCode are the two wording helpers, tested because every `read` sentence in the
// Diagnostics view is built from them and *1 containers* is the kind of thing a reader notices
// instead of the number.
func TestPluralAndCode(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{{0, "0 containers"}, {1, "1 container"}, {2, "2 containers"}, {86, "86 containers"}} {
		if got := Plural(tc.n, "container", "containers"); got != tc.want {
			t.Errorf("Plural(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
	if got := Code(0); got != "" {
		t.Errorf("Code(0) = %q, want none: a request that never got a status has no code", got)
	}
	if got := Code(403); got != "403" {
		t.Errorf("Code(403) = %q", got)
	}
}

// TestTargetsAreLabelledForAReader keeps the member names out of prose. `oidc` is the id in the
// payload; *the OIDC provider* is what a sentence says.
func TestTargetsAreLabelledForAReader(t *testing.T) {
	seen := map[string]bool{}
	for _, target := range Targets {
		label := target.Label()
		if label == "" || label == string(target) {
			t.Errorf("%q has no label of its own", target)
		}
		if seen[label] {
			t.Errorf("two targets share the label %q", label)
		}
		seen[label] = true
	}
	if len(Targets) != 5 {
		t.Errorf("Targets has %d members; §15 reports on docker, authentik, traefik, the probe and "+
			"the OIDC issuer", len(Targets))
	}
}

// TestClassificationIsTotal is the property that makes the taxonomy closed: every input produces a
// member of it, so a caller never has to handle an empty phase.
//
// The zero-valued wrappers in the list are deliberate and are not errors any transport produces:
// both *net.OpError and *fs.PathError dereference their wrapped error when formatting themselves, so
// either of them with a nil Err panics on Error(). Classifying one is degrading a request that had
// already failed; panicking on one would end the scan (I4).
func TestClassificationIsTotal(t *testing.T) {
	valid := func(p payload.ConnectionPhase) bool { return payload.ValidConnectionPhase(string(p)) }

	for _, err := range []error{
		nil, errors.New(""), errors.New("\x00"), fmt.Errorf("wrapped: %w", errors.New("x")),
		wrapped(nil), &net.OpError{}, &fs.PathError{},
	} {
		if p := FromError(err, 0, 0); !valid(p) {
			t.Errorf("FromError(%v) = %q, which is outside the closed set", err, p)
		}
	}
	for _, status := range []int{-1, 0, 1, 99, 100, 200, 399, 418, 599, 1000} {
		if p := FromStatus(status); !valid(p) {
			t.Errorf("FromStatus(%d) = %q, which is outside the closed set", status, p)
		}
	}
	var into map[string]any
	for _, body := range []string{"", "null", "[]", "{}", "\x00", "0"} {
		p, _, _ := ReadJSON(strings.NewReader(body), &into)
		if !valid(p) {
			t.Errorf("ReadJSON(%q) = %q, which is outside the closed set", body, p)
		}
	}
}
