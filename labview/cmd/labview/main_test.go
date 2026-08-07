package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/payload"
)

// What this suite is for. The pipeline, the surface and the gate are asserted in their own packages as
// pure functions; what is left here is the part that only this package has — the dispatch, the exit
// codes, and the two subcommands whose contract is their *output stream* (§2.5: the payload on stdout,
// every diagnostic on stderr). Those are not properties of any `internal/` package, so nothing else can
// assert them.
//
// `serve` is deliberately not exercised here: it binds a socket and blocks on a signal, and §18 already
// requires the whole surface be constructible without a listener — which is what internal/httpapi's
// suite does. What is asserted here is that dispatch reaches it, not what it then does.

// §2.5: **stdout stays parseable.** Every diagnostic goes to stderr, which is the whole reason the
// one-shot mode is usable in a pipe — a single log line on stdout makes the document unparseable.
func TestScanWritesThePayloadToStdoutAndEverythingElseToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer

	t.Setenv("LABVIEW_APPS_ROOT", "../../fixtures/apps")
	t.Setenv("LABVIEW_DOCKER_ENABLED", "false")
	t.Setenv("LABVIEW_TRAEFIK_ENABLED", "false")
	t.Setenv("LABVIEW_AUTHENTIK_ENABLED", "false")

	if code := scan(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("scan exited %d; stderr: %s", code, stderr.String())
	}

	var out payload.Overview
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout.String())
	}
	if out.Stats.Stacks == 0 {
		t.Fatalf("the payload reports no stacks, so the fixture root was not read: %s", stdout.String())
	}
	if out.Meta.Build.Source == "" {
		t.Fatalf("the build stamp has no source, and §16 requires one: %+v", out.Meta.Build)
	}

	// The connection block is a diagnostic, so it belongs on the other stream.
	if strings.Contains(stderr.String(), "docker") == false {
		t.Fatalf("stderr carries no connection block: %s", stderr.String())
	}
}

// §16: **no required list is ever null.** Asserted on the bytes the subcommand actually wrote, because
// the pipeline's own test asserts it on a value — and the thing an operator pipes into `jq` is the bytes.
func TestTheScannedPayloadCarriesNoNullList(t *testing.T) {
	var stdout, stderr bytes.Buffer

	t.Setenv("LABVIEW_APPS_ROOT", "../../fixtures/apps")
	t.Setenv("LABVIEW_DOCKER_ENABLED", "false")
	t.Setenv("LABVIEW_TRAEFIK_ENABLED", "false")
	t.Setenv("LABVIEW_AUTHENTIK_ENABLED", "false")

	if code := scan([]string{"-compact"}, &stdout, &stderr); code != 0 {
		t.Fatalf("scan exited %d; stderr: %s", code, stderr.String())
	}
	if got := stdout.String(); strings.Contains(got, ":null") {
		t.Fatalf("the payload carries a null: %s", firstNull(got))
	}
	// -compact is one line, which is what makes it pipeable.
	if lines := strings.Count(strings.TrimSpace(stdout.String()), "\n"); lines != 0 {
		t.Fatalf("-compact wrote %d newlines, so it is not one line", lines+1)
	}
}

func firstNull(s string) string {
	i := strings.Index(s, ":null")
	from := i - 60
	if from < 0 {
		from = 0
	}
	return s[from : i+5]
}

// §13.7's tri-state, at the command line. The default is *use the configuration*, which is not the same
// as `false` — a bool flag has no way to express it, which is why the flag is a string.
func TestTheProbeFlagIsATriStateAndNotABool(t *testing.T) {
	for _, tc := range []struct {
		given string
		want  *bool
		bad   bool
	}{
		{given: "", want: nil},
		{given: "true", want: payload.Ptr(true)},
		{given: "false", want: payload.Ptr(false)},
		{given: "on", want: payload.Ptr(true)},
		{given: "off", want: payload.Ptr(false)},
		{given: "maybe", bad: true},
	} {
		got, err := probeOverride(tc.given)
		switch {
		case tc.bad:
			if err == nil {
				t.Fatalf("-probe=%q was accepted", tc.given)
			}
			continue
		case err != nil:
			t.Fatalf("-probe=%q: %v", tc.given, err)
		case (got == nil) != (tc.want == nil):
			t.Fatalf("-probe=%q produced %v, want %v", tc.given, got, tc.want)
		case got != nil && *got != *tc.want:
			t.Fatalf("-probe=%q produced %v, want %v", tc.given, *got, *tc.want)
		}
	}
}

// §2.5 and §19: the minted line is `user:hash` at cost 12, and it verifies against the same
// implementation that reads the file — which is the reason this subcommand is in this binary at all.
func TestHashpwMintsALineThePasswdReaderAccepts(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := hashpw([]string{"ada"}, &stdout, &stderr, strings.NewReader("a good password\n")); code != 0 {
		t.Fatalf("hashpw exited %d: %s", code, stderr.String())
	}

	line := strings.TrimSpace(stdout.String())
	user, hash, ok := strings.Cut(line, ":")
	if !ok || user != "ada" {
		t.Fatalf("the minted line is %q, want `ada:<hash>`", line)
	}
	if !strings.HasPrefix(hash, "$2a$12$") {
		t.Fatalf("the hash is %q, want a cost-12 bcrypt hash", hash)
	}

	// Round-tripped through the file reader, so the format is not merely plausible.
	file := access.ParsePasswd([]byte(line + "\n"))
	if len(file.Entries) != 1 {
		t.Fatalf("the passwd reader took %d entries from the minted line: %+v", len(file.Entries), file)
	}
	if !access.Verify(file.Entries, "ada", "a good password") {
		t.Fatalf("the minted hash does not verify against the password it was minted from")
	}
	if access.Verify(file.Entries, "ada", "a good password ") {
		t.Fatalf("a different password verified, so the trailing newline was not the only thing stripped")
	}
}

// One trailing newline is stripped and nothing else is: `printf 'pw'` and `echo pw` must hash the same,
// while a password that legitimately ends in a space must survive.
func TestOnlyTheTrailingNewlineIsStrippedFromAPassword(t *testing.T) {
	for _, tc := range []struct{ given, want string }{
		{"pw", "pw"},
		{"pw\n", "pw"},
		{"pw\r\n", "pw"},
		{" pw ", " pw "},
		{" pw \n", " pw "},
		{"two\nlines", "two\nlines"},
	} {
		got, err := readPassword(strings.NewReader(tc.given))
		if err != nil {
			t.Fatalf("readPassword(%q): %v", tc.given, err)
		}
		if got != tc.want {
			t.Fatalf("readPassword(%q) is %q, want %q", tc.given, got, tc.want)
		}
	}
}

// §19's 1024-character cap, refused rather than hashed. The cap is about the work of hashing a
// megabyte — bcrypt truncates at 72 bytes regardless — so a pipe that delivers more is an error and
// not a password.
func TestAPasswordOverTheCapIsRefusedRatherThanHashed(t *testing.T) {
	var stdout, stderr bytes.Buffer

	long := strings.Repeat("x", access.MaxPasswordChars+1)
	if code := hashpw([]string{"ada"}, &stdout, &stderr, strings.NewReader(long)); code == 0 {
		t.Fatalf("a %d-character password was accepted: %s", len(long), stdout.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("a refused password still wrote a line: %s", stdout.String())
	}
}

// An empty password would hash and verify, producing a working account whose credential is the empty
// string. Refused, and refused before the hash rather than after.
func TestAnEmptyPasswordIsRefused(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := hashpw([]string{"ada"}, &stdout, &stderr, strings.NewReader("\n")); code == 0 {
		t.Fatalf("an empty password was accepted: %s", stdout.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("an empty password still wrote a line: %s", stdout.String())
	}
}

// §16's username pattern, applied at minting time: a name outside it can never match a session claim,
// so a line minted with one would be an account that exists in the file and cannot be signed in to.
func TestHashpwRefusesAUsernameASessionCouldNeverCarry(t *testing.T) {
	for _, user := range []string{"", "bad user", "a:b", strings.Repeat("a", 65), "üser"} {
		var stdout, stderr bytes.Buffer
		if code := hashpw([]string{user}, &stdout, &stderr, strings.NewReader("pw")); code == 0 {
			t.Fatalf("the username %q was accepted: %s", user, stdout.String())
		}
	}
}

// The password is never an argument (it would be in the process table and in shell history), so a
// second positional argument is a usage error rather than a password.
func TestHashpwTakesNoPasswordArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := hashpw([]string{"ada", "s3cr3t-in-argv"}, &stdout, &stderr, strings.NewReader("pw")); code != 2 {
		t.Fatalf("a password passed as an argument exited %d, want a usage error", code)
	}
	// The refusal must not echo the argument either: a usage line quoting it back would put the
	// credential in the log of whatever ran the command, which is the place the stdin rule exists to
	// keep it out of.
	if strings.Contains(stdout.String()+stderr.String(), "s3cr3t-in-argv") {
		t.Fatalf("the password reached the output: %s%s", stdout.String(), stderr.String())
	}
}

// **No arguments means serve**, because that is what the image's `CMD` runs — a binary that printed
// usage on an empty command line would be a deployment that fails on an empty `CMD`. A leading flag
// means serve too, so `labview -x` is not read as a subcommand named `-x`.
func TestDispatchDefaultsToServe(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "serve"},
		{[]string{}, "serve"},
		{[]string{"-addr=:9000"}, "serve"},
		{[]string{"serve"}, "serve"},
		{[]string{"scan"}, "scan"},
		{[]string{"hashpw", "ada"}, "hashpw"},
		{[]string{"version"}, "version"},
	} {
		if got, _ := split(tc.args); got != tc.want {
			t.Fatalf("%v dispatched to %q, want %q", tc.args, got, tc.want)
		}
	}
}

// An unknown subcommand is a usage error on stderr, and exit 2 — distinguishable from a run that
// started and failed, which is 1.
func TestAnUnknownSubcommandIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"rescan"}, &stdout, &stderr); code != 2 {
		t.Fatalf("an unknown subcommand exited %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("a usage error wrote to stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "rescan") {
		t.Fatalf("the error does not name the subcommand: %s", stderr.String())
	}
}

// `version` is the build stamp of §3.4 rather than a constant, so this answer and the payload's
// `meta.build` cannot disagree.
func TestVersionReportsTheBuildStamp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exited %d: %s", code, stderr.String())
	}

	stamp := buildStamp()
	line := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(line, "labview "+stamp.Version) {
		t.Fatalf("version printed %q, want it to lead with the stamp's version %q", line, stamp.Version)
	}
	// The source is part of the line, because *0.1.0 from a checkout* and *0.1.0 from a release build*
	// are different answers to the question an operator is asking when they run this.
	//
	// Only when there is a source to name, though. §3.4's rule is that an unstamped build carries no
	// source rather than the string "unknown", and versionLine implements exactly that. Asserting it
	// unconditionally made this test's result depend on whether some ancestor of the working directory
	// happens to be a git checkout — it passed from a clone and failed from an extracted tarball, which
	// is a property of the machine rather than of the code. Both branches are asserted instead.
	if stamp.Source == payload.BuildUnknown {
		if strings.Contains(line, string(payload.BuildUnknown)) {
			t.Fatalf("version printed %q, want an unstamped build to name no source at all", line)
		}
	} else if !strings.Contains(line, string(stamp.Source)) {
		t.Fatalf("version printed %q, want it to name the source %q", line, stamp.Source)
	}
	if stamp.Commit != "" && !strings.Contains(line, stamp.Commit) {
		t.Fatalf("version printed %q, want it to carry the commit %q", line, stamp.Commit)
	}
}

// §3.2: an unrecognised `LABVIEW_LOG_LEVEL` takes `info` and says so, rather than refusing to start.
// The level is how an operator asks to be told things, and refusing to start over its spelling would
// be refusing to start over the logging configuration.
func TestAnUnknownLogLevelFallsBackToInfo(t *testing.T) {
	for _, tc := range []struct {
		given string
		want  Level
		ok    bool
	}{
		{"", LevelInfo, true},
		{"debug", LevelDebug, true},
		{"WARN", LevelWarn, true},
		{"warning", LevelWarn, true},
		{"error", LevelError, true},
		{"chatty", LevelInfo, false},
	} {
		got, ok := ParseLevel(tc.given)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("ParseLevel(%q) is (%v, %v), want (%v, %v)", tc.given, got, ok, tc.want, tc.ok)
		}
	}
}

// A logger below its level writes nothing at all, which is what makes the level worth having: the
// connection block of §15 is a dozen strings, and building them for a writer that drops them is work
// nobody asked for.
func TestTheLoggerFiltersBelowItsLevel(t *testing.T) {
	var out bytes.Buffer
	lg := NewLogger(&out, LevelWarn)

	lg.Infof(logScan, "this should not appear")
	lg.Debugf(logScan, "nor this")
	if out.Len() != 0 {
		t.Fatalf("a filtered level still wrote: %s", out.String())
	}
	if lg.Enabled(LevelInfo) {
		t.Fatalf("Enabled says info is on at a warn logger")
	}

	lg.Warnf(logConn, "this should appear")
	if !strings.Contains(out.String(), "[conn] this should appear") {
		t.Fatalf("the warn line is %q", out.String())
	}
}

// A line that came from another package is written verbatim. `Line` exists because §15's reports and
// §17's notes arrive as strings a package produced, and passing them through a format string would
// make a `%` in an endpoint into a verb.
func TestAComposedLineIsNotReinterpretedAsAFormat(t *testing.T) {
	var out bytes.Buffer
	lg := NewLogger(&out, LevelInfo)

	lg.Line(LevelInfo, logConn, "traefik: http://host/a%2Fb — 100%% of routers read")
	if !strings.Contains(out.String(), "http://host/a%2Fb — 100%% of routers read") {
		t.Fatalf("the line was reinterpreted: %s", out.String())
	}
}
