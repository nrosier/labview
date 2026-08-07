package corpus

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
)

// §23's auth root. Three passwd files and no compose file at all, which makes this the one root that
// exercises §19 rather than the scanner: what a well-formed file yields, what a file full of mistakes
// yields, and what a file an operator has not filled in yet does to enforcement.
//
// The files are read here through `ParsePasswd` and `Resolve` rather than through a `PasswdReader`,
// because those two are the pure halves of §19 and the reader's job — the size+mtime+inode cache and
// the four distinguished unreadable cases — is asserted in the access package's own tests. What the
// corpus adds is the fixtures: real files, with real hashes, whose line numbers a warning has to point
// at correctly.

// passwdFile parses one of the root's files.
func passwdFile(t *testing.T, name string) access.PasswdFile {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root("auth"), name))
	if err != nil {
		t.Fatalf("the auth root must hold %s: %v", name, err)
	}
	return access.ParsePasswd(content)
}

// usersOf is the entry table's names, sorted. Sorted because a map has no order and the assertion is
// about which accounts exist, not about how Go happened to hash them.
func usersOf(f access.PasswdFile) []string {
	var out []string
	for u := range f.Entries {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// enabledPasswd is the configuration that turns the method on and names the file. The path is the
// fixture's name rather than an absolute one: `Resolve` never opens it, and a configuration that
// carried a host path would put one in the assertion for no reason (I2).
func enabledPasswd(name string) config.AuthConfig {
	return config.AuthConfig{Passwd: config.PasswdConfig{Enabled: true, File: name}}
}

func TestTheWellFormedFileYieldsItsThreeAccounts(t *testing.T) {
	f := passwdFile(t, "passwd.ok")

	if f.Err != nil {
		t.Fatalf("Err = %v, want nil: the file was read", f.Err)
	}
	if !f.Usable() {
		t.Fatal("Usable() = false, want true: three entries is more than none")
	}
	if got, want := usersOf(f), []string{"alice", "bob", "carol"}; !equalStrings(got, want) {
		t.Errorf("users = %v, want %v", got, want)
	}
	if len(f.Warnings) != 0 {
		t.Errorf("warnings = %v, want none: nothing in this file is skipped", f.Warnings)
	}
}

// The rule the whole format rests on: the algorithm is whatever the hash says it is. All three bcrypt
// ids exist in the wild — `htpasswd` writes one, an older tool another, a PHP-era tool the third — and
// a file LabView refuses because of the prefix is a file the operator's own tooling produced.
func TestAllThreeBcryptIdentifiersVerify(t *testing.T) {
	f := passwdFile(t, "passwd.ok")

	for _, c := range []struct{ user, password, id string }{
		{"alice", "alice-secret", "$2b$"},
		{"bob", "bob-secret", "$2a$"},
		{"carol", "carol-secret", "$2y$"},
	} {
		if !strings.HasPrefix(f.Entries[c.user], c.id) {
			t.Fatalf("%s's hash = %q, want the %s form: this fixture exists to cover that prefix",
				c.user, safePrefix(f.Entries[c.user]), c.id)
		}
		if !access.Verify(f.Entries, c.user, c.password) {
			t.Errorf("Verify(%s, %s) = false, want true", c.user, c.password)
		}
	}
}

// The two ways a sign-in fails, which have to be indistinguishable to whoever is trying: a real
// account with the wrong password, and a name that is not in the file at all. The second is verified
// against the memoised decoy of §19 rather than returning early, so both answers cost one bcrypt.
func TestAWrongPasswordAndAnUnknownNameBothFail(t *testing.T) {
	f := passwdFile(t, "passwd.ok")

	if access.Verify(f.Entries, "alice", "bob-secret") {
		t.Error("alice accepted bob's password")
	}
	if access.Verify(f.Entries, "dave", "alice-secret") {
		t.Error("dave is not in the file and was accepted")
	}
	if _, ok := f.Entries["dave"]; ok {
		t.Error("dave is in the entry table, so this test proved nothing about the decoy")
	}
}

// A usable file makes the method live, and that is the whole of what a client is told: enforced, one
// method, no notes. No usernames, no counts of them, no path (§19, I2).
func TestAUsableFileMakesPasswordSignInLive(t *testing.T) {
	p := access.Resolve(enabledPasswd("passwd.ok"), passwdFile(t, "passwd.ok"))

	if got, want := marshal(t, p.Mode), `{"enforced":true,"methods":["passwd"],"notes":null}`; got != want {
		t.Errorf("mode = %s, want %s", got, want)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings = %v, want none: nothing here needs an operator", p.Warnings)
	}
	if !p.Live(payload.MethodPasswd) {
		t.Error("Live(passwd) = false, want true")
	}
	if p.Live(payload.MethodOIDC) {
		t.Error("Live(oidc) = true, but oidc was never enabled")
	}
	if len(p.Passwd) != 3 {
		t.Errorf("the posture carries %d entries, want 3: the table used to sign in is the one that was read", len(p.Passwd))
	}
}

// §19's method names. The passwd file is never called "basic": that word belongs to the HTTP scheme
// this program deliberately does not use, and a payload that used it would tell a reader LabView sends
// credentials in a header on every request.
func TestTheMethodNamesAreTheTwoTheGuideNames(t *testing.T) {
	if got, want := string(payload.MethodPasswd), "passwd"; got != want {
		t.Errorf("MethodPasswd = %q, want %q", got, want)
	}
	if got, want := string(payload.MethodOIDC), "oidc"; got != want {
		t.Errorf("MethodOIDC = %q, want %q", got, want)
	}

	p := access.Resolve(enabledPasswd("passwd.ok"), passwdFile(t, "passwd.ok"))
	if strings.Contains(marshal(t, p.Mode), "basic") {
		t.Errorf("mode = %s, and none of it may say \"basic\"", marshal(t, p.Mode))
	}
}

// One of every mistake the parser can name, in the order the checks run, each warning pointing at the
// line an operator sees in their editor — comments and blank lines included in the count.
func TestEveryNameableMistakeIsNamedAtItsOwnLine(t *testing.T) {
	f := passwdFile(t, "passwd.messy")

	if f.Err != nil {
		t.Fatalf("Err = %v, want nil: a file full of bad lines is still a file that was read", f.Err)
	}
	want := []string{
		"passwd: line 10 skipped: no username:hash separator",
		"passwd: line 13 skipped: username is not " + access.UsernamePattern,
		"passwd: line 16 skipped: the value is not a hash",
		"passwd: line 19 skipped: the value is not a hash",
		"passwd: line 23 skipped: unsupported algorithm 5",
		"passwd: line 33 skipped: duplicate username, the first entry stands",
	}
	if !equalStrings(f.Warnings, want) {
		t.Fatalf("warnings =\n%s\nwant\n%s", strings.Join(f.Warnings, "\n"), strings.Join(want, "\n"))
	}
}

// A warning is a line an operator may paste into an issue, so none of them carries a hash, a password
// or the malformed name itself (§19). The clear-text line is the one that matters: `carol:hunter2` is
// somebody's actual password, and the warning that rejects it must not repeat it.
func TestNoWarningRepeatsWhatItRejected(t *testing.T) {
	f := passwdFile(t, "passwd.messy")

	for _, w := range f.Warnings {
		// The quoted pattern is the one place a `$` may appear: it is an anchor in the format's own
		// documentation rather than anything read out of the file, so it comes out before the check.
		body := strings.ReplaceAll(w, access.UsernamePattern, "")
		for _, forbidden := range []string{"$", "hunter2", strings.Repeat("u", 65), "sK3S6P7", "656000"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("warning %q contains %q, which is content of the line it rejected", w, forbidden)
			}
		}
	}
	if !strings.Contains(f.Warnings[1], access.UsernamePattern) {
		t.Errorf("the username warning must quote the pattern so an operator can see the rule: %q", f.Warnings[1])
	}
}

// The two entries the messy file yields, which is one more than its own comments claim. `erin`'s hash
// lost its tail to a copy-paste but kept an honoured `$2b$` prefix, and the parser does not measure
// hashes — so the line becomes an account that no password can ever open. That is the honest outcome
// and it is asserted here rather than papered over: the parser cannot tell a truncated hash from a
// short one it does not understand, and bcrypt is what refuses it.
func TestATruncatedHashBecomesAnAccountThatNothingOpens(t *testing.T) {
	f := passwdFile(t, "passwd.messy")

	if got, want := usersOf(f), []string{"erin", "frank"}; !equalStrings(got, want) {
		t.Fatalf("users = %v, want %v", got, want)
	}
	if access.Verify(f.Entries, "erin", "erin-secret") {
		t.Error("erin's truncated hash verified, so bcrypt accepted something it cannot have parsed")
	}
	for _, w := range f.Warnings {
		if strings.Contains(w, "line 26") {
			t.Errorf("warning %q names line 26, but the parser has no check that line fails", w)
		}
	}
}

// On a duplicate the first line wins, and smoke proves the second hash is never used by trying the
// password only the second hash was made from.
func TestOnADuplicateTheFirstEntryStandsAndTheSecondHashIsNeverUsed(t *testing.T) {
	f := passwdFile(t, "passwd.messy")

	if !access.Verify(f.Entries, "frank", "other-secret") {
		t.Error("frank's first password was refused, so the first entry did not stand")
	}
	if access.Verify(f.Entries, "frank", "long-secret") {
		t.Error("the duplicate's password was accepted, so the second line overwrote the first")
	}
}

// Skipped lines are counted for the client and named only for the log. The count is a note because a
// reader who sees a login form with two accounts in a six-mistake file should be told the file is
// wrong; the lines are warnings because their content is a name or a hash.
func TestSkippedLinesAreCountedForTheClientAndNamedOnlyForTheLog(t *testing.T) {
	f := passwdFile(t, "passwd.messy")
	p := access.Resolve(enabledPasswd("passwd.messy"), f)

	want := `{"enforced":true,"methods":["passwd"],"notes":["6 lines of the passwd file were skipped."]}`
	if got := marshal(t, p.Mode); got != want {
		t.Errorf("mode = %s, want %s", got, want)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("posture warnings = %v, want none: the file is usable, and the skipped lines are the parser's warnings", p.Warnings)
	}
	if strings.Contains(marshal(t, p.Mode), "frank") {
		t.Error("the note names an account; it may carry counts and never names")
	}
}

// The file an operator mounted and has not filled in yet. Comments only means no usable entry, which
// means the method is not live — and because enforcement is derived from what is live, LabView stays
// open rather than serving a login screen nobody can get past (§19).
func TestAFileWithNoEntriesLeavesLabViewOpenRatherThanLockedOut(t *testing.T) {
	f := passwdFile(t, "passwd.empty")

	if f.Err != nil {
		t.Fatalf("Err = %v, want nil: a file of comments was read successfully", f.Err)
	}
	if f.Usable() {
		t.Fatalf("Usable() = true with entries %v, want false", usersOf(f))
	}
	if len(f.Warnings) != 0 {
		t.Errorf("warnings = %v, want none: a comment is not a skipped line", f.Warnings)
	}

	p := access.Resolve(enabledPasswd("passwd.empty"), f)
	wantMode := `{"enforced":false,"methods":null,"notes":[` +
		`"Password sign-in is enabled but no usable accounts were found, so it is not available.",` +
		`"No sign-in method is available, so LabView is not requiring authentication."]}`
	if got := marshal(t, p.Mode); got != wantMode {
		t.Errorf("mode = %s, want %s", got, wantMode)
	}
	if p.Enforced() {
		t.Error("Enforced() = true, so an empty file locked the instance")
	}

	wantWarnings := []string{
		"auth: passwd enabled but the file yielded no usable entries (0 lines skipped)",
		"auth: every enabled method is unusable, so nothing is being enforced",
	}
	if !equalStrings(p.Warnings, wantWarnings) {
		t.Errorf("warnings =\n%s\nwant\n%s", strings.Join(p.Warnings, "\n"), strings.Join(wantWarnings, "\n"))
	}
	if len(p.Passwd) != 0 {
		t.Errorf("the posture carries %d entries for a method that is not live, want 0", len(p.Passwd))
	}
}

// Enabled means allowed, not on — and the two halves of *not live* are reported separately, because an
// operator who enabled the method without naming a file has made a different mistake from one whose
// file is empty. Neither ever names the path: a note is served to a browser (I2).
func TestEnabledWithoutAFileIsADifferentFindingFromEnabledWithAnEmptyOne(t *testing.T) {
	p := access.Resolve(config.AuthConfig{Passwd: config.PasswdConfig{Enabled: true}}, access.PasswdFile{})

	if p.Enforced() {
		t.Error("Enforced() = true with no file configured")
	}
	if !noteContains(p, "no passwd file is configured") {
		t.Errorf("notes = %v, want one about the missing setting", p.Mode.Notes)
	}
	if !warningContains(p, "auth.passwd.file is empty") {
		t.Errorf("warnings = %v, want one naming the setting", p.Warnings)
	}
	for _, s := range append(append([]string{}, p.Mode.Notes...), p.Warnings...) {
		if strings.Contains(s, "/") {
			t.Errorf("%q looks like it carries a path", s)
		}
	}
}

// Nothing enabled at all is the default, and it produces no note. An operator who never configured
// authentication is not surprised by its absence, and a sentence explaining it would appear on every
// page of every default install.
func TestTheDefaultIsOpenAndSaysNothingAboutIt(t *testing.T) {
	p := access.Resolve(config.AuthConfig{}, access.PasswdFile{})

	if got, want := marshal(t, p.Mode), `{"enforced":false,"methods":null,"notes":null}`; got != want {
		t.Errorf("mode = %s, want %s", got, want)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", p.Warnings)
	}
	if got, want := p.OIDCLabel, access.DefaultOIDCLabel; got != want {
		t.Errorf("OIDCLabel = %q, want %q: the API and the UI cannot disagree about the button", got, want)
	}
}

// The username pattern is one value, quoted in a warning and enforced by `hashpw`, so a line minted by
// this binary can always be signed in to.
func TestTheUsernamePatternIsTheOneTheWarningQuotes(t *testing.T) {
	if got, want := access.UsernamePattern, `^[A-Za-z0-9._@-]{1,64}$`; got != want {
		t.Errorf("UsernamePattern = %q, want %q", got, want)
	}
	for _, name := range []string{"alice", "bob.smith", "carol_1", "dave@example.com", "e-f", strings.Repeat("g", 64)} {
		if !access.ValidUsername(name) {
			t.Errorf("ValidUsername(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "a b", "a:b", "a$b", "a/b", strings.Repeat("g", 65)} {
		if access.ValidUsername(name) {
			t.Errorf("ValidUsername(%q) = true, want false", name)
		}
	}
}

// A root with no compose file in it is an empty fleet, not a failure (I4). This is the only root in the
// corpus that produces no stacks, which is why the harness exempts it from the guard that every other
// root reads something — and it has to stay silent: a directory that holds no compose file is not a
// finding, so nothing here reaches the operator's log.
func TestARootWithNoComposeFilesIsAnEmptyFleetAndNotAFailure(t *testing.T) {
	out := scanRoot(t, "auth", scanOptions{})

	if len(out.Stacks) != 0 {
		t.Errorf("stacks = %d, want 0: three passwd files are not a compose tree", len(out.Stacks))
	}
	if len(out.Meta.Warnings) != 0 {
		t.Errorf("warnings = %v, want none: a directory holding no compose file is not a finding", out.Meta.Warnings)
	}
	// Every counter is zero — but the distribution is still whole. `byAuthMethod` partitions, so an
	// empty fleet ships every mechanism at zero rather than an empty object: a member missing from a
	// partition reads as a member that cannot occur (§22.1).
	zero := payload.OverviewStats{ByAuthMethod: map[payload.AuthMethod]int{}}
	for _, m := range payload.AuthMethods {
		zero.ByAuthMethod[m] = 0
	}
	if got, want := marshal(t, out.Stats), marshal(t, zero); got != want {
		t.Errorf("stats = %s, want every counter zero and the partition whole:\n%s", got, want)
	}
}

// Determinism (I7): the same three files resolve to the same posture twice. `Resolve` is pure and the
// method list is sorted, so there is nothing left for a map iteration to reorder.
func TestTwoIdenticalResolutionsProduceTheSameBytes(t *testing.T) {
	for _, name := range []string{"passwd.ok", "passwd.messy", "passwd.empty"} {
		first := access.Resolve(enabledPasswd(name), passwdFile(t, name))
		second := access.Resolve(enabledPasswd(name), passwdFile(t, name))
		if a, b := marshal(t, first.Mode), marshal(t, second.Mode); a != b {
			t.Errorf("%s: mode differs between reads:\n%s\n%s", name, a, b)
		}
		if !equalStrings(first.Warnings, second.Warnings) {
			t.Errorf("%s: warnings differ between reads: %v then %v", name, first.Warnings, second.Warnings)
		}
	}
}

func noteContains(p access.Posture, text string) bool {
	for _, n := range p.Mode.Notes {
		if strings.Contains(n, text) {
			return true
		}
	}
	return false
}

func warningContains(p access.Posture, text string) bool {
	for _, w := range p.Warnings {
		if strings.Contains(w, text) {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// safePrefix is for a failure message about a hash: the `$id$cost$` head is the part under test and the
// rest is a credential, so only the head is printed even when the test is failing.
func safePrefix(hash string) string {
	parts := strings.SplitN(hash, "$", 4)
	if len(parts) < 4 {
		return hash
	}
	return strings.Join(parts[:3], "$") + "$..."
}
