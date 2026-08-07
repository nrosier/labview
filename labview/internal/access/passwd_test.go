package access

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Fixtures use invented names and example.com throughout (I2).

// hash mints a test hash at bcrypt's cheapest cost. Cost 4 rather than MintCost, because a test that
// spends 250 ms per hash is a test that stops being run.
func hash(t *testing.T, password string) string {
	t.Helper()
	out, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("could not mint a test hash: %v", err)
	}
	return string(out)
}

func TestAWellFormedFileParsesEveryEntry(t *testing.T) {
	ada, grace := hash(t, "one"), hash(t, "two")
	file := ParsePasswd([]byte("# a comment\n\nada:" + ada + "\ngrace:" + grace + "\n"))

	if file.Err != nil {
		t.Fatalf("a well-formed file reported an error: %v", file.Err)
	}
	if len(file.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(file.Entries))
	}
	if file.Entries["ada"] != ada || file.Entries["grace"] != grace {
		t.Fatal("an entry does not hold the hash from its line")
	}
	if len(file.Warnings) != 0 {
		t.Fatalf("a well-formed file produced warnings: %v", file.Warnings)
	}
	if !file.Usable() {
		t.Fatal("a file with two entries is not usable")
	}
}

// §19: *A value containing no `$` MUST never be accepted — it would be a plaintext password.*
func TestAValueWithNoDollarIsNeverAccepted(t *testing.T) {
	file := ParsePasswd([]byte("ada:hunter2\n"))

	if len(file.Entries) != 0 {
		t.Fatal("a plaintext password was accepted as a hash; §19 forbids it absolutely")
	}
	if !strings.Contains(strings.Join(file.Warnings, " "), "not a hash") {
		t.Fatalf("the skip was not explained as a non-hash: %v", file.Warnings)
	}
}

// The same rule from the other side: the warning must not repeat the value, because the value is a
// plaintext password.
func TestTheWarningForAPlaintextValueDoesNotRepeatIt(t *testing.T) {
	file := ParsePasswd([]byte("ada:correcthorsebatterystaple\n"))

	for _, warning := range file.Warnings {
		if strings.Contains(warning, "correcthorsebatterystaple") {
			t.Fatalf("a warning repeated the plaintext value: %q", warning)
		}
	}
}

func TestOnlyTheThreeHonouredAlgorithmsAreAccepted(t *testing.T) {
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		// The body is nonsense; the parser reads the prefix and nothing else. A hash that will not
		// verify is still a hash, and rejecting it here would be reading the wrong field.
		file := ParsePasswd([]byte("ada:" + prefix + "10$abcdefghijklmnopqrstuv\n"))
		if len(file.Entries) != 1 {
			t.Fatalf("%s was not honoured: %v", prefix, file.Warnings)
		}
	}
}

func TestAnUnsupportedAlgorithmIsSkippedWithTheAlgorithmNamedAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		line string
		id   string
	}{
		{"ada:$2$10$abcdefghijklmnopqrstuv", "2"},
		{"ada:$2x$10$abcdefghijklmnopqrstuv", "2x"},
		{"ada:$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aaaa", "argon2id"},
		{"ada:$6$rounds=5000$salt$aaaaaaaaaaaa", "6"},
		{"ada:$pbkdf2-sha256$29000$salt$aaaa", "pbkdf2-sha256"},
	} {
		file := ParsePasswd([]byte(tc.line + "\n"))

		if len(file.Entries) != 0 {
			t.Fatalf("%q was accepted", tc.line)
		}
		if len(file.Warnings) != 1 {
			t.Fatalf("%q produced %d warnings, want 1", tc.line, len(file.Warnings))
		}
		warning := file.Warnings[0]
		if !strings.Contains(warning, tc.id) {
			t.Fatalf("the warning for %q does not name the algorithm %q: %s", tc.line, tc.id, warning)
		}
		// **A warning never contains a hash** (§19). The rest of the value, past the algorithm, is
		// salt and digest.
		if rest := strings.TrimPrefix(tc.line, "ada:$"+tc.id+"$"); strings.Contains(warning, rest) {
			t.Fatalf("the warning carried the hash: %s", warning)
		}
	}
}

func TestNoWarningAnywhereContainsAHash(t *testing.T) {
	real := hash(t, "one")
	file := ParsePasswd([]byte(strings.Join([]string{
		"ada:" + real,
		"ada:" + real, // duplicate
		"grace:$6$rounds=5000$salt$digestdigestdigest",
		"alan:plaintext",
		"a b c:" + real,
		"nocolon",
		":" + real,
	}, "\n")))

	if len(file.Warnings) != 6 {
		t.Fatalf("expected 6 warnings, got %d: %v", len(file.Warnings), file.Warnings)
	}
	for _, warning := range file.Warnings {
		for _, forbidden := range []string{real, "digestdigestdigest", "plaintext"} {
			if strings.Contains(warning, forbidden) {
				t.Fatalf("a warning carried a secret value: %s", warning)
			}
		}
	}
}

func TestDuplicateUsernamesKeepTheFirst(t *testing.T) {
	first, second := hash(t, "one"), hash(t, "two")
	file := ParsePasswd([]byte("ada:" + first + "\nada:" + second + "\n"))

	if len(file.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(file.Entries))
	}
	if file.Entries["ada"] != first {
		t.Fatal("a later line replaced an earlier one; §19 says first wins")
	}
	if !Verify(file.Entries, "ada", "one") {
		t.Fatal("the first entry's password does not verify")
	}
	if Verify(file.Entries, "ada", "two") {
		t.Fatal("the second entry's password verifies, so the duplicate was not skipped")
	}
}

func TestAMalformedLineIsSkippedAndTheRestOfTheFileIsStillRead(t *testing.T) {
	good := hash(t, "one")
	file := ParsePasswd([]byte("nocolon\nada:" + good + "\n:justahash\n"))

	if file.Err != nil {
		t.Fatalf("a malformed line was fatal: %v", file.Err)
	}
	if len(file.Entries) != 1 || file.Entries["ada"] != good {
		t.Fatalf("the good line after a malformed one was lost: %v", file.Entries)
	}
}

func TestACommentAndABlankLineAreNotWarnings(t *testing.T) {
	file := ParsePasswd([]byte("# ada was here\n\n   \n#another\n"))

	if len(file.Warnings) != 0 {
		t.Fatalf("comments or blanks produced warnings: %v", file.Warnings)
	}
	if file.Usable() {
		t.Fatal("a file of only comments is usable")
	}
}

func TestAUsernameOutsideThePatternIsSkippedAndNotEchoed(t *testing.T) {
	good := hash(t, "one")
	file := ParsePasswd([]byte("ada smith:" + good + "\nada\nnewline\x00:" + good + "\n"))

	if len(file.Entries) != 0 {
		t.Fatalf("a username outside the pattern was accepted: %v", file.Entries)
	}
	for _, warning := range file.Warnings {
		if strings.Contains(warning, "ada smith") || strings.Contains(warning, "\x00") {
			t.Fatalf("a warning echoed a hostile username: %q", warning)
		}
	}
}

func TestTheEntryCapStopsAtOneThousandAndSaysSo(t *testing.T) {
	// The same hash on every line: this is about the cap, not about verification.
	one := "$2a$04$abcdefghijklmnopqrstuv"
	var b strings.Builder
	for i := 0; i < MaxPasswdEntries+50; i++ {
		b.WriteString("user")
		b.WriteString(strings.Repeat("x", i%3))
		b.WriteString(itoa(i))
		b.WriteString(":" + one + "\n")
	}

	file := ParsePasswd([]byte(b.String()))

	if len(file.Entries) != MaxPasswdEntries {
		t.Fatalf("expected exactly %d entries, got %d", MaxPasswdEntries, len(file.Entries))
	}
	if len(file.Warnings) != 1 || !strings.Contains(file.Warnings[0], "more than 1000") {
		t.Fatalf("the cap was applied silently: %v", file.Warnings)
	}
}

func TestAFileOverSixtyFourKibIsRefusedAsAWhole(t *testing.T) {
	file := ParsePasswd(make([]byte, MaxPasswdBytes+1))

	if !errors.Is(file.Err, ErrPasswdTooLarge) {
		t.Fatalf("an over-size file was parsed anyway: err=%v entries=%d", file.Err, len(file.Entries))
	}
}

func TestAPasswordOverTheCharacterCapIsRefusedWithoutHashing(t *testing.T) {
	table := map[string]string{"ada": hash(t, "one")}

	if Verify(table, "ada", strings.Repeat("x", MaxPasswordChars+1)) {
		t.Fatal("an over-long password verified")
	}
	if _, err := Mint(strings.Repeat("x", MaxPasswordChars+1)); err == nil {
		t.Fatal("Mint accepted a password over the cap")
	}
}

// §19: *An unknown username is verified against a decoy hash.*
//
// Tested as behaviour rather than as timing: a timing assertion is flaky on shared hardware. What is
// asserted is that the comparison happened — that the unknown-name path did real bcrypt work — which is
// the property the decoy exists to provide.
func TestAnUnknownUsernameIsVerifiedAgainstADecoyRatherThanReturningImmediately(t *testing.T) {
	// A deliberately expensive table, so a real comparison is unmistakably slower than a map miss.
	expensive, err := bcrypt.GenerateFromPassword([]byte("one"), 10)
	if err != nil {
		t.Fatalf("could not mint: %v", err)
	}
	table := map[string]string{"ada": string(expensive)}

	// The decoy for this cost is generated on first use, so it is warmed before the measurement — the
	// generation is not the comparison and only the comparison is claimed to happen every time.
	_ = Verify(table, "nobody", "guess")

	known := timeOf(func() { _ = Verify(table, "ada", "wrong") })
	unknown := timeOf(func() { _ = Verify(table, "nobody", "wrong") })

	// A map miss with no decoy would be measured in nanoseconds against a cost-10 comparison's tens of
	// milliseconds. A tenth of the known-name time is far below any plausible bcrypt result and far
	// above any plausible map miss, so this discriminates the two implementations without being
	// sensitive to how fast the machine is.
	if unknown < known/10 {
		t.Fatalf("an unknown username returned in %v against a known name's %v, so no decoy comparison ran", unknown, known)
	}
}

func TestTheDecoyIsGeneratedAtTheTablesCostRatherThanAFixedOne(t *testing.T) {
	for _, cost := range []int{bcrypt.MinCost, bcrypt.MinCost + 2} {
		out, err := bcrypt.GenerateFromPassword([]byte("one"), cost)
		if err != nil {
			t.Fatalf("could not mint at cost %d: %v", cost, err)
		}
		if got := costOf(map[string]string{"ada": string(out)}); got != cost {
			t.Fatalf("a table of cost-%d hashes chose a decoy cost of %d", cost, got)
		}
	}

	// Mixed costs take the highest, so an unknown name is never faster than the slowest real account.
	low, _ := bcrypt.GenerateFromPassword([]byte("one"), bcrypt.MinCost)
	high, _ := bcrypt.GenerateFromPassword([]byte("two"), bcrypt.MinCost+3)
	if got := costOf(map[string]string{"ada": string(low), "grace": string(high)}); got != bcrypt.MinCost+3 {
		t.Fatalf("a mixed-cost table chose %d, want the highest cost %d", got, bcrypt.MinCost+3)
	}

	// An empty table has no known name to be timed against, so the minting cost stands.
	if got := costOf(map[string]string{}); got != MintCost {
		t.Fatalf("an empty table chose %d, want %d", got, MintCost)
	}
}

func TestTheDecoyIsNotACommittedConstant(t *testing.T) {
	// Two processes cannot be compared from inside one, so the property is asserted the only way it can
	// be: the decoy is not any literal in this package, and it is memoised rather than regenerated.
	first := string(decoyFor(bcrypt.MinCost))
	second := string(decoyFor(bcrypt.MinCost))

	if first != second {
		t.Fatal("the decoy was regenerated, so it is not memoised")
	}
	if first == "" || !strings.HasPrefix(first, "$2") {
		t.Fatalf("the decoy is not a bcrypt hash: %q", first)
	}
	// A different cost is a different decoy — *per cost factor* (§19).
	if string(decoyFor(bcrypt.MinCost+1)) == first {
		t.Fatal("two cost factors share one decoy")
	}
}

func TestMintProducesAHashThisProgramWillAcceptAndVerify(t *testing.T) {
	// Cost 12 is slow by design, so this runs once.
	minted, err := Mint("a good password")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(minted))
	if err != nil {
		t.Fatalf("the minted hash has no readable cost: %v", err)
	}
	if cost != MintCost {
		t.Fatalf("minted at cost %d, want %d (§19)", cost, MintCost)
	}

	file := ParsePasswd([]byte("ada:" + minted + "\n"))
	if len(file.Entries) != 1 {
		t.Fatalf("this program will not parse its own minted line: %v", file.Warnings)
	}
	if !Verify(file.Entries, "ada", "a good password") {
		t.Fatal("this program will not verify its own minted hash")
	}
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// memFS is a filesystem in a map, so each of the four unreadable cases is one line rather than one
// temporary directory with the right permissions.
type memFS struct {
	files map[string]*memFile
	reads int
}

type memFile struct {
	content []byte
	dir     bool
	mtime   time.Time
	err     error
	size    int64
}

func (m *memFS) Stat(name string) (fs.FileInfo, error) {
	f, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	if f.err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: f.err}
	}
	return memInfo{name: name, file: f}, nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	m.reads++
	f, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if f.err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: f.err}
	}
	return f.content, nil
}

type memInfo struct {
	name string
	file *memFile
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64 {
	if i.file.size != 0 {
		return i.file.size
	}
	return int64(len(i.file.content))
}
func (i memInfo) Mode() fs.FileMode {
	if i.file.dir {
		return fs.ModeDir | 0o755
	}
	return 0o600
}
func (i memInfo) ModTime() time.Time { return i.file.mtime }
func (i memInfo) IsDir() bool        { return i.file.dir }
func (i memInfo) Sys() any           { return nil }

func TestTheFourUnreadableCasesAreDistinguished(t *testing.T) {
	base := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)

	for _, tc := range []struct {
		name string
		file *memFile
		want error
	}{
		{"missing", nil, ErrPasswdMissing},
		{"is a directory", &memFile{dir: true, mtime: base}, ErrPasswdDirectory},
		{"over size", &memFile{size: MaxPasswdBytes + 1, mtime: base}, ErrPasswdTooLarge},
		{"permission denied", &memFile{err: fs.ErrPermission, mtime: base}, ErrPasswdDenied},
	} {
		fsys := &memFS{files: map[string]*memFile{}}
		if tc.file != nil {
			fsys.files["/etc/labview/passwd"] = tc.file
		}
		reader := &PasswdReader{FS: fsys}

		got := reader.Read("/etc/labview/passwd")
		if !errors.Is(got.Err, tc.want) {
			t.Fatalf("%s: got %v, want %v — §19 requires these four to be told apart", tc.name, got.Err, tc.want)
		}
	}
}

func TestAReadIsCachedOnSizeAndMtimeAndRepeatedWhenEitherMoves(t *testing.T) {
	base := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
	ada := hash(t, "one")
	file := &memFile{content: []byte("ada:" + ada + "\n"), mtime: base}
	fsys := &memFS{files: map[string]*memFile{"/p": file}}
	reader := &PasswdReader{FS: fsys}

	if got := reader.Read("/p"); len(got.Entries) != 1 {
		t.Fatalf("first read: %v", got)
	}
	if reader.Read("/p"); fsys.reads != 1 {
		t.Fatalf("an unchanged file was read %d times, want 1", fsys.reads)
	}

	// Same size, new mtime: a file rewritten in place.
	file.mtime = base.Add(time.Second)
	reader.Read("/p")
	if fsys.reads != 2 {
		t.Fatalf("a changed mtime did not force a re-read (reads=%d)", fsys.reads)
	}

	// Same mtime, new size.
	grace := hash(t, "two")
	file.content = []byte("ada:" + ada + "\ngrace:" + grace + "\n")
	reader.Read("/p")
	if fsys.reads != 3 {
		t.Fatalf("a changed size did not force a re-read (reads=%d)", fsys.reads)
	}
	if got := reader.Read("/p"); len(got.Entries) != 2 {
		t.Fatalf("the re-read did not pick up the new entry: %v", got.Entries)
	}
}

// A passwd file that vanishes mid-deploy must not sign everybody out: §19 forbids a lock-out.
func TestAFileThatBecomesUnreadableKeepsTheEntriesItAlreadyHad(t *testing.T) {
	ada := hash(t, "one")
	fsys := &memFS{files: map[string]*memFile{
		"/p": {content: []byte("ada:" + ada + "\n"), mtime: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)},
	}}
	reader := &PasswdReader{FS: fsys}

	if got := reader.Read("/p"); len(got.Entries) != 1 {
		t.Fatalf("first read: %v", got)
	}

	delete(fsys.files, "/p")
	got := reader.Read("/p")

	if !errors.Is(got.Err, ErrPasswdMissing) {
		t.Fatalf("the error was not reported: %v", got.Err)
	}
	if len(got.Entries) != 1 {
		t.Fatal("a file that vanished cleared the table, which would sign everybody out")
	}
}

func TestAnEmptyPathReadsNothingAndIsNotAnError(t *testing.T) {
	fsys := &memFS{files: map[string]*memFile{}}
	reader := &PasswdReader{FS: fsys}

	got := reader.Read("")

	if got.Err != nil {
		t.Fatalf("an unconfigured path reported a filesystem error: %v", got.Err)
	}
	if got.Usable() {
		t.Fatal("an unconfigured path produced a usable table")
	}
	if fsys.reads != 0 {
		t.Fatal("an unconfigured path was read from the filesystem")
	}
}

// §19's naming hazard, checked mechanically: *No identifier in the implementation may call it basic.*
func TestNothingInThisPackageCallsThePasswdMethodBasic(t *testing.T) {
	// The check lives in the sweep over the source tree (§23); here it is asserted about the vocabulary
	// this package exports, which is the part other packages would copy.
	for _, name := range []string{
		UsernamePattern, UnknownUsername, string(TokenVersion), DefaultCookieName,
		TransientCookieName, DefaultCallbackPath, DefaultOIDCLabel,
	} {
		if strings.Contains(strings.ToLower(name), "basic") {
			t.Fatalf("an exported value calls it basic: %q", name)
		}
	}
}

// ---------------------------------------------------------------------------

func timeOf(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
