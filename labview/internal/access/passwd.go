package access

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/bcrypt"
)

// The passwd file (§19).
//
// **It is not HTTP Basic authentication and nothing here may call it basic** (§4.7). It is a file of
// bcrypt hashes, one `user:hash` per line, which LabView reads and re-reads without a restart.

// The caps §19 states, each with the reason it exists.
const (
	// MaxPasswdBytes bounds the file. A 64 KiB file holds a thousand entries with room to spare,
	// and refusing anything larger means a wrong path pointing at a disk image is a warning rather
	// than an out-of-memory.
	MaxPasswdBytes = 64 * 1024

	// MaxPasswdEntries bounds the parsed table.
	MaxPasswdEntries = 1000

	// MaxPasswordChars bounds what will be hashed. bcrypt truncates at 72 bytes, so this is not
	// about security — it is about the work of hashing a megabyte somebody posted.
	MaxPasswordChars = 1024

	// MintCost is the cost factor for hashes this program produces.
	MintCost = 12
)

// The three bcrypt identifiers §19 honours, and nothing else. `$2$` is the original, buggy variant
// and `$2x$` exists only to reproduce that bug; neither is accepted.
var honouredPrefixes = []string{"$2a$", "$2b$", "$2y$"}

// PasswdFile is one parsed file: the entries, and everything a reader needs to be told about what
// was skipped.
type PasswdFile struct {
	// Entries maps username to hash, first occurrence winning.
	Entries map[string]string

	// Warnings are the lines that were skipped and why. **None of them contains a hash** (§19): a
	// warning is written to a log a reader may paste into an issue.
	Warnings []string

	// Err is why the file could not be read at all, distinguished by kind so an operator is sent to
	// the right place. Nil when the file was read, even if every line in it was skipped.
	Err error
}

// Usable reports whether the file yielded at least one entry, which is half of what makes the
// `passwd` method live (§19).
func (p PasswdFile) Usable() bool { return len(p.Entries) > 0 }

// The distinguished unreadable cases (§19). They are separate values rather than one message,
// because each sends an operator somewhere different: a typo in the path, a directory where a file
// was meant, a file that is not what was intended, and a mount or ownership problem.
var (
	ErrPasswdMissing   = errors.New("passwd file does not exist")
	ErrPasswdDirectory = errors.New("passwd path is a directory")
	ErrPasswdTooLarge  = fmt.Errorf("passwd file is larger than %d bytes", MaxPasswdBytes)
	ErrPasswdDenied    = errors.New("passwd file cannot be read: permission denied")
)

// ParsePasswd parses the file's contents. It is pure: every caps and warning rule is testable
// without a filesystem.
func ParsePasswd(content []byte) PasswdFile {
	out := PasswdFile{Entries: map[string]string{}}

	if len(content) > MaxPasswdBytes {
		out.Err = ErrPasswdTooLarge
		return out
	}

	// Line numbers are one-based and reported, because "line 14" is a thing an operator can go and
	// look at and "a malformed line" is not.
	for n, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(out.Entries) >= MaxPasswdEntries {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d and after ignored: more than %d entries", n+1, MaxPasswdEntries))
			break
		}

		user, hash, ok := split(line)
		switch {
		case !ok:
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d skipped: no username:hash separator", n+1))
			continue
		case user == "":
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d skipped: no username", n+1))
			continue
		case !ValidUsername(user):
			// The name is not echoed. It failed the pattern, which is exactly the case where
			// echoing it would put arbitrary bytes into the log (§19).
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d skipped: username is not %s", n+1, UsernamePattern))
			continue
		case !strings.Contains(hash, "$"):
			// The one absolute rule of this parser. A value with no `$` is not a bcrypt hash, and
			// the overwhelmingly likely thing it *is* is a plaintext password somebody typed in
			// expecting it to work. Accepting it would authenticate against a plaintext file.
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d skipped: the value is not a hash", n+1))
			continue
		}

		if id, honoured := algorithm(hash); !honoured {
			// The algorithm only. Naming it lets an operator fix a file produced by the wrong tool;
			// including the hash would put a credential in a log (§19).
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d skipped: unsupported algorithm %s", n+1, id))
			continue
		}

		// First wins. The alternative — last wins — would let a line appended to the end of a file
		// silently replace an account, which is the shape of a change nobody reviews.
		if _, seen := out.Entries[user]; seen {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"passwd: line %d skipped: duplicate username, the first entry stands", n+1))
			continue
		}
		out.Entries[user] = hash
	}

	return out
}

// split cuts one line at its first colon. First rather than last: a bcrypt hash contains no colon,
// but a username that somehow did would otherwise take part of the hash with it.
func split(line string) (user, hash string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// algorithm reads the `$id$` prefix and reports whether it is one of the three honoured ones.
//
// The identifier it returns is bounded and character-checked before being handed to a warning, so a
// file whose "algorithm" is a megabyte of control characters cannot write it into the log.
func algorithm(hash string) (id string, honoured bool) {
	for _, prefix := range honouredPrefixes {
		if strings.HasPrefix(hash, prefix) {
			return strings.Trim(prefix, "$"), true
		}
	}

	// Everything from the first `$` to the second, which is where every crypt-style identifier
	// lives: `$2$`, `$argon2id$`, `$6$`, `$pbkdf2-sha256$`.
	rest := strings.TrimPrefix(hash, "$")
	if i := strings.Index(rest, "$"); i >= 0 {
		rest = rest[:i]
	}
	return safeIdentifier(rest), false
}

// safeIdentifier bounds an algorithm name to something printable and short enough to log.
func safeIdentifier(s string) string {
	const max = 16
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "unrecognised"
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Reading, with the cache §19 asks for
// ---------------------------------------------------------------------------

// stamp is what a cached read is keyed on: size, mtime and inode (§19).
//
// Inode as well as size and mtime, because the way a passwd file usually changes is that a
// deployment writes a new one and renames it over the old — same size, and a coarse mtime can
// collide. A new inode says *this is a different file* whatever the other two say.
type stamp struct {
	size  int64
	mtime int64
	inode uint64
}

// PasswdReader reads and caches one passwd file.
//
// Safe for concurrent use: the gate reads it on every login, and §19 requires a re-read when the
// file changes without a restart.
type PasswdReader struct {
	// FS is where the file is read from. Nil means the real filesystem. It exists so the caps, the
	// cache and the four unreadable cases are all testable without a temp directory per case.
	FS PasswdFS

	mu     sync.Mutex
	path   string
	at     stamp
	cached PasswdFile
	loaded bool
}

// PasswdFS is the filesystem access this reader needs, which is exactly two calls (I5).
type PasswdFS interface {
	Stat(name string) (fs.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

// osPasswdFS is the real filesystem.
type osPasswdFS struct{}

func (osPasswdFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }
func (osPasswdFS) ReadFile(name string) ([]byte, error)  { return os.ReadFile(name) }

// Read returns the file at path, from cache when nothing about it has changed.
//
// A read that fails does not clear a previously good table: a file that briefly vanishes mid-deploy
// would otherwise sign everybody out, and §19 is explicit that an unusable method must never produce
// a lock-out. The error is reported alongside what is still held.
func (r *PasswdReader) Read(path string) PasswdFile {
	r.mu.Lock()
	defer r.mu.Unlock()

	fsys := r.FS
	if fsys == nil {
		fsys = osPasswdFS{}
	}

	if strings.TrimSpace(path) == "" {
		r.loaded, r.cached, r.path = false, PasswdFile{Entries: map[string]string{}}, ""
		return r.cached
	}

	info, err := fsys.Stat(path)
	if err != nil {
		return r.fail(classify(err))
	}
	if info.IsDir() {
		return r.fail(ErrPasswdDirectory)
	}
	if info.Size() > MaxPasswdBytes {
		// Refused on the stat rather than after reading it, so an enormous file is never in memory.
		return r.fail(ErrPasswdTooLarge)
	}

	now := stampOf(info)
	if r.loaded && r.path == path && r.at == now {
		return r.cached
	}

	content, err := fsys.ReadFile(path)
	if err != nil {
		return r.fail(classify(err))
	}

	r.cached, r.at, r.path, r.loaded = ParsePasswd(content), now, path, true
	return r.cached
}

// fail reports an error while keeping whatever entries are still held. The caller holds the lock.
func (r *PasswdReader) fail(err error) PasswdFile {
	out := PasswdFile{Entries: map[string]string{}, Err: err}
	if r.loaded {
		out.Entries, out.Warnings = r.cached.Entries, r.cached.Warnings
	}
	return out
}

// classify turns a filesystem error into one of §19's distinguished cases.
func classify(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ErrPasswdMissing
	case errors.Is(err, fs.ErrPermission):
		return ErrPasswdDenied
	case errors.Is(err, syscall.EISDIR):
		return ErrPasswdDirectory
	default:
		return err
	}
}

// stampOf reads size, mtime and inode. The inode is platform-specific and absent on a synthetic
// FileInfo, in which case size and mtime carry the comparison on their own.
func stampOf(info fs.FileInfo) stamp {
	out := stamp{size: info.Size(), mtime: info.ModTime().UnixNano()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys != nil {
		out.inode = uint64(sys.Ino)
	}
	return out
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verify checks a password against a table.
//
// **An unknown username is verified against a decoy hash** (§19), so a wrong name and a wrong
// password take the same time. Without it, the response time to a login attempt tells an attacker
// which of a list of names exist, and enumerating accounts is the step before attacking one.
//
// It returns only true or false. Which of the two reasons it was is deliberately not returned: there
// is no caller that should behave differently, and a return value distinguishing them is a return
// value that will eventually reach a response body.
func Verify(table map[string]string, user, password string) bool {
	if len(password) > MaxPasswordChars {
		// Refused before hashing. bcrypt truncates at 72 bytes, so a megabyte of password is not a
		// stronger password — it is only work.
		return false
	}

	hash, known := table[user]
	if !known {
		// The decoy is compared against, and its result discarded. The comparison is the point.
		_ = bcrypt.CompareHashAndPassword(decoyFor(costOf(table)), []byte(password))
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// costOf is the cost factor the decoy is generated at, which is why §19 says *per cost factor* rather
// than naming one.
//
// The highest cost in the table. A decoy at a fixed cost would defeat its own purpose the moment the
// file held hashes minted by an older tool: a comparison against a cost-10 hash and a comparison against
// a cost-12 decoy differ by a factor of four, which is exactly the timing signal the decoy exists to
// remove. The highest rather than the average, because *slower than every real account* is the safe
// direction to be wrong in — an unknown name that answered faster than a known one would announce that
// the name does not exist.
func costOf(table map[string]string) int {
	best := 0
	for _, hash := range table {
		if cost, err := bcrypt.Cost([]byte(hash)); err == nil && cost > best {
			best = cost
		}
	}
	if best < bcrypt.MinCost || best > bcrypt.MaxCost {
		// An empty table, or one whose costs will not parse. Neither can be timed against, since
		// there is no known name to compare with.
		return MintCost
	}
	return best
}

// Mint produces a hash for a password, at cost MintCost (§19).
func Mint(password string) (string, error) {
	if len(password) > MaxPasswordChars {
		return "", fmt.Errorf("password is longer than %d characters", MaxPasswordChars)
	}
	out, err := bcrypt.GenerateFromPassword([]byte(password), MintCost)
	return string(out), err
}

// decoys memoises one decoy hash per cost factor.
var decoys sync.Map // int -> []byte

// decoyFor returns the decoy hash for a cost, generating it on first use from 32 random bytes.
//
// **Never a committed constant** (§19). A constant in the source is a hash whose preimage is
// unknown to nobody: an attacker reading this repository would know exactly which hash the unknown-
// username path compares against, and could tell a real account from a decoy by timing the one input
// that matches it. Random per process, and never logged.
func decoyFor(cost int) []byte {
	if v, ok := decoys.Load(cost); ok {
		return v.([]byte)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// crypto/rand does not fail on any supported platform, and if it did, a fixed string here
		// is still a hash of something no attacker chose. Degrading is right; refusing to
		// authenticate anybody because of it is not (I4).
		secret = []byte("labview decoy fallback")
	}
	hash, err := bcrypt.GenerateFromPassword(secret, cost)
	if err != nil {
		// The only way this fails is a cost outside bcrypt's range, which costOf already excludes. The
		// fallback is a hash at the library's own default rather than a literal, so this path still
		// costs real work — a decoy that returned instantly would be worse than no decoy, since the
		// unknown-name case would become the fastest answer the server gives.
		hash, _ = bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost)
	}

	actual, _ := decoys.LoadOrStore(cost, hash)
	return actual.([]byte)
}
