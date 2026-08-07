package access

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
)

// Posture resolution (§19).
//
// **Open unless configured.** With no method enabled, LabView is reachable exactly as it was before
// authentication existed. That is the default because the alternative — a lab tool that locks itself
// on upgrade — is a tool an operator cannot get back into, and because a homelab behind a tunnel
// already has a front door.
//
// The resolution is pure. What is enforced, which methods are live and what an operator needs to be
// told are all derived from configuration and one already-read passwd file, with no clock, no
// filesystem and no scanned data in it. That is what lets every one of §19's edge cases — enabled but
// unusable, enabled but empty, both enabled, neither enabled — be a table row.

// PostureTTL is how long a resolution is reused (§19).
//
// Five seconds rather than the build cache's minute: a posture is consulted on every request, so
// re-resolving it per request would stat the passwd file thousands of times an hour, and holding it
// for a minute would mean an operator who has just fixed a broken passwd file waits a minute to find
// out. Five seconds is short enough that a fix feels immediate and long enough that a burst of
// requests costs one read.
const PostureTTL = 5000 * time.Millisecond

// Posture is what one resolution concluded.
type Posture struct {
	// Mode is what a client is told: whether authentication is enforced, which methods it may use and
	// the notes explaining anything surprising. It carries **counts, never names** (§19).
	Mode payload.AccessMode

	// Warnings are for the log, not the client. They are what an operator has to act on — an enabled
	// method that is not live, a passwd file that cannot be read — and they are separate from
	// Mode.Notes because a note is a sentence a browser renders and a warning is a line an operator
	// greps for.
	Warnings []string

	// Passwd is the table the login route verifies against, empty when the method is not live. It is
	// carried on the posture rather than re-read by the route, so the decision that `passwd` is live
	// and the table used to act on it are the same read.
	Passwd map[string]string

	// OIDCLabel is the button text, defaulted here so the API and the UI cannot disagree about it.
	OIDCLabel string
}

// Enforced reports whether this posture gates anything.
func (p Posture) Enforced() bool { return p.Mode.Enforced }

// Live reports whether a method may be used right now.
func (p Posture) Live(m payload.LoginMethod) bool {
	for _, have := range p.Mode.Methods {
		if have == m {
			return true
		}
	}
	return false
}

// DefaultOIDCLabel is the button text when configuration names none.
const DefaultOIDCLabel = "Sign in with your provider"

// Resolve is the pure resolution: configuration plus one already-read passwd file in, posture out.
//
// The passwd file is a parameter rather than read here, because that is what makes this function
// testable without a filesystem and what keeps the 5000 ms cache outside it.
func Resolve(cfg config.AuthConfig, file PasswdFile) Posture {
	out := Posture{Passwd: map[string]string{}, OIDCLabel: label(cfg.OIDC.Label)}

	// **Enabled means allowed, not on** (§19). A method is live only if it is both enabled and
	// usable, and the two are reported separately so an operator is told which of the two they got
	// wrong.
	if cfg.Passwd.Enabled {
		switch {
		case strings.TrimSpace(cfg.Passwd.File) == "":
			out.note("Password sign-in is enabled but no passwd file is configured, so it is not available.")
			out.warn("auth: passwd enabled but auth.passwd.file is empty")
		case file.Err != nil:
			// The path is not in the note. A note is served to a browser, and a filesystem path is a
			// fact about the host that a client has no reason to receive (I2).
			out.note("Password sign-in is enabled but its file could not be read, so it is not available.")
			out.warn(fmt.Sprintf("auth: passwd enabled but unusable: %v", file.Err))
		case !file.Usable():
			out.note("Password sign-in is enabled but no usable accounts were found, so it is not available.")
			out.warn(fmt.Sprintf("auth: passwd enabled but the file yielded no usable entries (%d %s skipped)",
				len(file.Warnings), Plural(len(file.Warnings), "line", "lines")))
		default:
			out.Mode.Methods = append(out.Mode.Methods, payload.MethodPasswd)
			out.Passwd = file.Entries
			if n := len(file.Warnings); n > 0 {
				// Counted, not named. A skipped line is an operator's problem and its content is
				// either a malformed name or a hash (§19).
				out.note(fmt.Sprintf("%d line%s of the passwd file were skipped.", n, suffix(n)))
			}
		}
	}

	if cfg.OIDC.Enabled {
		missing := missingOIDC(cfg.OIDC)
		switch {
		case len(missing) > 0:
			out.note("Provider sign-in is enabled but is not fully configured, so it is not available.")
			out.warn("auth: oidc enabled but unusable: " + strings.Join(missing, " and ") + " missing")
		default:
			out.Mode.Methods = append(out.Mode.Methods, payload.MethodOIDC)
		}
	}

	// Methods are sorted so a payload is byte-identical for identical configuration (I7). It also
	// makes `passwd` come first, which is the order the login form should offer them in — the method
	// that needs no round trip before the one that does.
	sort.Slice(out.Mode.Methods, func(i, j int) bool { return out.Mode.Methods[i] < out.Mode.Methods[j] })

	// The invariant AccessMode.Consistent states, established here rather than asserted downstream:
	// enforcement is exactly *some method is live*.
	//
	// **An enabled-but-unusable method never produces a lock-out** (§19). This is the line that makes
	// that true: enforcement follows what is live, so a passwd file somebody deleted leaves LabView
	// open with a warning rather than shut with nobody able to sign in and fix it. Deriving it, rather
	// than taking a separate `enforce` setting, is why there is no configuration that can express
	// *enforced with no way in*.
	out.Mode.Enforced = len(out.Mode.Methods) > 0

	if !out.Mode.Enforced {
		if cfg.Passwd.Enabled || cfg.OIDC.Enabled {
			out.note("No sign-in method is available, so LabView is not requiring authentication.")
			out.warn("auth: every enabled method is unusable, so nothing is being enforced")
		}
		// With nothing enabled at all there is no note. An operator who never configured
		// authentication is not surprised by its absence, and a note explaining it would appear on
		// every page of every default install.
	}

	return out
}

// missingOIDC names the fields §19 requires for `oidc` to be live: a non-empty issuer and client id.
//
// The secret is not among them. A public client using PKCE has none, and requiring one would refuse a
// correct configuration.
func missingOIDC(o config.OIDCConfig) []string {
	var out []string
	if strings.TrimSpace(o.Issuer) == "" {
		out = append(out, "issuer")
	}
	if strings.TrimSpace(o.ClientID) == "" {
		out = append(out, "client id")
	}
	return out
}

func label(s string) string {
	if strings.TrimSpace(s) == "" {
		return DefaultOIDCLabel
	}
	return s
}

func (p *Posture) note(s string) { p.Mode.Notes = append(p.Mode.Notes, s) }
func (p *Posture) warn(s string) { p.Warnings = append(p.Warnings, s) }

// Plural picks between two words. The same helper as conn.Plural, restated rather than imported so
// that nothing in the posture path — the one thing consulted on every single request — reaches into
// the scan side of the program for a two-line function (I8).
func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func suffix(n int) string { return Plural(n, "", "s") }

// ---------------------------------------------------------------------------
// The cache §19 asks for
// ---------------------------------------------------------------------------

// Postures re-resolves the posture per request and caches it for PostureTTL, logging **only when it
// changes** (§19).
//
// Only when it changes, because a posture is resolved on every request: logging each resolution would
// write the same three lines several times a second, and a log where nothing stands out is a log where
// the one line that mattered is invisible.
type Postures struct {
	// Config returns the auth configuration as it stands. A function rather than a value because
	// configuration is re-read on rescan (§3) and the gate must not hold a copy from startup.
	Config func() config.AuthConfig

	// Passwd reads the file. Nil takes a reader of this struct's own.
	Passwd *PasswdReader

	// Now is the injected clock. Nil is time.Now.
	Now func() time.Time

	// Changed is called when the resolution differs from the previous one, with the new posture.
	// Nil means nobody is listening. It runs without the lock held.
	Changed func(p Posture)

	mu       sync.Mutex
	held     Posture
	at       time.Time
	loaded   bool
	previous string
	reader   PasswdReader
}

// Current returns the posture, re-resolving it when the cached one has expired.
func (p *Postures) Current() Posture {
	now := p.clock()()

	p.mu.Lock()
	if p.loaded && now.Sub(p.at) < PostureTTL {
		held := p.held
		p.mu.Unlock()
		return held
	}
	p.mu.Unlock()

	// Resolved outside the lock: it reads the passwd file, and holding a mutex across a filesystem
	// read on a slow mount would serialise every request in the program behind it. Two requests
	// arriving together may both resolve, which costs one extra stat and is a better trade than a
	// lock held across I/O.
	cfg := p.config()
	next := Resolve(cfg, p.read(cfg))
	key := postureKey(next)

	p.mu.Lock()
	p.held, p.at, p.loaded = next, now, true
	changed := key != p.previous
	p.previous = key
	p.mu.Unlock()

	if changed && p.Changed != nil {
		p.Changed(next)
	}
	return next
}

// read reads the configured passwd file, or nothing when the method is not enabled.
//
// Not read when the method is disabled, because reading a file nobody asked to be read is both work
// and a surprising line in an audit log of the host.
func (p *Postures) read(cfg config.AuthConfig) PasswdFile {
	if !cfg.Passwd.Enabled {
		return PasswdFile{Entries: map[string]string{}}
	}
	reader := p.Passwd
	if reader == nil {
		reader = &p.reader
	}
	return reader.Read(cfg.Passwd.File)
}

func (p *Postures) config() config.AuthConfig {
	if p.Config == nil {
		return config.AuthConfig{}
	}
	return p.Config()
}

func (p *Postures) clock() func() time.Time {
	if p.Now == nil {
		return time.Now
	}
	return p.Now
}

// postureKey is what *changed* means for the purpose of logging.
//
// Enforcement, the live methods and the notes. Deliberately not the passwd table: a new account
// appearing in the file does not change the posture, and keying on the table would log a posture
// change every time somebody added a user — which is a change in accounts, not in how LabView is
// gated. Not the warnings either, since each is paired with a note.
func postureKey(p Posture) string {
	var b strings.Builder
	if p.Mode.Enforced {
		b.WriteString("enforced")
	} else {
		b.WriteString("open")
	}
	for _, m := range p.Mode.Methods {
		b.WriteString("|" + string(m))
	}
	for _, n := range p.Mode.Notes {
		b.WriteString("\n" + n)
	}
	return b.String()
}
