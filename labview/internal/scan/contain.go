package scan

import (
	"os"
	"path/filepath"
	"strings"
)

// Root is the scan root and the one containment check of §6 (I8).
//
// Every file LabView reads out of a stack directory because a *file in the tree* named it
// — an `env_file` target, a sidecar — goes through Allows first. The check is lexical and
// through symlinks, because either alone is bypassed by the other: `../../etc/shadow`
// defeats a resolver that only follows links, and a `.labview` symlinked at
// `../../outside-root.labview` defeats a check that only compares strings. The corpus has
// one fixture for each (§23).
//
// The accepted forms are a set rather than a single path. Both the literal root and its
// fully resolved form count, because an apps root is usually reached through a symlink or
// a bind mount and refusing every read under `/private/var/...` when the operator wrote
// `/var/...` would make the check reject the whole fleet. Each discovered stack
// directory's resolved form is added the same way and for the same reason: a stack that
// is itself a symlink into a storage pool is an ordinary layout, and a read that stays
// under the directory the stack actually lives in has not escaped anything. Nothing else
// is ever added — in particular nothing derived from a path found in a scanned file,
// which is what the check exists to judge.
type Root struct {
	// path is the root as the operator spelled it, which is what the payload reports.
	path string
	// forms are the absolute prefixes a read may sit under.
	forms []string
}

// NewRoot resolves a configured scan root.
//
// It never fails. A root that does not exist yields a Root that allows nothing, and the
// scan reports an unreadable root — which is the same outcome by a shorter route than
// returning an error nobody may act on (I4).
func NewRoot(path string) Root {
	r := Root{path: path}
	abs, err := filepath.Abs(path)
	if err != nil {
		// Abs only fails when the working directory is unavailable. Clean is then the
		// best remaining answer, and an unclean relative path would fail every check.
		abs = filepath.Clean(path)
	}
	r.forms = append(r.forms, abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil && resolved != abs {
		r.forms = append(r.forms, resolved)
	}
	return r
}

// Path is the root as configured. It is the operator's own spelling on purpose: every
// path in the payload is relative to what they wrote, so a relative root stays relative
// and a scan of the same tree from two machines reads the same (I7).
func (r Root) Path() string { return r.path }

// Join builds a path inside the root from a slash-or-native relative name.
func (r Root) Join(names ...string) string {
	return filepath.Join(append([]string{r.path}, names...)...)
}

// With returns a Root that also accepts reads under dir's resolved form. dir must be a
// directory this scan discovered by listing the root, never one named by a scanned file.
func (r Root) With(dir string) Root {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return r
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return r
	}
	out := Root{path: r.path, forms: make([]string, 0, len(r.forms)+1)}
	out.forms = append(out.forms, r.forms...)
	for _, f := range out.forms {
		if f == resolved {
			return out
		}
	}
	out.forms = append(out.forms, resolved)
	return out
}

// Allows reports whether path may be read.
//
// The path is resolved as far as it exists: a file that is not there yet still has to
// name a place inside the root, or a missing-file diagnostic would be the only thing
// standing between an escape and a read.
func (r Root) Allows(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	if !r.within(abs) {
		return false // lexical: ../../etc/shadow never gets as far as a syscall
	}

	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Not there, or not readable. Resolve the parent instead and re-attach the name,
		// so a symlinked directory holding a file that does not exist is still judged
		// where it actually is.
		parent, perr := filepath.EvalSymlinks(filepath.Dir(abs))
		if perr != nil {
			return false
		}
		real = pointsAt(abs, parent)
	}
	return r.within(real)
}

// pointsAt is where a path that does not resolve would be, given its resolved parent.
//
// A symlink whose target does not exist is the case this exists for. The resolver cannot
// follow it, and treating it as a plain name inside the parent would judge the link where
// it sits rather than where it points — so `.labview -> ../../outside.labview` would pass
// the check as long as the target had not been created yet (§6, I8).
func pointsAt(abs, parent string) string {
	target, err := os.Readlink(abs)
	if err != nil {
		return filepath.Join(parent, filepath.Base(abs)) // an ordinary name, not a link
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(parent, target)
	}
	target = filepath.Clean(target)

	// The target may be a chain, or may itself not exist. Resolve as far as it goes and
	// judge the deepest form obtainable, which is the one closest to where a read lands.
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		return resolved
	}
	if grand, err := filepath.EvalSymlinks(filepath.Dir(target)); err == nil {
		return filepath.Join(grand, filepath.Base(target))
	}
	return target
}

// within is prefix containment on path boundaries, so /data/appsX is not inside
// /data/apps.
func (r Root) within(p string) bool {
	for _, form := range r.forms {
		if p == form {
			return true
		}
		if strings.HasPrefix(p, form+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
