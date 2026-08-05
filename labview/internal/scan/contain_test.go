package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// containTree builds the shape every case here needs:
//
//	tmp/secret.env          the file outside the root
//	tmp/apps/               the scan root
//	tmp/apps/stack/         a stack directory
//	tmp/apps/stack/local.env
//	tmp/apps/stack/escape   a symlink to ../../secret.env
//	tmp/apps/stack/dangling a symlink to a file that does not exist, outside the root
//	tmp/appsX/              a sibling whose name begins with the root's
//	tmp/link-to-apps        a symlink to tmp/apps
func containTree(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()

	mkdir := func(parts ...string) string {
		p := filepath.Join(append([]string{tmp}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write := func(name string, parts ...string) {
		p := filepath.Join(append([]string{tmp}, parts...)...)
		if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target string, parts ...string) {
		p := filepath.Join(append([]string{tmp}, parts...)...)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}

	mkdir("apps", "stack")
	mkdir("appsX")
	write("outside", "secret.env")
	write("inside", "apps", "stack", "local.env")
	link("../../secret.env", "apps", "stack", "escape")
	link("../../nothing-here.env", "apps", "stack", "dangling")
	link(filepath.Join(tmp, "apps"), "link-to-apps")
	return tmp
}

func TestRootAllows(t *testing.T) {
	tmp := containTree(t)
	root := NewRoot(filepath.Join(tmp, "apps"))

	tests := []struct {
		name string
		path string
		want bool
	}{{
		name: "a file in a stack directory",
		path: filepath.Join(tmp, "apps", "stack", "local.env"),
		want: true,
	}, {
		name: "the root itself",
		path: filepath.Join(tmp, "apps"),
		want: true,
	}, {
		// Lexical: this never gets as far as a syscall.
		name: "a lexical escape",
		path: filepath.Join(tmp, "apps", "stack", "..", "..", "secret.env"),
		want: false,
	}, {
		name: "the unresolved form of the same escape",
		path: filepath.Join(tmp, "apps", "stack") + "/../../secret.env",
		want: false,
	}, {
		// Through a symlink: the lexical check passes and the resolver is what refuses.
		name: "a symlink out of the tree",
		path: filepath.Join(tmp, "apps", "stack", "escape"),
		want: false,
	}, {
		// A file that is not there still has to name a place inside the root, or a
		// missing-file diagnostic would be the only thing standing between an escape and a
		// read.
		name: "a dangling symlink pointing outside",
		path: filepath.Join(tmp, "apps", "stack", "dangling"),
		want: false,
	}, {
		name: "a file that does not exist yet, inside the root",
		path: filepath.Join(tmp, "apps", "stack", "not-created.env"),
		want: true,
	}, {
		name: "a file that does not exist, outside the root",
		path: filepath.Join(tmp, "elsewhere.env"),
		want: false,
	}, {
		// within compares on path boundaries, so /data/appsX is not inside /data/apps.
		name: "a sibling directory whose name begins with the root's",
		path: filepath.Join(tmp, "appsX", "file"),
		want: false,
	}, {
		name: "the parent",
		path: tmp,
		want: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := root.Allows(tt.path); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestRootAcceptsBothForms is the reason the accepted forms are a set: an apps root is
// usually reached through a symlink or a bind mount, and refusing every read under the
// resolved path when the operator wrote the link would make the check reject the fleet.
func TestRootAcceptsBothForms(t *testing.T) {
	tmp := containTree(t)
	root := NewRoot(filepath.Join(tmp, "link-to-apps"))

	// The path as the operator would build it, under the link.
	viaLink := filepath.Join(tmp, "link-to-apps", "stack", "local.env")
	if !root.Allows(viaLink) {
		t.Errorf("Allows(%q) = false, want true (the root as configured)", viaLink)
	}
	// The same file by its resolved path — the spelling an absolute `env_file:` under a
	// bind-mounted root would use. It is derived rather than assembled, because the
	// temporary directory itself sits under a symlink on some platforms and a hand-written
	// path would be testing that link instead of this one.
	realRoot, err := filepath.EvalSymlinks(filepath.Join(tmp, "apps"))
	if err != nil {
		t.Fatal(err)
	}
	viaReal := filepath.Join(realRoot, "stack", "local.env")
	if !root.Allows(viaReal) {
		t.Errorf("Allows(%q) = false, want true (the root resolved)", viaReal)
	}
	// Widening to both forms must not widen to anything else.
	if root.Allows(filepath.Join(tmp, "secret.env")) {
		t.Error("accepting both root forms let a read outside the root through")
	}
	// Path() is the operator's own spelling, because every path in the payload is built
	// from it and a relative root has to stay relative (I7).
	if got := root.Path(); got != filepath.Join(tmp, "link-to-apps") {
		t.Errorf("Path() = %q, want the root as configured", got)
	}
}

// TestRootWith covers the one widening the scan performs: a stack directory that is itself
// a symlink into a storage pool is an ordinary layout, and a read that stays under where
// the stack actually lives has escaped nothing.
func TestRootWith(t *testing.T) {
	tmp := t.TempDir()
	for _, d := range []string{"apps", "pool/media"} {
		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "pool", "media", "local.env"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "pool", "other.env"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// apps/media is a link to the real stack directory in the pool.
	if err := os.Symlink(filepath.Join(tmp, "pool", "media"), filepath.Join(tmp, "apps", "media")); err != nil {
		t.Fatal(err)
	}

	root := NewRoot(filepath.Join(tmp, "apps"))
	target := filepath.Join(tmp, "apps", "media", "local.env")
	if root.Allows(target) {
		t.Fatal("a symlinked stack directory should not be readable before it is discovered")
	}

	scoped := root.With(filepath.Join(tmp, "apps", "media"))
	if !scoped.Allows(target) {
		t.Error("a file in the discovered stack directory should be readable")
	}
	// Scoping to the stack directory must not open its parent in the pool.
	if scoped.Allows(filepath.Join(tmp, "pool", "other.env")) {
		t.Error("scoping to a stack directory opened its parent")
	}
	if scoped.Path() != root.Path() {
		t.Error("With changed the reported root")
	}
}

// TestNewRootOnMissingPath pins that a root that is not there yields a Root that allows
// nothing rather than an error nobody may act on (I4). The scan reports the unreadable
// root; the check simply refuses everything under it.
func TestNewRootOnMissingPath(t *testing.T) {
	root := NewRoot(filepath.Join(t.TempDir(), "not-there"))
	if root.Allows(filepath.Join(root.Path(), "stack", "compose.yml")) {
		t.Error("a missing root allowed a read")
	}
}
