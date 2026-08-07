package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

const (
	fullSHA  = "0123456789abcdef0123456789abcdef01234567"
	shortSHA = "0123456"
	otherSHA = "fedcba9876543210fedcba9876543210fedcba98"
)

// TestStampFromEnvironment is §3.4's first source. It is the only one that can honestly say
// "built from this commit" — a checkout can only say a tree was at one.
func TestStampFromEnvironment(t *testing.T) {
	cases := []struct {
		value  string
		commit string
		source payload.BuildStampSource
	}{
		// A full object id is shortened to the displayed form.
		{value: fullSHA, commit: shortSHA, source: payload.BuildFromImage},
		{value: "  " + fullSHA + "\n", commit: shortSHA, source: payload.BuildFromImage},
		// Anything else is used as given: a tag is a deliberate answer, and truncating it to
		// seven characters would destroy the answer.
		{value: "v1.2.3", commit: "v1.2.3", source: payload.BuildFromImage},
		{value: "2026.08-nightly", commit: "2026.08-nightly", source: payload.BuildFromImage},
		{value: shortSHA, commit: shortSHA, source: payload.BuildFromImage},
		// Rejected, and therefore absent rather than repaired. Trimming "v1.2 (dirty)" down
		// to something that matches would make the binary claim an identity nobody gave it.
		{value: "", source: payload.BuildUnknown},
		{value: "   ", source: payload.BuildUnknown},
		{value: "v1.2 (dirty)", source: payload.BuildUnknown},
		{value: "sha:" + fullSHA, source: payload.BuildUnknown},
		{value: strings.Repeat("a", maxCommitLen+1), source: payload.BuildUnknown},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			// An empty directory, so a rejected value cannot be rescued by a checkout.
			got := Stamp(MapEnv(map[string]string{BuildSHAVar: c.value}), t.TempDir())
			if got.Source != c.source || got.Commit != c.commit {
				t.Errorf("Stamp = %+v, want commit %q from %q", got, c.commit, c.source)
			}
			if got.Version != Version {
				t.Errorf("version = %q, want %q", got.Version, Version)
			}
		})
	}
}

func TestStampFromCheckout(t *testing.T) {
	t.Run("symbolic HEAD and a loose ref", func(t *testing.T) {
		dir := gitTree(t, map[string]string{
			".git/HEAD":            "ref: refs/heads/main\n",
			".git/refs/heads/main": fullSHA + "\n",
		})
		assertStamp(t, dir, shortSHA, payload.BuildFromCheckout)
	})

	t.Run("detached HEAD", func(t *testing.T) {
		dir := gitTree(t, map[string]string{".git/HEAD": fullSHA + "\n"})
		assertStamp(t, dir, shortSHA, payload.BuildFromCheckout)
	})

	t.Run("packed refs", func(t *testing.T) {
		dir := gitTree(t, map[string]string{
			".git/HEAD": "ref: refs/heads/main\n",
			// The comment line and the peeled entry both have to be skipped: a peeled line is
			// the object a tag points at, not any ref's own value.
			".git/packed-refs": "# pack-refs with: peeled fully-peeled sorted\n" +
				otherSHA + " refs/heads/other\n" +
				fullSHA + " refs/heads/main\n" +
				"^" + otherSHA + "\n",
		})
		assertStamp(t, dir, shortSHA, payload.BuildFromCheckout)
	})

	t.Run("a loose ref wins over the packed form", func(t *testing.T) {
		dir := gitTree(t, map[string]string{
			".git/HEAD":            "ref: refs/heads/main\n",
			".git/refs/heads/main": fullSHA + "\n",
			".git/packed-refs":     otherSHA + " refs/heads/main\n",
		})
		assertStamp(t, dir, shortSHA, payload.BuildFromCheckout)
	})

	t.Run("a ref under a slashed name", func(t *testing.T) {
		dir := gitTree(t, map[string]string{
			".git/HEAD":                     "ref: refs/heads/test/minified\n",
			".git/refs/heads/test/minified": fullSHA + "\n",
		})
		assertStamp(t, dir, shortSHA, payload.BuildFromCheckout)
	})

	t.Run("a short object id is accepted", func(t *testing.T) {
		dir := gitTree(t, map[string]string{".git/HEAD": shortSHA + "\n"})
		assertStamp(t, dir, shortSHA, payload.BuildFromCheckout)
	})
}

// TestStampFromCheckoutRefusals: every one of these ends as unknown rather than as a guess.
func TestStampFromCheckoutRefusals(t *testing.T) {
	t.Run("no .git at all", func(t *testing.T) {
		assertUnknown(t, t.TempDir())
	})

	t.Run("HEAD names a ref that does not exist", func(t *testing.T) {
		assertUnknown(t, gitTree(t, map[string]string{".git/HEAD": "ref: refs/heads/main\n"}))
	})

	t.Run("HEAD holds something that is not an object id", func(t *testing.T) {
		// Unlike the environment path, a value read out of .git must be an object id: there
		// is no case in which a ref file legitimately holds a tag name.
		assertUnknown(t, gitTree(t, map[string]string{".git/HEAD": "v1.2.3\n"}))
	})

	t.Run("HEAD holds too few hex digits", func(t *testing.T) {
		assertUnknown(t, gitTree(t, map[string]string{".git/HEAD": "012345\n"}))
	})

	t.Run("a ref name that tries to leave .git", func(t *testing.T) {
		// I8 in the small: the ref name is used to build a path, so it may not escape.
		dir := gitTree(t, map[string]string{
			".git/HEAD":  "ref: refs/../../../../etc/passwd\n",
			"etc/passwd": fullSHA + "\n",
		})
		assertUnknown(t, dir)
	})

	t.Run("a ref name outside refs/", func(t *testing.T) {
		assertUnknown(t, gitTree(t, map[string]string{
			".git/HEAD":   "ref: config\n",
			".git/config": fullSHA + "\n",
		}))
	})

	t.Run("a file larger than the threshold", func(t *testing.T) {
		// Refused before the read, so an absurd HEAD is never held in memory (I8).
		dir := gitTree(t, map[string]string{
			".git/HEAD": strings.Repeat("x", maxGitFileBytes+1),
		})
		assertUnknown(t, dir)
	})
}

// TestGitFileTerminatesTheWalk. A .git that is a regular file is a worktree or submodule
// pointer. Following it would mean reading a path out of a file and then reading files out
// of that path, which is the kind of indirection I8 exists to refuse — and a worktree's
// commit is not reliably the commit this binary was built at. So the walk stops there rather
// than continuing up to the enclosing repository, whose commit would be the wrong answer
// stated confidently.
func TestGitFileTerminatesTheWalk(t *testing.T) {
	dir := gitTree(t, map[string]string{
		".git/HEAD":              fullSHA + "\n",
		"worktrees/feature/.git": "gitdir: /elsewhere/.git/worktrees/feature\n",
	})
	assertUnknown(t, filepath.Join(dir, "worktrees", "feature"))
	// The enclosing repository is still readable from a directory that has no pointer file.
	assertStamp(t, filepath.Join(dir, "worktrees"), shortSHA, payload.BuildFromCheckout)
}

// TestWalkDepth: §3.4 allows walking up at most four levels, which is read here as the
// starting directory plus four parents.
func TestWalkDepth(t *testing.T) {
	dir := gitTree(t, map[string]string{".git/HEAD": fullSHA + "\n"})

	reach := filepath.Join(dir, "a", "b", "c", "d")
	if err := os.MkdirAll(filepath.Join(reach, "e"), 0o755); err != nil {
		t.Fatal(err)
	}
	assertStamp(t, reach, shortSHA, payload.BuildFromCheckout)
	assertUnknown(t, filepath.Join(reach, "e"))
}

// TestEnvironmentWinsOverCheckout: the image's own stamp is the better claim, so it is not
// second-guessed by whatever tree the process happens to have started in.
func TestEnvironmentWinsOverCheckout(t *testing.T) {
	dir := gitTree(t, map[string]string{".git/HEAD": otherSHA + "\n"})
	got := Stamp(MapEnv(map[string]string{BuildSHAVar: fullSHA}), dir)
	if got.Commit != shortSHA || got.Source != payload.BuildFromImage {
		t.Errorf("Stamp = %+v, want %s from image", got, shortSHA)
	}
}

// TestUnknownOmitsTheCommitKey. §3.4 says the commit is absent when nothing established it,
// not an empty string: a consumer must not have to decide whether "" means unknown.
func TestUnknownOmitsTheCommitKey(t *testing.T) {
	got := Stamp(MapEnv(nil), t.TempDir())
	if got.Source != payload.BuildUnknown {
		t.Fatalf("source = %q, want unknown", got.Source)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "commit") {
		t.Errorf("build stamp = %s, want no commit key", data)
	}
	if !strings.Contains(string(data), `"source":"unknown"`) {
		t.Errorf("build stamp = %s, want the source stated", data)
	}
}

// TestStampDefaultsToTheWorkingDirectory covers the one implicit input: an empty startDir.
// It is the repository's own checkout under test, so the assertion is only that a source was
// established at all and that the two fields agree.
func TestStampDefaultsToTheWorkingDirectory(t *testing.T) {
	got := Stamp(MapEnv(nil), "")
	if got.Source == payload.BuildUnknown && got.Commit != "" {
		t.Errorf("Stamp = %+v: unknown with a commit", got)
	}
	if got.Source != payload.BuildUnknown && got.Commit == "" {
		t.Errorf("Stamp = %+v: a source with no commit", got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// gitTree writes a tree of files under a fresh directory and returns it. Paths are slash-
// separated and relative.
func gitTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func assertStamp(t *testing.T, dir, commit string, source payload.BuildStampSource) {
	t.Helper()
	got := Stamp(MapEnv(nil), dir)
	if got.Commit != commit || got.Source != source {
		t.Errorf("Stamp = %+v, want commit %q from %q", got, commit, source)
	}
}

func assertUnknown(t *testing.T, dir string) {
	t.Helper()
	got := Stamp(MapEnv(nil), dir)
	if got.Source != payload.BuildUnknown || got.Commit != "" {
		t.Errorf("Stamp = %+v, want unknown with no commit", got)
	}
}
