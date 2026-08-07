package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// The build stamp of §3.4: which build is running, and whether that is the image's own
// stamp or a checkout's. The distinction is the point — "built from that commit" and
// "started in a tree at that commit" are different claims, and a reader has to be able to
// tell them apart (I1).

const (
	// shortCommitLen is the displayed form.
	shortCommitLen = 7
	// maxCommitLen is the longest value accepted from anywhere.
	maxCommitLen = 40
	// maxGitFileBytes is the refusal threshold for any file read out of .git. A HEAD or a
	// packed-refs larger than this is not something LabView should be parsing (I8).
	maxGitFileBytes = 256 * 1024
	// gitWalkParents is how far up the tree the search goes: the starting directory plus
	// this many parents. §3.4 allows at most four levels of walking up.
	gitWalkParents = 4
)

var (
	// buildSHAPattern is §3.4's rule for LABVIEW_BUILD_SHA. A value that does not match is
	// treated as absent rather than trimmed into a different string: silently turning
	// "v1.2 (dirty)" into "v1.2" would make the binary claim an identity nobody gave it.
	buildSHAPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// refNamePattern bounds what a HEAD may point at. Combined with the ".." check it is
	// I8 in the small: a ref name is used to build a path under .git, so it may not escape.
	refNamePattern = regexp.MustCompile(`^refs/[A-Za-z0-9._\-/]+$`)
	fullSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	anySHAPattern  = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)
)

// Stamp resolves the running build's identity: the environment first, then a checkout, then
// nothing. startDir empty means the working directory.
func Stamp(env Lookup, startDir string) payload.BuildStamp {
	if commit, ok := stampFromEnv(env); ok {
		return payload.BuildStamp{Version: Version, Commit: commit, Source: payload.BuildFromImage}
	}
	if startDir == "" {
		if wd, err := os.Getwd(); err == nil {
			startDir = wd
		}
	}
	if commit, ok := stampFromCheckout(startDir); ok {
		return payload.BuildStamp{Version: Version, Commit: commit, Source: payload.BuildFromCheckout}
	}
	// No commit key at all, never an empty string (§3.4).
	return payload.BuildStamp{Version: Version, Source: payload.BuildUnknown}
}

func stampFromEnv(env Lookup) (string, bool) {
	v, ok := env(BuildSHAVar)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxCommitLen || !buildSHAPattern.MatchString(v) {
		return "", false
	}
	// A full object id is shortened; anything else is used as given, because a tag is a
	// deliberate answer and truncating it would destroy the answer.
	if fullSHAPattern.MatchString(v) {
		return v[:shortCommitLen], true
	}
	return v, true
}

// stampFromCheckout walks up looking for a .git directory and reads HEAD out of it.
//
// A .git that is a *file* — a worktree or submodule pointer — ends the walk with no answer
// rather than being followed. Following it would mean reading a path out of a file and
// then reading files out of that path, which is exactly the kind of indirection I8 exists
// to refuse; and a worktree's commit is not reliably the commit this binary was built at.
func stampFromCheckout(startDir string) (string, bool) {
	dir := startDir
	for i := 0; i <= gitWalkParents; i++ {
		if dir == "" {
			return "", false
		}
		gitPath := filepath.Join(dir, ".git")
		info, err := os.Lstat(gitPath)
		switch {
		case err == nil && info.Mode().IsRegular():
			return "", false
		case err == nil && info.IsDir():
			return commitFromGitDir(gitPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false // the filesystem root
		}
		dir = parent
	}
	return "", false
}

func commitFromGitDir(gitDir string) (string, bool) {
	head, ok := readGitFile(filepath.Join(gitDir, "HEAD"))
	if !ok {
		return "", false
	}
	head = strings.TrimSpace(head)

	if !strings.HasPrefix(head, "ref:") {
		return shortCommit(head)
	}

	name := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
	if !refNamePattern.MatchString(name) || strings.Contains(name, "..") {
		return "", false
	}

	if loose, ok := readGitFile(filepath.Join(gitDir, filepath.FromSlash(name))); ok {
		if commit, ok := shortCommit(strings.TrimSpace(loose)); ok {
			return commit, true
		}
	}
	return commitFromPackedRefs(filepath.Join(gitDir, "packed-refs"), name)
}

// commitFromPackedRefs reads the packed form, ignoring comment lines and peeled entries.
// A peeled line ("^<sha>") is the object a tag points at, not the ref's own value.
func commitFromPackedRefs(path, name string) (string, bool) {
	data, ok := readGitFile(path)
	if !ok {
		return "", false
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		sha, ref, found := strings.Cut(line, " ")
		if !found || strings.TrimSpace(ref) != name {
			continue
		}
		return shortCommit(sha)
	}
	return "", false
}

// readGitFile reads a file under .git, refusing anything over the size threshold. The size
// is checked before the read rather than after, so a large file is never held in memory.
func readGitFile(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxGitFileBytes {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// shortCommit accepts an object id and returns its seven-character form. Unlike the
// environment path, a value read out of .git must be an object id: there is no case in
// which a ref file legitimately holds a tag name.
func shortCommit(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if !anySHAPattern.MatchString(v) {
		return "", false
	}
	return v[:shortCommitLen], true
}
