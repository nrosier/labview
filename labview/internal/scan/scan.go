package scan

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nrosier/labview/internal/payload"
)

// Options is what a scan needs from configuration (§3.1). It is a value rather than the
// whole Config so that this package depends on nothing that can reach the network.
type Options struct {
	// Root is the scan root as the operator spelled it. Every path in the result is built
	// from it, so a relative root stays relative and two machines scanning one tree produce
	// the same payload (I7).
	Root string
	// ComposeFilenames are tried in order; the first that exists in a directory makes that
	// directory a stack (§6).
	ComposeFilenames []string
	// SidecarFilenames are the declaration-file candidates (§6.1).
	SidecarFilenames []string
	// RedactURI is secrets.redactUriCredentials (§20).
	RedactURI bool
}

// Result is the scanned half of the payload.
type Result struct {
	// Stacks are sorted by id, which is the directory name.
	Stacks []payload.AppStack
	// Warnings are scan-level: about the root or about a directory, never about a stack's
	// contents. A warning about a stack goes on that stack (§6).
	Warnings []string
}

// Run scans the tree. It never returns an error: a root that cannot be read is a warning
// and an empty fleet, because a payload that says "the root is unreadable" is useful and one
// that says nothing at all is not (I4).
func Run(opts Options) Result {
	root := NewRoot(opts.Root)

	dirs, err := os.ReadDir(opts.Root)
	if err != nil {
		return Result{Warnings: []string{"the scan root could not be read: " + errText(err)}}
	}

	var out Result
	// ReadDir sorts by filename and a stack's id is its directory name, so the stacks come
	// out sorted by id with no second pass.
	for _, d := range dirs {
		if !isDir(opts.Root, d) {
			continue
		}
		stack, warns, ok := scanStack(opts, root, d.Name())
		out.Warnings = append(out.Warnings, warns...)
		if ok {
			out.Stacks = append(out.Stacks, stack)
		}
	}
	return out
}

// isDir reports whether a root entry is a directory, following symlinks. A stack directory
// that is a symlink into a storage pool is an ordinary layout, and skipping it would leave a
// whole stack out of the payload with no warning at all.
func isDir(root string, d fs.DirEntry) bool {
	if d.IsDir() {
		return true
	}
	if d.Type()&fs.ModeSymlink == 0 {
		return false
	}
	info, err := os.Stat(filepath.Join(root, d.Name()))
	return err == nil && info.IsDir()
}

// scanStack reads one candidate directory. It returns ok false for a directory that is not a
// stack — no compose file — which is not a finding: a scan root may hold anything.
func scanStack(opts Options, root Root, id string) (payload.AppStack, []string, bool) {
	dir := root.Join(id)

	names, err := os.ReadDir(dir)
	if err != nil {
		// §6: an unreadable stack directory is a scan-level warning. It cannot be a stack
		// warning, because without the listing there is no stack to put one on.
		return payload.AppStack{}, []string{id + ": the directory could not be read: " + errText(err)}, false
	}

	present := make(map[string]bool, len(names))
	for _, n := range names {
		present[n.Name()] = true
	}

	composeFile := firstPresent(present, opts.ComposeFilenames)
	if composeFile == "" {
		return payload.AppStack{}, nil, false
	}

	stack := payload.AppStack{
		ID:          id,
		Name:        id,
		Dir:         dir,
		ComposeFile: composeFile,
		HasEnvFile:  present[".env"],
		ProjectName: normalizeProjectName(id),
	}

	// The stack directory's own resolved form is accepted from here on. It is discovered by
	// listing the root — never named by a scanned file — which is what keeps this from
	// widening the check the containment rule exists to make (§6, I8).
	scoped := root.With(dir)

	var env []envEntry
	if stack.HasEnvFile {
		entries, warns := readStackEnv(filepath.Join(dir, ".env"))
		env = entries
		stack.Warnings = append(stack.Warnings, warns...)
	}

	data, err := os.ReadFile(filepath.Join(dir, composeFile))
	if err != nil {
		stack.Warnings = append(stack.Warnings, composeFile+": could not be read: "+errText(err))
		return stack, nil, true
	}

	parsed, err := parseCompose(data, composeInput{
		StackID: id,
		Dir:     dir,
		Root:    scoped,
		Env:     env,
	})
	if err != nil {
		// §6: a parse error warns and the stack is **still listed**. A stack that vanishes
		// from the payload because of a typo is the failure mode this rule exists for.
		stack.Warnings = append(stack.Warnings, composeFile+": could not be parsed: "+errText(err))
		return stack, nil, true
	}

	stack.Name = parsed.Name
	stack.ProjectName = parsed.ProjectName
	stack.Services = parsed.Services
	stack.DeclaredNetworks = parsed.Networks
	stack.DeclaredVolumes = parsed.Volumes
	for _, w := range parsed.Warnings {
		stack.Warnings = append(stack.Warnings, composeFile+": "+w)
	}

	attachDeclarations(&stack, readSidecar(sidecarInput{
		Dir:       dir,
		Root:      scoped,
		Filenames: opts.SidecarFilenames,
		Services:  serviceNames(parsed.Services),
		RedactURI: opts.RedactURI,
	}))
	return stack, nil, true
}

// firstPresent is §6's "the configured filenames tried in order", answered from one
// directory listing. Doing it from the listing rather than by stat-ing each candidate is
// what makes an unreadable directory distinguishable from a directory holding no compose
// file: one is a warning and the other is not a stack.
func firstPresent(present map[string]bool, candidates []string) string {
	for _, c := range candidates {
		if c != "" && present[c] {
			return c
		}
	}
	return ""
}

// readStackEnv reads the stack's own .env, which supplies every substitution in the compose
// file and may set COMPOSE_PROJECT_NAME (§6).
func readStackEnv(path string) ([]envEntry, []string) {
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return nil, []string{".env: could not be read: " + errText(err)}
	case info.Size() > maxEnvFileBytes:
		return nil, []string{".env: is larger than " + itoa(maxEnvFileBytes>>20) + " MiB; ignored"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{".env: could not be read: " + errText(err)}
	}
	return parseEnvFile(data), nil
}

func serviceNames(services []payload.Service) []string {
	out := make([]string, 0, len(services))
	for _, s := range services {
		out = append(out, s.Name)
	}
	return out
}

// attachDeclarations puts the sidecar's contents where the payload carries them.
func attachDeclarations(stack *payload.AppStack, decl sidecarResult) {
	stack.Declared = decl.Stack
	stack.Warnings = append(stack.Warnings, decl.Warnings...)
	if len(decl.Services) == 0 {
		return
	}
	for i := range stack.Services {
		if d, ok := decl.Services[stack.Services[i].Name]; ok {
			stack.Services[i].Declared = d
		}
	}
}

// errText is an error's message with any absolute path this process happened to build
// stripped back to what it wraps.
//
// A filesystem error carries the full path it failed on, and a payload naming
// `/mnt/pool/apps/...` publishes the host's layout to every reader of the API (I2). The
// operation and the reason are the useful half and the only half kept.
func errText(err error) string {
	if perr, ok := err.(*fs.PathError); ok {
		return perr.Op + ": " + perr.Err.Error()
	}
	return err.Error()
}
