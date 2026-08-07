package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// The corpus of §23 is the scan's acceptance evidence. Every root under fixtures/ is a tree
// an operator could have written, and each case below asserts a rule §6 states rather than a
// shape this implementation happens to produce — which is what makes the corpus able to fail
// when a rule is reverted.
//
// The filenames are §3.1's defaults written out rather than imported, so this package keeps
// depending on nothing that reads configuration.
func fixtureOptions(root string) Options {
	return Options{
		Root:             filepath.Join("..", "..", "fixtures", root),
		ComposeFilenames: []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"},
		SidecarFilenames: []string{".labview", ".labview.yml", ".labview.yaml"},
		RedactURI:        true,
	}
}

func scanFixture(t *testing.T, root string) Result {
	t.Helper()
	res := Run(fixtureOptions(root))
	if len(res.Stacks) == 0 {
		t.Fatalf("fixtures/%s produced no stacks; warnings: %v", root, res.Warnings)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("fixtures/%s produced scan-level warnings: %v", root, res.Warnings)
	}
	return res
}

func stackByID(t *testing.T, res Result, id string) payload.AppStack {
	t.Helper()
	for _, s := range res.Stacks {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no stack %q in %d scanned", id, len(res.Stacks))
	return payload.AppStack{}
}

func serviceByName(t *testing.T, s payload.AppStack, name string) payload.Service {
	t.Helper()
	for _, sv := range s.Services {
		if sv.Name == name {
			return sv
		}
	}
	t.Fatalf("stack %q has no service %q", s.ID, name)
	return payload.Service{}
}

// TestFixtureDiscovery pins what §6's discovery produces over the three compose roots: one
// stack per immediate subdirectory holding a compose file, sorted by id, each id its
// directory name and each default project name that id normalised.
func TestFixtureDiscovery(t *testing.T) {
	tests := []struct {
		root string
		ids  []string
	}{{
		root: "apps",
		ids:  []string{"authentik", "emby", "jellyfin", "nextcloud", "outline", "proxy"},
	}, {
		root: "edge",
		ids: []string{
			"accepted", "authentik", "badsidecar", "cfdisabled", "dbstack", "declared",
			"declcompare", "escapedecl", "exposeonly", "hostport", "interp", "ldapapp",
			"otherprovider", "partialdrift", "sharednet", "sidecaryml", "staledecl",
			"tunnelorigin",
		},
	}, {
		root: "nets",
		ids: []string{
			"badref", "disjoint", "layered", "lonely",
			"shared-a", "shared-b", "shared-c", "shared-d",
		},
	}}

	for _, tt := range tests {
		t.Run(tt.root, func(t *testing.T) {
			res := scanFixture(t, tt.root)

			var got []string
			for _, s := range res.Stacks {
				got = append(got, s.ID)
			}
			if strings.Join(got, ",") != strings.Join(tt.ids, ",") {
				t.Fatalf("stacks =\n %v\nwant\n %v", got, tt.ids)
			}

			for _, s := range res.Stacks {
				// The directory name is the id, the default display name and — normalised —
				// the project name, and nothing in this corpus overrides any of them.
				if s.Name != s.ID {
					t.Errorf("%s: Name = %q, want the id", s.ID, s.Name)
				}
				if want := normalizeProjectName(s.ID); s.ProjectName != want {
					t.Errorf("%s: ProjectName = %q, want %q", s.ID, s.ProjectName, want)
				}
				if s.Dir != filepath.Join(fixtureOptions(tt.root).Root, s.ID) {
					t.Errorf("%s: Dir = %q, want it built from the root as configured", s.ID, s.Dir)
				}
				if len(s.Services) == 0 {
					t.Errorf("%s: no services", s.ID)
				}
				// hasEnvFile is the file's presence, so it must agree with the tree.
				_, err := os.Stat(filepath.Join(s.Dir, ".env"))
				if present := err == nil; present != s.HasEnvFile {
					t.Errorf("%s: HasEnvFile = %v, but .env present = %v", s.ID, s.HasEnvFile, present)
				}
			}
		})
	}
}

// TestFixtureEnvFileContainment is the env_file half of §6's containment check.
// fixtures/edge/dbstack lists three env_file entries, one of which climbs out of the root.
// The refusal has to be visible on the service and the entries either side of it have to
// still be read: a containment check that drops the whole list would pass a test that only
// looked for the absent key.
func TestFixtureEnvFileContainment(t *testing.T) {
	api := serviceByName(t, stackByID(t, scanFixture(t, "edge"), "dbstack"), "api")

	const want = `env_file[1]: "../../outside-root.env" is outside the scan root; not read`
	if len(api.Notes) != 1 || api.Notes[0] != want {
		t.Errorf("notes = %#v, want exactly [%q]", api.Notes, want)
	}

	// The entry before the refused one was read...
	loaded, ok := envEntryOf(api, "LOCAL_ENV_FILE_LOADED")
	if !ok || loaded.Value == nil || *loaded.Value != "yes" {
		t.Errorf("LOCAL_ENV_FILE_LOADED = %#v, want the value local.env sets", loaded)
	} else if loaded.Source != payload.EnvFromEnvFile {
		t.Errorf("LOCAL_ENV_FILE_LOADED source = %q, want %q", loaded.Source, payload.EnvFromEnvFile)
	}
	// ...and the refused one contributed nothing.
	if _, ok := envEntryOf(api, "LEAKED_FROM_OUTSIDE_ROOT"); ok {
		t.Error("a key from outside the scan root reached the payload")
	}
}

// TestFixtureSidecarContainment is the sidecar half of the same check.
// fixtures/edge/escapedecl/.labview is a symlink to a valid declaration file outside the
// root: valid on purpose, so that a regression shows up as declarations appearing rather
// than as a differently worded warning (§6.1).
func TestFixtureSidecarContainment(t *testing.T) {
	s := stackByID(t, scanFixture(t, "edge"), "escapedecl")

	const want = ".labview: resolves outside the scan root; ignored"
	if len(s.Warnings) != 1 || s.Warnings[0] != want {
		t.Errorf("warnings = %#v, want exactly [%q]", s.Warnings, want)
	}
	if s.Declared != nil {
		t.Errorf("stack declaration = %#v, want none", s.Declared)
	}
	for _, sv := range s.Services {
		if sv.Declared != nil {
			t.Errorf("%s: service declaration = %#v, want none", sv.Name, sv.Declared)
		}
	}
	// The stack is still listed, with its services, because refusing one file is not a
	// reason to lose the stack (I4).
	if len(s.Services) != 1 {
		t.Errorf("services = %d, want the stack still listed with its service", len(s.Services))
	}
}

// TestFixtureNothingFromOutsideRoot is the containment invariant stated once over the whole
// result: the two files deliberately placed outside fixtures/edge both carry the same
// sentinel, and no field of any kind may carry it (I8). Reading the serialised payload is
// the point — it covers env values, notes, warnings, declarations and anything a later
// change adds, without this test having to know where to look.
func TestFixtureNothingFromOutsideRoot(t *testing.T) {
	const sentinel = "LEAKED_FROM_OUTSIDE_ROOT"

	// The sentinel is only evidence if it is really out there to be found.
	for _, name := range []string{"outside-root.env", "outside-root.labview"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
		if err != nil {
			t.Fatalf("fixtures/%s: %v", name, err)
		}
		if !strings.Contains(string(data), sentinel) {
			t.Fatalf("fixtures/%s no longer carries %s, so this test proves nothing", name, sentinel)
		}
	}

	body, err := json.Marshal(scanFixture(t, "edge"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), sentinel) {
		t.Error("the scan result carries text from a file outside the scan root")
	}
}

// TestFixtureSidecarWarnings walks fixtures/edge/badsidecar, which holds four deliberate
// mistakes and two valid declarations. Both halves are the assertion: every mistake is
// reported in file order, and neither valid declaration is lost to its neighbour.
func TestFixtureSidecarWarnings(t *testing.T) {
	s := stackByID(t, scanFixture(t, "edge"), "badsidecar")

	want := []string{
		`.labview: unknown key(s) "descripton"; ignored`,
		`.labview services.app.auth[0].mechanism: "authentik-proxy" is not a known mechanism ` +
			`(app-local-accounts, app-ldap, app-oidc, app-saml, app-token, mtls, ` +
			`network-restricted, external-proxy, other); ignored`,
		`.labview services.app.unauthenticated: "intentional: true" needs a "reason" — ` +
			`an acceptance with no reason cannot be told from a mistake; ignored`,
		`.labview services.ghost: the compose file defines no service "ghost"; ignored`,
	}
	if len(s.Warnings) != len(want) {
		t.Fatalf("warnings =\n %#v\nwant %d:\n %#v", s.Warnings, len(want), want)
	}
	for i := range want {
		if s.Warnings[i] != want[i] {
			t.Errorf("warnings[%d] =\n %q\nwant\n %q", i, s.Warnings[i], want[i])
		}
	}

	if s.Declared == nil {
		t.Fatal("the stack declaration was lost with the mistyped key")
	}
	if s.Declared.File != ".labview" {
		t.Errorf("declaration file = %q, want the basename", s.Declared.File)
	}
	if s.Declared.Description != "The valid half of this file, which must still be read." {
		t.Errorf("description = %q, want the valid key's text", s.Declared.Description)
	}

	app := serviceByName(t, s, "app")
	if app.Declared == nil {
		t.Fatal("the service declaration was lost with its rejected neighbour")
	}
	if len(app.Declared.Auth) != 1 {
		t.Fatalf("declared auth = %#v, want only the valid mechanism", app.Declared.Auth)
	}
	if got := app.Declared.Auth[0]; got.Mechanism != payload.MechanismAppToken ||
		got.Detail != "An API key is required on every request." {
		t.Errorf("declared auth[0] = %#v, want the app-token declaration", got)
	}
	// The rejected acceptance left nothing behind: a half-read acceptance would read as an
	// operator's statement that being open is intended (§14).
	if app.Declared.UnauthenticatedAccepted != nil {
		t.Errorf("accepted exposure = %#v, want none", app.Declared.UnauthenticatedAccepted)
	}
}

// TestFixtureInterpolation runs the nested-substitution fixture, which a non-recursive
// pattern cannot brace-match. The env sources are the second half of the assertion: §4.8
// makes a value assembled from several sources take the weakest, and reading the tag from
// .env is a different fact from falling through to a literal default.
func TestFixtureInterpolation(t *testing.T) {
	s := stackByID(t, scanFixture(t, "edge"), "interp")
	web := serviceByName(t, s, "web")

	// `${IMAGE_TAG:-${DEFAULT_TAG:-1.27-alpine}}` with DEFAULT_TAG=1.27.2 in .env.
	if web.Image != "nginx:1.27.2" {
		t.Errorf("image = %q, want the inner default resolved from .env", web.Image)
	}

	tests := []struct {
		key    string
		value  string
		source payload.EnvVarSource
	}{{
		// Both levels unset, so the value is a literal nothing pinned: the weakest source.
		key: "DEEP_LITERAL", value: "deep-literal", source: payload.EnvFromShellDefault,
	}, {
		// Outer unset, inner set by .env.
		key: "RESOLVED_HOST", value: "fallback.example.com", source: payload.EnvFromEnvFile,
	}, {
		// Outer set, so the nested default is never evaluated.
		key: "PRESENT_WINS", value: "1.27.2", source: payload.EnvFromEnvFile,
	}, {
		// `$$` is a literal dollar, not a reference, so nothing was substituted at all.
		key: "LITERAL_DOLLAR", value: "cost is $5 per unit", source: payload.EnvFromEnvironment,
	}}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := envEntryOf(web, tt.key)
			if !ok {
				t.Fatalf("%s is absent", tt.key)
			}
			if got.Value == nil || *got.Value != tt.value {
				t.Errorf("value = %v, want %q", got.Value, tt.value)
			}
			if got.Source != tt.source {
				t.Errorf("source = %q, want %q", got.Source, tt.source)
			}
		})
	}

	// Every reference resolved, so there is nothing to report.
	if len(web.Notes) != 0 || len(s.Warnings) != 0 {
		t.Errorf("notes = %v, warnings = %v, want none of either", web.Notes, s.Warnings)
	}
}

// TestFixtureNetworkNames is §6's naming rule read off the corpus the network views are
// built from: a stack-local network is its project name and the declared name joined, an
// external one is verbatim, and only the second spelling can put two stacks on one network.
func TestFixtureNetworkNames(t *testing.T) {
	res := scanFixture(t, "nets")

	declared := map[string][]payload.NetworkDecl{
		"badref":   {{Name: "badref_side"}},
		"disjoint": {{Name: "disjoint_front-side"}, {Name: "disjoint_back-side"}},
		"layered":  {{Name: "layered_inner"}},
		"lonely":   {{Name: "outside", External: true}, {Name: "lonely_island"}},
		"shared-a": {{Name: "backup", External: true}},
		"shared-b": {{Name: "backup", External: true}},
		"shared-c": {{Name: "backup", External: true}},
		"shared-d": {{Name: "backup", External: true}, {Name: "shared-d_watch"}},
	}
	for id, want := range declared {
		got := stackByID(t, res, id).DeclaredNetworks
		if len(got) != len(want) {
			t.Errorf("%s: declared networks = %#v, want %#v", id, got, want)
			continue
		}
		for i := range want {
			// Document order, because §8's `via` is the dependent's compose order.
			if got[i] != want[i] {
				t.Errorf("%s: declared networks[%d] = %#v, want %#v", id, i, got[i], want[i])
			}
		}
	}

	members := map[string][]string{
		"badref/cache":          {"badref_side"},
		"badref/caller":         {"badref_side"},
		"disjoint/back":         {"disjoint_back-side"},
		"disjoint/front":        {"disjoint_front-side"},
		"layered/web":           {"layered_inner"},
		"lonely/edge-facing":    {"outside"},
		"lonely/islanded":       {"lonely_island"},
		"shared-a/db-a":         {"backup"},
		"shared-b/db-b":         {"backup", "shared-b_default"},
		"shared-c/backup-agent": {"backup"},
		"shared-d/monitor":      {"backup"},
		"shared-d/probe":        {"shared-d_watch"},
	}
	for ref, want := range members {
		id, name, _ := strings.Cut(ref, "/")
		got := serviceByName(t, stackByID(t, res, id), name).Networks
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: networks = %v, want %v", ref, got, want)
		}
	}

	// The whole point of the root: four stacks reach one network, and only because each of
	// them declared it external.
	var onBackup []string
	for _, s := range res.Stacks {
		for _, sv := range s.Services {
			for _, n := range sv.Networks {
				if n == "backup" {
					onBackup = append(onBackup, s.ID)
				}
			}
		}
	}
	if strings.Join(onBackup, ",") != "shared-a,shared-b,shared-c,shared-d" {
		t.Errorf("stacks on backup = %v, want the four shared-* stacks", onBackup)
	}
}

// TestFixtureSidecarFilenameOrder covers §6.1's candidate list over the corpus: the stack
// that writes the `.labview.yml` spelling gets its declarations, and the recorded file is
// the basename rather than a path (I2).
func TestFixtureSidecarFilenameOrder(t *testing.T) {
	s := stackByID(t, scanFixture(t, "edge"), "sidecaryml")
	if s.Declared == nil {
		t.Fatal("the .labview.yml spelling was not read")
	}
	if s.Declared.File != ".labview.yml" {
		t.Errorf("declaration file = %q, want the basename of the candidate that matched", s.Declared.File)
	}
	for _, sv := range s.Services {
		if sv.Declared != nil && sv.Declared.File != ".labview.yml" {
			t.Errorf("%s: declaration file = %q, want .labview.yml", sv.Name, sv.Declared.File)
		}
	}
}

// TestScanIsDeterministic is I7 over the corpus: the same tree scanned twice is the same
// payload, byte for byte. Map iteration in service labels, network resolution or sidecar
// merging is the way this usually breaks, and none of it is visible in a single run.
func TestScanIsDeterministic(t *testing.T) {
	for _, root := range []string{"apps", "edge", "nets"} {
		t.Run(root, func(t *testing.T) {
			first, err := json.Marshal(Run(fixtureOptions(root)))
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				again, err := json.Marshal(Run(fixtureOptions(root)))
				if err != nil {
					t.Fatal(err)
				}
				if string(again) != string(first) {
					t.Fatalf("run %d differs from the first", i+2)
				}
			}
		})
	}
}

// TestScanRootDiagnostics covers what discovery does with a tree that is not a tidy corpus.
// These are built here rather than added to fixtures/ because the corpus counts of §23 are
// asserted as literals, and a directory whose permissions the test has to change is not
// something to keep checked in.
func TestScanRootDiagnostics(t *testing.T) {
	tmp := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		full := filepath.Join(tmp, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	const oneService = "services:\n  app:\n    image: a\n"
	write("real/compose.yml", oneService)
	write("real/.env", "TAG=1\n")
	// Both spellings: the configured order decides, not the directory listing.
	write("ordered/docker-compose.yml", oneService)
	write("ordered/compose.yml", oneService)
	// Only the last candidate.
	write("last/docker-compose.yaml", oneService)
	// A directory that is not a stack. Not a finding: a scan root may hold anything.
	write("notes/README.md", "no compose file here\n")
	if err := os.Mkdir(filepath.Join(tmp, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file in the root, however it is named, is not a stack directory.
	write("compose.yml", oneService)
	// A stack directory that is a symlink into a pool is an ordinary layout, and skipping
	// it would leave a whole stack out of the payload with no warning at all.
	write("pool/media/compose.yml", oneService)
	if err := os.Symlink(filepath.Join(tmp, "pool", "media"), filepath.Join(tmp, "linked")); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Root:             tmp,
		ComposeFilenames: []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"},
		SidecarFilenames: []string{".labview"},
	}
	res := Run(opts)

	var ids []string
	for _, s := range res.Stacks {
		ids = append(ids, s.ID)
	}
	// "pool" is a stack directory's parent, not a stack: it holds no compose file itself.
	if want := "last,linked,ordered,real"; strings.Join(ids, ",") != want {
		t.Errorf("stacks = %v, want %s", ids, want)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none: a directory holding no compose file is not a finding", res.Warnings)
	}
	if got := stackByID(t, res, "ordered").ComposeFile; got != "compose.yml" {
		t.Errorf("ordered: compose file = %q, want the first configured candidate present", got)
	}
	if got := stackByID(t, res, "last").ComposeFile; got != "docker-compose.yaml" {
		t.Errorf("last: compose file = %q, want the candidate that is there", got)
	}
	if got := stackByID(t, res, "real"); !got.HasEnvFile {
		t.Error("real: HasEnvFile = false, want the .env that is there")
	}
	if got := stackByID(t, res, "linked"); len(got.Services) != 1 {
		t.Errorf("linked: services = %d, want the symlinked stack read", len(got.Services))
	}
}

// TestScanUnreadableStackDirectory pins §6's split: a directory that cannot be listed is a
// scan-level warning, because without the listing there is no stack to put one on.
func TestScanUnreadableStackDirectory(t *testing.T) {
	tmp := t.TempDir()
	locked := filepath.Join(tmp, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "compose.yml"), []byte("services:\n  app:\n    image: a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("this user can list a directory with no permissions")
	}

	res := Run(Options{Root: tmp, ComposeFilenames: []string{"compose.yml"}})
	if len(res.Stacks) != 0 {
		t.Errorf("stacks = %d, want none", len(res.Stacks))
	}
	const want = "locked: the directory could not be read: open: permission denied"
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Fatalf("warnings = %#v, want exactly [%q]", res.Warnings, want)
	}
	// The message says what failed and why, and not where the tree lives (I2).
	if strings.Contains(res.Warnings[0], tmp) {
		t.Error("the warning publishes a host path")
	}
}

// TestScanUnreadableRoot is I4 at the top: a root that cannot be read is a warning and an
// empty fleet, because a payload that says "the root is unreadable" is useful and one that
// says nothing at all is not.
func TestScanUnreadableRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")
	res := Run(Options{Root: missing, ComposeFilenames: []string{"compose.yml"}})

	if len(res.Stacks) != 0 {
		t.Errorf("stacks = %d, want none", len(res.Stacks))
	}
	const want = "the scan root could not be read: open: no such file or directory"
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Fatalf("warnings = %#v, want exactly [%q]", res.Warnings, want)
	}
	if strings.Contains(res.Warnings[0], missing) {
		t.Error("the warning publishes a host path")
	}
}

// TestScanOverSizeStackEnv bounds the one file every substitution in a stack reads (I8).
func TestScanOverSizeStackEnv(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "big")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  app:\n    image: a:${TAG}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "TAG=1\n" + strings.Repeat("# padding\n", (maxEnvFileBytes/9)+16)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Run(Options{Root: tmp, ComposeFilenames: []string{"compose.yml"}})
	s := stackByID(t, res, "big")
	const want = ".env: is larger than 1 MiB; ignored"
	if len(s.Warnings) == 0 || s.Warnings[0] != want {
		t.Fatalf("warnings = %#v, want %q first", s.Warnings, want)
	}
	// Ignored means ignored: the substitution it would have supplied is unresolved, and the
	// service says so rather than reading as though the file set nothing.
	app := serviceByName(t, s, "app")
	if app.Image != "a:${TAG}" {
		t.Errorf("image = %q, want the reference left as written", app.Image)
	}
	if len(app.Notes) == 0 {
		t.Error("no note about the unresolved reference")
	}
}

// TestScanUnparseableComposeStillLists is §6's other degrade-never-fail rule: a stack whose
// compose file will not parse is still listed. A stack that vanishes from the payload
// because of a typo is the failure mode the rule exists for.
func TestScanUnparseableComposeStillLists(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "broken")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  app:\n   image: a\n  - not a mapping\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Run(Options{Root: tmp, ComposeFilenames: []string{"compose.yml"}})
	s := stackByID(t, res, "broken")
	if len(s.Warnings) != 1 || !strings.HasPrefix(s.Warnings[0], "compose.yml: could not be parsed: ") {
		t.Fatalf("warnings = %#v, want one parse warning", s.Warnings)
	}
	if s.ID != "broken" || s.ComposeFile != "compose.yml" {
		t.Errorf("stack = %#v, want it listed with what is known about it", s)
	}
	if len(s.Services) != 0 {
		t.Errorf("services = %#v, want none: nothing was parsed", s.Services)
	}
}

// envEntryOf is one resolved environment entry by key.
func envEntryOf(sv payload.Service, key string) (payload.EnvVar, bool) {
	for _, e := range sv.Env {
		if e.Key == key {
			return e, true
		}
	}
	return payload.EnvVar{}, false
}
