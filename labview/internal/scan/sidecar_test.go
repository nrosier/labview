package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
)

// sidecarFilenames is the §3.1 default, in order.
var sidecarFilenames = []string{".labview", ".labview.yml", ".labview.yaml"}

// readOne writes one sidecar into a fresh stack directory and reads it back, with `app` and
// `db` as the services the compose file defines.
func readOne(t *testing.T, name, body string) sidecarResult {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return readSidecar(sidecarInput{
		Dir:       dir,
		Root:      NewRoot(dir),
		Filenames: sidecarFilenames,
		Services:  []string{"app", "db"},
		RedactURI: true,
	})
}

// TestSidecarWarnings is the §6.1 table: every shape the specification lists, asserted as a
// literal. The `where` prefixes are part of the assertion — a warning that cannot be traced
// back to the line that caused it is not actionable.
func TestSidecarWarnings(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		// ---- a wrong type ----------------------------------------------------------
		{
			name: "the file is not a mapping",
			body: "just a string\n",
			want: []string{".labview: expected a mapping; ignored"},
		}, {
			name: "services is not a mapping",
			body: "services: app\n",
			want: []string{".labview.services: expected a mapping; ignored"},
		}, {
			name: "one service is not a mapping",
			body: "services:\n  app: a description, written at the wrong level\n",
			want: []string{".labview services.app: expected a mapping; ignored"},
		}, {
			name: "a string field is not text",
			body: "description:\n  - one\n  - two\n",
			want: []string{".labview.description: expected text; ignored"},
		}, {
			name: "a link entry is not a mapping",
			body: "links:\n  - https://example.com/\n",
			want: []string{".labview.links[0]: expected {label, url}; ignored"},
		}, {
			name: "a dependency entry is neither a name nor a mapping",
			body: "dependencies:\n  - - nested\n",
			want: []string{".labview.dependencies[0]: expected a name or {name, detail}; ignored"},
		}, {
			name: "a depends_on entry is neither a reference nor a mapping",
			body: "services:\n  app:\n    depends_on:\n      - - nested\n",
			want: []string{`.labview services.app.depends_on[0]: expected "stack/service" or {service, detail}; ignored`},
		}, {
			name: "an auth entry is neither a name nor a mapping",
			body: "services:\n  app:\n    auth:\n      - - nested\n",
			want: []string{".labview services.app.auth[0]: expected a mechanism name or {mechanism, detail}; ignored"},
		}, {
			name: "unauthenticated is not a mapping",
			body: "services:\n  app:\n    unauthenticated: true\n",
			want: []string{".labview services.app.unauthenticated: expected {intentional, reason}; ignored"},
		}, {
			name: "expected is not a mapping",
			body: "services:\n  app:\n    expected: lan\n",
			want: []string{".labview services.app.expected: expected {ingress}; ignored"},
		}, {
			name: "the ingress list is a mapping",
			body: "services:\n  app:\n    expected:\n      ingress:\n        kind: lan\n",
			want: []string{".labview services.app.expected.ingress: expected a list; ignored"},
		},

		// ---- a missing required half -----------------------------------------------
		{
			name: "a link with no url",
			body: "links:\n  - label: Dashboard\n",
			want: []string{`.labview.links[0]: needs a "url"; ignored`},
		}, {
			name: "a link whose url is written empty",
			body: "links:\n  - label: Dashboard\n    url: \"\"\n",
			want: []string{`.labview.links[0]: needs a "url"; ignored`},
		}, {
			// The wrong type is one mistake and produces one warning: `needs a "url"` would
			// be a second sentence about the same line.
			name: "a link whose url is the wrong type",
			body: "links:\n  - label: Dashboard\n    url:\n      - https://a/\n",
			want: []string{".labview.links[0].url: expected text; ignored"},
		}, {
			name: "a dependency mapping with no name",
			body: "dependencies:\n  - detail: somewhere out there\n",
			want: []string{`.labview.dependencies[0]: needs a "name"; ignored`},
		}, {
			name: "a depends_on mapping with no service",
			body: "services:\n  app:\n    depends_on:\n      - detail: something\n",
			want: []string{`.labview services.app.depends_on[0]: needs a "service"; ignored`},
		}, {
			name: "an auth mapping with no mechanism",
			body: "services:\n  app:\n    auth:\n      - detail: a login of some kind\n",
			want: []string{`.labview services.app.auth[0]: needs a "mechanism"; ignored`},
		}, {
			name: "an acceptance that does not say it is intentional",
			body: "services:\n  app:\n    unauthenticated:\n      reason: trusted VLAN only\n",
			want: []string{`.labview services.app.unauthenticated: needs "intentional: true" to apply; ignored`},
		},

		// ---- a value outside a closed set -------------------------------------------
		{
			// The vocabulary is about who enforces the login, not which vendor supplies it,
			// so a product name is the mistake this warning exists for (§4.5).
			name: "a mechanism named after a product",
			body: "services:\n  app:\n    auth:\n      - authentik-proxy\n",
			want: []string{`.labview services.app.auth[0]: "authentik-proxy" is not a known mechanism (` +
				`app-local-accounts, app-ldap, app-oidc, app-saml, app-token, mtls, ` +
				`network-restricted, external-proxy, other); ignored`},
		}, {
			// In the mapping spelling the warning names the field, not just the entry.
			name: "a bad mechanism in the mapping spelling",
			body: "services:\n  app:\n    auth:\n      - mechanism: sso\n        detail: via the proxy\n",
			want: []string{`.labview services.app.auth[0].mechanism: "sso" is not a known mechanism (` +
				`app-local-accounts, app-ldap, app-oidc, app-saml, app-token, mtls, ` +
				`network-restricted, external-proxy, other); ignored`},
		}, {
			name: "other names no mechanism on its own",
			body: "services:\n  app:\n    auth:\n      - other\n",
			want: []string{`.labview services.app.auth[0]: needs a "detail" — "other" names no mechanism on its own; ignored`},
		}, {
			name: "an ingress kind outside the closed set",
			body: "services:\n  app:\n    expected:\n      ingress:\n        - vpn\n",
			want: []string{`.labview services.app.expected.ingress[0]: "vpn" is not one of ` +
				`public, traefik, lan, internal, none; ignored`},
		}, {
			name: "a service reference with a space in it",
			body: "services:\n  app:\n    depends_on:\n      - the media stack\n",
			want: []string{`.labview services.app.depends_on[0]: "the media stack" is not a service reference — ` +
				`write "stack/service", or the service name on its own; ignored`},
		}, {
			name: "a service reference with too many parts",
			body: "services:\n  app:\n    depends_on:\n      - fleet/stack/service\n",
			want: []string{`.labview services.app.depends_on[0]: "fleet/stack/service" is not a service reference — ` +
				`write "stack/service", or the service name on its own; ignored`},
		},

		// ---- a typo, and the two that explain rather than name a type ---------------
		{
			name: "unknown keys are named in one warning, in the order the file writes them",
			body: "descripton: typo\ndescription: read\nowners: also a typo\n",
			want: []string{`.labview: unknown key(s) "descripton", "owners"; ignored`},
		}, {
			name: "an unknown key at service level",
			body: "services:\n  app:\n    describe: typo\n",
			want: []string{`.labview services.app: unknown key(s) "describe"; ignored`},
		}, {
			// A real key written at the wrong level. Lumping it in with typos would not tell
			// the operator what to do about it.
			name: "depends_on at stack level",
			body: "depends_on:\n  - other/service\n",
			want: []string{`.labview: "depends_on" is a service-level key — at stack level it cannot ` +
				`say which service depends on the target; ignored`},
		}, {
			name: "an acceptance with no reason",
			body: "services:\n  app:\n    unauthenticated:\n      intentional: true\n",
			want: []string{`.labview services.app.unauthenticated: "intentional: true" needs a "reason" — ` +
				`an acceptance with no reason cannot be told from a mistake; ignored`},
		},

		// ---- a declaration for a service that does not exist -------------------------
		{
			name: "a declaration for a service the compose file does not define",
			body: "services:\n  ghost:\n    description: renamed and nobody carried it over\n",
			want: []string{`.labview services.ghost: the compose file defines no service "ghost"; ignored`},
		},

		// ---- a valid file warns about nothing ---------------------------------------
		{
			name: "every accepted key at both levels",
			body: `description: A stack.
owner: platform
criticality: high
notes: nothing unusual
data: user uploads
links:
  - label: UI
    url: https://ui.example.com/
dependencies:
  - name: offsite backup
    detail: nightly
services:
  app:
    description: The app.
    owner: platform
    criticality: high
    notes: none
    data: sessions
    links:
      - label: Admin
        url: https://ui.example.com/admin
    dependencies:
      - an external DNS provider
    depends_on:
      - other/db
      - service: db
        detail: reads the catalogue
    auth:
      - app-oidc
      - mechanism: other
        detail: a bearer token minted by hand
    unauthenticated:
      intentional: true
      reason: read-only status page
    expected:
      ingress:
        - lan
        - internal
`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readOne(t, ".labview", tt.body)
			if !reflect.DeepEqual(got.Warnings, tt.want) {
				t.Errorf("warnings:\n got %#v\nwant %#v", got.Warnings, tt.want)
			}
		})
	}
}

// TestSidecarCaps covers the bounds of §6.1. The sidecar is untrusted input served verbatim
// on the API, so each of these is a limit on what one file can make a reader render.
func TestSidecarCaps(t *testing.T) {
	t.Run("a string is truncated with an ellipsis", func(t *testing.T) {
		res := readOne(t, ".labview", "description: "+strings.Repeat("x", 2500)+"\n")
		want := []string{".labview.description: truncated to 2000 characters"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Fatalf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
		if res.Stack == nil {
			t.Fatal("the truncated value should still be kept")
		}
		// 2000 characters and the ellipsis that marks where it stopped.
		if n := len([]rune(res.Stack.Description)); n != 2001 {
			t.Errorf("kept %d characters, want 2001", n)
		}
		if !strings.HasSuffix(res.Stack.Description, "…") {
			t.Error("the truncated value does not end in an ellipsis")
		}
	})

	t.Run("characters, not bytes", func(t *testing.T) {
		// 1500 three-byte characters is over the byte limit and under the character limit.
		res := readOne(t, ".labview", "description: "+strings.Repeat("ま", 1500)+"\n")
		if len(res.Warnings) != 0 {
			t.Errorf("a value under the character limit was truncated: %#v", res.Warnings)
		}
	})

	t.Run("links are capped at 32", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("links:\n")
		for i := 0; i < 40; i++ {
			b.WriteString("  - {label: L, url: 'https://h/" + itoa(i) + "'}\n")
		}
		res := readOne(t, ".labview", b.String())
		want := []string{".labview.links: more than 32 entries; the rest ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Fatalf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
		if n := len(res.Stack.Links); n != 32 {
			t.Errorf("kept %d links, want 32", n)
		}
	})

	t.Run("dependencies are capped at 32", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("dependencies:\n")
		for i := 0; i < 33; i++ {
			b.WriteString("  - dep" + itoa(i) + "\n")
		}
		res := readOne(t, ".labview", b.String())
		want := []string{".labview.dependencies: more than 32 entries; the rest ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Errorf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
	})

	t.Run("depends_on is capped at 32", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("services:\n  app:\n    depends_on:\n")
		for i := 0; i < 33; i++ {
			b.WriteString("      - other/svc" + itoa(i) + "\n")
		}
		res := readOne(t, ".labview", b.String())
		want := []string{".labview services.app.depends_on: more than 32 entries; the rest ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Errorf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
	})

	t.Run("auth is capped at 8 per service", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("services:\n  app:\n    auth:\n")
		for i := 0; i < 9; i++ {
			b.WriteString("      - app-oidc\n")
		}
		res := readOne(t, ".labview", b.String())
		want := []string{".labview services.app.auth: more than 8 entries; the rest ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Fatalf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
		if n := len(res.Services["app"].Auth); n != 8 {
			t.Errorf("kept %d auth entries, want 8", n)
		}
	})

	t.Run("an over-size file is ignored, naming both numbers", func(t *testing.T) {
		body := "description: " + strings.Repeat("x", 70<<10) + "\n"
		res := readOne(t, ".labview", body)
		want := []string{".labview: " + itoa(len(body)) + " bytes is over the 65536 byte limit; ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Errorf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
		if res.Stack != nil || res.Services != nil {
			t.Error("an over-size file must contribute nothing")
		}
	})
}

// TestSidecarThreeDetails covers the three §6.1 names as the ones an implementation gets
// wrong by default.
func TestSidecarThreeDetails(t *testing.T) {
	t.Run("a url is redacted before the label falls back to it", func(t *testing.T) {
		res := readOne(t, ".labview", "links:\n  - url: https://admin:hunter2@ui.example.com/\n")
		if len(res.Warnings) != 0 {
			t.Fatalf("unexpected warnings: %#v", res.Warnings)
		}
		link := res.Stack.Links[0]
		if strings.Contains(link.URL, "hunter2") {
			t.Errorf("url still carries the password: %q", link.URL)
		}
		// The other order is the failure this pins: a password in visible link text.
		if strings.Contains(link.Label, "hunter2") {
			t.Errorf("label still carries the password: %q", link.Label)
		}
		if link.Label != link.URL {
			t.Errorf("label %q should have fallen back to the redacted url %q", link.Label, link.URL)
		}
		if !strings.Contains(link.URL, secrets.Mask) {
			t.Errorf("url %q was not redacted", link.URL)
		}
	})

	t.Run("a list-or-scalar value is tried as a list first", func(t *testing.T) {
		// A list reaching the single-entry reader would be reported as the wrong type — a
		// warning about the operator's correct file.
		res := readOne(t, ".labview", "dependencies:\n  - one\n  - two\n")
		if len(res.Warnings) != 0 {
			t.Fatalf("unexpected warnings: %#v", res.Warnings)
		}
		if n := len(res.Stack.Dependencies); n != 2 {
			t.Fatalf("read %d dependencies, want 2", n)
		}
		// And the scalar spelling still works, because the list is tried first and not only.
		res = readOne(t, ".labview", "dependencies: just the one\n")
		if len(res.Warnings) != 0 || len(res.Stack.Dependencies) != 1 {
			t.Errorf("the scalar spelling was refused: %#v %#v", res.Warnings, res.Stack)
		}
	})

	t.Run("an all-empty block produces no declaration", func(t *testing.T) {
		res := readOne(t, ".labview", "services:\n  app:\n    description: \"\"\n    links: []\n")
		if res.Stack != nil {
			t.Errorf("an empty stack block produced a declaration: %#v", res.Stack)
		}
		if res.Services != nil {
			t.Errorf("an empty service block produced a declaration: %#v", res.Services)
		}
	})
}

func TestSidecarReading(t *testing.T) {
	t.Run("the first candidate that exists wins", func(t *testing.T) {
		dir := t.TempDir()
		// Written in reverse order, so a reader that took the newest or the last would
		// pick the wrong one.
		for name, desc := range map[string]string{
			".labview.yaml": "third",
			".labview.yml":  "second",
			".labview":      "first",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("description: "+desc+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		res := readSidecar(sidecarInput{
			Dir: dir, Root: NewRoot(dir), Filenames: sidecarFilenames, Services: []string{"app"},
		})
		if res.Stack == nil || res.Stack.Description != "first" {
			t.Fatalf("read %#v, want the first candidate", res.Stack)
		}
		// §6.1 records the basename, never a full path (I2).
		if res.Stack.File != ".labview" {
			t.Errorf("file = %q, want the basename", res.Stack.File)
		}
	})

	t.Run("a later candidate is read when the first is absent", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".labview.yml"), []byte("description: second\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res := readSidecar(sidecarInput{
			Dir: dir, Root: NewRoot(dir), Filenames: sidecarFilenames, Services: []string{"app"},
		})
		if res.Stack == nil || res.Stack.File != ".labview.yml" {
			t.Fatalf("read %#v, want .labview.yml", res.Stack)
		}
	})

	t.Run("no sidecar at all is not a finding", func(t *testing.T) {
		dir := t.TempDir()
		res := readSidecar(sidecarInput{
			Dir: dir, Root: NewRoot(dir), Filenames: sidecarFilenames, Services: []string{"app"},
		})
		if res.Stack != nil || res.Services != nil || res.Warnings != nil {
			t.Errorf("a stack without a sidecar produced %#v", res)
		}
	})

	t.Run("an empty file declares nothing", func(t *testing.T) {
		res := readOne(t, ".labview", "")
		if res.Stack != nil || res.Warnings != nil {
			t.Errorf("an empty file produced %#v", res)
		}
	})

	t.Run("a file that is not YAML is reported and not fatal", func(t *testing.T) {
		res := readOne(t, ".labview", "description: [unclosed\n")
		if len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0], ".labview: is not valid YAML: ") {
			t.Fatalf("warnings: %#v", res.Warnings)
		}
		if !strings.HasSuffix(res.Warnings[0], "; ignored") {
			t.Errorf("warning does not follow the formula: %q", res.Warnings[0])
		}
	})

	t.Run("a symlink out of the tree is refused", func(t *testing.T) {
		// The escape is quiet: whatever the link points at would be parsed and served back
		// as a description on the API (§6, I8).
		outer := t.TempDir()
		if err := os.WriteFile(filepath.Join(outer, "outside.labview"),
			[]byte("description: LEAKED\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(outer, "apps", "stack")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outer, "outside.labview"), filepath.Join(dir, ".labview")); err != nil {
			t.Fatal(err)
		}

		res := readSidecar(sidecarInput{
			Dir:       dir,
			Root:      NewRoot(filepath.Join(outer, "apps")).With(dir),
			Filenames: sidecarFilenames,
			Services:  []string{"app"},
		})
		want := []string{".labview: resolves outside the scan root; ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Fatalf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
		if res.Stack != nil {
			t.Errorf("the refused file still produced a declaration: %#v", res.Stack)
		}
	})

	t.Run("a directory named like a sidecar is refused", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, ".labview"), 0o755); err != nil {
			t.Fatal(err)
		}
		res := readSidecar(sidecarInput{
			Dir: dir, Root: NewRoot(dir), Filenames: sidecarFilenames, Services: []string{"app"},
		})
		want := []string{".labview: is a directory; ignored"}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Errorf("warnings:\n got %#v\nwant %#v", res.Warnings, want)
		}
	})
}

// TestSidecarIsNotInterpolated is §6.1's rule that declarations are prose: an operator who
// writes `${VAR}` in a description means those six characters.
func TestSidecarIsNotInterpolated(t *testing.T) {
	res := readOne(t, ".labview", "description: runs on ${HOSTNAME:-somewhere}\n")
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", res.Warnings)
	}
	want := "runs on ${HOSTNAME:-somewhere}"
	if res.Stack.Description != want {
		t.Errorf("description = %q, want %q", res.Stack.Description, want)
	}
}

// TestSidecarValidValues checks that what a good file says arrives intact, in file order,
// with the reference stored exactly as typed — this parser cannot see other stacks, and the
// reference as written is the object a rescan compares (§8, §14).
func TestSidecarValidValues(t *testing.T) {
	res := readOne(t, ".labview", `services:
  app:
    depends_on:
      - db
      - service: other/db
        detail: reads the catalogue
    auth:
      - app-oidc
      - mechanism: network-restricted
        detail: only from the management VLAN
    unauthenticated:
      intentional: true
      reason: read-only status page
    expected:
      ingress: lan
`)
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", res.Warnings)
	}
	app := res.Services["app"]
	if app == nil {
		t.Fatal("no declaration for app")
	}

	wantDeps := []payload.DeclaredServiceDependency{
		{Ref: "db"},
		{Ref: "other/db", Detail: "reads the catalogue"},
	}
	if !reflect.DeepEqual(app.DependsOn, wantDeps) {
		t.Errorf("depends_on:\n got %#v\nwant %#v", app.DependsOn, wantDeps)
	}
	wantAuth := []payload.DeclaredAuth{
		{Mechanism: payload.MechanismAppOIDC},
		{Mechanism: payload.MechanismNetworkRestricted, Detail: "only from the management VLAN"},
	}
	if !reflect.DeepEqual(app.Auth, wantAuth) {
		t.Errorf("auth:\n got %#v\nwant %#v", app.Auth, wantAuth)
	}
	if app.UnauthenticatedAccepted == nil || app.UnauthenticatedAccepted.Reason != "read-only status page" {
		t.Errorf("unauthenticated: %#v", app.UnauthenticatedAccepted)
	}
	// The single-kind spelling, `ingress: lan`, tried after the list and never before.
	if !reflect.DeepEqual(app.ExpectedIngress, []payload.IngressKind{payload.IngressLan}) {
		t.Errorf("expected ingress: %#v", app.ExpectedIngress)
	}
	if app.File != ".labview" {
		t.Errorf("file = %q, want the basename", app.File)
	}
}
