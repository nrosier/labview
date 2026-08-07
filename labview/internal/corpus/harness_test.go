package corpus

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/dockerapi"
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/pipeline"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// Hermeticity (§23)
// ---------------------------------------------------------------------------

// scrubbed is the set of prefixes §23 requires removed from the environment before anything reads
// configuration. Each family names something that would otherwise be able to reach the network from
// a corpus run: an address, a credential, a switch that turns a read on.
//
// LABVIEW_APPS_ROOT and LABVIEW_DOCKER_* are here too although §23 does not list them. The first
// would point a run at a tree that is not a fixture, which changes every count below; the second
// would let an operator with a Docker socket produce a snapshot, which changes `running` and the
// whole of the drift comparison. Neither is a leak, but both are the same category of accident and
// the list is cheaper to over-scrub than to explain.
var scrubbed = []string{
	"LABVIEW_AUTHENTIK_",
	"LABVIEW_TRAEFIK_",
	"LABVIEW_PROBE_",
	"LABVIEW_AUTH_",
	"LABVIEW_OIDC_",
	"LABVIEW_APPS_ROOT",
	"LABVIEW_DOCKER_",
	"LABVIEW_CONFIG",
	"LABVIEW_SESSION_SECRET",
}

// TestMain removes them, once, before the first test function runs.
//
// os.Unsetenv rather than setting them empty, because those are different facts and this program is
// careful about the difference: §3.2 reads a set-and-empty credential as *the operator meant none*
// and reports it as such, so a scrub that emptied variables would leave the corpus running against a
// configuration state no deployment has.
//
// Not restored afterwards. A test binary's environment dies with the process, and a deferred restore
// would only create a window in which a parallel test could observe the original value.
func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		for _, prefix := range scrubbed {
			if strings.HasPrefix(name, prefix) {
				os.Unsetenv(name)
				break
			}
		}
	}
	os.Exit(m.Run())
}

// The scrub happened, and nothing in this package can undo it. Asserted rather than assumed, because
// TestMain runs before every test and a later edit that moves the scrub into a helper would still
// look correct at the call site.
func TestTheEnvironmentCarriesNoLabViewSettings(t *testing.T) {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		for _, prefix := range scrubbed {
			if strings.HasPrefix(name, prefix) {
				t.Fatalf("%s survived the scrub, so this run is not hermetic", name)
			}
		}
	}
}

// An operator's exported settings MUST be unable to change what the corpus asserts (§23).
//
// This is the assertion that makes the *shape* of the harness load-bearing rather than incidental.
// The scrub above is a start-up act; this one holds for the life of the process: a hostile value set
// while the binary is running must still change nothing, which is only true because every run below
// builds its configuration from config.Defaults() and never calls config.Load. A later change that
// reintroduced the loader would fail here, before it could send a credential to `edge.example.com`.
func TestExportedSettingsCannotReachTheCorpus(t *testing.T) {
	before := scanRoot(t, "apps", scanOptions{})

	for name, value := range map[string]string{
		"LABVIEW_APPS_ROOT":         "/nonexistent",
		"LABVIEW_AUTHENTIK_ENABLED": "true",
		"LABVIEW_AUTHENTIK_URL":     "http://198.51.100.7:9000",
		"LABVIEW_AUTHENTIK_TOKEN":   "an-operators-real-token",
		"LABVIEW_TRAEFIK_ENABLED":   "true",
		"LABVIEW_TRAEFIK_URL":       "https://edge.example.com",
		"LABVIEW_PROBE_ENABLED":     "true",
		"LABVIEW_PROBE_LAN_HOST":    "198.51.100.8",
		"LABVIEW_DOCKER_ENABLED":    "true",
	} {
		t.Setenv(name, value)
	}

	after := scanRoot(t, "apps", scanOptions{})

	// Compared through the counts and the connection block rather than byte-for-byte: the clock is a
	// counter so the payloads are identical anyway, and naming the parts says which of them an
	// escaped variable would have moved. The counts go through JSON because `byAuthMethod` is a map
	// and a struct holding one is not comparable — and the JSON is what a consumer reads anyway.
	if a, b := marshal(t, before.Stats), marshal(t, after.Stats); a != b {
		t.Fatalf("exported settings changed the counts:\n before %s\n after  %s", a, b)
	}
	if len(before.Meta.Connections) != len(after.Meta.Connections) {
		t.Fatalf("exported settings changed the connection block: %d targets became %d",
			len(before.Meta.Connections), len(after.Meta.Connections))
	}
	for i, report := range before.Meta.Connections {
		if got := after.Meta.Connections[i]; got.Target != report.Target || got.Phase != report.Phase ||
			got.Endpoint != report.Endpoint {
			t.Fatalf("exported settings changed the %s connection: %s at %q became %s at %q",
				report.Target, report.Phase, report.Endpoint, got.Phase, got.Endpoint)
		}
	}
	if after.Meta.DockerAvailable {
		t.Fatalf("LABVIEW_DOCKER_ENABLED reached the scan")
	}
}

// ---------------------------------------------------------------------------
// One run
// ---------------------------------------------------------------------------

// scanOptions is what differs between two runs of the corpus.
//
// Everything absent from it is fixed for every root: Docker off, the proxy read off, the identity
// provider off, the probe off, no configuration file, a counter for a clock.
type scanOptions struct {
	// rt answers every outbound request. Nil means no transport is injected at all, which is only
	// correct for a root where every integration is off — and a stray request would then reach the
	// real network, so the roots that need one always supply one.
	rt http.RoundTripper

	// mutate turns on what this root is about. It receives the hermetic default.
	mutate func(*config.Config)

	// probe is §13.7's override, nil for *use the configuration*.
	probe *bool
}

// root resolves a fixture root to the path the scan walks.
//
// Relative, because that is what a compose tree looks like to the walk and because §6's containment
// rule is expressed against the resolved root — handing it an absolute path would test the same rule
// through a shorter code path than a deployment uses.
func root(name string) string { return filepath.Join("..", "..", "fixtures", name) }

// hermetic is the configuration every run starts from: the defaults, with the four outbound reads
// switched off and the root pointed at a fixture.
//
// Built from config.Defaults() and never from config.Load, which is what makes the assertion above
// true. The token is set because a read that is switched on needs one to send; the value is a string
// the stub demands verbatim and is not a credential.
func hermetic(name string) config.Config {
	cfg := config.Defaults()
	cfg.AppsRoot = root(name)
	cfg.Docker.Enabled = false
	cfg.Authentik.Enabled = false
	cfg.Traefik.Enabled = false
	cfg.Probe.Enabled = false
	return cfg
}

// scanRoot runs the whole pipeline over one fixture root and returns the payload.
//
// The clock is a counter rather than time.Now, so `durationMs` is a fixed number and two runs of one
// root are byte-identical (I7) — which is what lets a test compare two payloads at all. The
// filesystem is a fake that reports nothing exists, so the Docker pre-check cannot see the host's
// real socket even if a future edit switches the Engine read on by accident.
func scanRoot(t *testing.T, name string, o scanOptions) payload.Overview {
	t.Helper()

	cfg := hermetic(name)
	if o.mutate != nil {
		o.mutate(&cfg)
	}

	out := pipeline.Run(context.Background(), pipeline.Options{
		Cfg:        cfg,
		Now:        counter(),
		Probe:      o.probe,
		Build:      payload.BuildStamp{Version: "0.0.0-corpus", Source: payload.BuildUnknown},
		Filesystem: noFilesystem{},
		Clients:    injected(o.rt),
	})

	// Every root asserts something else; all of them assert this. A payload with a null where a
	// required list belongs is one an operator's `jq` pipeline breaks on (§16), and the walk that
	// prevents it runs at the end of every scan whatever the root contained.
	if len(out.Stacks) == 0 && name != "auth" {
		t.Fatalf("%s produced no stacks, so the root was not read", root(name))
	}
	return out
}

// injected wraps one RoundTripper as all four transports.
//
// One is enough because the stubs below dispatch on the request's host: a corpus run reads at most
// two APIs and the fleet's own services, and they are distinguishable by where they are.
//
// The Docker client is given a socket endpoint so that a run which does switch the Engine read on
// reports the endpoint an operator would recognise rather than an empty string. Nothing listens
// there; the RoundTripper answers before a socket is opened.
func injected(rt http.RoundTripper) pipeline.Clients {
	if rt == nil {
		rt = refusing{}
	}
	one := func(endpoint string) *transport.Client {
		return transport.New(transport.Options{RoundTripper: rt, Endpoint: endpoint, Now: time.Now})
	}
	return pipeline.Clients{
		Docker:    one("unix:///var/run/docker.sock"),
		Authentik: one(""),
		Traefik:   one(""),
		Probe:     one(""),
	}
}

// counter is the injected clock: a fixed base plus a fixed step per call.
//
// A counter rather than a frozen instant, because a frozen clock makes every duration zero and a
// zero duration cannot distinguish *the scan took no measurable time* from *the clock was never
// read*. Seven milliseconds is arbitrary and stable.
func counter() func() time.Time {
	base := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
	n := 0
	return func() time.Time {
		out := base.Add(time.Duration(n) * 7 * time.Millisecond)
		n++
		return out
	}
}

// noFilesystem is the Docker pre-check's whole filesystem, and it holds nothing.
//
// §10's pre-check stats the socket path before the HTTP client sees it. On a developer's machine that
// path frequently exists, which would make one corpus run differ from another by whether Docker
// Desktop happens to be running. This makes the answer the same everywhere.
type noFilesystem struct{}

func (noFilesystem) Stat(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }
func (noFilesystem) Usable(string) error              { return fs.ErrNotExist }

var _ dockerapi.Filesystem = noFilesystem{}

// ---------------------------------------------------------------------------
// Reading a payload back
// ---------------------------------------------------------------------------

// service finds one service by its fleet key, `stack/service`, and fails the test when it is absent.
//
// A missing key is a fatal rather than a nil, because every call site below immediately reads a field
// off it: returning nil would turn a fixture rename into a panic in an unrelated assertion.
func service(t *testing.T, out payload.Overview, key string) payload.Service {
	t.Helper()
	if s := find(out, key); s != nil {
		return *s
	}
	t.Fatalf("no service %q in the payload; it has %s", key, strings.Join(keys(out), ", "))
	return payload.Service{}
}

// find is the same lookup without the assertion, for the tests whose subject is an absence.
func find(out payload.Overview, key string) *payload.Service {
	for i := range out.Stacks {
		for j := range out.Stacks[i].Services {
			if fleet.Key(out.Stacks[i].Name, out.Stacks[i].Services[j].Name) == key {
				return &out.Stacks[i].Services[j]
			}
		}
	}
	return nil
}

// stack finds one stack by name.
func stack(t *testing.T, out payload.Overview, name string) payload.AppStack {
	t.Helper()
	for _, s := range out.Stacks {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no stack %q in the payload", name)
	return payload.AppStack{}
}

// keys is every service key in the payload, for a failure message that says what was there instead.
func keys(out payload.Overview) []string {
	var list []string
	for _, s := range out.Stacks {
		for _, svc := range s.Services {
			list = append(list, fleet.Key(s.Name, svc.Name))
		}
	}
	return list
}

// env finds one environment entry by key.
//
// It returns the entry and not the value, because every question worth asking about an environment
// entry is about the entry: whether it was masked, and which file it came from. A helper that returned
// a string would be a helper that discarded both.
func env(s payload.Service, key string) (payload.EnvVar, bool) {
	for _, v := range s.Env {
		if v.Key == key {
			return v, true
		}
	}
	return payload.EnvVar{}, false
}

// envFileValues is every value in every `.env` file under a fixture root.
//
// It reads the fixtures rather than restating their contents, which is what makes the leak test cover
// a secret somebody adds to a fixture tomorrow. The parsing is deliberately naive — `KEY=value`, no
// quoting, no continuations — because these are files this package controls, and a parser with
// features would be a parser that could silently skip a line and pass.
func envFileValues(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != ".env" {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if name, value, ok := strings.Cut(line, "="); ok {
				out[strings.TrimSpace(name)] = strings.TrimSpace(value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the env files under %s: %v", dir, err)
	}
	if len(out) == 0 {
		t.Fatalf("no env file values under %s, so the leak test would pass by finding nothing", dir)
	}
	return out
}

// report finds one target's connection report (§15). Every scan emits one per target, whatever
// happened, so an absent report is a bug in the reporting rather than a target that stayed quiet.
func report(t *testing.T, out payload.Overview, target conn.Target) payload.ConnectionReport {
	t.Helper()
	for _, r := range out.Meta.Connections {
		if r.Target == string(target) {
			return r
		}
	}
	t.Fatalf("no %s connection report; the block has %d entries", target, len(out.Meta.Connections))
	return payload.ConnectionReport{}
}

// warned is whether any warning on the payload contains this text. Warnings are prose (§16), so a
// substring is the honest test — asserting the whole sentence would make every wording change a test
// change, and the wording is not the rule.
func warned(out payload.Overview, text string) bool {
	for _, w := range out.Meta.Warnings {
		if strings.Contains(w, text) {
			return true
		}
	}
	return false
}

// noted is the same for one service's notes (§14, §12: a note is where a fact that is nobody's count
// goes).
func noted(s payload.Service, text string) bool {
	for _, n := range s.Notes {
		if strings.Contains(n, text) {
			return true
		}
	}
	return false
}

// marshal renders any part of a payload as the JSON a consumer would receive.
//
// Used where two payloads are compared: the shape being compared is the served one, so comparing the
// served bytes both avoids Go's comparability rules and asserts the thing that actually matters.
func marshal(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("the payload would not marshal: %v", err)
	}
	return string(raw)
}
