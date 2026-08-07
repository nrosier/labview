package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// The fleet every test below scans
//
// Three stacks, because every interesting stage in §5 is fleet-wide: a middleware defined in one stack
// and referenced from another, a proxy in one stack answering for a service in another, a gate whose
// far end is a third service. One stack could not exercise any of them.
// ---------------------------------------------------------------------------

const mediaCompose = `
services:
  jellyfin:
    image: jellyfin/jellyfin:10.9
    container_name: jellyfin
    environment:
      ADMIN_PASSWORD: hunter2
      PUBLIC_URL: https://media.lan
    networks: [edge, internal]
    labels:
      traefik.enable: "true"
      traefik.http.routers.jellyfin.rule: Host(` + "`media.lan`" + `)
      traefik.http.routers.jellyfin.entrypoints: websecure
      traefik.http.routers.jellyfin.middlewares: authentik@docker
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: pgpass
      # A credential under a name no pattern matches, which is where §20's second rule lives.
      BACKUP_TARGET: postgresql://backup:pgpass@db:5432/media
    networks: [internal]
networks:
  edge:
    external: true
  internal: {}
`

// The reverse proxy, so the proxy API read has an endpoint to discover and stage 11 has somewhere to
// attach what only a live proxy knows. A fleet with no proxy would leave that whole half of §12
// untested here — and, less obviously, would leave the probe's placement untestable, because a read
// that issues no request cannot be shown to have happened first.
const edgeCompose = `
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    networks: [edge]
    ports:
      - "443:443"
      - "8080:8080"
    labels:
      traefik.enable: "true"
      traefik.http.routers.dashboard.rule: Host(` + "`proxy.lan`" + `)
      traefik.http.routers.dashboard.service: api@internal
networks:
  edge:
    external: true
`

const ssoCompose = `
services:
  server:
    image: ghcr.io/goauthentik/server:2024.6
    container_name: authentik-server
    networks: [edge]
    labels:
      traefik.enable: "true"
      traefik.http.routers.authentik.rule: Host(` + "`sso.lan`" + `)
      traefik.http.middlewares.authentik.forwardauth.address: http://server:9000/outpost.goauthentik.io/auth/traefik
networks:
  edge:
    external: true
`

// fleetRoot writes the fixture tree and returns its path.
func fleetRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for dir, body := range map[string]string{
		"edge":  edgeCompose,
		"media": mediaCompose,
		"sso":   ssoCompose,
	} {
		full := filepath.Join(root, dir)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "compose.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// ---------------------------------------------------------------------------
// The fake network
// ---------------------------------------------------------------------------

// socketFS answers the pre-check with a present, usable socket. It is the only filesystem access the
// Docker read makes (§10), so a fake one is the whole of it.
type socketFS struct{}

func (socketFS) Stat(name string) (fs.FileInfo, error) { return socketInfo{name: name}, nil }
func (socketFS) Usable(string) error                   { return nil }

type socketInfo struct{ name string }

func (i socketInfo) Name() string     { return i.name }
func (socketInfo) Size() int64        { return 0 }
func (socketInfo) Mode() fs.FileMode  { return fs.ModeSocket }
func (socketInfo) ModTime() time.Time { return time.Time{} }
func (socketInfo) IsDir() bool        { return false }
func (socketInfo) Sys() any           { return nil }

// engine answers every outbound request from a table and records what was asked, in order.
//
// It is how §23 runs the whole pipeline with no network: the bounds, the classification, the body cap
// and the redirect refusal all remain internal/transport's, and only the bytes are the test's.
type engine struct {
	mu    sync.Mutex
	asked []string // target names, in the order the requests arrived

	// gate is closed the first time a target is asked, so another target's handler can wait on it.
	// It is how the ordering §5 requires is asserted rather than assumed.
	gate  map[string]chan struct{}
	fired map[string]bool

	// holds is what a target's handler runs before answering — the waiting half of the pair above.
	holds map[string]func()

	// bodies overrides the canned answer for one path.
	bodies map[string]string
}

func newEngine() *engine {
	return &engine{
		gate:   map[string]chan struct{}{},
		fired:  map[string]bool{},
		holds:  map[string]func(){},
		bodies: map[string]string{},
	}
}

// target classifies a request by the surface it belongs to, which is the only thing the ordering
// assertions need to know about it.
func target(r *http.Request) string {
	p := r.URL.Path
	switch {
	case p == "/_ping" || strings.HasPrefix(p, "/containers/"):
		return "docker"
	case strings.HasPrefix(p, "/api/v3/"):
		return "authentik"
	case p == "/api/version" || p == "/api/rawdata" || p == "/api/entrypoints":
		return "traefik"
	default:
		return "probe"
	}
}

func (e *engine) record(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.asked = append(e.asked, name)
	if ch, ok := e.gate[name]; ok && !e.fired[name] {
		e.fired[name] = true
		close(ch)
	}
}

// waitFor blocks until the named target has been asked, or gives up. Giving up is a failure the
// caller reports: it means the pipeline serialized two reads §5 requires to overlap.
func (e *engine) waitFor(name string, d time.Duration) bool {
	e.mu.Lock()
	ch, ok := e.gate[name]
	if !ok {
		ch = make(chan struct{})
		e.gate[name] = ch
	}
	if e.fired[name] {
		e.mu.Unlock()
		return true
	}
	e.mu.Unlock()

	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// seen reports whether a target has been asked at least once.
func (e *engine) seen(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, asked := range e.asked {
		if asked == name {
			return true
		}
	}
	return false
}

// order returns the recorded targets.
func (e *engine) order() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.asked...)
}

func (e *engine) RoundTrip(r *http.Request) (*http.Response, error) {
	name := target(r)
	e.record(name)
	if hold := e.holdFor(name); hold != nil {
		hold()
	}

	body, code, ctype := e.answer(r)
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{ctype}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

// holdFor is set by a test that needs one target's request to wait on another's.
func (e *engine) holdFor(name string) func() {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.holds[name]
}

func (e *engine) answer(r *http.Request) (string, int, string) {
	if body, ok := e.bodies[r.URL.Path]; ok {
		return body, 200, "application/json"
	}
	switch {
	case r.URL.Path == "/_ping":
		return "OK", 200, "text/plain"
	case r.URL.Path == "/containers/json":
		return dockerList, 200, "application/json"
	case strings.HasPrefix(r.URL.Path, "/containers/"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		if body, ok := inspects[id]; ok {
			return body, 200, "application/json"
		}
		return `{"message":"no such container"}`, 404, "application/json"
	case r.URL.Path == "/api/v3/root/config/":
		return `{"capabilities":[]}`, 200, "application/json"
	case strings.HasPrefix(r.URL.Path, "/api/v3/"):
		return `{"pagination":{"next":0,"count":0},"results":[]}`, 200, "application/json"
	case r.URL.Path == "/api/version":
		return `{"Version":"3.0.4"}`, 200, "application/json"
	case r.URL.Path == "/api/rawdata":
		return `{"routers":{},"middlewares":{},"services":{}}`, 200, "application/json"
	case r.URL.Path == "/api/entrypoints":
		return `[]`, 200, "application/json"
	default:
		// A probe target. An open page, so the probe reaches a verdict rather than an error.
		return `<html><body><h1>Library</h1><a href="/browse">Browse</a></body></html>`, 200, "text/html"
	}
}

// dockerList is two running containers, keyed so the compose key finds `media/db` and the container
// name finds `media/jellyfin`. That is stage 5's two-key lookup, exercised both ways in one read: the
// service that named its container is found by that name, and the one that did not is found by the
// key Compose itself would have formed.
const dockerList = `[
  {"Id":"aaaaaaaaaaaa0000","Names":["/jellyfin"],"Image":"jellyfin/jellyfin:10.9","State":"running",
   "Status":"Up 2 hours","Labels":{}},
  {"Id":"bbbbbbbbbbbb0000","Names":["/media-db-1"],"Image":"postgres:16","State":"running",
   "Status":"Up 2 hours",
   "Labels":{"com.docker.compose.project":"media","com.docker.compose.service":"db"}}
]`

// inspects is the third of the Docker read's three requests, one per listed container (§10).
var inspects = map[string]string{
	"aaaaaaaaaaaa0000": inspect("aaaaaaaaaaaa0000", "jellyfin", "jellyfin/jellyfin:10.9"),
	"bbbbbbbbbbbb0000": inspect("bbbbbbbbbbbb0000", "media-db-1", "postgres:16"),
}

func inspect(id, name, image string) string {
	return `{
		"Id": "` + id + `",
		"Name": "/` + name + `",
		"Created": "2026-01-01T00:00:00Z",
		"Image": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"RestartCount": 0,
		"Config": {"Image": "` + image + `"},
		"State": {"Status": "running", "Running": true, "StartedAt": "2026-01-02T00:00:00Z"},
		"NetworkSettings": {"Networks": {"edge": {"IPAddress": "172.20.0.2"}}, "Ports": {}}
	}`
}

// ---------------------------------------------------------------------------
// Running one scan
// ---------------------------------------------------------------------------

// clock is a counter, so a scan's own duration is a fixed number and two scans of one fleet are
// byte-identical (I7). Run calls it twice and only from its own goroutine.
func clock() func() time.Time {
	base := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * 7 * time.Millisecond)
		n++
		return t
	}
}

func settings(root string) config.Config {
	cfg := config.Defaults()
	cfg.AppsRoot = root
	cfg.Authentik.Token = "test-token"
	return cfg
}

func clients(rt http.RoundTripper) Clients {
	one := func(endpoint string) *transport.Client {
		return transport.New(transport.Options{RoundTripper: rt, Endpoint: endpoint, Now: time.Now})
	}
	return Clients{
		Docker:    one("unix:///var/run/docker.sock"),
		Authentik: one(""),
		Traefik:   one(""),
		Probe:     one(""),
	}
}

func run(t *testing.T, e *engine, mutate func(*config.Config), probe *bool) payload.Overview {
	t.Helper()
	cfg := settings(fleetRoot(t))
	if mutate != nil {
		mutate(&cfg)
	}
	return Run(context.Background(), Options{
		Cfg:        cfg,
		Now:        clock(),
		Probe:      probe,
		Build:      payload.BuildStamp{Version: "1.2.3", Source: payload.BuildFromImage},
		Filesystem: socketFS{},
		Clients:    clients(e),
	})
}

// service finds one service in the payload by stack id and name.
func service(t *testing.T, out payload.Overview, stack, name string) payload.Service {
	t.Helper()
	for _, s := range out.Stacks {
		if s.ID != stack {
			continue
		}
		for _, v := range s.Services {
			if v.Name == name {
				return v
			}
		}
	}
	t.Fatalf("no service %s/%s in the payload", stack, name)
	return payload.Service{}
}

// envOf finds one environment entry by key, returning the entry rather than the value: masking is a
// property of the entry, and a helper that returned a string would discard the half under test.
func envOf(s payload.Service, key string) (payload.EnvVar, bool) {
	for _, v := range s.Env {
		if v.Key == key {
			return v, true
		}
	}
	return payload.EnvVar{}, false
}

// ---------------------------------------------------------------------------
// I7 — one scan is a function of its arguments
// ---------------------------------------------------------------------------

func TestTwoScansOfOneFleetAreByteIdentical(t *testing.T) {
	// The whole of I7 in one assertion. Every stage that walks a map has to walk it in a fixed order
	// for this to hold, and there are enough of them — the index, the network sets, the middleware
	// registry, the gate resolution — that any one of them regressing shows up here.
	root := fleetRoot(t)
	scan := func() string {
		out := Run(context.Background(), Options{
			Cfg:        settings(root),
			Now:        clock(),
			Build:      payload.BuildStamp{Version: "1.2.3", Source: payload.BuildFromImage},
			Filesystem: socketFS{},
			Clients:    clients(newEngine()),
		})
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	first := scan()
	for i := 0; i < 5; i++ {
		if again := scan(); again != first {
			t.Fatalf("two scans of one fleet differ\nfirst: %s\nthen:  %s", first, again)
		}
	}
}

func TestNoRequiredListIsEverNull(t *testing.T) {
	// The scanner leaves its slices nil, so the payload only satisfies Appendix A because the last
	// thing a scan does is normalize it. Reverting that call fails here.
	out := run(t, newEngine(), nil, nil)

	if out.Meta.Warnings == nil {
		t.Fatal("meta.warnings is a required list and would serialize as null")
	}
	if out.Meta.Connections == nil {
		t.Fatal("meta.connections is a required list and would serialize as null")
	}
	for _, stack := range out.Stacks {
		for _, svc := range stack.Services {
			if svc.Notes == nil {
				t.Fatalf("%s/%s has a null notes list", stack.ID, svc.Name)
			}
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `":null`) {
		t.Fatalf("a required field serialized as null: %s", string(b))
	}
}

// ---------------------------------------------------------------------------
// §5 — the order the stages run in
// ---------------------------------------------------------------------------

func TestAConfiguredEndpointIsAskedBeforeTheDockerSnapshotFinishes(t *testing.T) {
	// §5: a *configured* endpoint depends on nothing in the scan, so its request MUST start before the
	// Docker snapshot and be awaited after, overlapping the two.
	//
	// This is asserted by making it structural: the Docker read cannot complete until the identity
	// provider has been asked. A pipeline that dispatched the read after the snapshot deadlocks here
	// and the wait below reports it, which is what an ordering test has to do to be worth writing —
	// recording two timestamps and comparing them would pass on a fast machine either way.
	e := newEngine()
	e.holds = map[string]func(){
		"docker": func() {
			if !e.waitFor("authentik", 2*time.Second) {
				t.Error("the Docker snapshot ran to completion before the configured identity " +
					"endpoint was asked: §5 requires the two to overlap")
			}
		},
	}

	out := run(t, e, func(c *config.Config) {
		c.Authentik.URL = "https://sso.example.com"
		c.Traefik.Enabled = false
	}, nil)

	if !out.Meta.DockerAvailable {
		t.Fatalf("the fake engine answered, so the snapshot succeeded; got %q", out.Meta.DockerError)
	}
}

func TestADiscoveredEndpointIsAskedAfterTheRoutesAreParsed(t *testing.T) {
	// The other half of §5's scheduling. A read that has to find its own endpoint cannot be dispatched
	// early, because the candidate list comes from the parsed routes and the resolved origins — and the
	// proof that it waited is that it found the fleet's own provider rather than nothing.
	e := newEngine()
	out := run(t, e, nil, nil)

	if out.Meta.Authentik == nil {
		t.Fatal("the identity provider summary is always present (§15)")
	}
	if !strings.Contains(strings.Join(e.order(), ","), "authentik") {
		t.Fatalf("discovery produced no candidate to ask, so stage 9 had nothing to learn; asked %v",
			e.order())
	}
}

func TestTheProbeIsNeverPartOfTheConcurrentReads(t *testing.T) {
	// §5, stated as *the probe MUST NOT join the concurrent reads*, and §13.1's reason: whether this
	// scan found any authentication is unknown until both API reads have landed and pass 2a has derived
	// a posture, so a probe issued alongside them would spend requests on services whose posture was
	// about to make the question pointless.
	// Structural, so a revert cannot pass by scheduling luck: the first probe request checks that both
	// API reads have already been issued, which is only true if it was dispatched after the wait.
	e := newEngine()
	e.holds = map[string]func(){
		"probe": func() {
			for _, read := range []string{"authentik", "traefik"} {
				if !e.seen(read) {
					t.Errorf("a probe request was issued before the %s read: §5 puts the probe "+
						"between the halves of pass 2, not alongside the concurrent reads", read)
				}
			}
		},
	}

	out := run(t, e, func(c *config.Config) { c.Probe.Enabled = true }, nil)

	if !out.Meta.Probe.Enabled {
		t.Fatal("the probe was enabled, so it ran")
	}

	order := e.order()
	firstProbe, lastRead := -1, -1
	for i, name := range order {
		switch name {
		case "probe":
			if firstProbe < 0 {
				firstProbe = i
			}
		case "authentik", "traefik":
			lastRead = i
		}
	}
	if firstProbe < 0 {
		t.Fatalf("no probe request was issued at all; asked %v", order)
	}
	if lastRead > firstProbe {
		t.Fatalf("a probe request preceded an API read, so the probe joined the concurrent "+
			"reads: %v", order)
	}
}

func TestTheConnectionsAreOnePerOutboundTargetInAFixedOrder(t *testing.T) {
	// §15 and I7 together: comparing two scans compares target, ok, phase and endpoint, which is only
	// meaningful if the list itself is in the same order every time.
	out := run(t, newEngine(), nil, nil)

	want := []conn.Target{conn.TargetDocker, conn.TargetAuthentik, conn.TargetTraefik, conn.TargetProbe}
	if len(out.Meta.Connections) != len(want) {
		t.Fatalf("want one report per outbound target a scan uses (%d); got %d",
			len(want), len(out.Meta.Connections))
	}
	for i, target := range want {
		if got := out.Meta.Connections[i].Target; got != string(target) {
			t.Fatalf("connection %d is %q, want %q — the list is conn.Targets order", i, got, target)
		}
	}
}

// ---------------------------------------------------------------------------
// §5 stage 5 — what pass 1 attaches
// ---------------------------------------------------------------------------

func TestTheRoutesAndTheLiveContainerLandOnTheService(t *testing.T) {
	out := run(t, newEngine(), nil, nil)

	jellyfin := service(t, out, "media", "jellyfin")
	if len(jellyfin.Traefik) == 0 {
		t.Fatal("the router its own labels declare is pass 1's, and it is missing")
	}
	if jellyfin.Docker == nil {
		t.Fatal("the container name is one of the two keys a compose file can form (§10)")
	}
	if jellyfin.Docker.State != "running" {
		t.Fatalf("the live state is the engine's, not the file's; got %q", jellyfin.Docker.State)
	}

	db := service(t, out, "media", "db")
	if db.Docker == nil {
		t.Fatal("this one has no container_name, so it is found by the compose key or not at all")
	}
	if db.Docker.Name != "media-db-1" {
		t.Fatalf("and it is the right container; got %q", db.Docker.Name)
	}
}

func TestAServiceWithNoLiveContainerSimplyHasNone(t *testing.T) {
	// I4: an absent Docker read degrades the payload, it does not fail the scan.
	e := newEngine()
	out := run(t, e, func(c *config.Config) { c.Docker.Enabled = false }, nil)

	if out.Meta.DockerAvailable {
		t.Fatal("a disabled integration is not available")
	}
	if got := service(t, out, "media", "jellyfin").Docker; got != nil {
		t.Fatalf("and no live state was invented; got %+v", got)
	}
	if len(out.Stacks) != 3 {
		t.Fatalf("the scan still produced the fleet; got %d stacks", len(out.Stacks))
	}
}

func TestTheIngressSetIsClassifiedAgainstTheWholeFleet(t *testing.T) {
	// Stage 5b. `internal` is a claim about *other* containers, so a service reachable only on a
	// network nothing else joins is not the same as one on a shared network — which is exactly what
	// classifying per-service without the fleet's network index would get wrong.
	out := run(t, newEngine(), nil, nil)

	if len(service(t, out, "media", "db").Ingress) == 0 {
		t.Fatal("a service on a network another service joins has a classified ingress set")
	}
}

// ---------------------------------------------------------------------------
// §3.6 and §13.7 — the one request-scoped setting
// ---------------------------------------------------------------------------

func TestTheProbeOverrideProducesACopyAndNeverAMutation(t *testing.T) {
	// §3.6. The cache may have another build in flight still holding the old value, so a request that
	// overrides `probe.enabled` must not reach back into the configuration it was handed.
	cfg := settings(fleetRoot(t))
	cfg.Probe.Enabled = false
	on := true

	out := Run(context.Background(), Options{
		Cfg:        cfg,
		Now:        clock(),
		Probe:      &on,
		Filesystem: socketFS{},
		Clients:    clients(newEngine()),
	})

	if cfg.Probe.Enabled {
		t.Fatal("the override mutated the caller's configuration")
	}
	if !out.Meta.Probe.Enabled {
		t.Fatal("and the build it belongs to did not see it")
	}
	if out.Meta.Probe.Source != payload.ProbeSourceRequest {
		t.Fatalf("meta.probe.source says where the value came from; got %q", out.Meta.Probe.Source)
	}
}

func TestWithNoOverrideTheProbeValueAndItsSourceAreTheConfigurations(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		out := run(t, newEngine(), func(c *config.Config) { c.Probe.Enabled = enabled }, nil)

		if out.Meta.Probe.Enabled != enabled {
			t.Fatalf("probe.enabled = %v, want the configured %v", out.Meta.Probe.Enabled, enabled)
		}
		if out.Meta.Probe.Source != payload.ProbeSourceConfig {
			t.Fatalf("with no override the source is the configuration; got %q", out.Meta.Probe.Source)
		}
	}
}

func TestAnOverrideThatMatchesTheConfigurationIsStillARequest(t *testing.T) {
	// §13.7: the source records where the value came from, not whether it changed anything. A reader
	// looking at a probe run needs to know it was asked for.
	off := false
	out := run(t, newEngine(), func(c *config.Config) { c.Probe.Enabled = false }, &off)

	if out.Meta.Probe.Source != payload.ProbeSourceRequest {
		t.Fatalf("got %q, want the request", out.Meta.Probe.Source)
	}
}

// ---------------------------------------------------------------------------
// §20 — masking is the last thing pass 2 does
// ---------------------------------------------------------------------------

func TestAMaskedValueIsMaskedInThePayload(t *testing.T) {
	out := run(t, newEngine(), nil, nil)

	for _, svc := range []payload.Service{
		service(t, out, "media", "jellyfin"),
		service(t, out, "media", "db"),
	} {
		for _, env := range svc.Env {
			if !strings.Contains(env.Key, "PASSWORD") {
				continue
			}
			if !env.Masked {
				t.Fatalf("%s.%s matched a key pattern and is not marked masked", svc.Name, env.Key)
			}
			if env.Value != nil && (*env.Value == "hunter2" || *env.Value == "pgpass") {
				t.Fatalf("%s.%s carries its value into the payload (§20)", svc.Name, env.Key)
			}
		}
	}
}

// §20's second rule: a credential in a value, under a name that says nothing.
//
// `BACKUP_TARGET` matches no pattern and never will, and it carries the same password as the
// `POSTGRES_PASSWORD` beside it. A masking stage that read only keys would mask one and publish the
// other — and connection strings are where credentials most often actually are, so the leak would be
// the common case rather than the corner one.
//
// The host and the account survive on purpose. They are how a service is configured, which is what
// this payload is for; only the password is the secret.
func TestACredentialInAValueIsRedactedEvenUnderAnInnocentName(t *testing.T) {
	out := run(t, newEngine(), nil, nil)

	entry, ok := envOf(service(t, out, "media", "db"), "BACKUP_TARGET")
	if !ok {
		t.Fatal("BACKUP_TARGET is in the fixture and should be in the payload")
	}
	if entry.Value == nil {
		t.Fatal("BACKUP_TARGET has a value in the fixture")
	}
	if want := "postgresql://backup:" + secrets.Mask + "@db:5432/media"; *entry.Value != want {
		t.Fatalf("BACKUP_TARGET = %q, want %q", *entry.Value, want)
	}
	if !entry.Masked {
		t.Error("BACKUP_TARGET is not marked masked, and what it shows is not the whole value")
	}

	// The same secret, once, in the whole document. This is the assertion that survives a value being
	// copied into a note, a warning or a graph label by some later stage.
	if raw, err := json.Marshal(out); err != nil {
		t.Fatalf("the payload would not marshal: %v", err)
	} else if strings.Contains(string(raw), "pgpass") {
		t.Error("the password appears verbatim somewhere in the payload")
	}
}

func TestMaskingDoesNotTouchAValueNobodyAskedToMask(t *testing.T) {
	// The masked entries get a new pointer rather than a rewritten one, because the parser may hand
	// one string to more than one entry. This is the assertion that catches writing through it.
	out := run(t, newEngine(), nil, nil)

	for _, env := range service(t, out, "media", "jellyfin").Env {
		if env.Key != "PUBLIC_URL" {
			continue
		}
		if env.Masked {
			t.Fatal("PUBLIC_URL matches no pattern and no always-list")
		}
		if env.Value == nil || *env.Value != "https://media.lan" {
			t.Fatalf("its value is unchanged; got %v", env.Value)
		}
		return
	}
	t.Fatal("PUBLIC_URL is in the fixture and should be in the payload")
}

// ---------------------------------------------------------------------------
// I4 — every enrichment may be absent and the scan still produces a payload
// ---------------------------------------------------------------------------

func TestAFleetWithNothingReachableStillProducesAWholePayload(t *testing.T) {
	// The whole of I4 for §5: no socket, no API, nothing answering. There is no error to return,
	// because a caller that had to check for one would have two ways to render the same fleet.
	root := fleetRoot(t)
	out := Run(context.Background(), Options{
		Cfg:        settings(root),
		Now:        clock(),
		Filesystem: absentFS{},
		Clients:    clients(refusing{}),
	})

	if len(out.Stacks) != 3 {
		t.Fatalf("the compose tree is a filesystem read and did not depend on any of it; got %d stacks",
			len(out.Stacks))
	}
	if out.Meta.DockerAvailable {
		t.Fatal("nothing was available")
	}
	if out.Meta.DockerError == "" {
		t.Fatal("and the payload says why (§15)")
	}
	if out.Meta.Authentik == nil || out.Meta.Traefik == nil {
		t.Fatal("both summaries are present whatever happened, so a reader is never told nothing")
	}
	if len(out.Meta.Connections) != 4 {
		t.Fatalf("every target still reports; got %d", len(out.Meta.Connections))
	}
	for _, report := range out.Meta.Connections {
		if report.Target == "" || report.Phase == "" {
			t.Fatalf("a report with no target or no phase says nothing: %+v", report)
		}
	}
	if out.Graph.Nodes == nil {
		t.Fatal("the graph is built from the files, which were read")
	}
}

// absentFS is a filesystem with no Docker socket on it.
type absentFS struct{}

func (absentFS) Stat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}
func (absentFS) Usable(name string) error {
	return &fs.PathError{Op: "access", Path: name, Err: fs.ErrNotExist}
}

// refusing is a network where every dial fails.
type refusing struct{}

func (refusing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.OpError{Op: "dial", Err: errRefused{}}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

// ---------------------------------------------------------------------------
// §3.4 and §16 — the build stamp
// ---------------------------------------------------------------------------

func TestACallerThatSuppliedNoStampGetsUnknownAndNotAnAbsentField(t *testing.T) {
	out := run(t, newEngine(), nil, nil)
	if out.Meta.Build.Source != payload.BuildFromImage {
		t.Fatalf("the caller's stamp is used as given; got %q", out.Meta.Build.Source)
	}

	bare := Run(context.Background(), Options{
		Cfg:        settings(fleetRoot(t)),
		Now:        clock(),
		Filesystem: socketFS{},
		Clients:    clients(newEngine()),
	})
	if bare.Meta.Build.Source != payload.BuildUnknown {
		t.Fatalf("§16: a field describing the build is never optional; got %q", bare.Meta.Build.Source)
	}
	if bare.Meta.Build.Version != config.Version {
		t.Fatalf("and it carries the compiled-in version; got %q", bare.Meta.Build.Version)
	}
}

// ---------------------------------------------------------------------------
// The meta a caller renders the scan from
// ---------------------------------------------------------------------------

func TestTheScanIsStampedWithTheInjectedClockAndNotTheWallOne(t *testing.T) {
	// I7 again, at the one place a scan could read ambient state without anybody noticing.
	out := run(t, newEngine(), nil, nil)

	if out.Meta.ScannedAt != "2026-03-14T09:26:53Z" {
		t.Fatalf("scannedAt is the injected clock's first reading; got %q", out.Meta.ScannedAt)
	}
	if out.Meta.DurationMs != 7 {
		t.Fatalf("and the duration is measured on the same clock; got %d", out.Meta.DurationMs)
	}
}

func TestTheAppsRootInTheMetaIsTheOneThatWasScanned(t *testing.T) {
	root := fleetRoot(t)
	out := Run(context.Background(), Options{
		Cfg:        settings(root),
		Now:        clock(),
		Filesystem: socketFS{},
		Clients:    clients(newEngine()),
	})
	if out.Meta.AppsRoot != root {
		t.Fatalf("got %q, want %q", out.Meta.AppsRoot, root)
	}
}

func TestTheGraphAndTheCountersDescribeTheSameFleetThePayloadCarries(t *testing.T) {
	// Stages 13 and 14 are built from the stacks the scan produced, not from a second walk, so a
	// service in one and not the other is a wiring bug this catches.
	out := run(t, newEngine(), nil, nil)

	services := 0
	for _, stack := range out.Stacks {
		services += len(stack.Services)
	}
	if services != 4 {
		t.Fatalf("the fixture has four services; got %d", services)
	}
	if out.Stats.Services != services {
		t.Fatalf("the counters count the payload's own services; got %d for %d", out.Stats.Services, services)
	}
	if len(out.Graph.Nodes) == 0 {
		t.Fatal("the graph has the fleet's nodes")
	}
}

func TestAScanLevelWarningReachesTheMetaAndAStackLevelOneStaysOnItsStack(t *testing.T) {
	// The two warning lists are two different claims, and §5 is the only thing that carries either out.
	// `meta.warnings` is about the root or a directory; a file that would not parse is about one stack,
	// and putting it in the meta would tell a reader the *scan* went wrong when one application did.
	//
	// A root that is not there is the scan-level case, and it is not a failure either (I4).
	missing := filepath.Join(t.TempDir(), "not-there")
	bare := Run(context.Background(), Options{
		Cfg: settings(missing), Now: clock(), Filesystem: socketFS{}, Clients: clients(newEngine()),
	})

	if len(bare.Meta.Warnings) == 0 {
		t.Fatal("a root that could not be read is a scan-level warning")
	}
	if len(bare.Stacks) != 0 {
		t.Fatalf("and there was nothing to find; got %d stacks", len(bare.Stacks))
	}

	// And the stack-level case, which must not turn into the one above.
	root := t.TempDir()
	dir := filepath.Join(root, "broken")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services: [not, a, map]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := Run(context.Background(), Options{
		Cfg: settings(root), Now: clock(), Filesystem: socketFS{}, Clients: clients(newEngine()),
	})

	if len(out.Stacks) != 1 {
		t.Fatalf("the directory is still a stack, whatever its compose file said; got %d",
			len(out.Stacks))
	}
	if len(out.Stacks[0].Warnings) == 0 {
		t.Fatal("and it carries the account of what could not be read")
	}
	if len(out.Meta.Warnings) != 0 {
		t.Fatalf("which is not a scan-level warning; got %v", out.Meta.Warnings)
	}
}

// ---------------------------------------------------------------------------
// §5 stage 12 — pass 2 sees what pass 1 could not
// ---------------------------------------------------------------------------

func TestAMiddlewareDefinedInAnotherStackIsResolved(t *testing.T) {
	// The reason there are two passes at all. `authentik@docker` is referenced from `media` and defined
	// in `sso`, so a per-service pass could not have resolved it and the posture would depend on which
	// stack was read first.
	out := run(t, newEngine(), nil, nil)

	jellyfin := service(t, out, "media", "jellyfin")
	if jellyfin.Auth.Method == payload.AuthNone {
		t.Fatalf("the forward-auth middleware the other stack defines was not resolved; auth = %+v",
			jellyfin.Auth)
	}
}

func TestAServiceWithNoAuthenticationAnywhereIsSaidToHaveNone(t *testing.T) {
	// The control case for the assertion above: the resolution has to be able to answer *no*.
	out := run(t, newEngine(), nil, nil)

	if got := service(t, out, "media", "db").Auth.Method; got != payload.AuthNone {
		t.Fatalf("a database with no labels and no provider has no posture; got %q", got)
	}
}

func TestTheProbeAsksOnlyAboutServicesWhosePostureLeftTheQuestionOpen(t *testing.T) {
	// §13.1 through the pipeline: pass 2a runs first, so the service behind the forward-auth
	// middleware is never asked, and the count of skipped subjects is the proof.
	e := newEngine()
	out := run(t, e, func(c *config.Config) { c.Probe.Enabled = true }, nil)

	if got := service(t, out, "media", "jellyfin"); got.Probe != nil {
		t.Fatalf("a service with detected authentication is withheld, not probed; got %+v", got.Probe)
	}
	if out.Meta.Probe.Skipped == 0 {
		t.Fatal("and withholding it is counted, so the figure means *not asked* and not *not HTTP*")
	}
}

func TestADisabledProbeAsksNothingAndSaysSo(t *testing.T) {
	e := newEngine()
	out := run(t, e, func(c *config.Config) { c.Probe.Enabled = false }, nil)

	for _, name := range e.order() {
		if name == "probe" {
			t.Fatalf("a disabled probe issues no request; asked %v", e.order())
		}
	}
	if out.Meta.Probe.Enabled {
		t.Fatal("and the run says it was off")
	}
	for _, stack := range out.Stacks {
		for _, svc := range stack.Services {
			if svc.Probe != nil {
				t.Fatalf("%s/%s carries a probe record from a probe that never ran", stack.ID, svc.Name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// A cancelled scan
// ---------------------------------------------------------------------------

func TestACancelledScanStillReturnsAPayloadRatherThanNothing(t *testing.T) {
	// The caller that cancelled may still be the HTTP handler that has to render something, and I4
	// does not have an exception for it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := Run(ctx, Options{
		Cfg:        settings(fleetRoot(t)),
		Now:        clock(),
		Filesystem: socketFS{},
		Clients:    clients(newEngine()),
	})

	if len(out.Stacks) != 3 {
		t.Fatalf("the filesystem read does not take the context; got %d stacks", len(out.Stacks))
	}
	if len(out.Meta.Connections) != 4 {
		t.Fatalf("and every target still reports what happened to it; got %d",
			len(out.Meta.Connections))
	}
}
