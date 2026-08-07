package dockerapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// The fakes
// ---------------------------------------------------------------------------

// fakeInfo is the smallest fs.FileInfo the pre-check can be asked about: it reads the mode and
// nothing else.
type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// fakeFS produces any of the four socket states on demand.
//
// It is the reason Filesystem is an interface. Three of the four states cannot be produced for
// real inside a test: `unreadable` needs a second uid, and `present` needs something listening.
type fakeFS struct {
	state   SocketState
	statErr error // overrides state, for the branch where stat itself fails
}

func (f fakeFS) Stat(name string) (fs.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	switch f.state {
	case SocketAbsent:
		// Wrapped, as the real os.Stat wraps it — and as errors.Is unwraps it.
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	case SocketNotASocket:
		return fakeInfo{name: name, mode: fs.ModeDir}, nil
	default:
		return fakeInfo{name: name, mode: fs.ModeSocket}, nil
	}
}

func (f fakeFS) Usable(name string) error {
	if f.state == SocketUnreadable {
		return &fs.PathError{Op: "access", Path: name, Err: fs.ErrPermission}
	}
	return nil
}

// engine is a fake Docker Engine. It answers the three requests §10 permits, answers anything else
// with a teapot so a fourth request would be visible as a failure rather than as a pass, and
// records every URL it was asked for — which is how "exactly three kinds of request" is asserted
// rather than asserted about.
type engine struct {
	mu    sync.Mutex
	asked []string
	done  map[string]chan struct{}

	pingStatus int    // 0 means 200
	pingBody   string // empty means "OK"
	listStatus int    // 0 means 200
	listBody   string // empty means an empty list

	inspects map[string]string // full id -> inspect body
	refuse   map[string]int    // full id -> status answered instead of the body

	// waitFor makes one inspect answer only after another already has, which forces inspects to
	// complete in an order that is not list order.
	waitFor map[string]string

	// err is a transport failure for every request, for the paths where nothing answers at all.
	err error
}

func (e *engine) RoundTrip(r *http.Request) (*http.Response, error) {
	url := r.URL.Path
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	e.record(url)

	if e.err != nil {
		return nil, e.err
	}

	switch {
	case url == pathPing:
		return respond(or(e.pingStatus, 200), orString(e.pingBody, "OK")), nil

	case url == pathList:
		return respond(or(e.listStatus, 200), orString(e.listBody, "[]")), nil

	case strings.HasPrefix(url, pathInspect) && strings.HasSuffix(url, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(url, pathInspect), "/json")
		if before, ok := e.waitFor[id]; ok {
			<-e.signal(before)
		}
		defer close(e.signal(id))

		if status, ok := e.refuse[id]; ok {
			return respond(status, `{"message":"authorization denied by plugin"}`), nil
		}
		if body, ok := e.inspects[id]; ok {
			return respond(200, body), nil
		}
		return respond(404, `{"message":"No such container: `+id+`"}`), nil
	}

	return respond(418, `{"message":"this is not one of the three requests"}`), nil
}

func (e *engine) record(url string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.asked = append(e.asked, url)
}

func (e *engine) recorded() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.asked...)
}

func (e *engine) signal(id string) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done == nil {
		e.done = map[string]chan struct{}{}
	}
	if e.done[id] == nil {
		e.done[id] = make(chan struct{})
	}
	return e.done[id]
}

func respond(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func or(n, fallback int) int {
	if n == 0 {
		return fallback
	}
	return n
}

func orString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// ---------------------------------------------------------------------------
// Building a read
// ---------------------------------------------------------------------------

func read(t *testing.T, e *engine, fsys Filesystem, mutate func(*config.DockerConfig)) Snapshot {
	t.Helper()
	if fsys == nil {
		fsys = fakeFS{state: SocketPresent}
	}
	cfg := config.Defaults().Docker
	if mutate != nil {
		mutate(&cfg)
	}
	client := New(cfg, fsys, transport.New(transport.Options{
		RoundTripper:   e,
		MaxConcurrency: cfg.MaxConcurrency,
	}))
	return client.Read(context.Background())
}

// id pads a readable prefix out to the 64 hex characters the Engine returns, so that the 12-char
// short id in the index is a real truncation rather than the whole thing.
func id(prefix string) string { return prefix + strings.Repeat("0", 64-len(prefix)) }

type listSpec struct {
	id      string
	name    string
	status  string
	project string
	service string
}

func listJSON(specs ...listSpec) string {
	out := make([]map[string]any, 0, len(specs))
	for _, s := range specs {
		labels := map[string]string{}
		if s.project != "" {
			labels["com.docker.compose.project"] = s.project
		}
		if s.service != "" {
			labels["com.docker.compose.service"] = s.service
		}
		out = append(out, map[string]any{
			"Id":     s.id,
			"Names":  []string{"/" + s.name},
			"Status": s.status,
			"Labels": labels,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func minimalInspect(cid, name string) string {
	return `{
		"Id": "` + cid + `",
		"Name": "/` + name + `",
		"Created": "2026-01-01T00:00:00Z",
		"Image": "sha256:` + strings.Repeat("b", 64) + `",
		"RestartCount": 0,
		"Config": {"Image": "ghcr.io/example/` + name + `:1"},
		"State": {"Status": "running", "Running": true, "StartedAt": "2026-01-02T00:00:00Z"},
		"NetworkSettings": {"Networks": {"proxy": {"IPAddress": "172.20.0.2"}}, "Ports": {}}
	}`
}

// ---------------------------------------------------------------------------
// The socket pre-check
// ---------------------------------------------------------------------------

func TestTheFourSocketStatesEachGetTheirOwnAnswer(t *testing.T) {
	for _, tc := range []struct {
		state    SocketState
		phase    payload.ConnectionPhase
		says     string
		requests int
	}{
		// absent and not-a-socket share a phase and must not share a sentence: the fix for one is
		// to start Docker and the fix for the other is to correct a bind mount.
		{SocketAbsent, payload.PhaseNotFound, "nothing exists at", 0},
		{SocketNotASocket, payload.PhaseNotFound, "empty directory", 0},
		{SocketUnreadable, payload.PhaseAuthorize, "not usable by this user", 0},
		{SocketPresent, payload.PhaseConnected, "", 2},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
			e := &engine{}
			snap := read(t, e, fakeFS{state: tc.state}, nil)

			if snap.Report.Phase != tc.phase {
				t.Fatalf("phase = %q, want %q", snap.Report.Phase, tc.phase)
			}
			if tc.says != "" && !strings.Contains(snap.Report.Detail, tc.says) {
				t.Errorf("detail = %q, want it to contain %q", snap.Report.Detail, tc.says)
			}
			// The pre-check is only worth having if it happens *before* the HTTP client: a failing
			// state that still dialled would report whichever phase the dial produced.
			if got := len(e.recorded()); got != tc.requests {
				t.Errorf("issued %d requests %v, want %d", got, e.recorded(), tc.requests)
			}
		})
	}
}

func TestAStatThatFailsForAnotherReasonIsAPermissionProblem(t *testing.T) {
	// A directory component this uid cannot traverse produces exactly this, and it is a permission
	// problem even though the error is not about the socket itself.
	state := CheckSocket("/var/run/docker.sock", fakeFS{
		statErr: &fs.PathError{Op: "stat", Path: "/var/run/docker.sock", Err: fs.ErrPermission},
	})
	if state != SocketUnreadable {
		t.Fatalf("state = %q, want %q", state, SocketUnreadable)
	}
}

func TestATcpEndpointIsNotPreChecked(t *testing.T) {
	// There is no socket to stat, and consulting the filesystem anyway would report `not-found`
	// for an endpoint that is a host and a port.
	e := &engine{}
	snap := read(t, e, fakeFS{state: SocketAbsent}, func(c *config.DockerConfig) {
		c.Host = "dockerproxy"
		c.Port = 2375
	})
	if snap.Report.Phase != payload.PhaseConnected {
		t.Fatalf("phase = %q (%s), want connected", snap.Report.Phase, snap.Report.Detail)
	}
}

// ---------------------------------------------------------------------------
// The permitted surface (I5)
// ---------------------------------------------------------------------------

func TestExactlyThreeKindsOfRequestAreEverIssued(t *testing.T) {
	a, b := id("aaaa"), id("bbbb")
	e := &engine{
		listBody: listJSON(
			listSpec{id: a, name: "authentik-server-1", status: "Up 3 days (healthy)", project: "authentik", service: "server"},
			listSpec{id: b, name: "traefik-traefik-1", status: "Up 1 day", project: "traefik", service: "traefik"},
		),
		inspects: map[string]string{
			a: minimalInspect(a, "authentik-server-1"),
			b: minimalInspect(b, "traefik-traefik-1"),
		},
	}
	snap := read(t, e, nil, nil)
	if !snap.Report.OK {
		t.Fatalf("report = %+v", snap.Report)
	}

	// This is I5's claim made checkable: a read-only socket mount is sufficient because these are
	// the only URLs the package can build. No exec, no logs, no attach, no events, no write.
	want := []string{
		pathPing,
		pathList,
		pathInspect + a + "/json",
		pathInspect + b + "/json",
	}
	got := e.recorded()
	if len(got) != 2+2 {
		t.Fatalf("issued %d requests, want 2 + one per container: %v", len(got), got)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("requests =\n  %v\nwant\n  %v", got, want)
	}
}

func TestDisabledIssuesNoRequestAndNamesNoEndpoint(t *testing.T) {
	e := &engine{}
	snap := read(t, e, nil, func(c *config.DockerConfig) { c.Enabled = false })

	if snap.Report.Phase != payload.PhaseDisabled {
		t.Fatalf("phase = %q, want disabled", snap.Report.Phase)
	}
	if len(e.recorded()) != 0 {
		t.Errorf("issued %v, want nothing", e.recorded())
	}
	// Naming an endpoint would say one was tried. Nothing was.
	if snap.Report.Endpoint != "" || snap.Report.Source != "" {
		t.Errorf("endpoint = %q source = %q, want both empty", snap.Report.Endpoint, snap.Report.Source)
	}
	// `disabled` is a choice, not a fault, so the hint says how to undo the choice.
	if snap.Report.Hint == "" {
		t.Error("no hint on a disabled endpoint, want one naming how to enable it")
	}
}

func TestNeitherASocketNorAHostIsNotConfigured(t *testing.T) {
	e := &engine{}
	snap := read(t, e, nil, func(c *config.DockerConfig) {
		c.SocketPath = ""
		c.Host = ""
	})
	if snap.Report.Phase != payload.PhaseNotConfigured {
		t.Fatalf("phase = %q, want not-configured", snap.Report.Phase)
	}
	if len(e.recorded()) != 0 {
		t.Errorf("issued %v, want nothing", e.recorded())
	}
	if snap.Report.Endpoint != "" {
		t.Errorf("endpoint = %q, want empty", snap.Report.Endpoint)
	}
}

// ---------------------------------------------------------------------------
// The §10 field table
// ---------------------------------------------------------------------------

func TestTheFieldTableIsAppliedOnce(t *testing.T) {
	cid := id("c0ffee")
	e := &engine{
		listBody: listJSON(listSpec{
			id: cid, name: "monitoring-grafana-1",
			status:  "Up 3 days (healthy)",
			project: "monitoring", service: "grafana",
		}),
		inspects: map[string]string{cid: `{
			"Id": "` + cid + `",
			"Name": "/monitoring-grafana-1",
			"Created": "2026-01-01T10:00:00Z",
			"Image": "sha256:deadbeefcafe0123456789abcdef0123456789abcdef0123456789abcdef0123",
			"RestartCount": 3,
			"Config": {"Image": "grafana/grafana:11.0.0", "Labels": {"role": "dashboard"}},
			"State": {
				"Status": "running", "Running": true,
				"StartedAt": "2026-01-02T11:00:00Z",
				"Health": {"Status": "healthy"}
			},
			"NetworkSettings": {
				"Networks": {
					"proxy": {"IPAddress": "172.20.0.5"},
					"internal": {"IPAddress": ""}
				},
				"Ports": {
					"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}],
					"9090/tcp": [],
					"53/udp": [{"HostIp": "", "HostPort": "5353"}]
				}
			}
		}`},
	}

	snap := read(t, e, nil, nil)
	st, ok := snap.Get("monitoring-grafana-1")
	if !ok {
		t.Fatalf("container not indexed; states = %v, report = %+v", snap.States, snap.Report)
	}

	if st.ID != cid[:12] {
		t.Errorf("id = %q, want the 12-char short id %q", st.ID, cid[:12])
	}
	if st.Name != "monitoring-grafana-1" {
		t.Errorf("name = %q, want the leading slash trimmed", st.Name)
	}
	// The image is the *tag the operator wrote*, from Config, not the resolved digest in Image.
	if st.Image != "grafana/grafana:11.0.0" {
		t.Errorf("image = %q, want Config.Image", st.Image)
	}
	if st.ImageDigest != "sha256:deadbeefcafe" {
		t.Errorf("imageDigest = %q, want 19 characters of the sha256 form", st.ImageDigest)
	}
	if st.State != "running" {
		t.Errorf("state = %q", st.State)
	}
	// The summary status comes from the *list*, because an inspect has no equivalent of it.
	if st.Status != "Up 3 days (healthy)" {
		t.Errorf("status = %q, want the list entry's summary", st.Status)
	}
	if st.Health != payload.HealthHealthy {
		t.Errorf("health = %q", st.Health)
	}
	if !st.Running {
		t.Error("running = false")
	}
	if st.RestartCount == nil || *st.RestartCount != 3 {
		t.Errorf("restartCount = %v, want 3", st.RestartCount)
	}
	if st.CreatedAt != "2026-01-01T10:00:00Z" || st.StartedAt != "2026-01-02T11:00:00Z" {
		t.Errorf("timestamps = %q / %q", st.CreatedAt, st.StartedAt)
	}

	if want := []string{"internal", "proxy"}; !reflect.DeepEqual(st.Networks, want) {
		t.Errorf("networks = %v, want %v sorted", st.Networks, want)
	}
	// An empty address is left out rather than recorded: this map is what container-IP origin
	// resolution reads (§9), and an empty string in it would be an address resolving to nothing.
	if want := map[string]string{"proxy": "172.20.0.5"}; !reflect.DeepEqual(st.IPAddresses, want) {
		t.Errorf("ipAddresses = %v, want %v", st.IPAddresses, want)
	}

	// Sorted by the Engine's port key, and the three shapes in one reading: a bound port with a
	// host address, a bound port without one, and an exposed port with no binding at all.
	want := []payload.PortMapping{
		{Published: "3000", Target: "3000", Protocol: "tcp", Raw: "127.0.0.1:3000->3000/tcp"},
		{Published: "5353", Target: "53", Protocol: "udp", Raw: "5353->53/udp"},
		{Target: "9090", Protocol: "tcp", Raw: "9090/tcp"},
	}
	if !reflect.DeepEqual(st.PublishedPorts, want) {
		t.Errorf("publishedPorts =\n  %+v\nwant\n  %+v", st.PublishedPorts, want)
	}
}

func TestAnExposedPortWithNoBindingIsNotAPublishedOne(t *testing.T) {
	// *Exposed and unbound* is a different fact from *not exposed*, so the entry exists and has no
	// published port — which is what the posture rules read (§7).
	got := ports(map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"8080/tcp": nil})

	if len(got) != 1 {
		t.Fatalf("got %d mappings, want 1: %+v", len(got), got)
	}
	if got[0].Published != "" {
		t.Errorf("published = %q, want empty", got[0].Published)
	}
	if got[0].Raw != "8080/tcp" {
		t.Errorf("raw = %q, want the key itself", got[0].Raw)
	}
}

func TestHealthIsNoneForAnythingOutsideTheClosedSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  payload.HealthState
	}{
		{"healthy", `"Health":{"Status":"healthy"},`, payload.HealthHealthy},
		{"unhealthy", `"Health":{"Status":"unhealthy"},`, payload.HealthUnhealthy},
		{"starting", `"Health":{"Status":"starting"},`, payload.HealthStarting},
		// No health check declared. `none` rather than absent, because §4 keeps the member.
		{"absent", ``, payload.HealthNone},
		{"empty", `"Health":{"Status":""},`, payload.HealthNone},
		// §16 makes adding a union member a breaking change, so a string off the wire must never
		// become one.
		{"invented", `"Health":{"Status":"degraded"},`, payload.HealthNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cid := id("dddd")
			e := &engine{
				listBody: listJSON(listSpec{id: cid, name: "one", status: "Up"}),
				inspects: map[string]string{cid: `{
					"Id": "` + cid + `", "Name": "/one",
					"Config": {"Image": "x:1"},
					"State": {"Status": "running", "Running": true, ` + tc.value + ` "StartedAt": ""},
					"NetworkSettings": {"Networks": {}, "Ports": {}}
				}`},
			}
			st, ok := read(t, e, nil, nil).Get("one")
			if !ok {
				t.Fatal("not indexed")
			}
			if st.Health != tc.want {
				t.Errorf("health = %q, want %q", st.Health, tc.want)
			}
		})
	}
}

func TestTheDigestIsOnlyReportedWhenItIsOne(t *testing.T) {
	for _, tc := range []struct {
		name  string
		image string
		want  string
	}{
		{"a digest", "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 12)},
		// An old or unusual Engine can answer with a bare name here. Slicing that would publish 19
		// characters of an image name as if it were a digest.
		{"a name", "ghcr.io/example/app:1", ""},
		{"too short to slice", "sha256:abc", ""},
		{"absent", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := inspectResponse{Image: tc.image}
			if got := r.state(listEntry{}).ImageDigest; got != tc.want {
				t.Errorf("imageDigest = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestZeroRestartsAndNoReportAreDifferentFacts(t *testing.T) {
	// The Engine always sends the field, so a zero here means zero — and the pointer is what keeps
	// that distinguishable from a container that was never inspected (§16).
	st := inspectResponse{RestartCount: 0}.state(listEntry{})
	if st.RestartCount == nil {
		t.Fatal("restartCount = nil for an inspected container, want a pointer to 0")
	}
	if *st.RestartCount != 0 {
		t.Errorf("restartCount = %d, want 0", *st.RestartCount)
	}
}

// ---------------------------------------------------------------------------
// The index
// ---------------------------------------------------------------------------

func TestThreeKeysFindTheSameContainer(t *testing.T) {
	cid := id("eeee")
	e := &engine{
		listBody: listJSON(listSpec{
			id: cid, name: "media-jellyfin-1", status: "Up 2 hours",
			project: "media", service: "jellyfin",
		}),
		inspects: map[string]string{cid: minimalInspect(cid, "media-jellyfin-1")},
	}
	snap := read(t, e, nil, nil)

	for _, key := range []string{
		"media-jellyfin-1",
		cid[:12],
		ComposeKey("media", "jellyfin"),
	} {
		st, ok := snap.Get(key)
		if !ok {
			t.Errorf("key %q found nothing", key)
			continue
		}
		if st.ID != cid[:12] {
			t.Errorf("key %q found %q, want %q", key, st.ID, cid[:12])
		}
	}
}

func TestAContainerStartedByHandHasNoComposeKey(t *testing.T) {
	// That is the correct answer rather than a gap: nothing scanned will look for it by a compose
	// key it does not have.
	cid := id("ffff")
	e := &engine{
		listBody: listJSON(listSpec{id: cid, name: "watchtower", status: "Up 5 days"}),
		inspects: map[string]string{cid: minimalInspect(cid, "watchtower")},
	}
	snap := read(t, e, nil, nil)

	if len(snap.States) != 2 {
		t.Errorf("indexed under %d keys, want 2: %v", len(snap.States), keys(snap.States))
	}
	if _, ok := snap.Get(ComposeKey("", "")); ok {
		t.Error("an empty compose key found something")
	}
}

func TestTheIndexIsWrittenInListOrderAndNotInCompletionOrder(t *testing.T) {
	// Two containers whose labels give them the same compose key. Something has to win, and §10
	// says the Engine's list decides — not whichever inspect happened to come back first.
	first, second := id("1111"), id("2222")
	e := &engine{
		listBody: listJSON(
			listSpec{id: first, name: "first", status: "Up", project: "app", service: "web"},
			listSpec{id: second, name: "second", status: "Up", project: "app", service: "web"},
		),
		inspects: map[string]string{
			first:  minimalInspect(first, "first"),
			second: minimalInspect(second, "second"),
		},
		// The first-listed container answers only after the second already has, so completion order
		// is the reverse of list order.
		waitFor: map[string]string{first: second},
	}
	snap := read(t, e, nil, func(c *config.DockerConfig) { c.MaxConcurrency = 2 })

	if want := []string{first[:12], second[:12]}; !reflect.DeepEqual(snap.Order, want) {
		t.Errorf("order = %v, want list order %v", snap.Order, want)
	}
	st, ok := snap.Get(ComposeKey("app", "web"))
	if !ok {
		t.Fatal("the shared compose key found nothing")
	}
	// Last write in list order wins. Had completion order decided, this would be `first`.
	if st.Name != "second" {
		t.Errorf("the shared key resolved to %q, want the last-listed container", st.Name)
	}
}

func TestTwoReadsAreTheSameRead(t *testing.T) {
	specs := make([]listSpec, 0, 8)
	inspects := map[string]string{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		cid := id(strings.Repeat(name, 6))
		specs = append(specs, listSpec{
			id: cid, name: name, status: "Up", project: "stack", service: name,
		})
		inspects[cid] = minimalInspect(cid, name)
	}

	first := marshal(t, read(t, &engine{listBody: listJSON(specs...), inspects: inspects}, nil, nil))
	second := marshal(t, read(t, &engine{listBody: listJSON(specs...), inspects: inspects}, nil, nil))
	if first != second {
		t.Errorf("two reads differ (I7):\n%s\n%s", first, second)
	}
}

func TestComposeKeysCannotCollide(t *testing.T) {
	// Both halves are label *values*, which an operator can set to anything. A separator that
	// merely does not usually occur would let these two be the same key, and the winner between two
	// unrelated containers would be whichever the Engine listed later.
	if ComposeKey("a/b", "c") == ComposeKey("a", "b/c") {
		t.Error("two different project/service pairs produced the same key")
	}
}

// ---------------------------------------------------------------------------
// A refused inspect
// ---------------------------------------------------------------------------

func TestARefusedInspectIsPartialAndTheContainerIsLeftOut(t *testing.T) {
	ok, denied := id("0a0a"), id("0d0d")
	e := &engine{
		listBody: listJSON(
			listSpec{id: ok, name: "readable", status: "Up", project: "app", service: "readable"},
			listSpec{id: denied, name: "hidden", status: "Up", project: "app", service: "hidden"},
		),
		inspects: map[string]string{ok: minimalInspect(ok, "readable")},
		refuse:   map[string]int{denied: http.StatusForbidden},
	}
	snap := read(t, e, nil, nil)

	// `partial` is a success: what was read is used, and what was not is said.
	if snap.Report.Phase != payload.PhasePartial {
		t.Fatalf("phase = %q, want partial", snap.Report.Phase)
	}
	if !snap.Report.OK {
		t.Error("partial reported as not ok")
	}
	if want := "2 containers, 1 could not be inspected"; snap.Report.Read != want {
		t.Errorf("read = %q, want %q", snap.Report.Read, want)
	}

	if _, found := snap.Get("readable"); !found {
		t.Error("the container that was readable is not in the index")
	}
	// Never guessed at. Its ports, networks and health are absent rather than filled in from the
	// list entry, because a container whose networks are unknown must not be reported as on none.
	for _, key := range []string{"hidden", denied[:12], ComposeKey("app", "hidden")} {
		if _, found := snap.Get(key); found {
			t.Errorf("the refused container is in the index under %q", key)
		}
	}
	if want := []string{ok[:12]}; !reflect.DeepEqual(snap.Order, want) {
		t.Errorf("order = %v, want %v", snap.Order, want)
	}
}

func TestOneRefusedInspectOfOneContainerIsStillPartial(t *testing.T) {
	only := id("0b0b")
	e := &engine{
		listBody: listJSON(listSpec{id: only, name: "only", status: "Up"}),
		refuse:   map[string]int{only: http.StatusForbidden},
	}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhasePartial {
		t.Fatalf("phase = %q, want partial", snap.Report.Phase)
	}
	// Singular, from the one shared wording helper.
	if want := "1 container, 1 could not be inspected"; snap.Report.Read != want {
		t.Errorf("read = %q, want %q", snap.Report.Read, want)
	}
	if len(snap.States) != 0 {
		t.Errorf("states = %v, want none", keys(snap.States))
	}
}

func TestAnEmptyFleetIsConnectedAndNotPartial(t *testing.T) {
	snap := read(t, &engine{}, nil, nil)
	if snap.Report.Phase != payload.PhaseConnected {
		t.Fatalf("phase = %q, want connected", snap.Report.Phase)
	}
	if want := "0 containers"; snap.Report.Read != want {
		t.Errorf("read = %q, want %q", snap.Report.Read, want)
	}
}

// ---------------------------------------------------------------------------
// The Engine's own classifier
// ---------------------------------------------------------------------------

func TestAPingThatDoesNotAnswerOKIsProtocolAndNotConnected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		phase payload.ConnectionPhase
	}{
		{"OK", "OK", payload.PhaseConnected},
		{"trailing newline", "OK\n", payload.PhaseConnected},
		{"lower case", "ok", payload.PhaseConnected},
		// A reverse proxy or a socket proxy pointed at the wrong upstream produces exactly this: a
		// 200 from something that is not the Engine.
		{"a login page", "<!doctype html><title>Sign in</title>", payload.PhaseProtocol},
		{"nothing", " ", payload.PhaseProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{pingBody: tc.body}
			snap := read(t, e, nil, nil)
			if snap.Report.Phase != tc.phase {
				t.Errorf("phase = %q, want %q (detail %q)", snap.Report.Phase, tc.phase, snap.Report.Detail)
			}
			if tc.phase == payload.PhaseProtocol && len(e.recorded()) != 1 {
				t.Errorf("issued %v, want the ping only", e.recorded())
			}
		})
	}
}

func TestTheEnginesOwnMessageReachesTheDetail(t *testing.T) {
	// The phase always comes from the shared classification. What the Engine's error adds is the
	// only place the *reason* lives.
	e := &engine{
		listStatus: http.StatusInternalServerError,
		listBody:   `{"message":"cannot enumerate containers: layer store is corrupt"}`,
	}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhaseStatus {
		t.Errorf("phase = %q, want status", snap.Report.Phase)
	}
	for _, want := range []string{"500", "layer store is corrupt"} {
		if !strings.Contains(snap.Report.Detail, want) {
			t.Errorf("detail = %q, want it to contain %q", snap.Report.Detail, want)
		}
	}
}

func TestAForbiddenListIsAuthorizeAndNotConnect(t *testing.T) {
	// A socket proxy that permits /_ping and refuses /containers/json is a real arrangement, and
	// telling an operator `connect` for it would send them looking at the wrong thing.
	e := &engine{listStatus: http.StatusForbidden, listBody: `{"message":"container list denied"}`}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhaseAuthorize {
		t.Fatalf("phase = %q, want authorize", snap.Report.Phase)
	}
	if snap.Report.Hint == "" {
		t.Error("no hint for a Docker authorize failure, want one")
	}
}

func TestAListThatDoesNotParseIsProtocolAndSaysOnlyTheShape(t *testing.T) {
	e := &engine{listBody: `<!doctype html><title>super-secret-lab.example</title>`}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhaseProtocol {
		t.Fatalf("phase = %q, want protocol", snap.Report.Phase)
	}
	if !strings.Contains(snap.Report.Detail, "html") {
		t.Errorf("detail = %q, want the shape of the body", snap.Report.Detail)
	}
	// The code is a shape and never a value: whatever answered, its content does not reach the
	// payload (I6, I2).
	if strings.Contains(snap.Report.Detail, "super-secret-lab") {
		t.Errorf("detail = %q, want no part of the body in it", snap.Report.Detail)
	}
}

func TestNothingListeningStopsAtThePing(t *testing.T) {
	e := &engine{err: errors.New("dial unix /var/run/docker.sock: connect: connection refused")}
	snap := read(t, e, nil, nil)

	if snap.Report.OK {
		t.Fatalf("report = %+v, want a failure", snap.Report)
	}
	if len(e.recorded()) != 1 {
		t.Errorf("issued %v, want the ping only", e.recorded())
	}
	if snap.States != nil {
		t.Errorf("states = %v, want none", keys(snap.States))
	}
	// A failed read is still a Snapshot with a report, never a nil one, so a caller has a report to
	// attach and nothing to check for (I4).
	if snap.Report.Target != "docker" {
		t.Errorf("target = %q, want docker", snap.Report.Target)
	}
	if _, found := snap.Get("anything"); found {
		t.Error("a zero snapshot found something")
	}
}

// ---------------------------------------------------------------------------
// The endpoint and where it came from
// ---------------------------------------------------------------------------

func TestTheEndpointAndItsSourceAreDecidedOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*config.DockerConfig)
		endpoint string
		source   payload.EndpointSource
	}{
		{
			// Still the built-in path, so an operator reading a failing report knows the address is
			// not one they chose.
			name:     "the default socket",
			mutate:   nil,
			endpoint: "unix:///var/run/docker.sock",
			source:   payload.SourceDefault,
		},
		{
			name:     "a socket they chose",
			mutate:   func(c *config.DockerConfig) { c.SocketPath = "/run/docker-proxy.sock" },
			endpoint: "unix:///run/docker-proxy.sock",
			source:   payload.SourceConfig,
		},
		{
			name:     "a host and a port",
			mutate:   func(c *config.DockerConfig) { c.Host = "dockerproxy"; c.Port = 2375 },
			endpoint: "tcp://dockerproxy:2375",
			source:   payload.SourceConfig,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := read(t, &engine{}, nil, tc.mutate)
			if snap.Report.Endpoint != tc.endpoint {
				t.Errorf("endpoint = %q, want %q", snap.Report.Endpoint, tc.endpoint)
			}
			if snap.Report.Source != tc.source {
				t.Errorf("source = %q, want %q", snap.Report.Source, tc.source)
			}
		})
	}
}

func TestAHostConfiguredEndpointCarriesNoFleetIdentifierIntoTheRequests(t *testing.T) {
	// Over a socket the URL's host names nothing and is a constant, so no fleet identifier reaches
	// the wire (I2). The endpoint the report names is the socket path.
	e := &engine{}
	snap := read(t, e, nil, nil)
	for _, url := range e.recorded() {
		if strings.Contains(url, "docker.sock") {
			t.Errorf("request %q carried the socket path in its URL", url)
		}
	}
	if snap.Report.Endpoint != "unix:///var/run/docker.sock" {
		t.Errorf("endpoint = %q", snap.Report.Endpoint)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func keys(m map[string]payload.DockerState) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
