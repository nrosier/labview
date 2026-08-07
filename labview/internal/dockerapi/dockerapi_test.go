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
	"strconv"
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

	// refuseBody is the refusal's own message, for the tests that have to tell two refusals apart.
	// Absent means the same generic denial for every id.
	refuseBody map[string]string

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
			message := orString(e.refuseBody[id], "authorization denied by plugin")
			return respond(status, `{"message":"`+message+`"}`), nil
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

// TestThePartialDetailSaysWhyTheInspectsWereRefused is the count made actionable. *84 of 86 inspects
// were refused* is a number an operator can do nothing with; they are refused wholesale for one
// reason, and that reason is already in the response.
//
// One reason and not eighty-four copies of the same sentence — and the one quoted is the first in
// *list* order, not the first to finish. That is the same rule as the index (I7): nothing about this
// answer may depend on which of the fan-out's workers came back first.
func TestThePartialDetailSaysWhyTheInspectsWereRefused(t *testing.T) {
	first, second := id("0f0f"), id("05ec")
	e := &engine{
		listBody: listJSON(
			listSpec{id: first, name: "first-in-list", status: "Up"},
			listSpec{id: second, name: "second-in-list", status: "Up"},
		),
		refuse: map[string]int{first: http.StatusForbidden, second: http.StatusForbidden},
		// Two distinguishable refusals, so quoting the wrong one is a visible failure rather than a
		// coincidence that passes.
		refuseBody: map[string]string{
			first:  "denied: the first entry in list order",
			second: "denied: the second entry in list order",
		},
		// And the first entry in list order is made to answer last, so a detail built from completion
		// order quotes the second and a detail built from list order cannot.
		waitFor: map[string]string{first: second},
	}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhasePartial {
		t.Fatalf("phase = %q, want partial", snap.Report.Phase)
	}
	if !strings.Contains(snap.Report.Detail, "2 of 2 inspects were refused") {
		t.Errorf("detail = %q, want the count", snap.Report.Detail)
	}
	if !strings.Contains(snap.Report.Detail, "denied: the first entry in list order") {
		t.Errorf("detail = %q, want the reason the *first listed* inspect was refused; the answer must "+
			"not depend on which worker came back first (I7)", snap.Report.Detail)
	}
	// One reason, not eighty-four copies of the same sentence.
	if n := strings.Count(snap.Report.Detail, "denied:"); n != 1 {
		t.Errorf("detail = %q, want one reason and got %d", snap.Report.Detail, n)
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

// TestAListThatDoesNotParseSaysWhatAnsweredInstead is the report an operator gets when the path they
// configured is answered by something that is not the Engine.
//
// The shape alone is not a diagnosis. `not-json` is what a socket proxy's refusal, an SSO login page
// and a list cut at the body cap all report, and an operator handed those three words has to go and
// curl the endpoint themselves to learn which of the three they have. The body is the only thing that
// distinguishes them, so the detail carries the beginning of it — bounded, on one line, quoted and
// with any credential in it masked, which is what makes printing somebody else's output defensible
// (conn.Excerpt has the tests for each of those).
//
// The `protocol` *code* is unchanged and stays a shape: TestReadJSONNeverPutsTheBodyInTheCode holds
// that where it is decided.
func TestAListThatDoesNotParseSaysWhatAnsweredInstead(t *testing.T) {
	e := &engine{listBody: `<!doctype html>` + "\n" + `<title>Sign in — lab.example</title>`}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhaseProtocol {
		t.Fatalf("phase = %q, want protocol", snap.Report.Phase)
	}
	for _, want := range []string{
		"html",             // still the shape, from the shared classifier
		"54 bytes",         // how much of it there was
		`"<!doctype html>`, // and the body itself, quoted so a reader can see whose text it is
		"Sign in — lab.example",
	} {
		if !strings.Contains(snap.Report.Detail, want) {
			t.Errorf("detail = %q, want it to contain %q", snap.Report.Detail, want)
		}
	}
	// §15's format is one line per report plus one indented line per rejected candidate. A body that
	// arrived with newlines in it must not be able to forge either.
	if strings.ContainsAny(snap.Report.Detail, "\n\r") {
		t.Errorf("detail = %q, which carries the body's own line breaks into a one-line format",
			snap.Report.Detail)
	}
}

// TestAListCutAtTheBodyCapSaysSoRatherThanBlamingTheFarEnd is the failure this whole diagnostic was
// written for, and it is ours rather than the operator's.
//
// I8 caps every read at 64 KiB. A fleet whose container list exceeds that gets a body cut mid-array,
// which then fails to unmarshal and reports `not-json` — a phrase whose hint sends the operator off
// to find out what is answering on the Docker path, when the answer is that the Engine answered
// perfectly well and LabView stopped reading. The transport records the cut for exactly this reason;
// dropping it here was what made the two indistinguishable.
func TestAListCutAtTheBodyCapSaysSoRatherThanBlamingTheFarEnd(t *testing.T) {
	specs := make([]listSpec, 512)
	for i := range specs {
		name := "svc-" + strconv.Itoa(i)
		specs[i] = listSpec{id: id(strconv.FormatInt(int64(i), 16)), name: name,
			status: "Up 3 days", project: "lab", service: name}
	}
	body := listJSON(specs...)
	// The test's own premise, asserted rather than assumed: if the cap or the entry size ever moves,
	// this fails here instead of silently testing the ordinary path.
	if len(body) <= transport.BodyCap {
		t.Fatalf("the list is %d bytes and the cap is %d; this test needs a list that exceeds it",
			len(body), transport.BodyCap)
	}

	snap := read(t, &engine{listBody: body}, nil, nil)

	if snap.Report.Phase != payload.PhaseProtocol {
		t.Fatalf("phase = %q, want protocol (detail %q)", snap.Report.Phase, snap.Report.Detail)
	}
	// The cut is stated before anything else, because it changes what the rest of the line means: a
	// document cut mid-array did not fail to parse because it was the wrong document.
	for _, want := range []string{"cut at the 64 KiB body cap", "incomplete answer rather than a wrong one"} {
		if !strings.Contains(snap.Report.Detail, want) {
			t.Errorf("detail = %q, want it to say %q", snap.Report.Detail, want)
		}
	}
	// The excerpt of a cut list opens on the Engine's own output, which is the corroboration: an
	// operator who sees the list's first entries knows they were talking to the Engine all along.
	if !strings.Contains(snap.Report.Detail, `"[{`) {
		t.Errorf("detail = %q, want the beginning of the list that was cut", snap.Report.Detail)
	}
	// 64 KiB of container list must not become 64 KiB of detail.
	if len(snap.Report.Detail) > 1024 {
		t.Errorf("detail is %d bytes long, want a diagnostic and not a document", len(snap.Report.Detail))
	}
}

// TestAPingThatAnsweredSomethingElseQuotesIt is the same rule one request earlier. A ping is the
// cheapest possible check and the body it returns is one word, so *the endpoint answered 200 and did
// not answer `OK`* with nothing after it is a report that withholds the only evidence there was.
func TestAPingThatAnsweredSomethingElseQuotesIt(t *testing.T) {
	e := &engine{pingBody: `<html><head><title>docker-socket-proxy</title></head>`}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhaseProtocol {
		t.Fatalf("phase = %q, want protocol", snap.Report.Phase)
	}
	if !strings.Contains(snap.Report.Detail, "docker-socket-proxy") {
		t.Errorf("detail = %q, want what answered instead of OK", snap.Report.Detail)
	}
}

// TestARefusalThatIsNotTheEnginesOwnShapeIsStillAccountedFor is the socket proxy that was never given
// CONTAINERS=1. It answers 403 with its own page rather than the Engine's `{"message":...}`, so there
// is no message to quote and the body is the only account of the refusal in existence.
//
// Getting this one wrong is expensive in a specific way: `the Engine answered 403` reads as *the
// Docker daemon refused you*, and sends an operator to look at daemon permissions and group
// membership when what refused them is a container sitting in front of it, named in the body.
func TestARefusalThatIsNotTheEnginesOwnShapeIsStillAccountedFor(t *testing.T) {
	e := &engine{
		listStatus: http.StatusForbidden,
		listBody:   "Access to /containers/json is denied by tecnativa/docker-socket-proxy\n",
	}
	snap := read(t, e, nil, nil)

	if snap.Report.Phase != payload.PhaseAuthorize {
		t.Fatalf("phase = %q, want authorize", snap.Report.Phase)
	}
	for _, want := range []string{"403", "docker-socket-proxy"} {
		if !strings.Contains(snap.Report.Detail, want) {
			t.Errorf("detail = %q, want it to contain %q", snap.Report.Detail, want)
		}
	}
}

// TestABodyWithNothingInItIsNamedAndNotLeftAsAByteCount keeps the two cases with nothing to quote
// from reading as a sentence that lost its ending — a detail that stops after *2 bytes* looks like a
// diagnostic that broke halfway, and an operator cannot tell that from one that worked.
//
// Both are findings in their own right: something accepted the request, produced a status, and said
// nothing at all.
func TestABodyWithNothingInItIsNamedAndNotLeftAsAByteCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    *engine
		want string
	}{{
		// The engine fake reads an empty listBody as *an empty list*, so bytes that say nothing are
		// asked for as whitespace. It is also the honest wording: there were bytes.
		name: "whitespace",
		e:    &engine{listStatus: http.StatusBadGateway, listBody: " \n"},
		want: "the body was 2 bytes of whitespace",
	}, {
		// An inspect answering 200 with no body at all. This also covers the fourth site the excerpt
		// reaches — a single container's inspect — and its reason arriving in the partial detail.
		name: "no body at all",
		e: &engine{
			listBody: listJSON(listSpec{id: id("0e0e"), name: "silent", status: "Up"}),
			inspects: map[string]string{id("0e0e"): ""},
		},
		want: "the body was empty",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			snap := read(t, tc.e, nil, nil)

			if !strings.Contains(snap.Report.Detail, tc.want) {
				t.Errorf("detail = %q, want it to say %q", snap.Report.Detail, tc.want)
			}
			for _, trailing := range []string{"beginning", ",", ";"} {
				if strings.HasSuffix(snap.Report.Detail, trailing) {
					t.Errorf("detail = %q, which trails off", snap.Report.Detail)
				}
			}
		})
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
