// Package dockerapi is §10: the container snapshot, and the two classifiers the Docker endpoint adds
// to the shared taxonomy (§15).
//
// The permitted surface is exactly three requests — `GET /_ping`, `GET /containers/json?all=1`, and
// one `GET /containers/{id}/json` per listed container — and that is the whole of it (I5). There is
// no exec, no logs, no attach, no events and no write, so a read-only token or a `:ro` socket mount
// is sufficient. The three request paths are the only URLs this package builds, which is what makes
// the claim checkable rather than a promise.
//
// Nothing here throws out of its own boundary. A failure at any point becomes a connection report and
// an absent snapshot; the scan continues and says what it could not do (I4).
package dockerapi

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// The three requests, written once. A path assembled anywhere else in this package would be a fourth
// request nobody counted.
const (
	pathPing    = "/_ping"
	pathList    = "/containers/json?all=1"
	pathInspect = "/containers/" // + id + "/json"
)

// composeSep joins a compose project to a service name in the index.
//
// It is a NUL rather than the `/` the fleet index uses, because the two halves come from different
// places. The fleet's key is built from a directory name and a compose service name, where `/`
// cannot occur. This key is built from two *label values*, which an operator can set to anything —
// so a separator that merely does not usually occur would let `a/b` + `c` and `a` + `b/c` collide,
// and the winner between two unrelated containers would be whichever the Engine listed later.
const composeSep = "\x00"

// ComposeKey is how a container is found from a scanned service. The caller joins the stack's
// *compose project name* — not its directory id — to the service name, because that is what the
// Engine's labels carry.
func ComposeKey(project, service string) string { return project + composeSep + service }

// Snapshot is one read of the Engine. An unsuccessful read produces a Snapshot with a report and no
// states, never a nil one: every caller then has a report to attach and nothing to check for.
type Snapshot struct {
	Report payload.ConnectionReport

	// States is indexed by all three keys §10 requires — the compose key, the container name and the
	// 12-character short id — so a service found by any of them finds the same record.
	States map[string]payload.DockerState

	// Order is the short ids in the Engine's list order, which is the order the index was written in
	// and the order any list derived from this snapshot comes out in (I7).
	Order []string
}

// Get finds a container by any of its three keys.
func (s Snapshot) Get(key string) (payload.DockerState, bool) {
	st, ok := s.States[key]
	return st, ok
}

// Client reads the Engine. It holds no state between reads.
type Client struct {
	cfg  config.DockerConfig
	http *transport.Client
	fs   Filesystem

	base     string // the URL prefix the three paths hang off
	endpoint string // the credential-free endpoint the report names
	source   payload.EndpointSource
	socket   string // the path to pre-check, or empty for a tcp endpoint
}

// New builds a client for this configuration.
//
// The endpoint and its source are decided here and once: `unix://<socketPath>` when no host is
// configured, else `tcp://<host>:<port>`, with `source` reporting `default` while the socket path is
// still the built-in one. That distinction is what tells an operator whether the address in a failing
// report is one they chose (§10).
func New(cfg config.DockerConfig, fsys Filesystem, client *transport.Client) *Client {
	c := &Client{cfg: cfg, fs: fsys}
	if c.fs == nil {
		c.fs = OSFilesystem{}
	}

	if cfg.Host != "" {
		host := cfg.Host + ":" + strconv.Itoa(cfg.Port)
		c.base = "http://" + host
		c.endpoint = "tcp://" + host
		c.source = payload.SourceConfig
	} else {
		c.socket = cfg.SocketPath
		// The host in the URL names nothing: every request is dialled over the socket. It is there
		// because HTTP requires a Host header, and it is a constant so no fleet identifier reaches
		// the wire (I2).
		c.base = "http://docker"
		c.endpoint = "unix://" + cfg.SocketPath
		c.source = payload.SourceConfig
		if cfg.SocketPath == config.Defaults().Docker.SocketPath {
			c.source = payload.SourceDefault
		}
	}

	c.http = client
	if c.http == nil {
		c.http = transport.New(transport.Options{
			Timeout:        time.Duration(cfg.TimeoutMs) * time.Millisecond,
			MaxConcurrency: cfg.MaxConcurrency,
			Endpoint:       c.endpoint,
			UnixSocket:     c.socket,
		})
	}
	return c
}

// Read takes the snapshot.
func (c *Client) Read(ctx context.Context) Snapshot {
	empty := func(phase payload.ConnectionPhase, detail string) Snapshot {
		return Snapshot{Report: c.report(phase, detail, "")}
	}

	if !c.cfg.Enabled {
		return empty(payload.PhaseDisabled, "")
	}
	if c.socket == "" && c.cfg.Host == "" {
		// Neither a socket path nor a host. Nothing to talk to, and no request to make.
		return empty(payload.PhaseNotConfigured, "")
	}

	// The pre-check, before the HTTP client sees the path (§10).
	if c.socket != "" {
		if state := CheckSocket(c.socket, c.fs); state != SocketPresent {
			return empty(state.Phase(), state.Detail(c.socket))
		}
	}

	// 1 of 3: liveness.
	if phase, detail := c.ping(ctx); phase != payload.PhaseConnected {
		return empty(phase, detail)
	}

	// 2 of 3: the list.
	list, phase, detail := c.list(ctx)
	if phase != payload.PhaseConnected {
		return empty(phase, detail)
	}

	// 3 of 3: one inspect per listed container, under the configured fan-out.
	states, refused, reason := c.inspectAll(ctx, list)

	snap := Snapshot{States: map[string]payload.DockerState{}}
	// The index is written in list order, so which of two containers sharing a key wins is decided
	// by the Engine's list and not by which inspect happened to finish first (§10).
	for _, st := range states {
		if st == nil {
			continue
		}
		snap.Order = append(snap.Order, st.ID)
		for _, key := range keysFor(*st, list) {
			snap.States[key] = *st
		}
	}

	read := conn.Plural(len(list), "container", "containers")
	if refused > 0 {
		detail := strconv.Itoa(refused) + " of " + strconv.Itoa(len(list)) + " inspects were refused"
		if reason != "" {
			// One reason, not eighty-six of the same sentence. The first in list order is quoted
			// because a fleet where the inspects are refused wholesale is refused for one reason, and
			// a count with no reason is the report an operator can do nothing with.
			detail += "; the first said: " + reason
		}
		snap.Report = c.report(payload.PhasePartial, detail,
			read+", "+strconv.Itoa(refused)+" could not be inspected")
		return snap
	}
	snap.Report = c.report(payload.PhaseConnected, "", read)
	return snap
}

func (c *Client) report(phase payload.ConnectionPhase, detail, read string) payload.ConnectionReport {
	r := conn.Report(conn.TargetDocker, phase, c.endpoint, c.source, detail)
	r.Read = read
	if phase.BeforeTheNetwork() {
		// Nothing was attempted, so naming an endpoint would suggest one was tried.
		r.Endpoint, r.Source = "", ""
	}
	return r
}

// ---------------------------------------------------------------------------
// The three requests
// ---------------------------------------------------------------------------

func (c *Client) ping(ctx context.Context) (payload.ConnectionPhase, string) {
	// No Cap of its own: the Engine answers `OK`, two bytes, so the shared default is already
	// four orders of magnitude more than this read can legitimately need. Anything larger on
	// this path is something else answering, and the point of the ping is to notice that.
	res := c.http.Do(ctx, transport.Request{URL: c.base + pathPing})
	if phase, detail, bad := engineFailure(res); bad {
		return phase, detail
	}
	// The Engine answers `OK` in plain text. Anything else with a 200 is something *else* listening
	// on that path, which is `protocol` and not a successful ping — a reverse proxy or a socket proxy
	// pointed at the wrong upstream produces exactly this.
	if body := strings.TrimSpace(string(res.Body)); !strings.EqualFold(body, "OK") {
		return payload.PhaseProtocol, describing("the endpoint answered 200 and did not answer `OK`", res)
	}
	return payload.PhaseConnected, ""
}

func (c *Client) list(ctx context.Context) ([]listEntry, payload.ConnectionPhase, string) {
	// The one read whose size is a fact about this fleet rather than about a document somebody
	// else wrote: it grows by roughly a kilobyte per container, so the shared 64 KiB runs out at
	// around forty of them and the list arrives cut mid-array. Cut, it starts with `[` and
	// fails to parse, and the scan reports `protocol` — LabView's own ceiling described as the
	// far end not speaking Docker (§3.1's docker.bodyCapBytes).
	res := c.http.Do(ctx, transport.Request{URL: c.base + pathList, Cap: c.cfg.BodyCapBytes})
	if phase, detail, bad := engineFailure(res); bad {
		return nil, phase, detail
	}
	var list []listEntry
	phase, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &list)
	if err != nil {
		detail := "the container list did not parse"
		if code != "" {
			detail += " (" + code + ")"
		}
		return nil, phase, describing(detail, res)
	}
	return list, payload.PhaseConnected, ""
}

// describing appends what actually came back to a detail: how much of it there was, whether the
// body cap cut it, and its opening bytes.
//
// This is where *show me what answered* lands. A phase says the Engine was not read and a
// `protocol` code says which shape arrived instead, and between them they cannot tell an operator
// whether they are looking at a socket proxy's refusal, an SSO login page, or the Engine answering
// perfectly well into a read cap. Only the body says which, so the body is reported (§15's
// detail is where the reason lives, and I7 makes it data rather than a log line).
//
// The truncation clause is the one an operator is least able to work out for themselves, and it is
// stated first because it changes what the rest of the line means: a document cut mid-array did not
// fail to parse because it was the wrong document. The transport already records the cut for exactly
// this reason (I8's cap is a bound, not a silent one) and dropping it here was hiding the difference
// between *not the Engine* and *more Engine than fits*.
func describing(detail string, res transport.Result) string {
	if len(res.Body) == 0 {
		return detail + "; the body was empty"
	}
	if res.Truncated {
		// res.Cap and not the shared constant: this read asks for a cap of its own (§3.1's
		// docker.bodyCapBytes), so naming the constant would tell an operator to raise a number
		// that had nothing to do with the cut and leave them looking at the wrong setting.
		detail += ", and it was cut at the " + capSize(res.Cap) +
			" body cap, so what did not parse is an incomplete answer rather than a wrong one"
	}
	size := conn.Plural(len(res.Body), "byte", "bytes")
	excerpt := conn.Excerpt(res.Body)
	if excerpt == "" {
		// There were bytes and none of them said anything. Named rather than left as a byte count with
		// no sentence after it, because a detail that trails off reads as a diagnostic that broke
		// halfway — and *it answered with whitespace* is itself a finding about what is on that path.
		return detail + "; the body was " + size + " of whitespace"
	}
	return detail + "; " + size + ", beginning " + excerpt
}

// capSize renders a byte count the way the cap was written, so an operator reading the detail
// sees the number they would type back.
//
// A cap is set in round binary units and a detail that says "8388608 bytes" makes the reader do
// the division before they can tell whether it is the default. A value that is *not* a round
// unit is left in bytes rather than rounded, because a cap of 100000 reported as "97 KiB" is a
// number that does not appear in the configuration.
func capSize(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return strconv.Itoa(n>>20) + " MiB"
	case n >= 1<<10 && n%(1<<10) == 0:
		return strconv.Itoa(n>>10) + " KiB"
	default:
		return conn.Plural(n, "byte", "bytes")
	}
}

// inspectAll issues one inspect per listed container under the configured fan-out, and returns the
// results in list order alongside the number refused and why the first of them was.
//
// A refused inspect is skipped and counted, never guessed at. That container's ports, networks and
// health are simply absent, and §10 requires them left out of every conclusion rather than filled in
// from the list entry — a container whose networks are unknown must not be reported as being on none.
//
// The *reason* is carried out even though the state is not. A socket proxy that permits the list and
// refuses the inspects is an ordinary arrangement, and it produced a report that said how many
// inspects were refused and nothing whatever about what refused them.
func (c *Client) inspectAll(ctx context.Context, list []listEntry) ([]*payload.DockerState, int, string) {
	states := make([]*payload.DockerState, len(list))

	// why[i] is why inspect i was refused, written to its own slot for the same reason states is:
	// nothing about this answer may depend on which worker finished first (I7).
	why := make([]string, len(list))

	workers := c.cfg.MaxConcurrency
	if workers <= 0 {
		workers = 1
	}
	if workers > len(list) {
		workers = len(list)
	}

	var (
		next = make(chan int)
		wg   sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				st, refusal := c.inspect(ctx, list[i])
				if st == nil {
					why[i] = refusal
					continue
				}
				// Written to its own slot, so nothing here depends on completion order (I7).
				states[i] = st
			}
		}()
	}
	for i := range list {
		next <- i
	}
	close(next)
	wg.Wait()

	// Counted after the fan-out rather than under a lock during it. A slot with no state *is* a
	// refusal, so a count derived from the slice cannot disagree with the slice it describes — and
	// the reason quoted is the first in the Engine's list order rather than the first to finish.
	refused, reason := 0, ""
	for i, st := range states {
		if st != nil {
			continue
		}
		refused++
		if reason == "" {
			reason = why[i]
		}
	}
	return states, refused, reason
}

// inspect reads one container. A nil state is a refusal, and the string beside it is why.
func (c *Client) inspect(ctx context.Context, entry listEntry) (*payload.DockerState, string) {
	// The same cap as the list. One container is small next to the whole list, but a container
	// carrying a long environment, many mounts or a large label set is the same kind of data —
	// this fleet's own, sized by how it was deployed — and cutting it produces the same
	// misdirected `protocol` report for one service instead of all of them.
	res := c.http.Do(ctx, transport.Request{
		URL: c.base + pathInspect + entry.ID + "/json",
		Cap: c.cfg.BodyCapBytes,
	})
	if _, detail, bad := engineFailure(res); bad {
		return nil, detail
	}
	var got inspectResponse
	if _, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &got); err != nil {
		detail := "the inspect did not parse"
		if code != "" {
			detail += " (" + code + ")"
		}
		return nil, describing(detail, res)
	}
	st := got.state(entry)
	return &st, ""
}

// ---------------------------------------------------------------------------
// The Engine's own classifier
// ---------------------------------------------------------------------------

// engineFailure is the second classifier §15 says the Docker endpoint adds: an Engine response read
// as a phase and a detail.
//
// The phase itself always comes from the shared classification — the transport produced it from the
// status or from the transport error. What this adds is the Engine's own error message, which is the
// only place the *reason* lives: a 404 from the Engine says which container is gone, and a 500 says
// what it could not do.
func engineFailure(res transport.Result) (payload.ConnectionPhase, string, bool) {
	if res.OK() {
		return res.Phase, "", false
	}
	if res.Err != nil {
		return res.Phase, conn.Prose(res.Phase), true
	}

	detail := "the Engine answered " + strconv.Itoa(res.Status)
	var e engineError
	if _, _, err := conn.ReadJSON(bytes.NewReader(res.Body), &e); err == nil && e.Message != "" {
		return res.Phase, detail + ": " + e.Message, true
	}
	// Not the Engine's own error shape, so there is no message to quote and the body is the only
	// account of the refusal there is. This is the socket proxy that was never given CONTAINERS=1:
	// the status alone reads as *the Engine refused us*, and what actually refused is in front of it.
	return res.Phase, describing(detail, res), true
}

// engineError is the shape every Engine error shares.
type engineError struct {
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// The Engine's wire shapes, and the fields §10 takes from them
// ---------------------------------------------------------------------------

// listEntry is what `GET /containers/json?all=1` returns per container. Only three fields are read:
// the id to inspect, the names to index by, and the summary status — which §10 takes from *here*
// rather than from the inspect, because the inspect has no equivalent of `Up 3 days (healthy)`.
type listEntry struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

// inspectResponse is what `GET /containers/{id}/json` returns. Every field §10 tabulates is here and
// nothing else is: an unread field is one fewer thing that can change meaning under us.
type inspectResponse struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Created      string `json:"Created"`
	Image        string `json:"Image"`
	RestartCount int    `json:"RestartCount"`

	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`

	State struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`

	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// state is the §10 field table, applied once.
func (r inspectResponse) state(entry listEntry) payload.DockerState {
	st := payload.DockerState{
		ID:      shortID(r.ID),
		Name:    strings.TrimPrefix(r.Name, "/"),
		Image:   r.Config.Image,
		State:   r.State.Status,
		Status:  entry.Status, // from the list response, per §10
		Running: r.State.Running,

		Health:      healthOf(r.healthStatus()),
		Networks:    []string{},
		IPAddresses: map[string]string{},
	}

	// The digest is only reported when the Engine gave one in the form that is a digest. `Image` on
	// an inspect is normally `sha256:…`, but on an old or unusual Engine it can be a bare name, and
	// slicing that would publish 19 characters of an image name as a digest.
	if strings.HasPrefix(r.Image, "sha256:") && len(r.Image) >= 19 {
		st.ImageDigest = r.Image[:19]
	}
	// Zero restarts and no report are different facts, so this is a pointer (§16). The Engine always
	// sends the field, so a zero here means zero.
	restarts := r.RestartCount
	st.RestartCount = &restarts

	st.CreatedAt = r.Created
	st.StartedAt = r.State.StartedAt

	// Sorted, because these end up in a payload and I7 does not exempt a map's iteration order.
	for name := range r.NetworkSettings.Networks {
		st.Networks = append(st.Networks, name)
	}
	sort.Strings(st.Networks)
	for _, name := range st.Networks {
		// Only where non-empty: this map is what container-IP lookup is built from (§9), and an
		// empty string in it would be an address that resolves to nothing.
		if ip := r.NetworkSettings.Networks[name].IPAddress; ip != "" {
			st.IPAddresses[name] = ip
		}
	}

	st.PublishedPorts = ports(r.NetworkSettings.Ports)
	return st
}

// healthStatus is the Engine's health string, or empty when the container declares no health check.
func (r inspectResponse) healthStatus() string {
	if r.State.Health == nil {
		return ""
	}
	return r.State.Health.Status
}

// healthOf is `State.Health.Status`, else `none` (§10). A container with no health check declared is
// `none` rather than absent, because §4 keeps the member and the UI colours off it.
func healthOf(status string) payload.HealthState {
	switch payload.HealthState(status) {
	case payload.HealthHealthy:
		return payload.HealthHealthy
	case payload.HealthUnhealthy:
		return payload.HealthUnhealthy
	case payload.HealthStarting:
		return payload.HealthStarting
	default:
		// An Engine reporting a status outside the closed set is reported as having none rather than
		// as having invented a member: §16 makes adding a union member a breaking change, so a
		// string from the wire must never become one (§4).
		return payload.HealthNone
	}
}

// ports turns `NetworkSettings.Ports` into the payload's port mappings.
//
// The raw string is the evidence and the presence of a published port is the signal; no rule anywhere
// parses the number back out (§6). An exposed port with no binding gets one entry with no
// `published`, because *exposed and unbound* is a different fact from *not exposed*.
func ports(from map[string][]struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}) []payload.PortMapping {
	out := []payload.PortMapping{}

	keys := make([]string, 0, len(from))
	for key := range from {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		target, protocol := splitPortKey(key)
		bindings := from[key]
		if len(bindings) == 0 {
			out = append(out, payload.PortMapping{
				Target: target, Protocol: protocol, Raw: key,
			})
			continue
		}
		for _, b := range bindings {
			host := b.HostPort
			if b.HostIP != "" {
				host = b.HostIP + ":" + b.HostPort
			}
			out = append(out, payload.PortMapping{
				Published: b.HostPort,
				Target:    target,
				Protocol:  protocol,
				Raw:       host + "->" + key,
			})
		}
	}
	return out
}

func splitPortKey(key string) (target, protocol string) {
	target, protocol, found := strings.Cut(key, "/")
	if !found {
		return target, "tcp"
	}
	return target, protocol
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// keysFor is the three keys §10 requires per container.
//
// The compose key comes from the labels, so a container started by hand has only the other two — and
// that is the correct answer rather than a gap: nothing scanned will look for it by a compose key it
// does not have.
func keysFor(st payload.DockerState, list []listEntry) []string {
	keys := []string{st.Name, st.ID}

	for _, entry := range list {
		if shortID(entry.ID) != st.ID {
			continue
		}
		project := entry.Labels["com.docker.compose.project"]
		service := entry.Labels["com.docker.compose.service"]
		if project != "" && service != "" {
			keys = append(keys, ComposeKey(project, service))
		}
		break
	}

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if key != "" {
			out = append(out, key)
		}
	}
	return out
}
