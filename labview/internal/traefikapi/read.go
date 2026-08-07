package traefikapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// Read is one read of the reverse proxy. It is complete on its own: a failure produces a report
// and an empty snapshot, never a nil that a caller has to check for (I4).
type Read struct {
	Report payload.ConnectionReport

	// Endpoint is credential-free, from the one formatter (§20). Source is only `config` or
	// `discovered`: there is no built-in proxy address to fall back to.
	Endpoint string
	Source   payload.EndpointSource

	// Enabled and Configured are two different facts a reader needs kept apart: whether the
	// integration was switched on at all, and whether the operator named its address.
	Enabled    bool
	Configured bool

	// Credential is which credential the API needed. CredentialNone means it answered without
	// one, which is evidence about how that API is exposed on the fleet's network and is reported
	// as a note on the proxy service rather than passed over (§12).
	Credential payload.TraefikCredential

	// EndpointKey is the service key the endpoint that answered belongs to, empty for a
	// configured address that matched no candidate. It is one half of where `role: "proxy"` comes
	// from; the other half is §9's resolved origins.
	EndpointKey string

	// Snapshot is the routing table. Empty and safe to walk when the read failed.
	Snapshot Snapshot

	// Attempts is what discovery tried and why each rejected candidate was rejected.
	Attempts []payload.ConnectionAttempt
}

// Reachable is whether the API answered. It is conn's definition of a working target and not a
// second one, so `partial` counts (§15).
func (r Read) Reachable() bool { return r.Report.OK }

// ChainComplete is reachable **and** the entrypoints were read (§12).
//
// It is derived rather than stored, because it is the condition a live chain may supersede a label
// list under, and a stored copy could disagree with the reachability a reader is shown.
func (r Read) ChainComplete() bool { return r.Reachable() && r.Snapshot.EntrypointsRead }

// Options is one read's whole input. Candidates arrive already built, because building them needs
// the scanned fleet and this package holds no fleet knowledge.
type Options struct {
	Cfg        config.TraefikConfig
	Client     *transport.Client
	Candidates []Candidate
}

// Do performs the read.
func Do(ctx context.Context, o Options) Read {
	r := Read{
		Enabled:    o.Cfg.Enabled,
		Credential: payload.CredentialNone,
		Attempts:   []payload.ConnectionAttempt{},
		Snapshot: Snapshot{
			Middlewares: map[string]RawMiddleware{},
			Services:    map[string]RawService{},
			Entrypoints: map[string][]string{},
		},
	}

	client := o.Client
	if client == nil {
		client = transport.New(transport.Options{Timeout: milliseconds(o.Cfg.TimeoutMs)})
	}

	if !o.Cfg.Enabled {
		r.Report = r.report(payload.PhaseDisabled, "")
		return r
	}

	base, creds, ok := r.selectEndpoint(ctx, client, o)
	if !ok {
		return r
	}

	// The routing table. Without it there is nothing to match, so its failure is the read's
	// failure — the version alone says a proxy is there and says nothing about this fleet.
	raw, phase, detail := readRawData(ctx, client, base, creds)
	if phase != payload.PhaseConnected {
		r.Report = r.report(phase, detail)
		return r
	}
	r.absorb(raw)

	// The entrypoints. Their absence is a `partial` read rather than a failure: every router and
	// every chain was obtained, and what is missing is the one thing that licenses a live chain to
	// supersede a label. §12 requires that gap noted and no posture changed, which is exactly what
	// a `partial` phase with EntrypointsRead false expresses.
	eps, phase, detail := readEntrypoints(ctx, client, base, creds)
	if phase != payload.PhaseConnected {
		r.Report = r.report(payload.PhasePartial,
			"the routing table was read and "+pathEntrypoints+" was not ("+detail+"), so a "+
				"middleware attached at an entrypoint cannot be seen and no live chain may "+
				"supersede a label")
		r.Report.Read = r.readLine()
		return r
	}
	r.Snapshot.Entrypoints = eps
	r.Snapshot.EntrypointsRead = true

	r.Report = r.report(payload.PhaseConnected, "")
	r.Report.Read = r.readLine()
	return r
}

// readLine is the one-line summary of what was obtained, for the connection report.
func (r Read) readLine() string {
	return conn.Plural(len(r.Snapshot.Routers), "router", "routers") + ", " +
		conn.Plural(len(r.Snapshot.Middlewares), "middleware", "middlewares") + ", " +
		conn.Plural(len(r.Snapshot.Services), "service", "services")
}

func (r Read) report(phase payload.ConnectionPhase, detail string) payload.ConnectionReport {
	rep := conn.Report(conn.TargetTraefik, phase, r.Endpoint, r.Source, detail)
	rep.Attempts = r.Attempts
	if rep.Attempts == nil {
		rep.Attempts = []payload.ConnectionAttempt{}
	}
	if phase.BeforeTheNetwork() {
		rep.Endpoint, rep.Source = "", ""
	}
	return rep
}

// absorb turns the wire document into the snapshot. It is the only place the two shapes meet, so
// the wire spellings stop here and nothing downstream reads a `json` tag.
func (r *Read) absorb(raw wireRawData) {
	for key, w := range raw.Routers {
		name := strings.TrimSpace(w.Name)
		if name == "" {
			name = strings.TrimSpace(key)
		}
		provider := strings.TrimSpace(w.Provider)
		if provider == "" {
			// Traefik always sends it, but the reference is `name@provider` and the provider half
			// decides whether matching rule 2 may apply — so it is derived from the key rather
			// than left empty, which would silently make a `@file` router eligible for it.
			if at := strings.LastIndex(name, "@"); at >= 0 {
				provider = name[at+1:]
			}
		}
		r.Snapshot.Routers = append(r.Snapshot.Routers, RawRouter{
			Name:        name,
			Provider:    provider,
			Status:      strings.TrimSpace(w.Status),
			Errors:      []string(w.Error),
			Rule:        strings.TrimSpace(w.Rule),
			Service:     strings.TrimSpace(w.Service),
			EntryPoints: w.EntryPoints,
			Middlewares: w.Middlewares,
			TLS:         w.tls(),
		})
	}
	sortRouters(r.Snapshot.Routers)

	for key, body := range raw.Middlewares {
		def := parseMiddleware(key, body)
		r.Snapshot.Middlewares[strings.ToLower(strings.TrimSpace(key))] = def
		// Also under the name the definition carries, when the two differ. A router refers to a
		// middleware by one or the other and a lookup that missed would report the proxy as
		// holding no definition for a middleware it plainly holds.
		if other := strings.ToLower(def.Name); other != "" {
			if _, exists := r.Snapshot.Middlewares[other]; !exists {
				r.Snapshot.Middlewares[other] = def
			}
		}
	}

	for key, w := range raw.Services {
		svc := RawService{Servers: []payload.TraefikLiveServer{}, Errors: []string(w.Error)}
		if w.LoadBalancer != nil {
			for _, s := range w.LoadBalancer.Servers {
				addr := strings.TrimSpace(s.URL)
				if addr == "" {
					continue
				}
				svc.Servers = append(svc.Servers, payload.TraefikLiveServer{
					URL: addr,
					// Whatever the proxy last observed, and nothing when it observed nothing.
					// An absent status MUST NOT read as healthy (Appendix A).
					Status: strings.TrimSpace(w.ServerStatus[addr]),
				})
			}
		}
		r.Snapshot.Services[strings.ToLower(strings.TrimSpace(key))] = svc
	}
}

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

// credentials is what may be sent, and to whom. It is a value rather than two strings so that
// every request in one read carries the same decision, and so that `none` is representable as the
// absence of a header rather than as an empty one.
type credentials struct {
	header  map[string]string
	cookies []*http.Cookie
}

func basic(username, password string) map[string]string {
	if strings.TrimSpace(username) == "" && password == "" {
		return nil
	}
	raw := username + ":" + password
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))}
}

// request issues one read with whatever credential was established, replaying the cookies from the
// authenticated exchange.
//
// Cookies are replayed because an Authentik outpost in front of the dashboard expects its session
// cookie echoed, and a retry that authenticated and then dropped the cookie would be challenged
// again on the very next request (§12).
func request(ctx context.Context, client *transport.Client, rawURL string, creds credentials) transport.Result {
	if creds.header == nil && len(creds.cookies) == 0 {
		// No credential of any kind, and by signature rather than by omission.
		return client.Anonymous(ctx, rawURL)
	}
	return client.Do(ctx, transport.Request{URL: rawURL, Header: creds.header, Cookies: creds.cookies})
}

// ---------------------------------------------------------------------------
// Endpoint selection
// ---------------------------------------------------------------------------

// selectEndpoint decides which address is read and what may be sent to it, and returns false
// having filled in the report when there is none.
//
// A configured URL is used verbatim: the operator named it, so a failure against it is a fact
// about their configuration and silently trying somewhere else would hide it. A discovered URL is
// a guess, and `/api/version` — which needs no authentication — is what turns a guess into an
// endpoint.
func (r *Read) selectEndpoint(ctx context.Context, client *transport.Client, o Options) (string, credentials, bool) {
	configured := basic(o.Cfg.Username, o.Cfg.Password)

	if raw := strings.TrimSpace(o.Cfg.URL); raw != "" {
		base := strings.TrimSuffix(raw, "/")
		r.Configured = true
		r.Source = payload.SourceConfig
		r.Endpoint = transport.Endpoint(base)

		creds, phase, detail := r.handshake(ctx, client, base, configured, true)
		if phase != payload.PhaseConnected {
			r.Report = r.report(phase, detail)
			return "", credentials{}, false
		}
		return base, creds, true
	}

	candidates := o.Candidates
	if len(candidates) == 0 {
		// Nothing in the scanned fleet identifies a proxy, and there is no default address to
		// fall back to. `not-configured` says that; a `connect` failure against a guessed address
		// would say something untrue.
		r.Report = r.report(payload.PhaseNotConfigured,
			"no traefik.url is configured and no scanned service identifies a Traefik API")
		return "", credentials{}, false
	}
	if len(candidates) > MaxCandidates {
		candidates = candidates[:MaxCandidates]
	}

	r.Source = payload.SourceDiscovered
	for _, c := range candidates {
		base := strings.TrimSuffix(c.URL, "/")

		// The credential goes only where ownership was proved. A hostname that merely looks like
		// a proxy — because something's origin resolved to it, or because it runs the image — is
		// probed anonymously and is never offered one (§12).
		var offer map[string]string
		if c.Owned {
			offer = configured
		}

		creds, phase, detail := r.handshake(ctx, client, base, offer, false)
		if phase != payload.PhaseConnected {
			r.reject(c, phase, detail)
			continue
		}

		r.Endpoint = transport.Endpoint(base)
		r.EndpointKey = c.Key
		return base, creds, true
	}

	// Every candidate was rejected. The attempt list is the diagnosis and it is already on the
	// report; the phase is the last one, because the last is the weakest evidence and a reader
	// looking at the list can see the rest.
	last := payload.PhaseConnect
	if n := len(r.Attempts); n > 0 {
		last = r.Attempts[n-1].Phase
	}
	r.Report = r.report(last, conn.Plural(len(candidates), "discovered address", "discovered addresses")+
		" answered, and none of them is a Traefik API")
	return "", credentials{}, false
}

// handshake probes one address on `/api/version` and settles what may be sent to it.
//
// Anonymous first, always. A candidate that answers that way is used **with no credential at all,
// and none is sent** — and `Credential` records `none`, which is itself the finding that this
// API is open on the network it is on.
//
// A 401, 403 or a redirect triggers the authenticated retry, and only when a credential was
// offered — which `selectEndpoint` decides, and which is the whole of the ownership rule.
func (r *Read) handshake(ctx context.Context, client *transport.Client, base string, offer map[string]string, configured bool) (credentials, payload.ConnectionPhase, string) {
	res := client.Anonymous(ctx, base+pathVersion)

	switch {
	case res.Err != nil:
		return credentials{}, res.Phase, conn.Prose(res.Phase)

	case res.OK():
		version, phase, detail := decodeVersion(res)
		if phase != payload.PhaseConnected {
			return credentials{}, phase, detail
		}
		r.Snapshot.Version = version
		r.Credential = payload.CredentialNone
		return credentials{}, payload.PhaseConnected, ""

	case challenged(res.Status):
		if offer == nil {
			if configured {
				// The address is configured and the credential is what is missing. `credential`
				// rather than `authenticate`, because the hint for the two is different: one asks
				// for a password and the other says the password was wrong.
				return credentials{}, payload.PhaseCredential,
					"the configured endpoint answered " + strconv.Itoa(res.Status) +
						" and no traefik.username and traefik.password are configured"
			}
			return credentials{}, conn.FromStatus(res.Status),
				"answered " + strconv.Itoa(res.Status) + ", and no credential may be sent to an " +
					"address the scan did not prove is the proxy's own API"
		}
		return r.retry(ctx, client, base, offer, res.Cookies)

	default:
		return credentials{}, res.Phase, "answered " + strconv.Itoa(res.Status)
	}
}

// retry is the authenticated second attempt, carrying the cookies the challenge set.
func (r *Read) retry(ctx context.Context, client *transport.Client, base string, offer map[string]string, jar []*http.Cookie) (credentials, payload.ConnectionPhase, string) {
	creds := credentials{header: offer, cookies: jar}

	res := client.Do(ctx, transport.Request{URL: base + pathVersion, Header: creds.header, Cookies: creds.cookies})
	if res.Err != nil {
		return credentials{}, res.Phase, conn.Prose(res.Phase)
	}
	if !res.OK() {
		return credentials{}, res.Phase,
			"answered " + strconv.Itoa(res.Status) + " to an authenticated read as well"
	}

	version, phase, detail := decodeVersion(res)
	if phase != payload.PhaseConnected {
		return credentials{}, phase, detail
	}

	// The cookies this exchange set are added to the ones it replayed, because an outpost issues
	// its session on the authenticated response and the reads that follow need it (§12).
	creds.cookies = mergeCookies(creds.cookies, res.Cookies)

	r.Snapshot.Version = version
	r.Credential = payload.CredentialBasic
	return creds, payload.PhaseConnected, ""
}

// challenged reports whether a status is the proxy asking for a credential.
//
// A redirect counts. A dashboard behind an Authentik outpost answers an anonymous request with a
// 302 to the login flow rather than with a 401, so reading only the two authentication statuses
// would classify a gated API as merely `status` and never retry (§12).
func challenged(status int) bool {
	switch {
	case status == 401 || status == 403 || status == 407:
		return true
	case status >= 300 && status < 400:
		return true
	default:
		return false
	}
}

// decodeVersion reads the version document, and is also the check that this is a Traefik API at
// all.
//
// A JSON *object*, specifically. An array or a bare string is a well-formed answer from something
// that is not this API, and a guess that merely returns valid JSON has not earned an endpoint —
// nor, where it is owned, a credential.
func decodeVersion(res transport.Result) (string, payload.ConnectionPhase, string) {
	var probe wireVersion
	phase, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &probe)
	if err != nil {
		return "", phase, "answered " + strconv.Itoa(res.Status) +
			" and did not answer a JSON object (" + code + ")"
	}
	return probe.version(), payload.PhaseConnected, ""
}

func mergeCookies(into, from []*http.Cookie) []*http.Cookie {
	for _, c := range from {
		if c == nil || c.Name == "" {
			continue
		}
		replaced := false
		for i, existing := range into {
			if existing != nil && existing.Name == c.Name {
				into[i], replaced = c, true
				break
			}
		}
		if !replaced {
			into = append(into, c)
		}
	}
	return into
}

// reject records one candidate that will not be read, and why it was a candidate at all.
//
// `Why` is the evidence — which service identified a proxy and by which of the three signals —
// because an attempt list without it says a scan tried some addresses, and with it says what the
// scan believed and where that belief was wrong (§15). It never holds an environment value
// (I2, I6).
func (r *Read) reject(c Candidate, phase payload.ConnectionPhase, detail string) {
	r.Attempts = append(r.Attempts, payload.ConnectionAttempt{
		Endpoint: transport.Endpoint(c.URL),
		Why:      c.Why,
		Phase:    phase,
		Detail:   detail,
	})
}

// ---------------------------------------------------------------------------
// The two reads
// ---------------------------------------------------------------------------

func readRawData(ctx context.Context, client *transport.Client, base string, creds credentials) (wireRawData, payload.ConnectionPhase, string) {
	res := request(ctx, client, base+pathRawData, creds)
	if res.Err != nil {
		return wireRawData{}, res.Phase, conn.Prose(res.Phase)
	}
	if !res.OK() {
		return wireRawData{}, res.Phase,
			"the API answered " + strconv.Itoa(res.Status) + " for " + pathOf(base+pathRawData)
	}

	var raw wireRawData
	phase, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &raw)
	if err != nil {
		return wireRawData{}, phase, pathRawData + " did not answer JSON (" + code + ")"
	}
	return raw, payload.PhaseConnected, ""
}

// readEntrypoints reads the entrypoint list and keeps only the middleware references, keyed on the
// entrypoint name.
//
// The list is a bare array rather than an envelope, which is what Traefik answers here.
func readEntrypoints(ctx context.Context, client *transport.Client, base string, creds credentials) (map[string][]string, payload.ConnectionPhase, string) {
	res := request(ctx, client, base+pathEntrypoints, creds)
	if res.Err != nil {
		return nil, res.Phase, conn.Prose(res.Phase)
	}
	if !res.OK() {
		return nil, res.Phase, "answered " + strconv.Itoa(res.Status)
	}

	var got []wireEntrypoint
	phase, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &got)
	if err != nil {
		return nil, phase, "did not answer JSON (" + code + ")"
	}

	out := map[string][]string{}
	for _, ep := range got {
		name := strings.ToLower(strings.TrimSpace(ep.Name))
		if name == "" || ep.HTTP == nil {
			continue
		}
		for _, ref := range ep.HTTP.Middlewares {
			if ref = strings.TrimSpace(ref); ref != "" {
				out[name] = appendOnce(out[name], ref)
			}
		}
	}
	return out, payload.PhaseConnected, ""
}

// pathOf is the path of a URL, for a detail line. It never carries the query string, which is
// where a credential could live (§20).
func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "the endpoint"
	}
	return u.Path
}

func milliseconds(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

// sortedNames is the middleware names a snapshot holds, for a count and for a stable note.
func sortedNames(in map[string]RawMiddleware) []string {
	out := make([]string, 0, len(in))
	for _, def := range in {
		out = appendOnce(out, def.Name)
	}
	sort.Strings(out)
	return out
}
