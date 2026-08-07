// Package pipeline is §5: one scan, from a compose tree to one Overview.
//
// One scan is a **pure function of (configuration, filesystem, Docker state, injected clock)**.
// It takes no logger, because a diagnostic inside the analysis would be a fact this program knows
// and the payload does not: every one of them is data on `meta.connections`, which callers print
// (I7). Nothing here is kept between runs — Run's arguments are the whole input and its return
// value is the whole output.
//
// The order below is §5's table, and each block says which stage it is. Where the placement is
// load-bearing — the two passes, the probe between the halves of pass 2, the scheduling of the two
// API reads — the reason is stated at the point the order is fixed, not only here.
//
// This package holds **no rule of its own**. Every conclusion is another package's, asserted in
// that package's tests as a pure function; what is asserted here is the wiring: which stage runs
// before which, what each one is handed, and where its answer lands.
package pipeline

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/authentik"
	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/declare"
	"github.com/nrosier/labview/internal/dockerapi"
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/probe"
	"github.com/nrosier/labview/internal/scan"
	"github.com/nrosier/labview/internal/secrets"
	"github.com/nrosier/labview/internal/traefikapi"
	"github.com/nrosier/labview/internal/transport"
)

// Clients are the four outbound targets' transports.
//
// A nil client is built by the package that owns the target, from that target's own configuration.
// Supplying one is how the corpus keeps every test hermetic: a RoundTripper answers from a table
// and no server is stood up (§23).
type Clients struct {
	Docker    *transport.Client
	Authentik *transport.Client
	Traefik   *transport.Client
	Probe     *transport.Client
}

// Options is one scan's whole input. Everything that could differ between two runs of the same
// binary arrives here, so a scan is a function of its arguments and reads no ambient state (I7).
type Options struct {
	// Cfg is the resolved configuration. Run never mutates it: the one request-scoped setting
	// arrives as Probe below and produces a copy (§3.6).
	Cfg config.Config

	// Now is the injected clock (I7). Nil means time.Now, which is what a process uses and what a
	// test replaces with a counter.
	Now func() time.Time

	// Probe is §13.7's override of `probe.enabled`, nil for *use configuration*. It is a parameter
	// of the build, so the build that starts owns the value and a coalesced caller's is discarded.
	Probe *bool

	// Build is the stamp of §3.4. The caller computes it once at start-up, because deriving it
	// reads the environment and a git checkout and neither is an input to a scan (I7). An unset
	// stamp reports `unknown` rather than being absent (§16).
	Build payload.BuildStamp

	// Filesystem is the Docker socket pre-check's only filesystem access (§10). Nil is the real one.
	Filesystem dockerapi.Filesystem

	Clients Clients
}

// Run performs one scan.
//
// It never fails. Every enrichment may be absent, unreachable, partial or hostile and the scan
// still produces a payload that says what it could not do (I4), so there is no error to return and
// no half-built Overview a caller has to check for.
func Run(ctx context.Context, o Options) payload.Overview {
	clock := o.Now
	if clock == nil {
		clock = time.Now
	}
	started := clock()

	cfg, probeEnabled, probeSource := probeDecision(o.Cfg, o.Probe)

	// -----------------------------------------------------------------------
	// Stages 1 and 2 — discover and parse
	//
	// One call, because §6 is one walk: an immediate subdirectory holding a compose file *is* a
	// stack, and there is nothing to decide between finding it and reading it.
	// -----------------------------------------------------------------------
	scanned := scan.Run(scan.Options{
		Root:             cfg.AppsRoot,
		ComposeFilenames: cfg.ComposeFilenames,
		SidecarFilenames: cfg.SidecarFilenames,
		RedactURI:        cfg.Secrets.RedactURICredentials,
	})
	stacks := scanned.Stacks

	// -----------------------------------------------------------------------
	// Scheduling (§5)
	//
	// A read that already has its endpoint — configured by hand, or switched off entirely —
	// depends on nothing in the scan, so it starts *before* the Docker snapshot and is awaited
	// after, overlapping the two. A read that has to discover its endpoint cannot start until pass
	// 1 has parsed the routes and stage 6 has resolved the origins, so it is dispatched there, and
	// then both discovered exchanges go out concurrently.
	//
	// The single wait is after that second dispatch rather than immediately after the snapshot.
	// That can only widen the overlap §5 asks for: nothing between the snapshot and stage 6 reads
	// either answer, and the first stage that does is stage 9.
	// -----------------------------------------------------------------------
	var wg sync.WaitGroup
	var identity authentik.Read
	var proxy traefikapi.Read

	readIdentity := func(candidates []authentik.Candidate) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			identity = authentik.Do(ctx, authentik.Options{
				Cfg:        cfg.Authentik,
				Client:     o.Clients.Authentik,
				Candidates: candidates,
			})
		}()
	}
	readProxy := func(candidates []traefikapi.Candidate) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy = traefikapi.Do(ctx, traefikapi.Options{
				Cfg:        cfg.Traefik,
				Client:     o.Clients.Traefik,
				Candidates: candidates,
			})
		}()
	}

	identityDiscovers := discovers(cfg.Authentik.Enabled, cfg.Authentik.URL)
	proxyDiscovers := discovers(cfg.Traefik.Enabled, cfg.Traefik.URL)
	if !identityDiscovers {
		readIdentity(nil)
	}
	if !proxyDiscovers {
		readProxy(nil)
	}

	// -----------------------------------------------------------------------
	// Stage 3 — the Docker snapshot, overlapping whichever reads started above
	// -----------------------------------------------------------------------
	snapshot := dockerapi.New(cfg.Docker, o.Filesystem, o.Clients.Docker).Read(ctx)

	// -----------------------------------------------------------------------
	// Stage 4 — the middleware registry
	//
	// Every middleware *defined* anywhere in the fleet, by bare name. It is fleet-wide and comes
	// before pass 1 because a reference such as `authentik@docker` is usually defined in another
	// stack, and reading it per-service would make the answer depend on scan order (§5, §7).
	// -----------------------------------------------------------------------
	registry := labels.NewRegistry(stacks, cfg.Labels.Traefik.Prefix)

	// -----------------------------------------------------------------------
	// Stage 5 — pass 1: routes and live container state
	// -----------------------------------------------------------------------
	routes(stacks, cfg, snapshot)

	// -----------------------------------------------------------------------
	// Stage 5b — ingress classification, over the whole fleet at once
	//
	// `internal` is a claim about *other* containers, so every service's networks must be counted
	// before any service is classified — which is what the network index is (§5, §8).
	// -----------------------------------------------------------------------
	networks := fleet.NewNetworks(stacks)
	classify(stacks, networks)

	// -----------------------------------------------------------------------
	// Stage 6 — the fleet index and the resolved origins
	//
	// The index is built once and shared by every later stage: the identity-provider match, the
	// proxy cross-check, the gate resolution and the probe all ask it the same questions, and a
	// second index would be a second set of answers (§9).
	// -----------------------------------------------------------------------
	index := fleet.NewIndex(stacks)
	proxies := fleet.Origins(index, networks)

	// -----------------------------------------------------------------------
	// Stage 6b — declared dependencies
	//
	// It needs both indexes — stage 6's to resolve a name in any stack, stage 5b's to know which
	// network the pair shares — and runs before the graph, because that is where a resolved pair
	// lands (§5).
	// -----------------------------------------------------------------------
	deps := fleet.Dependencies(index, networks)

	// -----------------------------------------------------------------------
	// Stages 7 and 8 — the two API reads, concurrent with each other
	//
	// Behind stage 6 on purpose: a resolved origin structurally identifies the service acting as
	// reverse proxy, which is one of §12's three discovery signals, so origin resolution has to
	// have run before the candidate list is built.
	// -----------------------------------------------------------------------
	if identityDiscovers {
		readIdentity(authentik.Candidates(stacks, registry))
	}
	if proxyDiscovers {
		readProxy(traefikapi.Candidates(stacks, proxies))
	}
	wg.Wait()

	// -----------------------------------------------------------------------
	// Stage 9 — provider discovery
	//
	// The hints identifying the SSO provider *in this fleet*: configured, discovered from the
	// stack that runs it, and — strongest of the three — the endpoint that answered the identity
	// provider's own API. That one is not a name match at all: the far end answered as an
	// Authentik API, which is what attributes an issuer correctly when the provider runs outside
	// the scanned root (§5, §7).
	// -----------------------------------------------------------------------
	hints := labels.NewHints(
		cfg.Labels.Authentik.HostHints,
		labels.Discover(stacks, registry),
		answered(identity),
	)

	// The service the identity-provider API answered on, when it answered on one this scan can
	// see. Exactly one candidate or nothing: an address two services answer to is a tie, and
	// picking between them would attribute a gate to the wrong far end (§9).
	identityKey := ""
	if identity.Report.OK {
		if key, ok := fleet.GateService(index, identity.Endpoint); ok {
			identityKey = key
		}
	}

	// -----------------------------------------------------------------------
	// Stage 10 — application matching
	// -----------------------------------------------------------------------
	apps := authentik.Apply(identity, index)
	for _, key := range index.Keys() {
		svc := index.Service(key)
		if match := apps.ByService[key]; match != nil {
			svc.Authentik = match
		}
		// The reasons, before pass 2 decides anything. A provider assigned to no outpost contributes
		// no account, so by the time the posture is rolled up there is nothing left to explain why a
		// matched application did not protect this service (§11).
		svc.Notes = append(svc.Notes, apps.Notes[key]...)
	}

	// -----------------------------------------------------------------------
	// Stage 11 — live router matching
	// -----------------------------------------------------------------------
	live := traefikapi.Apply(proxy.Snapshot, index)
	for _, key := range index.Keys() {
		if routers := live.ByService[key]; len(routers) > 0 {
			index.Service(key).TraefikLive = routers
		}
	}
	proxyNotes(index, proxy, registry)

	// -----------------------------------------------------------------------
	// Stage 12a — every service's posture
	//
	// Everything fleet-wide has now happened, which is what pass 2 is for: the registry knows
	// every middleware definition, the hints know who the provider is, the live chain is attached
	// and the applications are matched. A rule that needed any of it could not have run in pass 1.
	// -----------------------------------------------------------------------
	gates := map[string]string{}
	for _, key := range index.Keys() {
		svc := index.Service(key)

		label, notes := labels.FromLabels(labels.Input{
			Service:       *svc,
			Registry:      registry,
			Hints:         hints,
			LDAPEnvHints:  cfg.Labels.Authentik.LDAPEnvHints,
			OAuthEnvHints: cfg.Labels.Authentik.OAuthEnvHints,
		})
		svc.Notes = append(svc.Notes, notes...)

		chain := traefikapi.PostureOf(traefikapi.PostureInput{
			Routers:       svc.TraefikLive,
			Reachable:     proxy.Reachable(),
			ChainComplete: proxy.ChainComplete(),
			Absent:        live.Absent(*svc),
			LabelAccounts: label,
			Hints:         hints,
			Index:         index,
			AuthentikKey:  identityKey,
			Applications:  svc.Authentik,
		})
		svc.Notes = append(svc.Notes, chain.Notes...)

		// §12's downgrade. A label declaring an auth middleware the live chain does not contain is
		// discarded outright — not weakened — which is what frees the service to land in the
		// exposure finding. What is *not* discarded is the identity provider's own account of it:
		// that is not a label, and the proxy read says nothing about it.
		groups := [][]labels.Account{label, chain.Accounts, apps.Accounts[key]}
		if chain.Suppress {
			groups = [][]labels.Account{chain.Accounts, apps.Accounts[key]}
		}
		svc.Auth = labels.Resolve(groups...)

		// Where the winning gate is answered, resolved to the service that answers it, so the gate
		// can be drawn *on* the ingress path rather than only beside its far end (§22.5). A service
		// that gates itself is no hop and is not recorded as one.
		if gate, ok := fleet.GateService(index, labels.GateAddress(groups...)); ok && gate != key {
			gates[key] = gate
		}
	}

	// -----------------------------------------------------------------------
	// Stage 8b — the active probe
	//
	// **It must not join the concurrent reads.** Whether this scan found any authentication is
	// unknown until both API reads have landed and 12a has derived a posture, and §13.1's whole
	// point is not asking a question whose answer could not have changed anything. So it runs
	// here, between the halves of pass 2, and an enabled probe adds its own wall-clock time.
	// -----------------------------------------------------------------------
	subjects := make([]probe.Subject, 0, len(index.Keys()))
	for _, key := range index.Keys() {
		subjects = append(subjects, probe.Subject{Key: key, Service: *index.Service(key)})
	}
	probed := probe.Do(ctx, probe.Options{
		Cfg:      cfg.Probe,
		Enabled:  probeEnabled,
		Source:   probeSource,
		Client:   o.Clients.Probe,
		Subjects: subjects,
	})
	for _, key := range index.Keys() {
		if record, ok := probed.Results[key]; ok {
			index.Service(key).Probe = &record
		}
	}

	// -----------------------------------------------------------------------
	// Stage 12b — exposure verdicts, the declaration comparison and its notes
	//
	// §14 in one walk, so a service cannot end up in the drift list and not the unconfirmed list
	// by accident. It reads the probe result, which is why it is here and not in 12a.
	// -----------------------------------------------------------------------
	declare.Apply(declare.Input{Stacks: stacks, Refused: deps.Refused})

	// And then the masking, at the very end of pass 2b so that no later stage can read an unmasked
	// value (§20).
	mask(stacks, cfg)

	// -----------------------------------------------------------------------
	// Stages 13 and 14 — the graph and the counters
	// -----------------------------------------------------------------------
	identitySummary := authentik.Summarize(identity, apps)
	proxySummary := traefikapi.Summarize(proxy, live)

	graph := fleet.BuildGraph(fleet.GraphInput{
		Stacks:   stacks,
		Index:    index,
		Networks: networks,
		Deps:     deps,
		// Both halves of `role: "proxy"` (§9): the services something's tunnel origin resolved to,
		// and the service whose proxy API answered.
		Proxies:   with(proxies, proxy.EndpointKey),
		Gates:     gates,
		Authentik: &identitySummary,
		Traefik:   &proxySummary,
	})
	stats := fleet.Stats(fleet.StatsInput{Stacks: stacks, Networks: networks, Deps: deps})

	out := payload.Overview{
		Meta: payload.ScanMeta{
			ScannedAt:       started.UTC().Format(time.RFC3339),
			AppsRoot:        cfg.AppsRoot,
			DockerAvailable: snapshot.Report.OK,
			DockerError:     detail(snapshot.Report),
			Authentik:       &identitySummary,
			Traefik:         &proxySummary,
			// In `conn.Targets` order, so two scans of one fleet produce the same list (I7, §15).
			Connections: []payload.ConnectionReport{
				snapshot.Report, identity.Report, proxy.Report, probed.Report,
			},
			Probe:      probed.Run,
			DurationMs: int(clock().Sub(started) / time.Millisecond),
			Warnings:   scanned.Warnings,
			Build:      stamp(o.Build),
		},
		Stats:  stats,
		Stacks: stacks,
		Graph:  graph,
	}

	// Appendix A's required lists are lists, never null. It is a walk over the payload rather than
	// a discipline every builder has to remember, because that discipline fails silently (§16).
	payload.Normalize(&out)
	return out
}

// ---------------------------------------------------------------------------
// The stages that are a walk over the fleet
// ---------------------------------------------------------------------------

// routes is stage 5: the routes one service's own labels declare, and the live container behind it.
//
// Per-service on purpose — a tunnel label set and a router label set are read from one service's
// labels and nothing else — which is exactly why every conclusion that needs a neighbour is in
// pass 2 instead (§5).
func routes(stacks []payload.AppStack, cfg config.Config, snapshot dockerapi.Snapshot) {
	for si := range stacks {
		stack := &stacks[si]
		for vi := range stack.Services {
			svc := &stack.Services[vi]

			tunnels, tunnelNotes := labels.Cloudflare(svc.Labels, cfg.Labels.Dockflare.Prefix)
			routers, routerNotes := labels.Traefik(svc.Labels, cfg.Labels.Traefik.Prefix)

			svc.Cloudflare = tunnels
			svc.Traefik = routers
			svc.Notes = append(svc.Notes, tunnelNotes...)
			svc.Notes = append(svc.Notes, routerNotes...)

			svc.Docker = container(snapshot, *stack, *svc)
		}
	}
}

// container finds one service's live state by the two keys a scanned file can form: the compose
// key, from the project name and the service name, then the container name (§10). The short id is
// the snapshot's third key and no compose file names it.
//
// A snapshot that failed holds nothing, so this returns nil and the service simply has no live
// state — which is what an absent Docker read is supposed to look like (I4).
func container(snapshot dockerapi.Snapshot, stack payload.AppStack, svc payload.Service) *payload.DockerState {
	for _, key := range []string{
		dockerapi.ComposeKey(stack.ProjectName, svc.Name),
		svc.ContainerName,
	} {
		if strings.TrimSpace(key) == "" {
			continue
		}
		if state, ok := snapshot.Get(key); ok {
			return &state
		}
	}
	return nil
}

// classify is stage 5b: every service's ingress set, from the network index the whole fleet built.
func classify(stacks []payload.AppStack, networks *fleet.Networks) {
	for si := range stacks {
		stack := &stacks[si]
		for vi := range stack.Services {
			svc := &stack.Services[vi]
			svc.Ingress = fleet.ServiceIngress(*svc, networks, fleet.Key(stack.ID, svc.Name))
		}
	}
}

// proxyNotes attaches the two things the live proxy read knows that no scanned file could say, to
// the service whose API answered.
//
// Which credential that API needed, because `none` is not a convenience but a fact about how that
// API is exposed on the network it is on; and the middlewares the proxy holds that no scanned
// stack defines, because a file-provider definition is invisible to a file scan and a reader
// looking for one would otherwise find nothing at all (§12).
func proxyNotes(index *fleet.Index, read traefikapi.Read, registry labels.Registry) {
	svc := index.Service(read.EndpointKey)
	if svc == nil {
		return
	}
	if note := traefikapi.CredentialNote(read); note != "" {
		svc.Notes = append(svc.Notes, note)
	}
	if held := traefikapi.FileProviderMiddlewares(read.Snapshot, registry); len(held) > 0 {
		svc.Notes = append(svc.Notes, "The proxy holds "+
			conn.Plural(len(held), "middleware", "middlewares")+
			" that no scanned compose file defines: "+quoted(held))
	}
}

// mask is §20, run at the end of pass 2b.
//
// Two rules, and the second is the one a name pattern cannot reach. `AUTHENTIK_SECRET_KEY` is caught
// by what it is called; `DATABASE_URL` is not a secret name, and
// `postgresql://appuser:hunter2@db:5432/app` is a password in the payload all the same. A masking
// stage that read only keys would publish every credential anybody embedded in a connection string,
// which is where credentials most often are.
//
// A masked entry gets a **new** pointer rather than a rewritten one. The parser may hand the same
// string to more than one entry, and writing through the pointer would mask a value nobody asked
// to have masked.
func mask(stacks []payload.AppStack, cfg config.Config) {
	for si := range stacks {
		stack := &stacks[si]
		for vi := range stack.Services {
			env := stack.Services[vi].Env
			for ei := range env {
				entry := &env[ei]
				switch {
				case cfg.Masked(entry.Key):
					entry.Masked = true
					if entry.Value != nil {
						masked := secrets.MaskValue(*entry.Value)
						entry.Value = &masked
					}

				case entry.Value != nil:
					// Redaction rather than a mask, because the rest of the value is evidence: which
					// host a service connects to and as which account are things an operator reading
					// this payload needs, and only the password is the secret (§20). `Masked` is set
					// all the same — what is shown is not the whole value, and a reader has to be
					// able to see that and to filter on it.
					redacted := secrets.RedactURIs(*entry.Value)
					if redacted != *entry.Value {
						entry.Masked = true
						entry.Value = &redacted
					}
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The small decisions
// ---------------------------------------------------------------------------

// probeDecision applies §13.7's request-scoped override.
//
// The override produces a **copy** of the configuration and never a mutation, because the cache may
// have another build in flight still holding the old value (§3.6). The returned decision is
// authoritative for this build, which is why it is passed to the probe explicitly rather than left
// to be re-read from the configuration it came from.
func probeDecision(cfg config.Config, override *bool) (config.Config, bool, payload.ProbeRunSource) {
	if override == nil {
		return cfg, cfg.Probe.Enabled, payload.ProbeSourceConfig
	}
	return cfg.WithProbe(*override), *override, payload.ProbeSourceRequest
}

// discovers reports whether a read has to find its own endpoint, which is what decides when it is
// dispatched (§5). An integration that is switched off, or whose address the operator named, has
// nothing to learn from the scan.
func discovers(enabled bool, url string) bool {
	return enabled && strings.TrimSpace(url) == ""
}

// answered is the identity-provider endpoint that answered, as a hint (§5, stage 9). Nothing
// answered means nothing learned: a hint is never invented from an address that failed.
func answered(read authentik.Read) []string {
	if !read.Report.OK {
		return nil
	}
	if host := fleet.ParseAddress(read.Endpoint).Host; host != "" {
		return []string{host}
	}
	return nil
}

// with is a copy of a key set plus one more, empty keys ignored. A copy because the set it is given
// was handed to proxy discovery, and adding to it there would have made a service a candidate on
// the strength of an answer that had not arrived yet.
func with(keys map[string]bool, key string) map[string]bool {
	out := make(map[string]bool, len(keys)+1)
	for k := range keys {
		out[k] = true
	}
	if strings.TrimSpace(key) != "" {
		out[key] = true
	}
	return out
}

// detail is the error a summary or `meta.dockerError` carries. A `partial` read is reachable *and*
// has something to say, so it carries one too — it is `dockerAvailable` that says whether anything
// was obtained (§15).
func detail(report payload.ConnectionReport) string {
	if !report.OK || report.Phase == payload.PhasePartial {
		return report.Detail
	}
	return ""
}

// stamp is §3.4's build stamp, with §16's rule that a field describing the build is never optional:
// a caller that supplied none gets `unknown` rather than an absent source.
func stamp(in payload.BuildStamp) payload.BuildStamp {
	if in.Source == "" {
		return payload.BuildStamp{Version: config.Version, Source: payload.BuildUnknown}
	}
	return in
}

// quoted is a list of names in backticks, for a note.
func quoted(names []string) string {
	out := ""
	for i, name := range names {
		switch {
		case i == 0:
		case i == len(names)-1:
			out += " and "
		default:
			out += ", "
		}
		out += "`" + name + "`"
	}
	return out
}
