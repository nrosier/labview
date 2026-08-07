package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/cache"
	"github.com/nrosier/labview/internal/changes"
	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/httpapi"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/pipeline"
	"github.com/nrosier/labview/internal/transport"
	"github.com/nrosier/labview/internal/webui"
)

// This file is the whole of LabView's assembly, and it is the only place in the program that reads
// ambient state: the environment, the working directory, the clock and the random source. Everything
// below the `internal/` boundary takes what it needs as an argument (I7), which is what makes the
// corpus able to run the entire pipeline with no network and no filesystem — and that property only
// survives if there is exactly one place where the real world is admitted. This is it.
//
// **Configuration is loaded once.** §3.6 is explicit: the probe override is the one request-scoped
// setting and *everything else is fixed for the life of the process*, and §17 adds that a rescan
// re-runs both API exchanges but does not re-read credentials. So the config value below is built at
// start-up and shared by every build. The one thing genuinely re-read is the passwd **file**, which
// §19 requires be picked up without a restart — that is the posture cache's 5000 ms and not a
// configuration reload.

// process is one assembled LabView: the configuration it was started with, and everything built from
// it. Built by assemble, used by serve.
type process struct {
	cfg   config.Config
	log   *Logger
	stamp payload.BuildStamp

	gate     *access.Gate
	provider *access.Provider
	cache    *cache.Cache
	server   *httpapi.Server

	// previous is the connection block the last build reported, so a working target is not
	// re-announced on every rescan (§15: comparing connections MUST NOT compare `read`).
	previous []payload.ConnectionReport
	// first is whether the next build is the first one. The first scan logs every connection
	// regardless of level (§15).
	first bool
}

// assemble builds the process from a loaded configuration.
//
// It returns an error only for httpapi.New's two refusals — a missing cache or gate — which cannot
// happen here and are checked rather than ignored. Everything else degrades and says so (I4): no
// session secret is a generated one, no assets is a running API with no dashboard, an unusable auth
// method is a note and never a lock-out (§19).
func assemble(cfg config.Config, lg *Logger, stamp payload.BuildStamp) (*process, error) {
	p := &process{cfg: cfg, log: lg, stamp: stamp, first: true}

	p.gate = p.buildGate()
	p.provider = p.buildProvider()
	p.cache = cache.New(cache.Options{
		Build: p.build,
		TTL:   time.Duration(cfg.CacheTTLSeconds) * time.Second,
		Built: p.built,
	})

	// **No assets is not a failure** (§18: the API MUST NOT depend on the presence of UI assets). A
	// binary whose UI subtree was misnamed still answers `/api/overview`, and an operator reading the
	// log learns which of the two problems they have.
	assets, err := webui.Assets()
	if err != nil {
		lg.Warnf(logServer, "the embedded UI could not be opened, so this build serves the API only: %v", err)
		assets = nil
	}

	server, err := httpapi.New(httpapi.Options{
		Cache:  p.cache,
		Gate:   p.gate,
		OIDC:   p.provider,
		Assets: assets,
		Logged: p.logged,
	})
	if err != nil {
		return nil, err
	}
	p.server = server
	return p, nil
}

// build is one scan: the cache's Build function.
//
// The probe override is passed through untouched — pipeline.Run makes the copy §3.6 requires, so
// this function holds no configuration state of its own and two concurrent builds cannot see each
// other's override.
func (p *process) build(ctx context.Context, probe *bool) payload.Overview {
	return pipeline.Run(ctx, pipeline.Options{
		Cfg:   p.cfg,
		Build: p.stamp,
		Probe: probe,
	})
}

// built is the cache's Built callback: one line per build, never one per waiter (§17).
//
// It is also where §15's connection logging happens, because the connection block is a fact about
// the scan that just finished and the cache is what knows a scan finished.
func (p *process) built(note changes.Note, forced bool) {
	current := p.cache.Peek()
	if current == nil {
		// Unreachable: the callback runs after the result is published. Guarded anyway, because the
		// alternative is a nil dereference in the one code path that exists to report what happened.
		return
	}

	p.logConnections(current.Meta.Connections)
	for _, warning := range current.Meta.Warnings {
		p.log.Line(LevelWarn, logScan, warning)
	}

	// §17's cadence: the baseline always speaks, a change always speaks, a forced rescan answers even
	// when nothing moved because somebody asked, and only a quiet timer rebuild stays silent.
	if note.Quiet() && !forced {
		p.log.Debugf(logScan, "rebuilt in %dms; nothing moved", current.Meta.DurationMs)
		return
	}
	lines := note.Lines()
	if len(lines) == 0 {
		// A forced rescan over an unchanged fleet. Somebody asked, so it answers.
		lines = []string{"rescanned; nothing moved"}
	}
	for _, line := range lines {
		p.log.Line(LevelInfo, logScan, line)
	}
}

// logConnections writes §15's block.
//
// **The first scan logs all of them; later scans log what changed.** Both halves are §15's: a
// working target at info and a failure at warn, and comparing target, `ok`, phase and endpoint but
// never `read` — a container count ticking up is not news about a connection.
func (p *process) logConnections(reports []payload.ConnectionReport) {
	for _, report := range reports {
		level := LevelInfo
		if conn.LevelOf(report) == conn.LevelWarn {
			level = LevelWarn
		}
		if !p.first && p.sameAsBefore(report) {
			continue
		}
		for _, line := range conn.Format(report) {
			p.log.Line(level, logConn, line)
		}
	}
	p.previous = reports
	p.first = false
}

// sameAsBefore reports whether this target said the same thing last time, by conn.Same — which
// compares target, ok, phase and endpoint and deliberately not `read` (§15).
func (p *process) sameAsBefore(report payload.ConnectionReport) bool {
	for _, before := range p.previous {
		if before.Target == report.Target {
			return conn.Same(before, report)
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// buildGate assembles §19's access control.
//
// The posture's `Config` is a closure over the loaded configuration rather than a copy handed in,
// which is the shape internal/access asks for: the gate must not hold a snapshot, so that what it
// consults is always the current answer. What makes it *current* here is the passwd file being
// re-read on the 5000 ms cadence, not the configuration changing.
func (p *process) buildGate() *access.Gate {
	auth := p.cfg.Auth

	return &access.Gate{
		Postures: &access.Postures{
			Config:  func() config.AuthConfig { return p.cfg.Auth },
			Changed: p.postureChanged,
		},
		Signer:  access.NewSigner(p.sessionSecret(), time.Duration(auth.Session.TTLMinutes)*time.Minute),
		Cookies: access.Cookies{Name: auth.Session.CookieName, Secure: auth.Session.Secure},
		Throttle: &access.Throttle{
			Max:    auth.MaxFailedAttempts,
			Window: time.Duration(auth.LockoutSeconds) * time.Second,
		},
		Rejected: p.rejected,
	}
}

// sessionSecret is §3.2's rule: unset means a random secret per start, so restarts sign everyone out.
//
// A generated secret is announced, because the consequence — every session invalidated by a restart
// — is one an operator should be able to explain without reading this source. It is announced by
// **existence and never by value**, like every other credential in this program (§20).
func (p *process) sessionSecret() string {
	if configured := strings.TrimSpace(p.cfg.Auth.Session.Secret); configured != "" {
		return configured
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand does not fail on any supported platform. If it did, refusing to start would
		// take the dashboard down over the one subsystem that is off by default (I4) — so this
		// degrades to a secret nobody chose, which is still nobody's known value.
		p.log.Warnf(logAuth, "no random source for a session secret, so sessions this process signs are weakly keyed: %v", err)
		return fmt.Sprintf("labview-fallback-%d", time.Now().UnixNano())
	}
	p.log.Infof(logAuth, "no LABVIEW_SESSION_SECRET is set, so one was generated: restarting this process signs everyone out")
	return base64.RawURLEncoding.EncodeToString(raw)
}

// postureChanged logs the access summary when it changes (§19).
//
// **Counts, never names.** §19 requires it, and the reason is that this line lands in whatever
// collects the container's logs: the number of accounts in a passwd file is operational, and the
// list of who they are is not.
func (p *process) postureChanged(posture access.Posture) {
	methods := make([]string, 0, 2)
	for _, method := range []payload.LoginMethod{payload.MethodPasswd, payload.MethodOIDC} {
		if posture.Live(method) {
			methods = append(methods, string(method))
		}
	}
	sort.Strings(methods)

	switch {
	case !posture.Enforced():
		p.log.Infof(logAuth, "no login method is live, so the dashboard is open")
	default:
		p.log.Infof(logAuth, "enforcing: %s live, %d local %s",
			strings.Join(methods, " and "), len(posture.Passwd),
			access.Plural(len(posture.Passwd), "account", "accounts"))
	}

	// The warnings are the enabled-but-unusable cases §19 says must produce a note and never a
	// lock-out — a passwd file that is a directory, an OIDC block with no client id.
	for _, warning := range posture.Warnings {
		p.log.Line(LevelWarn, logAuth, warning)
	}
}

// rejected is the gate's refusal log: the half of the outcome the client is never told (§19).
func (p *process) rejected(entry access.Rejection) {
	p.log.Warnf(logAuth, "%d on %s for %s: %s", entry.Status, entry.Path, entry.Username, entry.Reason)
}

// logged is the server's event log (§19). One line per login, logout, rescan or handshake step.
func (p *process) logged(e httpapi.Event) {
	level := LevelInfo
	if !e.OK {
		level = LevelWarn
	}

	line := e.What
	if e.Via != "" {
		line += " via " + string(e.Via)
	}
	if e.Username != "" {
		line += " for " + e.Username
	}
	if e.Reason != "" {
		line += ": " + string(e.Reason)
	}
	if e.Detail != "" {
		line += " — " + e.Detail
	}
	if e.Status != 0 {
		line += fmt.Sprintf(" (%d)", e.Status)
	}
	p.log.Line(level, logAuth, line)

	// A provider read that failed carries a connection report, and it is the same shape §15 formats
	// everywhere else — an operator debugging a sign-in gets the endpoint, the phase and the hint
	// rather than a sentence about a token.
	if e.Report != nil {
		for _, l := range conn.Format(*e.Report) {
			p.log.Line(level, logConn, l)
		}
	}
}

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

// buildProvider assembles the OIDC handshake, or nil when the method is not configured.
//
// Nil is a supported state and not an error: §18 keeps both OIDC routes registered either way, so a
// browser that still has the sign-in page open is answered with `method-unavailable` rather than
// with the UI shell from a route that vanished.
//
// The test for *configured* is issuer and client id both present, which is §19's liveness rule for
// the method. Enabled with neither is a posture warning, not a provider.
func (p *process) buildProvider() *access.Provider {
	oidc := p.cfg.Auth.OIDC
	if !oidc.Enabled {
		return nil
	}
	if strings.TrimSpace(oidc.Issuer) == "" || strings.TrimSpace(oidc.ClientID) == "" {
		// The posture reports this to the reader as a warning (§19). Logged here too, because the
		// operator who set one of the two variables is the one who needs to know the other is missing.
		p.log.Warnf(logAuth, "oidc is enabled but not configured, so it is not offered: both an issuer and a client id are needed")
		return nil
	}
	if oidc.ClientSecret == "" {
		// §3.2: set-and-empty is a startup note and a public client, **never** a refusal to start.
		// PKCE is used either way, so a public client is a supported deployment rather than a
		// degraded one.
		p.log.Infof(logAuth, "no oidc client secret is set, so this instance is a public client (PKCE either way)")
	}

	return &access.Provider{
		Config: func() access.OIDCSettings {
			current := p.cfg.Auth.OIDC
			return access.OIDCSettings{
				Issuer:        current.Issuer,
				ClientID:      current.ClientID,
				ClientSecret:  current.ClientSecret,
				RedirectURI:   current.RedirectURI,
				Scopes:        current.Scopes,
				UsernameClaim: current.UsernameClaim,
			}
		},
		// The same chokepoint every other outbound target uses (§15), so a provider that will not
		// resolve reports the phases the Diagnostics view already knows how to draw.
		HTTP:   transport.New(transport.Options{Timeout: time.Duration(p.cfg.Auth.OIDC.TimeoutMs) * time.Millisecond}),
		Signer: p.gate.Signer,
	}
}

// ---------------------------------------------------------------------------
// Start-up reporting
// ---------------------------------------------------------------------------

// report writes what this process was started with. Nothing here is a credential: §20's rule is that
// a credential is reported by existence, and the values below are paths, hosts and switches.
func (p *process) report() {
	stamp := p.stamp.Version
	if p.stamp.Commit != "" {
		stamp += " " + p.stamp.Commit
	}
	p.log.Infof(logServer, "LabView %s (%s)", stamp, p.stamp.Source)
	p.log.Infof(logConfig, "scanning %s", p.cfg.AppsRoot)

	docker := p.cfg.Docker.SocketPath
	if p.cfg.Docker.Host != "" {
		docker = fmt.Sprintf("%s:%d", p.cfg.Docker.Host, p.cfg.Docker.Port)
	}
	if !p.cfg.Docker.Enabled {
		docker = "disabled"
	}
	p.log.Infof(logConfig, "docker %s; cache %ds; probe %s; secrets %s",
		docker, p.cfg.CacheTTLSeconds, onOff(p.cfg.Probe.Enabled), maskedUnmasked(p.cfg.Secrets.MaskValues))

	// The posture is resolved once here so the access summary appears at start-up rather than on
	// whichever request happens to arrive first. Resolving it is enough: the first resolution is a
	// change, so `Postures.Changed` fires and writes the block. Calling postureChanged directly would
	// write it twice.
	p.gate.Postures.Current()
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func maskedUnmasked(v bool) string {
	if v {
		return "masked"
	}
	return "unmasked"
}

// address is the listener's address (§2.4: one inbound listener, default `0.0.0.0:8080`).
func (p *process) address() string {
	return fmt.Sprintf("%s:%d", p.cfg.Server.Host, p.cfg.Server.Port)
}

// handler is the composed HTTP surface. A method so serve does not reach into the struct.
func (p *process) handler() http.Handler { return p.server }
