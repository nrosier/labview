package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/nrosier/labview/internal/config"
)

// Timeouts on the inbound listener. They are not configurable, because none of them is a preference:
// each one bounds a way a client can hold a connection open, and a deployment that needed a different
// value would be a deployment doing something this program does not do.
const (
	// readHeaderTimeout is the slowloris bound. A client that opens a connection and sends a header
	// byte a minute costs a goroutine until it stops; five seconds is generous for a browser on the
	// far side of a home connection and short for anything else.
	readHeaderTimeout = 5 * time.Second

	// writeTimeout must exceed the slowest honest response, which is a forced rescan that probes a
	// fleet. The probe's own budgets bound that work; this is the outer edge, and it is long because
	// a reader who asked for a rescan of eighty services should get one rather than a truncated body.
	writeTimeout = 120 * time.Second

	// idleTimeout closes a kept-alive connection nobody is using.
	idleTimeout = 120 * time.Second

	// shutdownGrace is how long a stop waits for in-flight requests. A scan in flight is the long
	// case, and it is bounded by the same budgets as any other build.
	shutdownGrace = 20 * time.Second
)

// serve starts the HTTP listener and blocks until a signal stops it.
//
// The exit code is the contract with whatever supervises the process: 0 for a clean stop on a signal,
// 1 for a start-up failure. **A failure to read configuration is not a start-up failure** (§3: a
// malformed file logs and falls back to defaults) — the two things that can genuinely stop a start
// are a port that will not bind and a surface that will not assemble.
func serve(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}

	lg, cfg, diag := start(stderr)
	for _, warning := range diag.Warnings {
		lg.Line(LevelWarn, logConfig, warning)
	}

	p, err := assemble(cfg, lg, buildStamp())
	if err != nil {
		lg.Errorf(logServer, "%v", err)
		return 1
	}
	p.report()

	// **Bound before warming.** A port already in use is the commonest start-up failure there is, and
	// discovering it after a scan has begun would mean the first thing an operator sees is a scan
	// they cannot reach. Listen first, then warm.
	listener, err := net.Listen("tcp", p.address())
	if err != nil {
		lg.Errorf(logServer, "could not listen on %s: %v", p.address(), err)
		return 1
	}

	// **The signal context is installed before the first scan**, so a container stopped during a
	// slow first scan stops rather than finishing it. It also cancels the scan itself: pipeline.Run
	// answers a cancelled context with a payload saying what it managed (I4), so the shutdown path
	// has nothing to special-case.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// §18: the cache MUST be warmed in the background at start-up, so the first reader does not wait
	// for a scan.
	p.cache.Warm(ctx)

	srv := &http.Server{
		Handler:           p.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		// No ReadTimeout: it bounds the whole request including the body, and the only bodies here
		// are two small JSON objects. ReadHeaderTimeout is the bound that matters.
	}

	failed := make(chan error, 1)
	go func() {
		lg.Infof(logServer, "listening on %s", p.address())
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
		close(failed)
	}()

	select {
	case err, ok := <-failed:
		if ok && err != nil {
			lg.Errorf(logServer, "the listener stopped: %v", err)
			return 1
		}
		// Closed without an error, which only happens if something else shut the server down.
		return 0

	case <-ctx.Done():
		// Signal received. Stop honouring it immediately so a second signal kills the process rather
		// than being swallowed by a graceful shutdown that is taking too long — an operator pressing
		// Ctrl-C twice means it.
		stop()
		lg.Infof(logServer, "stopping")

		grace, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(grace); err != nil {
			// The in-flight requests outlasted the grace period. Reported, not fatal: the process is
			// stopping either way and the exit code should say whether it was asked to.
			lg.Warnf(logServer, "some requests did not finish within %s: %v", shutdownGrace, err)
		}
		return 0
	}
}

// start does the ambient reading every subcommand needs: the log level, then the configuration.
//
// The order is load-bearing. Configuration loading produces log lines of its own — §3's *failed to
// parse … using defaults* among them — so the logger has to exist first, which means the level comes
// from the environment directly rather than from the configuration it is about to report on.
func start(stderr io.Writer) (*Logger, config.Config, config.Diagnostics) {
	level, ok := ParseLevel(config.LogLevel(config.OSEnv()))
	lg := NewLogger(stderr, level)
	if !ok {
		lg.Warnf(logConfig, "%s is not a level this program knows, so %s is used", "LABVIEW_LOG_LEVEL", level)
	}

	cfg, diag := config.Load(config.Options{Env: config.OSEnv()})
	for _, line := range diag.Logs {
		lg.Line(LevelWarn, logConfig, line)
	}
	return lg, cfg, diag
}
