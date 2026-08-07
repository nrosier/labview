package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/pipeline"
)

// scan is §2.5's one-shot mode: one scan, the `Overview` payload on stdout as JSON, every diagnostic
// on stderr so stdout stays parseable.
//
// It exists for the case the dashboard cannot serve: an operator who cannot reach the UI, a CI job
// asserting something about a fleet, a bug report that needs the payload rather than a screenshot. So
// it runs the **same** pipeline the server runs, with the same configuration precedence — a one-shot
// mode that took a different path would answer a question about itself.
//
// **The exit code is about the scan, not about the fleet.** A fleet with nothing reachable still
// produces a whole payload (I4) and still exits 0, because the payload *is* the answer and a non-zero
// code would make a wrapper script treat a correct reading as a failure. Only a scan that could not
// be written out fails.
func scan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	probe := flags.String("probe", "", "override probe.enabled for this scan: `true` or `false`")
	compact := flags.Bool("compact", false, "write one line instead of indented JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	lg, cfg, diag := start(stderr)

	// §3.3: the retired settings are reported by both entry points — the server as a payload warning,
	// the one-shot scan on stderr.
	for _, warning := range diag.Warnings {
		lg.Line(LevelWarn, logConfig, warning)
	}

	override, err := probeOverride(*probe)
	if err != nil {
		lg.Errorf(logConfig, "%v", err)
		return 2
	}

	// Signals matter here too: a scan of a large tree with the probe on is not instant, and a
	// cancelled scan still returns a payload describing what it managed rather than nothing (I4).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	began := time.Now()
	out := pipeline.Run(ctx, pipeline.Options{
		Cfg:   cfg,
		Build: buildStamp(),
		Probe: override,
	})

	// The diagnostics go to stderr in the shape §15 formats everywhere else, so the same block that
	// appears in the server's log appears here — one line per target plus one indented line per
	// rejected candidate.
	for _, report := range out.Meta.Connections {
		level := LevelInfo
		if conn.LevelOf(report) == conn.LevelWarn {
			level = LevelWarn
		}
		for _, line := range conn.Format(report) {
			lg.Line(level, logConn, line)
		}
	}
	for _, warning := range out.Meta.Warnings {
		lg.Line(LevelWarn, logScan, warning)
	}
	// conn.Plural carries the count as well as the noun — it is the helper §15's `read` sentences are
	// built with (*86 containers*), so the number is part of what it returns.
	lg.Infof(logScan, "%s, %s in %dms",
		conn.Plural(out.Stats.Stacks, "stack", "stacks"),
		conn.Plural(out.Stats.Services, "service", "services"),
		out.Meta.DurationMs)

	if err := write(stdout, out, *compact); err != nil {
		// Writing the payload is the one thing this subcommand cannot degrade: a truncated JSON
		// document on stdout would be parsed by whatever is downstream as a fleet with fewer stacks.
		lg.Errorf(logScan, "the payload could not be written: %v", err)
		return 1
	}
	lg.Debugf(logScan, "wrote the payload in %s", time.Since(began).Round(time.Millisecond))
	return 0
}

// write emits the payload.
//
// Indented by default, because the reader of a one-shot scan is usually a person and 130 kilobytes of
// one-line JSON is not readable. `-compact` is for the pipe into `jq`.
//
// `SetEscapeHTML(false)` is deliberate: the default escapes `<`, `>` and `&` into `<` and friends,
// which turns a Traefik rule like `Host(\`a\`) && Path(\`/b\`)` into something an operator has to
// decode by eye. Nothing here is written into an HTML document — the UI reads this as JSON over
// `fetch` and the API sets `nosniff` (§19) — so the escaping buys nothing and costs legibility.
func write(w io.Writer, out payload.Overview, compact bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if !compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(out)
}

// probeOverride reads the `-probe` flag into §13.7's tri-state.
//
// The flag is a string rather than a bool because a bool flag has no *absent* — and absent is the
// value that means *use the configuration*, which is the default and is not the same as `false`. It
// is the same tri-state the rescan route carries as `{"probe": …}`.
func probeOverride(v string) (*bool, error) {
	switch v {
	case "":
		return nil, nil
	case "true", "1", "yes", "on":
		return payload.Ptr(true), nil
	case "false", "0", "no", "off":
		return payload.Ptr(false), nil
	}
	return nil, &badFlag{name: "probe", value: v}
}

type badFlag struct {
	name, value string
}

func (e *badFlag) Error() string {
	return "-" + e.name + " must be true or false, not " + e.value
}

// buildStamp resolves §3.4's identity once per process: the environment, then a checkout, then
// nothing. It reads the working directory and a git tree, neither of which is an input to a scan
// (I7), which is why the pipeline takes the answer as a parameter rather than computing it.
func buildStamp() payload.BuildStamp {
	return config.Stamp(config.OSEnv(), "")
}
