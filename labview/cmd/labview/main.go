// Command labview is the whole binary: the server, the one-shot scan and the password minter.
//
// §2.5 requires the three of them in one executable, and §2.3 requires the image to hold nothing but
// that executable and two example files — so there is no second entry point to build, no diagnostic
// tool to ship and no shell in the image to run one with. An operator who needs to know what LabView
// can see runs `labview scan`; an operator who needs a credential line runs `labview hashpw`.
//
// **The listener lives here and nowhere else.** §18 requires every route, hook and header to be
// registered in one place a test can construct without opening a socket, which means this package
// holds the one thing that package cannot: `http.Server`. Everything below is either the socket, the
// signal handling, or the reading of ambient state that `internal/` is forbidden (I7).
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with its ambient state as parameters, so the dispatch, the usage text and the exit
// codes are testable without a process (I7).
//
// **Diagnostics go to stderr for every subcommand**, not only for the scan. §2.5 requires it of the
// scan so stdout stays parseable; making the server agree means there is one answer to *where does
// LabView write* rather than one per subcommand, and a container's log collector reads both anyway.
func run(args []string, stdout, stderr io.Writer) int {
	command, rest := split(args)

	switch command {
	case "serve":
		return serve(rest, stderr)
	case "scan":
		return scan(rest, stdout, stderr)
	case "hashpw":
		return hashpw(rest, stdout, stderr, os.Stdin)
	case "version":
		fmt.Fprintln(stdout, versionLine())
		return 0
	case "help":
		usage(stdout)
		return 0
	}

	fmt.Fprintf(stderr, "labview: unknown subcommand %q\n\n", command)
	usage(stderr)
	return 2
}

// split separates the subcommand from its arguments.
//
// **No arguments means serve**, because that is what the image's entrypoint runs and a container that
// printed usage instead of starting would be a deployment that fails on an empty `CMD`. A leading
// flag also means serve, so `labview -addr=…` is not read as a subcommand named `-addr`.
func split(args []string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "serve", args
	}
	return args[0], args[1:]
}

// versionLine is what `labview version` prints, and it is the build stamp of §3.4 rather than a
// constant — so the answer here and the answer in the payload's `meta.build` cannot disagree.
func versionLine() string {
	stamp := config.Stamp(config.OSEnv(), "")
	out := "labview " + stamp.Version
	if stamp.Commit != "" {
		out += " " + stamp.Commit
	}
	if stamp.Source != payload.BuildUnknown {
		out += " (" + string(stamp.Source) + ")"
	}
	return out
}

func usage(w io.Writer) {
	fmt.Fprint(w, `LabView — a read-only view of what a homelab exposes and what protects it.

Usage:
  labview [serve]          start the HTTP server (the default, and the image's command)
  labview scan             run one scan and write the Overview payload to stdout as JSON
  labview hashpw <user>    read a password from stdin and print a `+"`user:hash`"+` line
  labview version          print the build stamp
  labview help             print this

Configuration is read from `+config.DefaultConfigPath+` (override with `+config.ConfigPathVar+`) and then
from the environment, which wins. Credentials are environment-only. See config.example.yml.
`)
}
