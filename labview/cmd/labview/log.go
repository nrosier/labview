package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// Package-level note on the log, because §19 makes it load-bearing rather than incidental.
//
// **A reply says less than the log.** The client is told `401 {"error":"authentication required"}`
// and the log is told which session kind was refused on which path for which sanitised name. That
// split only holds if the log is a place with rules, so this is one: four levels, one writer, one
// lock, and a prefix per subsystem so an operator can grep for the thing they are chasing.
//
// It is deliberately not `log/slog`. Every line this program writes is a sentence some section of
// the specification dictates — `[config] failed to parse …; using defaults` (§3), the connection
// format of §15, the change note of §17 — and structured key-value output would either restate
// those sentences as fields or carry them as one opaque `msg`. What is wanted is the sentence.

// Level is a log level. Ordered by severity so a configured level can filter.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel reads §3.2's `LABVIEW_LOG_LEVEL`.
//
// An unrecognised value takes `info` and says so at warn rather than being rejected: the level is
// how an operator asks to be told things, and refusing to start because they misspelled `warning`
// would be refusing to start over the logging configuration.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace":
		return LevelDebug, true
	case "info", "":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error", "fatal":
		return LevelError, true
	}
	return LevelInfo, false
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	}
	return "info"
}

// Logger writes the program's lines.
//
// **Everything goes to stderr, including the server's.** §2.5 requires it of the one-shot scan so
// stdout stays parseable, and having the server agree means there is one answer to *where does
// LabView write* rather than one per subcommand — and a container's logs are stderr either way.
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	min Level
}

// NewLogger builds a logger writing to w at or above min.
func NewLogger(w io.Writer, min Level) *Logger { return &Logger{w: w, min: min} }

// Enabled reports whether a level would be written. Exported so a caller can skip building an
// expensive line — the connection block of §15 is a dozen strings — rather than formatting it for a
// writer that will drop it.
func (l *Logger) Enabled(level Level) bool { return level >= l.min }

// Printf writes one line at level, prefixed with the subsystem.
//
// The prefix is a parameter rather than part of the format string so every call site spells it the
// same way; §3 fixes at least one of them (`[config]`) as contract.
func (l *Logger) Printf(level Level, prefix, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	line := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%-5s [%s] %s\n", level.String(), prefix, line)
}

// Line writes an already-composed line. It is what the formatted blocks use — §15's connection
// report and §17's change note both arrive as strings a package produced, and passing them through
// Printf would mean a `%` in an endpoint became a format verb.
func (l *Logger) Line(level Level, prefix, line string) {
	l.Printf(level, prefix, "%s", line)
}

func (l *Logger) Debugf(prefix, format string, args ...any) {
	l.Printf(LevelDebug, prefix, format, args...)
}
func (l *Logger) Infof(prefix, format string, args ...any) {
	l.Printf(LevelInfo, prefix, format, args...)
}
func (l *Logger) Warnf(prefix, format string, args ...any) {
	l.Printf(LevelWarn, prefix, format, args...)
}
func (l *Logger) Errorf(prefix, format string, args ...any) {
	l.Printf(LevelError, prefix, format, args...)
}

// The subsystem prefixes. Constants rather than literals at the call sites, so the set is
// enumerable and an operator's grep has something to be told about.
const (
	logConfig = "config"
	logServer = "server"
	logScan   = "scan"
	logConn   = "conn"
	logAuth   = "auth"
)
