// Package webui is §22: the reading instrument for one payload, and the contract that instrument
// is built from.
//
// **Why a Go package for a user interface.** §16 says it plainly: every pure rule the corpus
// asserts — filters, roll-ups, view state, wording — MUST live where it can be tested without
// rendering, and MUST NOT be implemented twice. §23 then makes three of those rules gate CI:
// payload coverage, card destinations and the diagram text export. A rule asserted in Go and
// applied in a browser is the same rule twice unless one of them is the definition and the other
// reads it. So this package holds the definitions:
//
//   - the fourteen views and their columns (§22.2), which are also the coverage map (§22.1);
//   - the vocabulary: one label, one tone and one non-colour mark per union member (§22.1);
//   - view state as a query string, both directions (§22.7);
//   - the filter grammar and its evaluation over rows (§22.6);
//   - the overview cards and where each one goes (§22.3);
//   - the drawer sections (§22.4);
//   - the four diagrams, their caps, their edge lists and their text export (§22.5).
//
// The browser reads all of it. `contract.js` is **generated from this package** (contract.go) and
// committed beside the hand-written modules, with a test that the committed bytes are what this
// package produces. The JavaScript is therefore an evaluator of tables rather than a second
// statement of the rules: it holds no view slug, no colour, no member spelling and no card
// destination of its own. What is written twice is deliberately only the *mechanical* half — how
// to read a tag off a row, how to draw a table — and never a rule the corpus asserts.
//
// **Nothing here renders HTML.** The payload never reaches this package at runtime either: the
// assets are static bytes (§2.2) served without a session, and everything below is either a
// compile-time table, a pure function used by the tests and the generator, or the embed.
//
// **State lives in the query string, and that is not only §22.7's requirement.** §2.2 requires
// relative asset URLs so a path-prefixed mount works. A path-routed single-page app breaks that:
// the shell served at `/stack/media` resolves `assets/app.js` against `/stack/`, and the request
// 404s. With every view, filter, diagram selection and drawer expressible as a query string, the
// document path never moves off the mount point, so relative URLs resolve from one place and a
// shared link reproduces a state (§22.7) without the server having to know any of the view slugs.
package webui

import (
	"embed"
	"io/fs"
)

// bundle is the built UI. `all:` is deliberate: without it `embed` drops files whose names begin
// with `_` or `.`, and a bundler's output is allowed to contain both — a silently missing chunk
// would be served as the shell and reported by the browser as a syntax error in a file that does
// not exist (§18).
//
//go:embed all:dist
var bundle embed.FS

// Assets is the embedded UI, rooted so `index.html` sits at the top (§18 serves it from `/`).
//
// It returns an error rather than panicking so `cmd/labview` can start with no dashboard and say
// so: §18 requires the API to answer identically with no assets present, and a binary that
// refused to boot because its UI subtree was misnamed would take the diagnostics down with the
// dashboard (I4).
func Assets() (fs.FS, error) { return fs.Sub(bundle, "dist") }

// IndexFile is the document §18 falls back to. Named here as well as there because this is the
// package that produces it.
const IndexFile = "index.html"
