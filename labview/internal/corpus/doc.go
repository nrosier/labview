// Package corpus is §23's test entry point: the full pipeline, over the real fixture files, with
// every outbound transport injected.
//
// It holds no production code. It exists as a package rather than as a file inside internal/pipeline
// because what it asserts is a different kind of claim. The pipeline's own suite asserts the stages
// against a fleet it builds in a temp directory — small, synthetic, and shaped to isolate one rule at
// a time. This one asserts the *conclusions*, over the seven fixture roots, and each of those roots
// is a fleet somebody would recognise: a proxy that publishes 80 and 443 and serves its API on 8080
// because that is Traefik's default, an identity provider whose internal address is a different
// number from its published one, eighteen directories that each exist because a defect existed.
//
// # Why the fixtures are files and the probe answers are not
//
// §23 draws the line and it is worth restating: a fleet is a tree of compose files, so the fixtures
// are compose files, read by the same walk a deployment is read by. A probe answer is a status, three
// headers and a fragment of HTML — there is no file format for that which is not an invention, so the
// answer table below is Go.
//
// # Hermeticity
//
// The corpus never calls config.Load. Every run builds its configuration from config.Defaults() and
// sets the handful of fields the root under test needs, so no file and no variable can reach it. The
// environment is scrubbed anyway, in TestMain, before the first test function runs: §23 requires it,
// and the reason is that the roots name real-looking addresses. `fixtures/traefik` contains a
// container called `edge-proxy` and a hostname `edge.example.com`; an operator with
// LABVIEW_TRAEFIK_URL exported and a corpus that read it would send a credential somewhere.
//
// The scrub and the never-read-the-environment rule are both here on purpose. Either alone would
// work today. Together they mean that a later change which reintroduces config.Load still cannot
// leak, and a later change which drops the scrub still cannot leak.
package corpus
