package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/nrosier/labview/internal/payload"
)

// The three data routes (§18).
//
// None of them scans. They ask the cache, which decides whether a scan is needed — so the coalescing
// §18 requires ("concurrent requests share one in-flight build unless one is forced") is one property
// in one place rather than a rule each route has to remember.

// overview answers with the cached payload, rebuilding past `cacheTtlSeconds`.
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	out := s.cache.Get(r.Context(), false, nil)

	if r.Context().Err() != nil {
		// The reader disconnected while the build ran. The cache answers a cancelled caller with the
		// previous build or an empty payload, and writing an empty payload as a 200 would be this
		// server stating that the fleet is empty. Nobody is listening, so nothing is said.
		return
	}

	writeJSON(w, http.StatusOK, out)
}

// rescan forces a rebuild and answers with it.
//
// The forced request is what §17's cache contract is about: *a forced request may only be answered by a
// build that started after it arrived*. That is why this route passes `forced` through rather than
// clearing the cache and asking again — clearing and re-asking is a race with every other reader, and
// the one that lost it would get the scan the operator asked to replace.
func (s *Server) rescan(w http.ResponseWriter, r *http.Request) {
	probe := probeOverride(r)

	out := s.cache.Get(r.Context(), true, probe)

	if r.Context().Err() != nil {
		return
	}

	// Logged after the build so the line can state what the build actually did rather than what was
	// requested — `meta.probe` is the authority on that, and it says `request` only when the override
	// reached the build that answered (§13.7).
	s.log(Event{
		What:     EventRescan,
		Username: viewerName(r),
		OK:       true,
		Status:   http.StatusOK,
		Detail:   "rescan requested; " + probeDetail(out.Meta.Probe),
	})

	writeJSON(w, http.StatusOK, out)
}

// healthz reports that the process is answering, and **runs no scan** (§18).
//
// Nothing here touches the cache. A health check that waited on a fleet scan would report a slow
// filesystem as a dead process and would let an orchestrator restart LabView for being busy — and the
// question a container probe asks is whether this process is answering, which is answered by answering.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, payload.Health{OK: true})
}

// ---------------------------------------------------------------------------
// §13.7 — the switch beside Rescan
// ---------------------------------------------------------------------------

// probeOverride reads the one request-scoped setting, **validated rather than coerced** (§13.7).
//
// One known key, one known type. A missing body, an array, a JSON `null`, `{"probe":"yes"}` and
// `{"probe":1}` all mean *use configuration*, and unknown fields are ignored rather than rejected (I4).
// Coercion is what is being avoided: `{"probe":"false"}` coerced by truthiness would turn *do not probe
// my fleet* into fleet-wide outbound requests, which is the one mistake this switch must not make.
//
// The value is returned rather than applied, because §13.7 requires it to be threaded as a parameter of
// the build: the build that starts owns the override and a coalesced caller's value is discarded.
func probeOverride(r *http.Request) *bool {
	body, err := readBody(r)
	if err != nil || len(body) == 0 {
		// An unreadable or oversized body is not a reason to refuse the rescan (I4). It is a reason not
		// to believe anything it claimed about the probe, which is what *use configuration* means.
		return nil
	}

	// Decoded into raw fields rather than into a struct with a `*bool`, so a wrong *type* is
	// distinguishable from an absent key. `json.Unmarshal` into `*bool` would report an error for
	// `{"probe":1}` — but it reports one for the whole document, and this route must ignore the field
	// rather than refuse the request.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil
	}

	raw, ok := fields["probe"]
	if !ok {
		return nil
	}

	// An explicit `null` is *no value*, which is the same thing as no key. Checked separately because
	// `json.Unmarshal` accepts `null` into a bool and leaves it false — so decoding it would silently turn
	// *I have no opinion* into *do not probe* and would disable a probe configuration asked for.
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}

	var want bool
	if err := json.Unmarshal(raw, &want); err != nil {
		return nil
	}
	return &want
}

// probeDetail states what the answering build did about the probe, for the log line.
//
// It reads the payload rather than the request, so a coalesced rescan whose override was discarded says
// so — a line claiming *probe: request true* on a build that ran without one would be the log agreeing
// with the request instead of with the scan.
func probeDetail(run payload.ProbeRun) string {
	if run.Enabled {
		return "probe on (" + string(run.Source) + ")"
	}
	return "probe off (" + string(run.Source) + ")"
}
