package probe

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// The only part of §13 that touches a socket
// ---------------------------------------------------------------------------

// Subject is one service the probe may ask about, with the key its result is filed under. The service
// arrives already scanned and already postured, because §13.1's detected-authentication test is the
// posture's own expression and this package computes no posture of its own.
type Subject struct {
	Key     string
	Service payload.Service
}

// Options is one probe run's whole input.
type Options struct {
	Cfg config.ProbeConfig

	// Enabled is **authoritative for this build**, not the configured default. §13.7 makes the
	// request's value fully decisive, so the decision arrives here already made and this package
	// never reads `Cfg.Enabled` to make it.
	Enabled bool
	Source  payload.ProbeRunSource

	// Client is the one way out. Nil builds one from Cfg, which is what the corpus overrides through
	// transport.Options.RoundTripper instead of standing up a server.
	Client *transport.Client

	Subjects []Subject
}

// Read is one probe run. Complete on its own: a failure produces a report and an empty result set,
// never a nil a caller has to check for (I4).
type Read struct {
	Report payload.ConnectionReport

	// Run is what the payload states about the mode this build ran in (§13.7).
	Run payload.ProbeRun

	// Results is one record per service that was asked, by key. A service that was skipped or was
	// never a candidate has no entry — the counts below carry those facts instead.
	Results map[string]payload.ServiceProbe

	// The five numbers the report is summed from. Gated and Open partition the services that
	// answered; Silent is the ones that did not; Skipped is withheld candidates only (§13.1).
	Gated   int
	Open    int
	Silent  int
	Skipped int

	// ExtraRequests is §13.4's second question, summed across services. It travels separately
	// because those addresses stay out of every attempt list.
	ExtraRequests int
}

// Probed is the services that were asked. It is the sum §13.6's sentence opens with.
func (r Read) Probed() int { return r.Gated + r.Open + r.Silent }

// Do runs the probe.
//
// Containment (I8, §13.6), all of it in this function and none of it in a rule: GET only through
// `Anonymous`, which has nowhere to put a credential; no redirect ever followed, because where a 3xx
// points is the evidence; a per-request timeout and a bounded number in flight, both the transport's;
// at most four addresses per service; and the body kept only when the content type is HTML.
func Do(ctx context.Context, o Options) Read {
	r := Read{
		Run:     payload.ProbeRun{Enabled: o.Enabled, Source: o.Source},
		Results: map[string]payload.ServiceProbe{},
	}

	if !o.Enabled {
		r.Run.Skipped = len(o.Subjects)
		r.Report = r.report(payload.PhaseDisabled, "")
		return r
	}

	client := o.Client
	if client == nil {
		client = transport.New(transport.Options{
			Timeout:        milliseconds(o.Cfg.TimeoutMs),
			MaxConcurrency: o.Cfg.MaxConcurrency,
		})
	}

	// Eligibility first, for every subject, before a single request. Two facts come out of it and they
	// are counted separately: a withheld candidate is Skipped, and a service with no HTTP address is
	// nothing at all — it was never a candidate, so counting it as skipped would make the skipped
	// figure mean *not an HTTP service* (§13.1).
	var asking []Subject
	targets := map[string][]Target{}
	for _, s := range o.Subjects {
		e := Eligible(s.Service, o.Cfg.LanHost)
		switch {
		case e.Skipped:
			r.Skipped++
		case len(e.Targets) > 0:
			asking = append(asking, s)
			targets[s.Key] = e.Targets
		}
	}
	r.Run.Skipped = r.Skipped

	if len(asking) == 0 && r.Skipped == 0 {
		r.Report = r.report(payload.PhaseNotFound,
			"no service carried a tunnel hostname or a Traefik router, so there was no address to ask")
		return r
	}

	// A run whose candidates were **all** skipped is a success, not `not-found` (§13.1): every
	// question that could have been asked had already been answered by configuration.
	if len(asking) == 0 {
		r.Report = r.report(payload.PhaseConnected, "")
		return r
	}

	records := make([]payload.ServiceProbe, len(asking))
	var wg sync.WaitGroup
	for i, s := range asking {
		wg.Add(1)
		go func(i int, s Subject) {
			defer wg.Done()
			records[i] = ask(ctx, client, targets[s.Key])
		}(i, s)
	}
	wg.Wait()

	// The tally is walked in the subject order and not in completion order, so a run over the same
	// fleet produces the same numbers and the same report (I7).
	for i, s := range asking {
		rec := records[i]
		r.Results[s.Key] = rec
		if rec.State != nil {
			r.ExtraRequests += rec.State.Asked
		}
		switch VerdictOf(rec) {
		case VerdictGated:
			r.Gated++
		case VerdictOpen:
			r.Open++
		default:
			r.Silent++
		}
	}

	phase := payload.PhaseConnected
	if r.Silent > 0 {
		// Part of the fleet did not answer. Still `ok`: everything that did answer was read, and a
		// service claiming no measurement is a reported gap rather than a failed integration (I4).
		phase = payload.PhasePartial
	}
	r.Report = r.report(phase, "")
	return r
}

// ---------------------------------------------------------------------------
// One service
// ---------------------------------------------------------------------------

// ask walks one service's addresses most- to least-exposed and **stops at the first that answers**.
//
// Answering means an HTTP response arrived whatever its status — a 401 is the best outcome available
// here, so a status is never a reason to keep walking. **Only a transport failure falls through**, and
// each one is recorded as an attempt.
func ask(ctx context.Context, client *transport.Client, targets []Target) payload.ServiceProbe {
	out := payload.ServiceProbe{Attempts: []payload.ConnectionAttempt{}}

	for _, t := range targets {
		res := client.Anonymous(ctx, t.URL)

		if res.Status == 0 {
			// Nothing answered at this address. The reason is the transport's own classification, not
			// one derived here (§15).
			if len(out.Attempts) < transport.AttemptCap {
				out.Attempts = append(out.Attempts, payload.ConnectionAttempt{
					Endpoint: transport.Endpoint(t.URL),
					Why:      t.Why,
					Phase:    res.Phase,
					Code:     res.Code,
					Detail:   errText(res),
				})
			}
			out.Endpoint, out.Vantage, out.Phase = transport.Endpoint(t.URL), t.Vantage, res.Phase
			out.Detail = errText(res)
			continue
		}

		out = readAnswer(ctx, client, t, res, out.Attempts)
		return out
	}

	// Every address failed. The record keeps the last failure's phase, which is what makes this
	// *No answer* rather than *No login page* (§13.6).
	if out.Phase == "" {
		out.Phase = payload.PhaseNotConfigured
		out.Detail = "no address resolved"
	}
	out.Detail = Reason(out)
	return out
}

// readAnswer turns one transport result into a record: the pure reading, then §13.4's second question
// when the shortfall calls for it, then the sentence.
func readAnswer(ctx context.Context, client *transport.Client, t Target, res transport.Result, attempts []payload.ConnectionAttempt) payload.ServiceProbe {
	status := res.Status
	out := payload.ServiceProbe{
		Endpoint: transport.Endpoint(t.URL),
		Vantage:  t.Vantage,
		// An HTTP answer of any status is a connected probe. `conn.FromStatus` is deliberately not
		// used: it would read a 401 as `authenticate` and a 404 as `not-found`, which are the right
		// readings for an API being consumed and the wrong ones for an address being asked a question
		// (§13.2).
		Phase:    payload.PhaseConnected,
		Status:   &status,
		Attempts: attempts,
	}
	if out.Attempts == nil {
		out.Attempts = []payload.ConnectionAttempt{}
	}

	reading := ReadResult(res, t.URL)
	out.Gate = reading.Gate
	out.MediaType = reading.MediaType
	out.Redirect = reading.Redirect
	out.Refresh = reading.Refresh
	out.Truncated = reading.Truncated
	out.Form = reading.Form
	out.Anon = reading.Anon

	if reading.NeedsState {
		out.State = AskState(ctx, t.URL, func(ctx context.Context, address string) (StateAnswer, bool) {
			got := client.Anonymous(ctx, address)
			if got.Status == 0 {
				return StateAnswer{}, false
			}
			// The two facts §13.4 permits reading, and nothing else. No body is parsed, and no other
			// header is looked at.
			return StateAnswer{
				Status:    got.Status,
				Challenge: got.Header.Get("WWW-Authenticate") != "",
			}, true
		})
		out.Gate = StateGate(out.State)
	}

	out.Detail = Reason(out)
	return out
}

// ReadResult is the bridge from a transport result to the pure Answer, and the only place the HTML
// condition on keeping a body is applied.
//
// §13.6 requires the body read **only when the content type is HTML**. The transport reads every
// body — a 401's realm and a 403's permission are the detail its own failures need — so the dropping
// happens here, once, before any rule sees it. A rule that received a JSON body and had to remember
// not to read it would be a rule.
func ReadResult(res transport.Result, url string) Reading {
	a := Answer{
		URL:    url,
		Status: res.Status,
		Header: res.Header,
	}
	if HTML(MediaType(header(res.Header, "Content-Type"))) {
		a.Body, a.Truncated = res.Body, res.Truncated
	}
	return Signals(a)
}

func header(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	return h.Get(name)
}

func errText(res transport.Result) string {
	if res.Err != nil {
		return res.Err.Error()
	}
	return conn.Prose(res.Phase)
}

func milliseconds(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// ---------------------------------------------------------------------------
// The one meta.connections entry
// ---------------------------------------------------------------------------

// report builds §13.6's single connection report. The probe has no one endpoint — every request goes
// somewhere else — so the endpoint field stays empty and the detail carries the whole story.
func (r Read) report(phase payload.ConnectionPhase, detail string) payload.ConnectionReport {
	if detail == "" {
		detail = r.summary(phase)
	}
	out := conn.Report(conn.TargetProbe, phase, "", payload.SourceDiscovered, detail)
	out.Attempts = []payload.ConnectionAttempt{}
	return out
}

// summary is the sentence §13.6 gives:
//
//	31 services probed — 12 gated, 17 open, 2 did not answer — 9 extra requests at current-user
//	addresses — 1 service not asked (authentication already detected)
//
// The last two segments are present only when there were some. A run that asked no second questions
// should not say "0 extra requests"; that reads as a bound having been hit rather than as a shape that
// never came up.
func (r Read) summary(phase payload.ConnectionPhase) string {
	if phase == payload.PhaseDisabled {
		return ""
	}

	var parts []string
	if probed := r.Probed(); probed > 0 {
		parts = append(parts, fmt.Sprintf("%s probed", conn.Plural(probed, "service", "services")))
		parts = append(parts, fmt.Sprintf("%d gated, %d open, %d did not answer", r.Gated, r.Open, r.Silent))
	}
	if r.ExtraRequests > 0 {
		parts = append(parts, fmt.Sprintf("%s at current-user addresses",
			conn.Plural(r.ExtraRequests, "extra request", "extra requests")))
	}
	if r.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s not asked (authentication already detected)",
			conn.Plural(r.Skipped, "service", "services")))
	}
	return strings.Join(parts, " — ")
}

// Keys is the result keys in order, for a caller that walks them (I7).
func (r Read) Keys() []string {
	out := make([]string, 0, len(r.Results))
	for key := range r.Results {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
