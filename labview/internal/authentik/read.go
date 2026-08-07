// Package authentik is §11: the identity-provider read, and the match that ties its
// applications onto scanned services.
//
// The two halves are separated by the I/O boundary and stay separated. Read does every network
// operation, holds no fleet knowledge and never throws — a failure becomes a connection report.
// Match does no network work at all and is a pure function of a Read plus the fleet index, which
// is what makes the four rules of §11 testable as a table rather than against a live server.
package authentik

import (
	"bytes"
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// MaxCandidates bounds discovery. It is transport.AttemptCap so that the number of addresses a
// reader sees in an attempt list and the number actually tried are the same number (§13.6, I8).
const MaxCandidates = transport.AttemptCap

// Read is one read of the identity provider. It is complete on its own: a failure produces a
// report and empty lists, never a nil that a caller has to check for (I4).
type Read struct {
	Report payload.ConnectionReport

	// Endpoint is credential-free, from the one formatter (§20). Source is only `config` or
	// `discovered`: there is no built-in identity-provider address to fall back to.
	Endpoint string
	Source   payload.EndpointSource

	// Enabled and Configured are two different facts a reader needs kept apart: whether the
	// integration was switched on at all, and whether the operator named its address.
	Enabled    bool
	Configured bool

	// Applications is pass one then pass two, each pass in slug order (I7).
	Applications []payload.AuthentikApplication

	// Listed is how many the application list itself returned, and Total is what Authentik said
	// exists before its policy engine filtered the page — nil when the envelope carried none.
	Listed int
	Total  *int

	// Recovered is how many withheld applications a readable provider let LabView rebuild.
	Recovered int

	Providers int
	Outposts  int

	// Attempts is what discovery tried and why each rejected candidate was rejected.
	Attempts []payload.ConnectionAttempt
}

// Withheld is `configured − listed`, floored at zero.
//
// A count can be smaller than the page it summarises when a proxy sits in front of Authentik, and
// a negative withheld would render as a finding about a fleet that has none.
func (r Read) Withheld() int {
	if r.Total == nil {
		return 0
	}
	if n := *r.Total - r.Listed; n > 0 {
		return n
	}
	return 0
}

// Invisible is `withheld − recovered`, derived here and never stored (§11). It is the number the
// `partial` phase depends on, so storing it would make it possible for the count a reader sees and
// the phase they see to disagree.
func (r Read) Invisible() int {
	if n := r.Withheld() - r.Recovered; n > 0 {
		return n
	}
	return 0
}

// readLine is §15's `read`: what actually came back, as prose.
//
// Five numbers, and each earns its place by being one a reader would otherwise have to go and ask
// for. `14 of 16` is the shortfall the whole two-pass assembly exists for — the second number is
// Authentik's own count and the first is what it was willing to hand *this* token — so a gap is
// visible without opening the panel. The parenthesis says how much of that gap the provider lists
// closed. And the provider and outpost counts are what make a fleet's gates countable: a proxy
// provider assigned to no outpost enforces nothing (§11), so `0 outposts` says that about every
// provider at once, which is worth a reader seeing on the line that says the read worked.
//
// Only numbers that carry something are printed. `16 applications` rather than `16 of 16` when
// nothing was withheld, and no parenthesis when nothing was rebuilt — a line that always shows every
// field is a line a reader learns to skip.
func (r Read) readLine() string {
	applications := conn.Plural(r.Listed, "application", "applications")
	if r.Withheld() > 0 {
		// Withheld is only ever positive when Total is set, so the dereference is safe here and
		// nowhere else.
		applications = strconv.Itoa(r.Listed) + " of " + strconv.Itoa(*r.Total) + " applications"
	}
	if r.Recovered > 0 {
		applications += " (" + strconv.Itoa(r.Recovered) + " recovered from providers)"
	}
	return applications +
		", " + conn.Plural(r.Providers, "provider", "providers") +
		", " + conn.Plural(r.Outposts, "outpost", "outposts")
}

// Candidate is one address discovery may try, with what made it a candidate.
type Candidate struct {
	URL string
	// Why is the evidence, for the attempt list. It names the service and what about it
	// identified Authentik — never an environment value (I2, I6).
	Why string
	// Internal is true for a container address and false for a public hostname. Internal
	// candidates are tried first: reaching the API over the fleet's own network avoids the
	// gate in front of the public name, which would answer every probe with a login page.
	Internal bool
}

// Options is one read's whole input. Candidates arrive already built, because building them needs
// the scanned fleet and this package holds no fleet knowledge.
type Options struct {
	Cfg        config.AuthentikConfig
	Client     *transport.Client
	Candidates []Candidate
}

// Do performs the read.
func Do(ctx context.Context, o Options) Read {
	r := Read{
		Enabled:      o.Cfg.Enabled,
		Applications: []payload.AuthentikApplication{},
		Attempts:     []payload.ConnectionAttempt{},
	}

	client := o.Client
	if client == nil {
		client = transport.New(transport.Options{
			Timeout: milliseconds(o.Cfg.TimeoutMs),
		})
	}

	if !o.Cfg.Enabled {
		r.Report = r.report(payload.PhaseDisabled, "")
		return r
	}

	base, ok := r.selectEndpoint(ctx, client, o)
	if !ok {
		return r
	}
	if strings.TrimSpace(o.Cfg.Token) == "" {
		// The endpoint answered and there is nothing to read it with. `authenticate` rather than
		// `not-configured`, because the address is configured and the credential is what is
		// missing — and the hint for the two is different.
		r.Report = r.report(payload.PhaseAuthenticate, "no API token is configured")
		return r
	}

	token := strings.TrimSpace(o.Cfg.Token)
	pages := o.Cfg.MaxPages
	if pages <= 0 {
		pages = config.Defaults().Authentik.MaxPages
	}

	// The one request that widens rather than narrows. `superuser_full_list=true` is ignored for a
	// non-superuser token, so it can only ever return more; there is no configuration knob for it
	// because there is no reason an operator would want the narrower answer (§11).
	apps, total, phase, detail := readApplications(ctx, client, base, token, pages)
	if phase != payload.PhaseConnected {
		r.Report = r.report(phase, detail)
		return r
	}
	r.Listed, r.Total = len(apps), total

	proxies, phase, detail := readProviders(ctx, client, base+pathProxy, token, pages)
	if phase != payload.PhaseConnected {
		r.Report = r.report(phase, detail)
		return r
	}
	oauth2, phase, detail := readProviders(ctx, client, base+pathOAuth2, token, pages)
	if phase != payload.PhaseConnected {
		r.Report = r.report(phase, detail)
		return r
	}
	outposts, phase, detail := readOutposts(ctx, client, base, token, pages)
	if phase != payload.PhaseConnected {
		r.Report = r.report(phase, detail)
		return r
	}

	details := append(append([]wireProvider{}, proxies...), oauth2...)
	byOutpost := outpostsByProvider(outposts)

	r.Applications, r.Recovered = assemble(apps, details, byOutpost)
	r.Providers = countProviders(r.Applications)
	r.Outposts = len(outposts)

	read := r.readLine()
	if r.Invisible() > 0 {
		// `partial` exactly when something stayed invisible. Not when anything was withheld:
		// a withheld application a provider let us rebuild is not missing from the answer, and
		// reporting `partial` for it would leave a permanent warning on a correct read.
		r.Report = r.report(payload.PhasePartial,
			strconv.Itoa(r.Invisible())+" of "+strconv.Itoa(r.Withheld())+
				" applications this token cannot list could not be rebuilt from a provider either")
		r.Report.Read = read + ", " + strconv.Itoa(r.Invisible()) + " not visible to this token"
		return r
	}

	r.Report = r.report(payload.PhaseConnected, "")
	r.Report.Read = read
	return r
}

func (r Read) report(phase payload.ConnectionPhase, detail string) payload.ConnectionReport {
	rep := conn.Report(conn.TargetAuthentik, phase, r.Endpoint, r.Source, detail)
	rep.Attempts = r.Attempts
	if rep.Attempts == nil {
		rep.Attempts = []payload.ConnectionAttempt{}
	}
	if phase.BeforeTheNetwork() {
		rep.Endpoint, rep.Source = "", ""
	}
	return rep
}

// ---------------------------------------------------------------------------
// Endpoint selection
// ---------------------------------------------------------------------------

// selectEndpoint decides which address the token may be sent to, and returns false having filled
// in the report when there is none.
//
// A configured URL is used verbatim and is not probed: the operator named it, so a failure against
// it is a fact about their configuration and silently trying somewhere else would hide it.
//
// A discovered URL is a guess, and the probe is what turns a guess into an endpoint. Only a
// candidate that answers `/api/v3/root/config/` with a JSON object may receive the token — upstream
// allows that path anonymously, so a real Authentik answers it and anything else does not.
func (r *Read) selectEndpoint(ctx context.Context, client *transport.Client, o Options) (string, bool) {
	if raw := strings.TrimSpace(o.Cfg.URL); raw != "" {
		r.Configured = true
		r.Source = payload.SourceConfig
		r.Endpoint = transport.Endpoint(raw)
		return strings.TrimSuffix(raw, "/"), true
	}

	candidates := o.Candidates
	if len(candidates) == 0 {
		// Nothing in the scanned fleet identifies an identity provider, and there is no default
		// address to fall back to. `not-configured` says that; a `connect` failure against a
		// guessed address would say something untrue.
		r.Report = r.report(payload.PhaseNotConfigured,
			"no authentik.url is configured and no scanned service identifies Authentik")
		return "", false
	}
	if len(candidates) > MaxCandidates {
		candidates = candidates[:MaxCandidates]
	}

	r.Source = payload.SourceDiscovered
	for _, c := range candidates {
		base := strings.TrimSuffix(c.URL, "/")
		res := client.Anonymous(ctx, base+pathRootConfig)

		if res.Err != nil {
			r.reject(c, res.Phase, conn.Prose(res.Phase))
			continue
		}

		// A candidate that answered at all and refused is conclusive. It *is* an API, and asking
		// the next address would either find nothing or find a second Authentik — and either way
		// the operator's problem is this one's credential, which is what they need told.
		if res.Status == 401 || res.Status == 403 || res.Status == 407 {
			r.Endpoint = transport.Endpoint(base)
			r.Report = r.report(conn.FromStatus(res.Status),
				"the discovered endpoint refused an anonymous read of "+pathRootConfig+
					", so no token was sent to it")
			return "", false
		}
		if !res.OK() {
			r.reject(c, res.Phase, "answered "+strconv.Itoa(res.Status))
			continue
		}

		// A JSON *object*, specifically. An array or a bare string is a well-formed answer from
		// something that is not this API, and a guess that merely returns valid JSON has not
		// earned a credential.
		var probe map[string]any
		phase, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &probe)
		if err != nil {
			r.reject(c, phase, "answered 200 and did not answer a JSON object ("+code+")")
			continue
		}

		r.Endpoint = transport.Endpoint(base)
		return base, true
	}

	// Every candidate was rejected. The attempt list is the diagnosis and it is already on the
	// report; the phase is the last one, because the last is the weakest evidence and a reader
	// looking at the list can see the rest.
	last := payload.PhaseConnect
	if n := len(r.Attempts); n > 0 {
		last = r.Attempts[n-1].Phase
	}
	r.Report = r.report(last, conn.Plural(len(candidates), "discovered address", "discovered addresses")+
		" answered, and none of them is an Authentik API")
	return "", false
}

// reject records one candidate that will not receive the token, and why it was a candidate at all.
//
// `Why` is the evidence — which service identified Authentik and by what — because an attempt list
// without it says a scan tried some addresses, and with it says what the scan believed and where
// that belief was wrong (§15). It may hold a service key, an image name or a hostname, and never an
// environment value (I2, I6).
func (r *Read) reject(c Candidate, phase payload.ConnectionPhase, detail string) {
	r.Attempts = append(r.Attempts, payload.ConnectionAttempt{
		Endpoint: transport.Endpoint(c.URL),
		Why:      c.Why,
		Phase:    phase,
		Detail:   detail,
	})
}

// ---------------------------------------------------------------------------
// The four reads
// ---------------------------------------------------------------------------

func authHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// page fetches one page and hands back the envelope. It is the only place a token-carrying request
// is issued, so there is one place where the credential can be seen to be sent.
func page(ctx context.Context, client *transport.Client, rawURL, token string) (envelope, payload.ConnectionPhase, string) {
	res := client.Do(ctx, transport.Request{URL: rawURL, Header: authHeader(token)})
	if res.Err != nil {
		return envelope{}, res.Phase, conn.Prose(res.Phase)
	}
	if !res.OK() {
		detail := "the API answered " + strconv.Itoa(res.Status) + " for " + pathOf(rawURL)
		return envelope{}, res.Phase, detail
	}

	var env envelope
	phase, code, err := conn.ReadJSON(bytes.NewReader(res.Body), &env)
	if err != nil {
		return envelope{}, phase, pathOf(rawURL) + " did not answer JSON (" + code + ")"
	}
	if env.Results == nil {
		// A bare array rather than an envelope. Read it as one page of results with no
		// pagination, which is exactly what it is.
		env.Results = res.Body
	}
	return env, payload.PhaseConnected, ""
}

// pathOf is the path of a URL, for a detail line. It never carries the query string, which is
// where a page cursor and anything else lives (§20).
func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "the endpoint"
	}
	return u.Path
}

// readApplications reads `core/applications/` with `superuser_full_list=true`, and keeps the
// unfiltered total from the *first* page.
//
// The first page, because pagination runs before the policy filter: page one's count is what
// Authentik says exists, and a later page's count is the same number. Taking the last would be
// equivalent and taking the largest would invent a total no page reported.
func readApplications(ctx context.Context, client *transport.Client, base, token string, maxPages int) ([]wireApplication, *int, payload.ConnectionPhase, string) {
	var out []wireApplication
	var total *int

	for p := 1; p <= maxPages; p++ {
		url := base + pathApplications + "?superuser_full_list=true&page_size=" +
			strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(p)

		env, phase, detail := page(ctx, client, url, token)
		if phase != payload.PhaseConnected {
			return nil, nil, phase, detail
		}
		if p == 1 {
			total = env.total()
		}

		var got []wireApplication
		if _, _, err := conn.ReadJSON(bytes.NewReader(env.Results), &got); err != nil {
			return nil, nil, payload.PhaseProtocol, "the application list did not parse"
		}
		out = append(out, got...)

		if !env.hasNext() || len(got) == 0 {
			break
		}
	}
	return out, total, payload.PhaseConnected, ""
}

func readProviders(ctx context.Context, client *transport.Client, endpoint, token string, maxPages int) ([]wireProvider, payload.ConnectionPhase, string) {
	var out []wireProvider
	for p := 1; p <= maxPages; p++ {
		url := endpoint + "?page_size=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(p)

		env, phase, detail := page(ctx, client, url, token)
		if phase != payload.PhaseConnected {
			return nil, phase, detail
		}
		var got []wireProvider
		if _, _, err := conn.ReadJSON(bytes.NewReader(env.Results), &got); err != nil {
			return nil, payload.PhaseProtocol, pathOf(endpoint) + " did not parse"
		}
		out = append(out, got...)
		if !env.hasNext() || len(got) == 0 {
			break
		}
	}
	return out, payload.PhaseConnected, ""
}

func readOutposts(ctx context.Context, client *transport.Client, base, token string, maxPages int) ([]wireOutpost, payload.ConnectionPhase, string) {
	var out []wireOutpost
	for p := 1; p <= maxPages; p++ {
		url := base + pathOutposts + "?page_size=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(p)

		env, phase, detail := page(ctx, client, url, token)
		if phase != payload.PhaseConnected {
			return nil, phase, detail
		}
		var got []wireOutpost
		if _, _, err := conn.ReadJSON(bytes.NewReader(env.Results), &got); err != nil {
			return nil, payload.PhaseProtocol, "the outpost list did not parse"
		}
		out = append(out, got...)
		if !env.hasNext() || len(got) == 0 {
			break
		}
	}
	return out, payload.PhaseConnected, ""
}

// ---------------------------------------------------------------------------
// Two-pass assembly
// ---------------------------------------------------------------------------

// outpostsByProvider inverts the outpost list: provider pk to the names of the outposts carrying
// it. This is the whole reason the outpost list is read — a proxy provider assigned to no outpost
// is in nobody's request path and protects nothing (§11).
func outpostsByProvider(outposts []wireOutpost) map[string][]string {
	out := map[string][]string{}
	for _, o := range outposts {
		for _, pk := range o.Providers {
			key := strings.TrimSpace(pk.String())
			if key == "" {
				continue
			}
			out[key] = append(out[key], o.Name)
		}
	}
	return out
}

// assemble is §11's two passes.
//
// Pass one is the applications the list returned, tagged `list`. Pass two walks the provider lists
// for slugs pass one did not produce and rebuilds them, tagged `provider`, in slug order. The list
// response wins for any slug in both: it alone carries the launch URL and the group, and a rebuilt
// record that overwrote it would lose the strongest matching evidence there is.
func assemble(apps []wireApplication, details []wireProvider, byOutpost map[string][]string) ([]payload.AuthentikApplication, int) {
	byPK := map[string]wireProvider{}
	for _, d := range details {
		if pk := d.pk(); pk != "" {
			byPK[pk] = d
		}
	}

	out := make([]payload.AuthentikApplication, 0, len(apps))
	listed := map[string]bool{}

	// Pass one, in slug order. The list arrives in the API's order, which is stable but is not a
	// promise; sorting makes the payload reproducible across two reads (I7).
	sorted := append([]wireApplication{}, apps...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Slug < sorted[j].Slug })

	for _, app := range sorted {
		listed[app.Slug] = true
		out = append(out, payload.AuthentikApplication{
			Name:          app.Name,
			Slug:          app.Slug,
			Group:         app.Group,
			LaunchURL:     app.launchURL(),
			Providers:     providersOf(app, byPK, byOutpost),
			DiscoveredVia: payload.DiscoveredViaList,
		})
	}

	// Pass two: what the providers know about and the list did not say.
	rebuilt := map[string]*payload.AuthentikApplication{}
	var slugs []string
	for _, d := range details {
		slug, backchannel := d.slug()
		if slug == "" || listed[slug] {
			continue
		}
		if rebuilt[slug] == nil {
			name := strings.TrimSpace(d.AssignedApplicationName)
			if backchannel {
				name = strings.TrimSpace(d.AssignedBackchannelApplicationName)
			}
			if name == "" {
				name = slug
			}
			rebuilt[slug] = &payload.AuthentikApplication{
				Name: name,
				Slug: slug,
				// No launch URL and no group. A rebuilt record is thinner because the provider
				// list does not carry them, and inventing either would let rule 2 match an
				// application on evidence nobody produced.
				Providers:     []payload.AuthentikProvider{},
				DiscoveredVia: payload.DiscoveredViaProvider,
			}
			slugs = append(slugs, slug)
		}
		rebuilt[slug].Providers = append(rebuilt[slug].Providers, fromDetail(d, backchannel, byOutpost))
	}

	sort.Strings(slugs)
	for _, slug := range slugs {
		out = append(out, *rebuilt[slug])
	}
	return out, len(slugs)
}

// providersOf is one listed application's providers: its own view of them, deepened by the detail
// record where the provider lists carried one.
//
// The application's view is the authority on *which* providers it has and what kind they are —
// it is the only evidence for an LDAP or SAML provider, neither of which has a detail list among
// the four endpoints. The detail record adds the hosts, the mode and the redirect URIs.
func providersOf(app wireApplication, byPK map[string]wireProvider, byOutpost map[string][]string) []payload.AuthentikProvider {
	out := []payload.AuthentikProvider{}

	add := func(ref wireProviderRef, backchannel bool) {
		p := payload.AuthentikProvider{
			Name:        ref.Name,
			RawKind:     ref.rawKind(),
			Kind:        kindOf(ref.rawKind()),
			Backchannel: backchannel,
			Outposts:    []string{},
		}
		if names := sortedUnique(byOutpost[ref.pk()]); len(names) > 0 {
			p.Outposts = names
		}
		if d, ok := byPK[ref.pk()]; ok {
			p.Mode = d.Mode
			p.InternalHost = d.InternalHost
			p.ExternalHost = d.ExternalHost
			p.RedirectURIs = []string(d.RedirectURIs)
			if p.Name == "" {
				p.Name = d.Name
			}
			// The detail record's own kind is preferred when the application's view had none:
			// `provider_obj` is absent in some releases, and a nil there must not turn a proxy
			// provider into `other` when the proxy list said what it was.
			if p.RawKind == "" {
				p.RawKind = d.rawKind()
				p.Kind = kindOf(d.rawKind())
			}
		}
		out = append(out, p)
	}

	if app.Provider != nil {
		add(*app.Provider, false)
	}
	for _, ref := range app.BackchannelProviders {
		add(ref, true)
	}
	return out
}

func fromDetail(d wireProvider, backchannel bool, byOutpost map[string][]string) payload.AuthentikProvider {
	p := payload.AuthentikProvider{
		Name:         d.Name,
		RawKind:      d.rawKind(),
		Kind:         kindOf(d.rawKind()),
		Mode:         d.Mode,
		InternalHost: d.InternalHost,
		ExternalHost: d.ExternalHost,
		RedirectURIs: []string(d.RedirectURIs),
		Backchannel:  backchannel,
		Outposts:     []string{},
	}
	if names := sortedUnique(byOutpost[d.pk()]); len(names) > 0 {
		p.Outposts = names
	}
	return p
}

func countProviders(apps []payload.AuthentikApplication) int {
	n := 0
	for _, app := range apps {
		n += len(app.Providers)
	}
	return n
}

func milliseconds(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }
