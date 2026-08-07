package webui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// Rows is the row set behind a view: §22.2's *one row is*, §22.6's filters, and §22.2's stated order,
// as one pure function of a state and a payload.
//
// **This is what makes §23's second check possible.** §22.3 requires every overview card to resolve to
// a destination showing *exactly* the rows the number counted; the check is
// `len(Rows(card.Dest, ov)) == card.Count(ov)`, which is only a check if the row set is computable
// without rendering (§16). Everything a card's destination needs — the projection switch on a boolean
// narrowing, the tri-state evaluation, the free-text haystack — therefore lives here rather than in the
// browser, and the browser is given the tags on each row and evaluates the same tables.
//
// Three properties this file is responsible for:
//
//   - **Filtering never mutates the payload and never changes a total** (§22.6). Nothing here writes
//     to the payload it was given; the one function that must (fleet.Dependencies writes §8's notes)
//     is called on a copy, made below.
//   - **Free text searches names, images, hostnames, router names, label keys and env var KEYS —
//     never env var values, masked or not** (§22.6, I6). The haystack is built explicitly, field by
//     field, so a value cannot arrive in it by someone serialising a struct into the search index.
//   - **Deterministic order** (§22.1). Every row carries an explicit sort key and a findings-lead
//     bucket, and the final tie-break is the row's own id, so no two payloads with the same content
//     can order differently.

// Row is one row of one view: the tags a filter tests, the text a search matches, and the identity a
// drawer opens.
type Row struct {
	Kind RowKind

	// ID is stable and addressable: what `svc`, `net` or a diagram selection carries (§22.7).
	ID    string
	Label string

	// Stack is the stack this row belongs to, for the `stack` scope. Empty when the row is not a
	// stack's.
	Stack string

	// Service is the `stack/service` key of the service behind this row, for opening its drawer.
	// Empty on rows that are not about one service.
	Service string

	// Networks are the real networks this row sits on, for the `net` scope.
	Networks []string

	// Tags are the filter dimensions this row answers (§22.6). A dimension absent from the map is a
	// dimension this row has nothing to say about, and an include filter on it excludes the row.
	Tags map[Dim][]string

	// Text is the free-text haystack. Names, images, hostnames, router names, label keys and env var
	// keys — nothing else ever (I6).
	Text []string

	// The three boolean narrowings of §22.7, as facts about the row.
	Exposed  bool
	Accepted bool
	Drift    bool

	// Count is the number this row reports, for the roll-up columns (a stack's services, a network's
	// members). Zero on rows that count nothing.
	Count int

	// Numbers are the row's other numeric columns, keyed by the column key they fill. Two views
	// declare more than one numeric column — a network has members, stacks and dependencies crossing
	// it; a diagram has nodes and edges — and keying by the column key means the number and the
	// header that names it are matched by the view's own table rather than by position.
	Numbers map[string]int

	// Lead is the findings-lead bucket: lower sorts first. §22.2 requires findings to lead in three
	// views, and stating the bucket on the row keeps the ordering rule beside the fact it is about.
	Lead int

	// Sort is the ordering key inside a bucket.
	Sort []string
}

// Tag adds tag values to a dimension, skipping empties: a union member that is absent is not a member
// spelled "".
func (r *Row) Tag(d Dim, values ...string) {
	if r.Tags == nil {
		r.Tags = map[Dim][]string{}
	}
	for _, v := range values {
		if v != "" {
			r.Tags[d] = appendOnceString(r.Tags[d], v)
		}
	}
}

// Num records a numeric column's value. A column with nothing to report stays absent rather than
// being set to zero, so *no dependency crosses this network* and *this was never counted* stay
// distinguishable (§15).
func (r *Row) Num(column string, n int) {
	if r.Numbers == nil {
		r.Numbers = map[string]int{}
	}
	r.Numbers[column] = n
}

// Say adds text to the haystack.
func (r *Row) Say(values ...string) {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			r.Text = appendOnceString(r.Text, v)
		}
	}
}

// Rows is the filtered, ordered row set for a state.
func Rows(s State, ov payload.Overview) []Row {
	all, consumed := project(s, ov)

	out := make([]Row, 0, len(all))
	for _, r := range all {
		if keep(s, r, consumed) {
			out = append(out, r)
		}
	}
	sortRows(out)
	return out
}

// consumedFlags records which boolean narrowings the projection already applied. A narrowing that
// chose the row set must not then be applied again as a filter: `drift=1` on the Declarations view
// means *one row per drift entry*, and re-testing it afterwards would be harmless there but wrong on
// the rows it produced — they are entries, and an entry has no drift of its own.
type consumedFlags struct {
	exposed  bool
	accepted bool
	drift    bool
}

// project builds every row for the state's view, before filtering.
func project(s State, ov payload.Overview) ([]Row, consumedFlags) {
	view, ok := ViewOf(s.ViewSlug())
	if !ok {
		// An unknown slug cannot arrive from Parse, which drops one. A caller building a State by
		// hand still gets the overview rather than nothing (I4).
		view, _ = ViewOf(SlugOverview)
	}

	kind := view.Kind
	var consumed consumedFlags

	switch kind {
	case RowDeclaration:
		// §22.7's boolean narrowings switch the projection, because §22.3's counts are of different
		// things: `declarationDrift` counts drift *entries* and `exposureAccepted` counts services.
		switch {
		case s.Drift:
			kind, consumed.drift = RowDrift, true
		case s.Accepted:
			kind, consumed.accepted = RowAccepted, true
		}
	case RowDiagram:
		// §22.5 requires a tabular equivalent for every diagram, reachable from it — which means
		// addressable (§22.7). The edge list is that table.
		if s.Panel == PanelEdges {
			kind = RowEdge
		}
	case RowReport:
		if s.Panel == PanelWarnings {
			kind = RowWarning
		}
	}

	switch kind {
	case RowStat:
		return statRows(ov), consumed
	case RowStack:
		return stackRows(ov), consumed
	case RowService:
		return serviceRows(ov), consumed
	case RowRoute:
		return routeRows(ov), consumed
	case RowNetwork:
		return networkRows(ov), consumed
	case RowDiagram:
		return diagramRows(ov), consumed
	case RowEdge:
		return edgeRows(s, ov), consumed
	case RowContainer:
		return containerRows(ov), consumed
	case RowStorage:
		return storageRows(ov), consumed
	case RowConfig:
		return configRows(ov), consumed
	case RowApplication:
		return applicationRows(ov), consumed
	case RowRouter:
		return routerRows(ov), consumed
	case RowProbe:
		return probeRows(ov), consumed
	case RowDeclaration:
		return declarationRows(ov), consumed
	case RowDrift:
		return entryRows(ov, RowDrift), consumed
	case RowUnconfirmed:
		return entryRows(ov, RowUnconfirmed), consumed
	case RowAccepted:
		return acceptedRows(ov), consumed
	case RowReport:
		return reportRows(ov), consumed
	case RowWarning:
		return warningRows(ov), consumed
	default:
		return nil, consumed
	}
}

// keep is §22.6's evaluation for one row.
func keep(s State, r Row, consumed consumedFlags) bool {
	for dim, f := range s.Tags {
		if !f.Matches(r.Tags[dim]) {
			return false
		}
	}
	if s.Stack != "" && r.Stack != s.Stack {
		return false
	}
	if s.Net != "" && !containsString(r.Networks, s.Net) {
		return false
	}
	if s.Exposed && !consumed.exposed && !r.Exposed {
		return false
	}
	if s.Accepted && !consumed.accepted && !r.Accepted {
		return false
	}
	if s.Drift && !consumed.drift && !r.Drift {
		return false
	}
	if s.Q != "" && !matches(r.Text, s.Q) {
		return false
	}
	return true
}

// matches is the free-text test: case-insensitive substring over the row's declared haystack.
//
// Substring rather than prefix or word match, because the strings being searched are image
// references, hostnames and label keys — `traefik.http.routers` and `ghcr.io/org/app:1.2` are found by
// the middle far more often than by the start.
func matches(haystack []string, q string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return true
	}
	for _, h := range haystack {
		if strings.Contains(strings.ToLower(h), q) {
			return true
		}
	}
	return false
}

func sortRows(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Lead != b.Lead {
			return a.Lead < b.Lead
		}
		for k := 0; k < len(a.Sort) && k < len(b.Sort); k++ {
			if a.Sort[k] != b.Sort[k] {
				return a.Sort[k] < b.Sort[k]
			}
		}
		if len(a.Sort) != len(b.Sort) {
			return len(a.Sort) < len(b.Sort)
		}
		return a.ID < b.ID
	})
}

// ---------------------------------------------------------------------------
// The projections
// ---------------------------------------------------------------------------

// statRows is the overview: one row per card (§22.3).
func statRows(ov payload.Overview) []Row {
	cards := Cards(ov)
	out := make([]Row, 0, len(cards))
	for i, c := range cards {
		r := Row{
			Kind:  RowStat,
			ID:    c.ID,
			Label: c.Label,
			Sort:  []string{pad(i)},
		}
		if n, ok := c.Count(ov); ok {
			r.Count = n
		}
		r.Say(c.Label)
		out = append(out, r)
	}
	return out
}

// stackRows is one row per stack, with the roll-ups §22.2 allows: every distinct ingress kind and auth
// mechanism its services have, plus an exposure count. **Filtering stays service-level** — the tags
// here are what the stack row *shows*, and a stack row is never what an ingress filter narrows on the
// Services view.
func stackRows(ov payload.Overview) []Row {
	out := make([]Row, 0, len(ov.Stacks))
	for _, stack := range ov.Stacks {
		r := Row{
			Kind:  RowStack,
			ID:    stack.ID,
			Label: stack.Name,
			Stack: stack.ID,
			Count: len(stack.Services),
		}
		r.Say(stack.Name, stack.ID, stack.Dir, stack.ComposeFile, stack.ProjectName)

		for _, svc := range stack.Services {
			// `none` rolls up to nothing (§22.2): a stack with one unexposed service and four public
			// ones is not *partly not-exposed*, it is public.
			for _, kind := range svc.Ingress {
				if kind != payload.IngressNone {
					r.Tag(DimIngress, string(kind))
				}
			}
			if m := methodOf(svc); m.Detected() {
				r.Tag(DimAuth, string(m))
			}
			if svc.Auth.ExposedWithoutAuth {
				r.Exposed = true
			}
			if svc.Declared != nil && len(svc.Declared.Drift) > 0 {
				r.Drift = true
			}
			r.Networks = append(r.Networks, svc.Networks...)
			r.Say(svc.Name, svc.Image)
		}

		// Stacks with warnings first (§22.8: nothing renders as a bare table, and a warning is the
		// reason a stack may be incomplete).
		if len(stack.Warnings) > 0 {
			r.Lead = 0
		} else {
			r.Lead = 1
		}
		r.Sort = []string{strings.ToLower(stack.Name), stack.ID}
		out = append(out, r)
	}
	return out
}

// serviceRows is the comparable row: every dimension of §22.6 on one line.
func serviceRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		r := Row{
			Kind:     RowService,
			ID:       key,
			Label:    svc.Name,
			Stack:    stack.ID,
			Service:  key,
			Networks: svc.Networks,
			Exposed:  svc.Auth.ExposedWithoutAuth,
		}
		tagService(&r, svc)
		sayService(&r, svc)

		if d := svc.Declared; d != nil {
			r.Accepted = d.UnauthenticatedAccepted != nil
			r.Drift = len(d.Drift) > 0
		}

		// Findings lead: exposed without auth first (§22.2), then the rest by stack and name.
		if r.Exposed {
			r.Lead = 0
		} else {
			r.Lead = 1
		}
		r.Sort = []string{strings.ToLower(stack.Name), strings.ToLower(svc.Name)}
		out = append(out, r)
	})
	return out
}

// tagService puts every dimension a service answers on the row, by evaluating §22.6's rule table
// (tagrules.go).
//
// One place, so the Services view, the Containers view and a card's destination cannot disagree
// about what `state=running` means — and one *form*, so the browser evaluating the same table
// against the same payload cannot disagree either (§16, §22.1).
func tagService(r *Row, svc payload.Service) { r.Apply(RulesService, svc) }

// Has reports whether a row carries a member in a dimension. The projections read their own tags to
// decide findings order, so *answered with no login page leads* is stated once, as the tag rule, and
// the ordering reads it (§22.2).
func (r Row) Has(d Dim, member string) bool { return containsString(r.Tags[d], member) }

// methodOf normalises an absent method to `none`, exactly as the counters do (§22.3: the card and its
// destination must not be able to disagree).
func methodOf(svc payload.Service) payload.AuthMethod {
	if svc.Auth.Method == "" {
		return payload.AuthNone
	}
	return svc.Auth.Method
}

// The two state members this package supplies rather than reads. Everything else in the dimension is
// the Engine's own word, which is why the dimension has no closed vocabulary (§22.6).
const (
	StateRunning = "running"
	StateNotRead = "not-read"
)

// sayService builds the haystack: names, images, hostnames, router names, label keys, env var keys
// (§22.6). **No env var value, masked or not** (I6) — which is why this walks the fields it wants
// rather than everything it has.
func sayService(r *Row, svc payload.Service) {
	r.Say(svc.Name, svc.ContainerName, svc.Image)
	for _, route := range svc.Cloudflare {
		r.Say(route.Hostname)
	}
	for _, route := range svc.Traefik {
		r.Say(route.Router)
		r.Say(route.Hosts...)
	}
	for _, live := range svc.TraefikLive {
		r.Say(live.Router)
		r.Say(live.Hosts...)
	}
	for key := range svc.Labels {
		r.Say(key)
	}
	for _, env := range svc.Env {
		r.Say(env.Key)
	}
}

// routeRows is one row per route: a tunnel ingress or a proxy router, from the scanned configuration.
func routeRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		for i, route := range svc.Cloudflare {
			r := Row{
				Kind:     RowRoute,
				ID:       key + "#tunnel/" + pad(i),
				Label:    route.Hostname,
				Stack:    stack.ID,
				Service:  key,
				Networks: svc.Networks,
			}
			r.Say(route.Hostname, route.Service, route.Path, svc.Name, svc.Image)
			r.Tag(DimIngress, string(payload.IngressPublic))
			r.Tag(DimAuth, string(methodOf(svc)))
			r.Tag(DimConf, string(svc.Auth.Confidence))
			if route.Origin != nil {
				r.Say(route.Origin.Address, route.Origin.Host)
			}
			// An ungated external path leads (§22.2, §22.5's reserved colour).
			gated := route.Access != nil || methodOf(svc).Detected()
			r.Exposed = !gated
			r.Lead = leadIf(!gated)
			r.Sort = []string{strings.ToLower(route.Hostname), route.Path, r.ID}
			out = append(out, r)
		}
		for i, route := range svc.Traefik {
			label := strings.Join(route.Hosts, ", ")
			if label == "" {
				label = route.Router
			}
			r := Row{
				Kind:     RowRoute,
				ID:       key + "#router/" + pad(i),
				Label:    label,
				Stack:    stack.ID,
				Service:  key,
				Networks: svc.Networks,
			}
			r.Say(route.Router, route.Service, svc.Name, svc.Image)
			r.Say(route.Hosts...)
			r.Tag(DimIngress, string(payload.IngressTraefik))
			r.Tag(DimAuth, string(methodOf(svc)))
			r.Tag(DimConf, string(svc.Auth.Confidence))
			r.Exposed = !methodOf(svc).Detected()
			r.Lead = leadIf(r.Exposed)
			r.Sort = []string{strings.ToLower(label), route.Router, r.ID}
			out = append(out, r)
		}
	})
	return out
}

// networkRows is one row per real network, read from the one membership index (§8) rather than from a
// second walk over the services — the counters read the same index, so the card and the view cannot
// disagree about what *connecting* means.
func networkRows(ov payload.Overview) []Row {
	nets := fleet.NewNetworks(ov.Stacks)
	drivers := networkDrivers(ov)
	crossing := crossingCounts(ov)

	var out []Row
	for _, net := range nets.All() {
		facts := NetFacts{
			Name:        net.Name,
			Scope:       string(net.Scope()),
			MemberCount: len(net.Members),
			StackCount:  len(net.Stacks),
			External:    net.External,
		}
		r := Row{
			Kind:     RowNetwork,
			ID:       net.Name,
			Label:    net.Name,
			Networks: []string{net.Name},
			Count:    facts.MemberCount,
		}
		r.Apply(RulesNetwork, facts)
		r.Num("stacks", facts.StackCount)
		r.Num("crossing", crossing[net.Name])

		r.Say(net.Name, drivers[net.Name])
		if len(net.Stacks) == 1 {
			// A stack-scoped network belongs to its one stack, so the `stack` scope keeps it. A
			// network joining two stacks belongs to neither, and scoping to one stack must not
			// silently claim it.
			r.Stack = net.Stacks[0]
		}
		for _, key := range net.Members {
			r.Say(key)
		}
		r.Lead = leadIf(r.Has(DimState, NetCrossStack))
		r.Sort = []string{padDesc(len(net.Stacks)), padDesc(len(net.Members)), strings.ToLower(net.Name)}
		out = append(out, r)
	}
	return out
}

// crossingCounts is how many dependencies cross each network, read off the graph's own dependency
// edges (§22.2's `graph.edges.via`).
//
// The graph rather than a second resolution pass: the edges already say which networks each dependency
// crosses, and re-resolving them here would be §16's second implementation of §8's crossing rule —
// with the Networks view free to disagree with the diagram drawn from the same relation.
func crossingCounts(ov payload.Overview) map[string]int {
	out := map[string]int{}
	for _, e := range ov.Graph.Edges {
		if e.Kind != payload.EdgeDependsOn {
			continue
		}
		for _, via := range e.Via {
			out[via]++
		}
	}
	return out
}

// The network predicates of §22.3, carried in the `state` dimension. The dimension is *what this row
// is doing*: for a service or a container that is the Engine's status word, and for a network it is
// what the network does. §22.7's parameter list is closed, so a predicate the cards must link to
// belongs in the dimension that already holds a row's own state rather than in a parameter the grammar
// does not have.
const (
	NetConnecting = "connecting"
	NetCrossStack = "cross-stack"
	NetSoloLocal  = "solo-local"
)

// networkDrivers is the driver each stack declared for a network, for the Networks view's column.
func networkDrivers(ov payload.Overview) map[string]string {
	out := map[string]string{}
	for _, stack := range ov.Stacks {
		for _, decl := range stack.DeclaredNetworks {
			if decl.Driver != "" && out[decl.Name] == "" {
				out[decl.Name] = decl.Driver
			}
		}
	}
	return out
}

// diagramRows is one row per diagram (§22.5).
func diagramRows(ov payload.Overview) []Row {
	out := make([]Row, 0, len(Diagrams))
	for i, d := range Diagrams {
		edges := d.Edges(ov)
		r := Row{
			Kind:  RowDiagram,
			ID:    d.ID,
			Label: d.Title,
			Count: len(edges),
			Sort:  []string{pad(i)},
		}
		r.Num("nodes", len(d.nodes(ov, edges)))
		r.Num("edges", len(edges))
		r.Say(d.Title, d.Shows)
		out = append(out, r)
	}
	return out
}

// edgeRows is a diagram's tabular equivalent: the edge list §22.5 requires, as rows.
func edgeRows(s State, ov payload.Overview) []Row {
	d, ok := DiagramOf(s.Diagram)
	if !ok {
		d = Diagrams[0]
	}
	edges := d.Edges(ov)

	out := make([]Row, 0, len(edges))
	for i, e := range edges {
		r := Row{
			Kind:  RowEdge,
			ID:    d.ID + "#" + pad(i),
			Label: e.From + " → " + e.To,
			Sort:  []string{pad(i)},
		}
		r.Say(e.From, e.To, e.Label)
		for _, tag := range e.Tags {
			r.Tag(DimState, tag)
		}
		r.Networks = e.Via
		out = append(out, r)
	}
	return out
}

// containerRows is one row per service, not one per container found.
//
// That is deliberate and it is §22.8: a service whose container was never read must appear, with its
// runtime columns reading *not read*. A projection over the containers the Engine returned would make
// an unread fleet an empty table, which is the one thing a degraded state may not be.
func containerRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		r := Row{
			Kind:     RowContainer,
			ID:       key,
			Label:    svc.Name,
			Stack:    stack.ID,
			Service:  key,
			Networks: svc.Networks,
			Exposed:  svc.Auth.ExposedWithoutAuth,
		}
		tagService(&r, svc)
		sayService(&r, svc)
		if d := svc.Docker; d != nil {
			r.Say(d.Name, d.Image, d.ImageDigest, d.ID)
			if d.RestartCount != nil {
				r.Count = *d.RestartCount
			}
		}

		// Unhealthy first, then not running, then the rest (§22.2's findings-lead rule applied to
		// the runtime view).
		switch {
		case svc.Docker != nil && svc.Docker.Health == payload.HealthUnhealthy:
			r.Lead = 0
		case svc.Docker != nil && !svc.Docker.Running:
			r.Lead = 1
		default:
			r.Lead = 2
		}
		r.Sort = []string{strings.ToLower(svc.Name), key}
		out = append(out, r)
	})
	return out
}

// storageRows is one row per mount, plus one per declared volume nothing mounts — a volume declared and
// unused is a fact about the stack, and a projection over mounts alone would hide it.
func storageRows(ov payload.Overview) []Row {
	mounted := map[string]bool{}
	var out []Row

	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		for i, m := range svc.Mounts {
			mounted[stack.ID+"\x00"+m.Source] = true
			r := Row{
				Kind:     RowStorage,
				ID:       key + "#mount/" + pad(i),
				Label:    m.Target,
				Stack:    stack.ID,
				Service:  key,
				Networks: svc.Networks,
			}
			r.Say(m.Source, m.Target, svc.Name)
			r.Apply(RulesMount, m)
			r.Lead = leadIf(r.Has(DimState, StorageWritable))
			r.Sort = []string{strings.ToLower(m.Target), r.ID}
			out = append(out, r)
		}
	})

	for _, stack := range ov.Stacks {
		for i, vol := range stack.DeclaredVolumes {
			if mounted[stack.ID+"\x00"+vol.Name] {
				continue
			}
			r := Row{
				Kind:  RowStorage,
				ID:    stack.ID + "#volume/" + pad(i),
				Label: vol.Name,
				Stack: stack.ID,
				Lead:  2,
			}
			r.Say(vol.Name, vol.Driver)
			r.Tag(DimState, string(payload.MountVolume), StorageUnused)
			if vol.External {
				r.Tag(DimState, StorageExternal)
			}
			r.Sort = []string{strings.ToLower(vol.Name), r.ID}
			out = append(out, r)
		}
	}
	return out
}

// The storage readings carried in the `state` dimension.
const (
	StorageReadOnly = "read-only"
	StorageWritable = "writable"
	StorageExternal = "external"
	StorageUnused   = "unused"
)

// configRows is one row per env var and one per label.
//
// The value is on the row for the *view* to show as §22.2 requires — masked where the scan masked it —
// and is deliberately not in Text: free text never searches values, masked or not (§22.6, I6).
func configRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		for i, env := range svc.Env {
			r := Row{
				Kind:    RowConfig,
				ID:      key + "#env/" + pad(i),
				Label:   env.Key,
				Stack:   stack.ID,
				Service: key,
				Lead:    1,
			}
			r.Say(env.Key, svc.Name)
			r.Apply(RulesEnv, env)
			r.Sort = []string{strings.ToLower(env.Key), key}
			out = append(out, r)
		}
		for _, label := range sortedLabelKeys(svc.Labels) {
			r := Row{
				Kind:    RowConfig,
				ID:      key + "#label/" + label,
				Label:   label,
				Stack:   stack.ID,
				Service: key,
			}
			r.Say(label, svc.Name)
			r.Tag(DimState, ConfigLabel)
			// A label that produced a conclusion leads: the reader looking at Config is usually
			// looking for the one label a verdict cited.
			r.Lead = leadIf(cited(svc, label))
			r.Sort = []string{strings.ToLower(label), key}
			out = append(out, r)
		}
	})
	return out
}

// The config readings carried in the `state` dimension.
const (
	ConfigEnv    = "env"
	ConfigLabel  = "label"
	ConfigMasked = "masked"
)

// cited reports whether a label key appears in the evidence for this service's verdict — §22.2's
// *which label produced which conclusion*, answered by reading the evidence rather than by re-deriving
// the rule that produced it (§22.1: the UI may relabel, never conclude).
func cited(svc payload.Service, label string) bool {
	for _, e := range svc.Auth.Evidence {
		if strings.Contains(e, label) {
			return true
		}
	}
	return false
}

func sortedLabelKeys(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for k := range labels {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// applicationRows is one row per identity-provider application: those matched to a service, then every
// unmatched one with its reason, detail and trace (§22.2 — findings lead).
func applicationRows(ov payload.Overview) []Row {
	var out []Row
	seen := map[string]bool{}

	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		if svc.Authentik == nil {
			return
		}
		for i, app := range svc.Authentik.Applications {
			id := "app/" + app.Slug
			if app.Slug == "" {
				id = key + "#app/" + pad(i)
			}
			if seen[id] {
				// One application may protect two services. It is one application, and the second
				// service is a fact about the match rather than a second row.
				continue
			}
			seen[id] = true

			r := Row{
				Kind:    RowApplication,
				ID:      id,
				Label:   app.Name,
				Stack:   stack.ID,
				Service: key,
				Lead:    1,
			}
			r.Say(app.Name, app.Slug, app.Group, app.LaunchURL, svc.Name)
			for _, p := range app.Providers {
				r.Say(p.Name, p.InternalHost, p.ExternalHost)
				r.Tag(DimState, string(p.Kind))
			}
			r.Tag(DimMatch, MatchMatched)
			if app.DiscoveredVia == payload.DiscoveredViaProvider {
				r.Tag(DimMatch, MatchRebuilt)
			}
			for _, s := range svc.Authentik.Strength {
				r.Tag(DimConf, string(s))
			}
			r.Sort = []string{strings.ToLower(app.Slug), id}
			out = append(out, r)
		}
	})

	if a := ov.Meta.Authentik; a != nil {
		for i, un := range a.UnmatchedApplications {
			r := Row{
				Kind:  RowApplication,
				ID:    "unmatched-app/" + pad(i),
				Label: un.Application.Name,
				Lead:  0,
			}
			r.Say(un.Application.Name, un.Application.Slug, un.Application.Group, un.Application.LaunchURL)
			for _, p := range un.Application.Providers {
				r.Say(p.Name, p.InternalHost, p.ExternalHost)
			}
			r.Apply(RulesUnmatched, un)
			if un.Application.DiscoveredVia == payload.DiscoveredViaProvider {
				r.Tag(DimMatch, MatchRebuilt)
			}
			r.Sort = []string{strings.ToLower(un.Application.Slug), r.ID}
			out = append(out, r)
		}
	}
	return out
}

// routerRows is one row per live router, matched ones and unmatched ones, findings first.
func routerRows(ov payload.Overview) []Row {
	var out []Row
	seen := map[string]bool{}

	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		for i, live := range svc.TraefikLive {
			id := "router/" + live.Router
			if live.Router == "" {
				id = key + "#router/" + pad(i)
			}
			if seen[id] {
				continue
			}
			seen[id] = true

			r := Row{
				Kind:     RowRouter,
				ID:       id,
				Label:    live.Router,
				Stack:    stack.ID,
				Service:  key,
				Networks: svc.Networks,
			}
			r.Say(live.Router, live.Provider, live.Service, svc.Name)
			r.Say(live.Hosts...)
			r.Apply(RulesLiveRouter, live)
			r.Tag(DimIngress, string(payload.IngressTraefik))
			r.Lead = leadIf(r.Has(DimState, RouterErrored))
			r.Sort = []string{strings.ToLower(live.Router), id}
			out = append(out, r)
		}
	})

	if t := ov.Meta.Traefik; t != nil {
		for i, un := range t.UnmatchedRouters {
			r := Row{
				Kind:  RowRouter,
				ID:    "unmatched-router/" + pad(i),
				Label: un.Router.Router,
				Lead:  0,
			}
			r.Say(un.Router.Router, un.Router.Provider, un.Router.Service)
			r.Say(un.Router.Hosts...)
			r.Apply(RulesUnmatched, un)
			r.Tag(DimIngress, string(payload.IngressTraefik))
			r.Sort = []string{strings.ToLower(un.Router.Router), r.ID}
			out = append(out, r)
		}
	}
	return out
}

// RouterErrored is the `state` reading for a router the proxy reported an error on.
const RouterErrored = "errored"

// probeRows is one row per probed service, in §22.2's stated finding order: answered with no login
// page, then answered with one, then did not answer.
func probeRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		if svc.Probe == nil {
			return
		}
		p := svc.Probe
		r := Row{
			Kind:     RowProbe,
			ID:       key,
			Label:    svc.Name,
			Stack:    stack.ID,
			Service:  key,
			Networks: svc.Networks,
			Exposed:  svc.Auth.ExposedWithoutAuth,
		}
		tagService(&r, svc)
		sayService(&r, svc)
		r.Say(p.Endpoint)
		r.Tag(DimState, string(p.Phase))

		// The order §22.2 states, read off the tags the rule table already granted rather than
		// re-derived from the probe record: the ordering and the filter cannot disagree about which
		// probes answered without a gate.
		switch {
		case r.Has(DimProbe, OutcomeOpen):
			r.Lead = 0
		case r.Has(DimProbe, OutcomeGated):
			r.Lead = 1
		default:
			r.Lead = 2
		}
		r.Sort = []string{strings.ToLower(svc.Name), key}
		out = append(out, r)
	})
	return out
}

// declarationRows is one row per declaring service: drift first, then not confirmed, then accepted
// exposures, then the rest (§22.2).
func declarationRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		d := svc.Declared
		if d == nil {
			return
		}
		r := Row{
			Kind:     RowDeclaration,
			ID:       key,
			Label:    svc.Name,
			Stack:    stack.ID,
			Service:  key,
			Networks: svc.Networks,
			Exposed:  svc.Auth.ExposedWithoutAuth,
			Accepted: d.UnauthenticatedAccepted != nil,
			Drift:    len(d.Drift) > 0,
			Count:    len(d.Drift),
		}
		tagService(&r, svc)
		sayService(&r, svc)
		r.Say(d.Owner, d.Description, d.File)

		switch {
		case len(d.Drift) > 0:
			r.Lead = 0
		case len(d.Unconfirmed) > 0:
			r.Lead = 1
		case d.UnauthenticatedAccepted != nil:
			r.Lead = 2
		default:
			r.Lead = 3
		}
		r.Sort = []string{strings.ToLower(svc.Name), key}
		out = append(out, r)
	})
	return out
}

// entryRows is one row per drift or not-confirmed **entry**, which is what `stats.declarationDrift`
// counts: a service with two drift entries contributes two (§22.3).
func entryRows(ov payload.Overview, kind RowKind) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		d := svc.Declared
		if d == nil {
			return
		}
		entries, tag := d.Drift, DeclDrift
		if kind == RowUnconfirmed {
			entries, tag = d.Unconfirmed, DeclNotConfirmed
		}
		for i, entry := range entries {
			r := Row{
				Kind:     kind,
				ID:       key + "#" + string(kind) + "/" + pad(i),
				Label:    entry,
				Stack:    stack.ID,
				Service:  key,
				Networks: svc.Networks,
				Exposed:  svc.Auth.ExposedWithoutAuth,
				Drift:    kind == RowDrift,
			}
			r.Say(svc.Name, entry, d.File)
			r.Tag(DimDecl, tag)
			r.Sort = []string{strings.ToLower(svc.Name), pad(i)}
			out = append(out, r)
		}
	})
	return out
}

// acceptedRows is §22.3's accepted list: one row per service whose exposure the operator accepted,
// **labelled as still exposed** — an acceptance records a decision and changes nothing about
// reachability (§14 rule 3).
func acceptedRows(ov payload.Overview) []Row {
	var out []Row
	eachService(ov, func(stack payload.AppStack, svc payload.Service, key string) {
		d := svc.Declared
		if d == nil || d.UnauthenticatedAccepted == nil {
			return
		}
		r := Row{
			Kind:     RowAccepted,
			ID:       key,
			Label:    svc.Name,
			Stack:    stack.ID,
			Service:  key,
			Networks: svc.Networks,
			Exposed:  svc.Auth.ExposedWithoutAuth,
			Accepted: true,
			Lead:     leadIf(svc.Auth.ExposedWithoutAuth),
		}
		tagService(&r, svc)
		sayService(&r, svc)
		r.Say(d.UnauthenticatedAccepted.Reason)
		r.Sort = []string{strings.ToLower(svc.Name), key}
		out = append(out, r)
	})
	return out
}

// reportRows is one row per connection report: failures and `partial` first (§22.2).
func reportRows(ov payload.Overview) []Row {
	out := make([]Row, 0, len(ov.Meta.Connections))
	for i, rep := range ov.Meta.Connections {
		r := Row{
			Kind:  RowReport,
			ID:    "report/" + pad(i),
			Label: rep.Target,
		}
		r.Say(rep.Target, rep.Endpoint, rep.Detail, rep.Code, rep.Hint)
		r.Apply(RulesReport, rep)
		r.Lead = leadIf(r.Has(DimState, ReportFailing))
		r.Sort = []string{strings.ToLower(rep.Target), r.ID}
		out = append(out, r)
	}
	return out
}

// ReportFailing is the `state` reading for a connection worth a banner.
const ReportFailing = "failing"

// Failing is §22.8's banner test, as one call for the callers that need a boolean — the banner itself
// and the failing-connections card. The rule is CondReportFailing, so the banner, the Diagnostics
// ordering and the card read the same condition and the browser reads it out of the contract.
func Failing(rep payload.ConnectionReport) bool { return Holds(CondReportFailing, rep) }

// warningRows is one row per scan warning: §22.3's bounded list, as its own panel.
func warningRows(ov payload.Overview) []Row {
	out := make([]Row, 0, len(ov.Meta.Warnings))
	for i, w := range ov.Meta.Warnings {
		r := Row{
			Kind:  RowWarning,
			ID:    "warning/" + pad(i),
			Label: w,
			Sort:  []string{pad(i)},
		}
		r.Say(w)
		out = append(out, r)
	}
	return out
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// eachService walks the fleet in scan order, which is the order every projection here inherits and
// every sort breaks ties with.
func eachService(ov payload.Overview, fn func(payload.AppStack, payload.Service, string)) {
	for _, stack := range ov.Stacks {
		for _, svc := range stack.Services {
			fn(stack, svc, fleet.Key(stack.ID, svc.Name))
		}
	}
}

func leadIf(finding bool) int {
	if finding {
		return 0
	}
	return 1
}

// pad is a sortable rendering of an index: fixed width, so `10` sorts after `9`.
func pad(n int) string { return fmt.Sprintf("%06d", n) }

// padDesc sorts a number descending in a lexicographic key, for the views that lead with the biggest.
func padDesc(n int) string { return fmt.Sprintf("%06d", 999999-n) }
