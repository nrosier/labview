package webui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// §22.5's four diagrams.
//
// Each one is **a selection of `graph` by edge kind**, and that is the whole of it. The scan already
// built the graph the diagrams need — services and networks with their scope and member counts,
// dependencies with the networks they cross, ingress paths from outside through a hostname to a
// service, applications and providers and outposts — so a diagram here chooses which of those edges
// it draws and says how to read them. It never derives a relation of its own, which is §22.1's *no
// fleet knowledge in the UI* and §16's *one implementation* in the place they are easiest to violate:
// a picture is where an invented line looks most like a fact.
//
// The rules that apply to all four:
//
//   - **A `service → service` line is always a dependency, never co-membership** (§16). Where the
//     dependency crosses a shared network the line carries that network as its *label*, which is what
//     §22.5's Dependencies row asks for; where `via` is empty it is drawn direct and marked. Two
//     services that merely share a network get no line between them at all — they get two membership
//     edges through the network node, which is the Networks diagram.
//
//     §22.5's bullet and §23's check 3 both compress this to *survives only where `via` is empty*.
//     Taken alone that would forbid the labelled dependency the same section's Dependencies row
//     requires, and redrawing `web → api` as `web → layered_inner → api` would erase the dependency
//     into something indistinguishable from co-membership — the confusion §16 exists to prevent. The
//     clause after the semicolon is the reading implemented here: *otherwise requires a dependency,
//     never co-membership*. The caveat is stated once per diagram, in Note, rather than once per row.
//   - **Focus and depth.** Above NodeThreshold a diagram opens focused rather than drawing the fleet,
//     and the focus is in the URL (§22.7) so the picture someone is looking at is the picture they can
//     send.
//   - **A cap states what it dropped.** Spokes past Cap are not drawn, and the count that was dropped
//     is carried out of here as a fact — never as a silently shorter picture.
//   - **The text export is deterministic** for a payload, so a test can assert it as a literal.
//   - **The tabular equivalent is the edge list**, which is rows.go's RowEdge and is reachable at
//     `panel=edges`. Everything below is also what those rows are built from, so the picture and the
//     table cannot show different edges.

// Diagram is one of §22.5's four.
type Diagram struct {
	// ID is the `diagram` parameter (§22.7).
	ID string

	Title string

	// Shows is §22.5's own description of what it draws, for the heading and the diagram list.
	Shows string

	// Kinds are the graph edge kinds this diagram draws. The selection *is* the diagram.
	Kinds []payload.GraphEdgeKind

	// Note is the caveat this picture needs to be read honestly — the membership one for the
	// networks diagram, the declared-is-not-observed one for dependencies. §22.5: stated once per
	// diagram, not once per row.
	Note string

	// NodeThreshold is the node count above which the diagram MUST open focused (§22.5).
	NodeThreshold int

	// Cap is the most spokes drawn off one hub. Zero means uncapped.
	Cap int

	// GroupByStack draws service nodes grouped by their stack, which is what the dependencies diagram
	// does with them.
	GroupByStack bool
}

// The diagram ids, in §22.5's order.
const (
	DiagramDependencies = "dependencies"
	DiagramNetworks     = "networks"
	DiagramIngress      = "ingress"
	DiagramIdentity     = "identity"
)

// Diagrams is §22.5's table.
var Diagrams = []Diagram{
	{
		ID:    DiagramDependencies,
		Title: "Dependencies",
		Shows: "services, grouped by stack; `depends_on` and declared dependencies, labelled with the network each crosses",
		Kinds: []payload.GraphEdgeKind{payload.EdgeDependsOn},
		Note: "a declared dependency is marked as declared: it is what an operator said, and this diagram " +
			"draws it beside what was observed without merging the two (§14 rule 1). An edge with no network " +
			"to cross is drawn direct and marked — the dependency is real and the path to it is not visible here (§8).",
		NodeThreshold: 60,
		Cap:           24,
		GroupByStack:  true,
	},
	{
		ID:    DiagramNetworks,
		Title: "Networks",
		Shows: "services and networks; membership, with arrowheads carrying flow and styling carrying its provenance",
		Kinds: []payload.GraphEdgeKind{payload.EdgeNetwork},
		Note: "a line here is membership, not a relation: two services on one network can reach each other and " +
			"that is all this says (§16). An arrowhead means something crossed the network — a dependency — and a " +
			"dashed leg means every dependency across it was declared rather than observed.",
		NodeThreshold: 60,
		Cap:           12,
	},
	{
		ID:    DiagramIngress,
		Title: "Ingress paths",
		Shows: "outside → hostname → tunnel or router → origin → service, one path per route, with the gate drawn on the path",
		Kinds: []payload.GraphEdgeKind{payload.EdgeIngress},
		Note: "the reserved colour marks a path from outside with no gate this scan could find. A tunnel whose " +
			"origin resolved to another service is drawn through that hop; every other origin keeps its direct " +
			"edge, because an invented hop would be a claim about the path (§9).",
		NodeThreshold: 80,
		Cap:           24,
	},
	{
		ID:    DiagramIdentity,
		Title: "Identity and auth",
		Shows: "providers, applications, outposts, proxies and services; which application protects which service, at what strength",
		Kinds: []payload.GraphEdgeKind{payload.EdgeAuth},
		Note: "an unmatched application or router is drawn unattached rather than hidden: a record that protects " +
			"nothing this scan found is the finding (§11, §12). An edge's label is the strength of the match, and " +
			"`name` is the weakest of them (§4.3).",
		NodeThreshold: 80,
		Cap:           24,
	},
}

// DiagramIDs is every `diagram` value §22.7 accepts.
func DiagramIDs() []string {
	out := make([]string, 0, len(Diagrams))
	for _, d := range Diagrams {
		out = append(out, d.ID)
	}
	return out
}

// DiagramOf finds a diagram by id.
func DiagramOf(id string) (Diagram, bool) {
	for _, d := range Diagrams {
		if d.ID == id {
			return d, true
		}
	}
	return Diagram{}, false
}

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

// Edge is one drawn relation: a graph edge with the readings this diagram gives it.
type Edge struct {
	ID string

	// From and To are node ids, in the graph's own spelling (`svc:stack/name`, `net:name`), so
	// clicking a node can open that object's drawer (§22.5) without a second naming scheme.
	From string
	To   string

	// Label is what the edge is labelled with: the network a dependency crosses, the router or tunnel
	// on an ingress hop, the strength of an identity match.
	Label string

	Kind payload.GraphEdgeKind

	// Via are the networks this relation crosses, empty on a direct edge.
	Via []string

	// Tags are the readings, which are also the members `state` filters the edge list on (§22.6).
	Tags []string

	// Tone is the colour. Only an ungated path from outside gets the reserved one (§22.5).
	Tone Tone
}

// The edge readings. Members of the `state` dimension, because that is the dimension a row's own
// condition lives in and §22.7's parameter list is closed — an edge list is a table like any other.
const (
	// EdgeDeclared marks a dependency an operator declared.
	EdgeDeclared = "declared"
	// EdgeObserved marks one the scan resolved from the compose file.
	EdgeObserved = "observed"
	// EdgeDirect marks a dependency with no network to cross: the pair is real and no shared network
	// explains how it is reached (§8).
	EdgeDirect = "direct"
	// EdgeUngated marks a path from outside with no gate found — the one reading that takes the
	// reserved colour (§22.5).
	EdgeUngated = "ungated"
	// EdgeUnattached marks an edge whose endpoint is a record nothing in the fleet matched.
	EdgeUnattached = "unattached"
)

// Edges is the diagram's edges, in a deterministic order.
//
// Order is the graph's own edge order, which fleet builds by walking the fleet in scan order and
// which is therefore stable for a payload (I7). The edge list view and the text export both read
// this, so the picture, the table and the export cannot disagree.
func (d Diagram) Edges(ov payload.Overview) []Edge {
	declared := declaredPairs(ov)
	ungated := ungatedHosts(ov)

	out := make([]Edge, 0, len(ov.Graph.Edges))
	for _, e := range ov.Graph.Edges {
		if !d.draws(e.Kind) {
			continue
		}
		edge := Edge{
			ID:    e.ID,
			From:  e.Source,
			To:    e.Target,
			Label: e.Label,
			Kind:  e.Kind,
			Via:   e.Via,
		}

		switch e.Kind {
		case payload.EdgeDependsOn:
			// Declared and observed are both readings an edge can carry, and a pair that is both
			// carries both: merging them would lose the distinction §14 rule 1 exists to keep.
			if e.DeclaredBy != nil || declared[e.Source+"\x00"+e.Target] {
				edge.Tags = append(edge.Tags, EdgeDeclared)
			}
			if e.DeclaredBy == nil {
				edge.Tags = append(edge.Tags, EdgeObserved)
			}
			if len(e.Via) == 0 {
				// §22.5: drawn direct and marked. This is the only place a service → service line is
				// allowed, and it is allowed because there is no network to route it through.
				edge.Tags = append(edge.Tags, EdgeDirect)
				edge.Tone = ToneWarn
			}
		case payload.EdgeNetwork:
			edge.Tags = appendNonEmpty(edge.Tags, string(e.Flow), string(e.FlowSource))
		case payload.EdgeIngress:
			if ungated[e.Source] || ungated[e.Target] {
				edge.Tags = append(edge.Tags, EdgeUngated)
				edge.Tone = ToneAlert
			}
		case payload.EdgeAuth:
			edge.Tags = appendNonEmpty(edge.Tags, e.Label)
		}
		if unattachedNode(ov, e.Source) || unattachedNode(ov, e.Target) {
			edge.Tags = append(edge.Tags, EdgeUnattached)
		}
		out = append(out, edge)
	}
	return out
}

func (d Diagram) draws(kind payload.GraphEdgeKind) bool {
	for _, k := range d.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// declaredPairs is every `source → target` pair a declaration named, in graph node spelling.
//
// This exists because the graph marks `declaredBy` only where a declaration is the edge's *only*
// account (§14: dashing a pair compose already resolved would claim it was never measured). A pair
// that is both observed and declared therefore has to be recognised from the declaration itself,
// which is what this does — and it is why `stats.declaredDependencies` has a destination that shows
// exactly the edges it counted (§22.3).
//
// The reference forms are §14's: qualified (`stack/service`) names one service; bare names the
// declaring stack's own service if it has one, and otherwise a service elsewhere. The same order
// resolveRef uses, and the reason it is restated as *which pairs a declaration accounts for* rather
// than as resolution is that resolution already happened — this reads the answer off the pair.
func declaredPairs(ov payload.Overview) map[string]bool {
	names := map[string][]string{}
	for _, stack := range ov.Stacks {
		for _, svc := range stack.Services {
			names[svc.Name] = append(names[svc.Name], fleet.Key(stack.ID, svc.Name))
		}
	}

	out := map[string]bool{}
	for _, stack := range ov.Stacks {
		for _, svc := range stack.Services {
			if svc.Declared == nil {
				continue
			}
			from := fleet.PrefixService + fleet.Key(stack.ID, svc.Name)
			for _, ref := range svc.Declared.DependsOn {
				for _, target := range refTargets(names, stack.ID, ref.Ref) {
					out[from+"\x00"+fleet.PrefixService+target] = true
				}
			}
		}
	}
	return out
}

// refTargets is the keys a declared reference accounts for.
func refTargets(names map[string][]string, stackID, ref string) []string {
	if stack, name, qualified := strings.Cut(ref, "/"); qualified {
		return []string{fleet.Key(stack, name)}
	}
	// A bare reference prefers the declaring stack's own service, exactly as resolution does; only
	// when the stack has no service of that name can it mean one elsewhere.
	local := fleet.Key(stackID, ref)
	for _, key := range names[ref] {
		if key == local {
			return []string{local}
		}
	}
	return names[ref]
}

// ungatedHosts is every hostname node whose path into the fleet had no gate this scan could find.
//
// Read off the stored finding — a service's `exposedWithoutAuth`, which §4.2 requires the payload to
// carry rather than have anyone recompute — so the reserved colour on a path and the exposure count on
// the overview are the same statement (§22.3).
func ungatedHosts(ov payload.Overview) map[string]bool {
	out := map[string]bool{}
	for _, stack := range ov.Stacks {
		for _, svc := range stack.Services {
			if !svc.Auth.ExposedWithoutAuth {
				continue
			}
			out[fleet.PrefixService+fleet.Key(stack.ID, svc.Name)] = true
			for _, route := range svc.Cloudflare {
				if route.Hostname != "" && route.Access == nil {
					out[fleet.PrefixHostname+route.Hostname] = true
				}
			}
			for _, route := range svc.Traefik {
				for _, host := range route.Hosts {
					out[fleet.PrefixHostname+host] = true
				}
			}
		}
	}
	return out
}

// unattachedNode reports whether a node id names a record that matched nothing in this fleet.
//
// §22.5 requires unmatched records to be drawn unattached rather than hidden, so the diagram needs to
// know which ones they are — and the payload already says: they are the records in the two unmatched
// lists (§11, §12).
func unattachedNode(ov payload.Overview, id string) bool {
	if a := ov.Meta.Authentik; a != nil {
		for _, un := range a.UnmatchedApplications {
			if id == fleet.PrefixApp+un.Application.Slug {
				return true
			}
		}
	}
	if t := ov.Meta.Traefik; t != nil {
		for _, un := range t.UnmatchedRouters {
			if id == fleet.PrefixRouter+un.Router.Router+"@"+un.Router.Provider {
				return true
			}
		}
	}
	return false
}

func appendNonEmpty(list []string, values ...string) []string {
	for _, v := range values {
		if v != "" {
			list = appendOnceString(list, v)
		}
	}
	return list
}

// ---------------------------------------------------------------------------
// What is actually drawn: focus, depth and caps
// ---------------------------------------------------------------------------

// Cap is one hub whose spokes were not all drawn: §22.5's *showing 12 of 31 members*.
//
// A cap is carried out as a fact with the hub it applies to, so the sentence names what was capped
// and the reader can go to the edge list — which is uncapped — for the rest.
type Cap struct {
	Node  string
	Shown int
	Total int
}

// Sentence is the cap in words, in the diagram's own terms.
func (c Cap) Sentence(noun string) string {
	return fmt.Sprintf("showing %d of %d %s of %s", c.Shown, c.Total, noun, c.Node)
}

// Drawing is what a diagram draws for one state: the nodes and edges after focus and caps, plus
// everything a reader needs to know about what is missing.
type Drawing struct {
	Diagram Diagram

	Nodes []payload.GraphNode
	Edges []Edge

	// Focus is the node the drawing is centred on, empty when it draws everything.
	Focus string
	// Depth is the neighbourhood radius actually used.
	Depth int

	// Forced records that the diagram opened focused because the fleet is over the threshold
	// (§22.5), rather than because the reader asked. It is the difference between *you chose this*
	// and *the whole picture would be unreadable*, and the UI says which.
	Forced bool

	// Caps are the hubs whose spokes were cut, each with what it dropped.
	Caps []Cap

	// Total is the node count before focus, so the drawing can say how much of the fleet it is.
	Total int
}

// DefaultDepth is the neighbourhood radius a focused diagram uses when the URL does not say.
//
// One hop: the service and what it touches. Deep enough to answer *what does this depend on and what
// depends on it*, shallow enough that the answer is legible — and `depth` is in the URL, so a reader
// who wants two hops asks for two (§22.7).
const DefaultDepth = 1

// Draw is what the diagram shows for a state.
func (d Diagram) Draw(s State, ov payload.Overview) Drawing {
	edges := d.Edges(ov)
	nodes := d.nodes(ov, edges)

	out := Drawing{Diagram: d, Focus: s.Focus, Depth: s.Depth, Total: len(nodes)}
	if out.Depth <= 0 {
		out.Depth = DefaultDepth
	}

	// §22.5: above the threshold the diagram MUST open focused rather than draw the whole fleet. With
	// no focus in the URL there is still a choice to make about *what* to focus on, and the honest one
	// is the finding: the first node that is exposed without authentication, else the busiest hub —
	// never an arbitrary one, because the picture has to be the same picture on every reload (I7).
	if out.Focus == "" && len(nodes) > d.NodeThreshold {
		out.Focus, out.Forced = defaultFocus(ov, nodes, edges), true
	}

	if out.Focus != "" {
		nodes, edges = neighbourhood(out.Focus, out.Depth, nodes, edges)
	}
	// Which nodes no edge touched *before* the cap ran. Those are the unattached records §22.5 requires
	// to be drawn rather than hidden, and they have to be recognised here because after the cap a node
	// stranded by the cap looks exactly the same as one that never had an edge.
	unattached := untouchedNodes(nodes, edges)

	edges, out.Caps = d.applyCap(nodes, edges)
	out.Nodes, out.Edges = keepConnected(nodes, edges, out.Focus, unattached), edges
	return out
}

// nodes is every node an edge of this diagram touches, in the graph's order.
//
// Derived from the edges rather than filtered by node kind, because a node's kind does not say which
// diagram it belongs to — a service is in all four — and because a node no drawn edge touches is not
// part of this picture. The exception is the unmatched records, which §22.5 requires to be drawn
// unattached: they have no edges, and they are added back here for the diagram that shows them.
func (d Diagram) nodes(ov payload.Overview, edges []Edge) []payload.GraphNode {
	want := map[string]bool{}
	for _, e := range edges {
		want[e.From], want[e.To] = true, true
	}
	if d.draws(payload.EdgeAuth) {
		for _, n := range ov.Graph.Nodes {
			if unattachedNode(ov, n.ID) {
				want[n.ID] = true
			}
		}
	}

	out := make([]payload.GraphNode, 0, len(want))
	for _, n := range ov.Graph.Nodes {
		if want[n.ID] {
			out = append(out, n)
		}
	}
	return out
}

// defaultFocus is the node a forced-focus diagram opens on: the finding first, then the busiest hub.
func defaultFocus(ov payload.Overview, nodes []payload.GraphNode, edges []Edge) string {
	ungated := ungatedHosts(ov)
	for _, n := range nodes {
		if ungated[n.ID] {
			return n.ID
		}
	}

	degree := map[string]int{}
	for _, e := range edges {
		degree[e.From]++
		degree[e.To]++
	}
	best, bestDegree := "", -1
	for _, n := range nodes {
		// Strictly greater, walking the graph's own node order: ties resolve to the first node the
		// scan emitted, which is deterministic for a payload.
		if degree[n.ID] > bestDegree {
			best, bestDegree = n.ID, degree[n.ID]
		}
	}
	return best
}

// neighbourhood is the focus node and everything within depth hops of it, by breadth-first search
// over the drawn edges regardless of direction.
//
// Undirected on purpose: *what depends on this* and *what this depends on* are both the
// neighbourhood, and a reader focusing on a service to see its blast radius means both directions.
func neighbourhood(focus string, depth int, nodes []payload.GraphNode, edges []Edge) ([]payload.GraphNode, []Edge) {
	reach := map[string]int{focus: 0}
	frontier := []string{focus}
	for hop := 1; hop <= depth && len(frontier) > 0; hop++ {
		var next []string
		for _, e := range edges {
			for _, pair := range [2][2]string{{e.From, e.To}, {e.To, e.From}} {
				if !containsString(frontier, pair[0]) {
					continue
				}
				if _, seen := reach[pair[1]]; seen {
					continue
				}
				reach[pair[1]] = hop
				next = append(next, pair[1])
			}
		}
		frontier = next
	}

	keptNodes := make([]payload.GraphNode, 0, len(reach))
	for _, n := range nodes {
		if _, ok := reach[n.ID]; ok {
			keptNodes = append(keptNodes, n)
		}
	}
	keptEdges := make([]Edge, 0, len(edges))
	for _, e := range edges {
		_, from := reach[e.From]
		_, to := reach[e.To]
		if from && to {
			keptEdges = append(keptEdges, e)
		}
	}
	return keptNodes, keptEdges
}

// applyCap drops spokes past the cap and says what it dropped.
//
// The cap is per hub and counted over the hub's whole degree, so *showing 12 of 31* is the truth
// about that node rather than about the diagram. Edges are kept in the graph's own order, so which
// twelve are shown is deterministic — and the edge list at `panel=edges` is uncapped, which is the
// *way to see the rest* §22.5 requires.
func (d Diagram) applyCap(nodes []payload.GraphNode, edges []Edge) ([]Edge, []Cap) {
	if d.Cap <= 0 {
		return edges, nil
	}

	total := map[string]int{}
	for _, e := range edges {
		total[e.From]++
		total[e.To]++
	}

	shown := map[string]int{}
	out := make([]Edge, 0, len(edges))
	dropped := map[string]int{}
	for _, e := range edges {
		if shown[e.From] >= d.Cap {
			dropped[e.From]++
			continue
		}
		if shown[e.To] >= d.Cap {
			dropped[e.To]++
			continue
		}
		shown[e.From]++
		shown[e.To]++
		out = append(out, e)
	}

	caps := make([]Cap, 0, len(dropped))
	for _, n := range nodes {
		if dropped[n.ID] > 0 {
			caps = append(caps, Cap{Node: n.ID, Shown: shown[n.ID], Total: total[n.ID]})
		}
	}
	return out, caps
}

// keepConnected drops nodes no surviving edge touches, keeping the focus itself and any node that was
// unattached to begin with.
//
// A node stranded by a *cap* is not a node with nothing to say — it is a node whose edges this
// picture chose not to draw — and leaving it floating would read as *nothing connects here*, which is
// the opposite of true.
//
// The unattached set is the opposite case and must survive: a node that had no edge before the cap ran
// is an unmatched application or router, and §22.5 requires it drawn unattached rather than hidden,
// because a record that protects nothing this scan found is the finding (§11, §12).
func keepConnected(nodes []payload.GraphNode, edges []Edge, focus string, unattached map[string]bool) []payload.GraphNode {
	touched := map[string]bool{}
	for _, e := range edges {
		touched[e.From], touched[e.To] = true, true
	}
	out := make([]payload.GraphNode, 0, len(nodes))
	for _, n := range nodes {
		if touched[n.ID] || n.ID == focus || unattached[n.ID] {
			out = append(out, n)
		}
	}
	return out
}

// untouchedNodes is the nodes no edge in the given set touches.
func untouchedNodes(nodes []payload.GraphNode, edges []Edge) map[string]bool {
	touched := map[string]bool{}
	for _, e := range edges {
		touched[e.From], touched[e.To] = true, true
	}
	out := map[string]bool{}
	for _, n := range nodes {
		if !touched[n.ID] {
			out[n.ID] = true
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The text export
// ---------------------------------------------------------------------------

// Mermaid is the drawing's own source: copyable, and deterministic for a payload (§22.5).
//
// Deterministic means every choice in here is made from the payload's own order and nothing else —
// node ids are numbered in the order the graph emitted them, subgraphs are the stacks in scan order,
// and the caps are stated in node order. No map iteration reaches the output. That is what lets a
// test assert the whole string as a literal, which is the only way to know a diagram did not quietly
// change shape.
func (dr Drawing) Mermaid() string {
	var b strings.Builder
	b.WriteString("%% LabView " + dr.Diagram.Title + "\n")
	if dr.Focus != "" {
		reason := "focused"
		if dr.Forced {
			// The reader is told the picture is partial *because* the fleet is over the threshold —
			// the export carries it too, since a copied diagram outlives its page (§22.8).
			reason = "opened focused: " + itoa(dr.Total) + " nodes is over the threshold of " +
				itoa(dr.Diagram.NodeThreshold)
		}
		b.WriteString("%% " + reason + " on " + dr.Focus + " at depth " + itoa(dr.Depth) + "\n")
	}
	for _, c := range dr.Caps {
		b.WriteString("%% " + c.Sentence("edges") + "; the edge list shows all of them\n")
	}
	b.WriteString("graph LR\n")

	ids := map[string]string{}
	for i, n := range dr.Nodes {
		ids[n.ID] = fmt.Sprintf("n%d", i)
	}

	if dr.Diagram.GroupByStack {
		for _, stack := range stacksOf(dr.Nodes) {
			b.WriteString("  subgraph " + quote(stack) + "\n")
			for _, n := range dr.Nodes {
				if n.Stack == stack {
					b.WriteString("    " + ids[n.ID] + nodeShape(n) + "\n")
				}
			}
			b.WriteString("  end\n")
		}
		for _, n := range dr.Nodes {
			if n.Stack == "" {
				b.WriteString("  " + ids[n.ID] + nodeShape(n) + "\n")
			}
		}
	} else {
		for _, n := range dr.Nodes {
			b.WriteString("  " + ids[n.ID] + nodeShape(n) + "\n")
		}
	}

	for _, e := range dr.Edges {
		from, to := ids[e.From], ids[e.To]
		if from == "" || to == "" {
			// An edge whose endpoint the drawing dropped is not drawn. It is still in the edge list.
			continue
		}
		b.WriteString("  " + from + arrow(e) + to + "\n")
	}
	return b.String()
}

// nodeShape is the node's label and shape: a network is a rounded box, an external record is a
// stadium, a service is a plain box.
func nodeShape(n payload.GraphNode) string {
	label := n.Label
	if n.MemberCount != nil {
		// The count is on the node because §22.5 asks for it there — a network that connects nothing
		// looks the same as one connecting eight until it says so.
		label += " (" + itoa(*n.MemberCount) + ")"
	}
	switch n.Kind {
	case payload.NodeNetwork:
		return "(" + quote(label) + ")"
	case payload.NodeExternal:
		return "([" + quote(label) + "])"
	default:
		return "[" + quote(label) + "]"
	}
}

// arrow is the edge's line: dashed where every dependency across it was declared rather than
// observed, labelled with what the edge is labelled with, and arrowless where nothing crosses.
func arrow(e Edge) string {
	dashed := containsString(e.Tags, string(payload.FlowSourceDeclared)) ||
		(containsString(e.Tags, EdgeDeclared) && !containsString(e.Tags, EdgeObserved))

	line := "-->"
	switch {
	case dashed:
		line = "-.->"
	case e.Kind == payload.EdgeNetwork && !containsString(e.Tags, string(payload.FlowBoth)) &&
		!containsString(e.Tags, string(payload.FlowToNetwork)) &&
		!containsString(e.Tags, string(payload.FlowToService)):
		// Membership with no flow: the service is on the network and nothing crosses it. A line
		// without an arrowhead, because an arrow would claim direction the payload does not carry.
		line = "---"
	}
	label := e.Label
	if label == "" && containsString(e.Tags, EdgeDirect) {
		// §22.5: an empty `via` is drawn direct **and marked**. In the picture the marking is the warn
		// tone; an export has no colour, so here it is the word. Without it a copied diagram shows a
		// service → service line with nothing on it saying why that line is allowed to exist (§16).
		label = EdgeDirect
	}

	if label == "" {
		return " " + line + " "
	}
	if dashed {
		return " -." + quote(label) + ".-> "
	}
	if line == "---" {
		return " --- " + quote(label) + " --- "
	}
	return " --" + quote(label) + "--> "
}

// stacksOf is the stacks the drawn service nodes belong to, in the order the nodes appeared.
func stacksOf(nodes []payload.GraphNode) []string {
	var out []string
	for _, n := range nodes {
		if n.Stack != "" {
			out = appendOnceString(out, n.Stack)
		}
	}
	return out
}

// quote makes a label safe for the export: Mermaid's own delimiters are the only thing removed.
//
// Removed rather than escaped, and the rest kept as it is — a container name in Cyrillic or an emoji
// in a label survives here exactly as it survives the URL (§22.7).
func quote(s string) string {
	s = strings.NewReplacer(`"`, "'", "\n", " ", "\r", " ", "[", "(", "]", ")").Replace(s)
	return `"` + s + `"`
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// SortDiagramEdges orders edges by their id, for a caller that needs an order independent of the
// graph's. The diagrams themselves do not use it: their order is the graph's, which is already
// deterministic and which keeps an ingress path's hops adjacent.
func SortDiagramEdges(edges []Edge) {
	sort.SliceStable(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
}
