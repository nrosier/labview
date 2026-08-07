package corpus

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/webui"
)

// §23's third UI check, and the last of the three the guide says MUST gate CI: **diagram export.** The
// text export for each of the four diagrams over `fixtures/nets` is asserted as a literal, which pins
// both determinism and the edge rules.
//
// A literal is a strong assertion and a blunt one: it fails on any change, including a good one. That is
// the point — a diagram is the one place in the UI where an invented line looks exactly like a fact, so
// the check is *these bytes and no others*, and changing a diagram means changing the literal on
// purpose. What a literal does not do is say **why** the bytes are what they are, so the rules the
// literals happen to demonstrate are also asserted directly, over every fleet, further down.
//
// Two of the four diagrams are empty over `fixtures/nets` — that root has no ingress and no identity
// provider — so their literals pin only that emptiness. Their edge rules are pinned over `edge`,
// `authentik` and `traefik`, which is more than §23 asks for and needed for the check to mean anything.

// ---------------------------------------------------------------------------
// The four literals over fixtures/nets
// ---------------------------------------------------------------------------

// The dependencies diagram. Every rule §22.5 gives this diagram is visible in these twenty-eight lines:
//
//   - Services are grouped by stack, and the stacks are in scan order.
//   - `n3 --"direct"--> n2` is `front → back` in the `disjoint` stack — a `depends_on` with no shared
//     network, drawn direct and **marked**, which is the one service → service line §22.5's bullet
//     allows without argument.
//   - `n1 -."badref_side".-> n0` is dashed because that pair is declared and not observed; `n4
//     --"layered_inner"--> n5` is solid because compose resolved it. §14 rule 1: drawn beside each
//     other, never merged.
//   - The label on a solid edge is the network the dependency crosses. That line is service → service
//     *and* carries a via, which is what the Dependencies row asks for and what a strict reading of the
//     bullet would forbid; the reasoning is in diagram.go's header.
//   - `n8` and `n9` are `db-a` and `db-b`, in different stacks, both on the `backup` network. There is
//     no line between them. Co-membership draws nothing.
const netsDependencies = `
%% LabView Dependencies
graph LR
  subgraph "badref"
    n0["cache"]
    n1["caller"]
  end
  subgraph "disjoint"
    n2["back"]
    n3["front"]
  end
  subgraph "layered"
    n4["api"]
    n5["cache"]
    n6["extra"]
    n7["web"]
  end
  subgraph "shared-a"
    n8["db-a"]
  end
  subgraph "shared-b"
    n9["db-b"]
  end
  subgraph "shared-c"
    n10["backup-agent"]
  end
  n1 -."badref_side".-> n0
  n2 -."direct".-> n10
  n3 --"direct"--> n2
  n4 --"layered_inner"--> n5
  n6 -."layered_inner".-> n5
  n7 --"layered_inner"--> n4
  n8 -."backup".-> n10
  n9 -."backup".-> n10
`

// The networks diagram, and the reason co-membership cannot become a relation: it is drawn as
// membership. `backup (4)` has four members and four edges, not the six pairs four members could form.
//
//   - Network nodes are rounded and carry their member count (§22.5). `outside (1)` connects one thing.
//   - An arrowhead means a dependency crossed the network; `---` means membership with nothing crossing.
//     `n5 --- n13` is the `probe` service on `layered_inner`, a member that nothing depends on and that
//     depends on nothing.
//   - A dashed leg means every dependency across that network was declared rather than observed, which
//     is `flowSource` doing exactly what §16 asks of it.
//   - `badref_side` has two members and is on the diagram even though the compose file that names it
//     never defines it: a name is not a promise it exists, and hiding it would hide the finding.
const netsNetworks = `
%% LabView Networks
graph LR
  n0["cache"]
  n1["caller"]
  n2["api"]
  n3["cache"]
  n4["extra"]
  n5["probe"]
  n6["web"]
  n7["edge-facing"]
  n8["db-a"]
  n9["db-b"]
  n10["backup-agent"]
  n11["monitor"]
  n12("badref_side (2)")
  n13("layered_inner (5)")
  n14("outside (1)")
  n15("backup (4)")
  n0 -.-> n12
  n1 -.-> n12
  n2 --> n13
  n3 --> n13
  n4 -.-> n13
  n5 --- n13
  n6 --> n13
  n7 --- n14
  n8 -.-> n15
  n9 -.-> n15
  n10 -.-> n15
  n11 --- n15
`

// Ingress and identity over `fixtures/nets`: two empty pictures, asserted rather than skipped.
//
// `nets` exists to exercise network topology, so it has no route from outside and no identity provider,
// and the honest export of a diagram with nothing to draw is a heading and `graph LR`. Asserting it says
// two things worth saying: an empty diagram is not an error, and it does not invent nodes to look busy.
// The edge rules these two diagrams own are pinned below, over the roots that have the records.
const netsIngress = `
%% LabView Ingress paths
graph LR
`

const netsIdentity = `
%% LabView Identity and auth
graph LR
`

func TestTheFourDiagramExportsOverTheNetworkFixtures(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	for _, tc := range []struct {
		id   string
		want string
	}{
		{webui.DiagramDependencies, netsDependencies},
		{webui.DiagramNetworks, netsNetworks},
		{webui.DiagramIngress, netsIngress},
		{webui.DiagramIdentity, netsIdentity},
	} {
		t.Run(tc.id, func(t *testing.T) {
			assertExport(t, diagramOf(t, tc.id), webui.State{}, out, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// The two diagrams fixtures/nets cannot exercise
// ---------------------------------------------------------------------------

// Ingress over `edge`, which is where the routes are.
//
// The shape §22.5 requires is `outside → hostname → tunnel or router → origin → service`, and the export
// shows it flattened to the hops the payload actually carries: `outside → hostname`, then `hostname →
// service` labelled with the tunnel or the router that carries it. The label is the gate drawn **on**
// the path rather than beside it.
//
//   - `n16` is `app.edge.example.com` with two edges out of it, to two different services. One hostname
//     serving two services is a real configuration and the diagram draws both rather than picking.
//   - `n9` is `api`, reached twice: once through `api.tunnel.example.com` by tunnel and once through
//     `api.edge.example.com` by the router `pdapi`. Two paths to one service, both drawn (§9).
//   - No hop is invented. A tunnel whose origin resolved to another service would be drawn through that
//     hop; every origin here resolved to the service itself, so every path is two edges long.
const edgeIngress = `
%% LabView Ingress paths
graph LR
  n0["server"]
  n1["live"]
  n2["defence"]
  n3["app"]
  n4["media"]
  n5["app"]
  n6["headersonly"]
  n7["oidconly"]
  n8["unresolved"]
  n9["api"]
  n10["ambiguous"]
  n11["offsite"]
  n12(["outside"])
  n13(["sso.edge.example.com"])
  n14(["live.example.com"])
  n15(["portal.edge.example.com"])
  n16(["app.edge.example.com"])
  n17(["media.edge.example.com"])
  n18(["hdr.edge.example.com"])
  n19(["oidc.edge.example.com"])
  n20(["unres.edge.example.com"])
  n21(["api.tunnel.example.com"])
  n22(["api.edge.example.com"])
  n23(["ambiguous.edge.example.com"])
  n24(["offsite.edge.example.com"])
  n12 --> n13
  n13 --"authentik"--> n0
  n12 --> n14
  n14 --"tunnel"--> n1
  n12 --> n15
  n15 --"dcportal"--> n2
  n12 --> n16
  n16 --"hpapp"--> n3
  n12 --> n17
  n17 --"tunnel"--> n4
  n16 --"opapp"--> n5
  n12 --> n18
  n18 --"ophdr"--> n6
  n12 --> n19
  n19 --"opoidc"--> n7
  n12 --> n20
  n20 --"opunres"--> n8
  n12 --> n21
  n21 --"tunnel"--> n9
  n12 --> n22
  n22 --"pdapi"--> n9
  n12 --> n23
  n23 --"tunnel"--> n10
  n12 --> n24
  n24 --"tunnel"--> n11
`

// Identity over `traefik`, which is the root that has both halves of §22.5's identity row: the
// application-to-service chain and the forward-auth middleware, plus unmatched records.
//
//   - `n4 --"authentik-forward-auth"--> n1` is a middleware edge: the outpost service gating three other
//     services, labelled with the middleware that does it. That is a service → service line and it is a
//     relation the labels state, not co-membership.
//   - `n7 --"proxy"--> n6` then `n6 --"address"--> n0` is the chain: provider → application → service,
//     labelled with the **strength** of the match. `address` is stronger than `name` (§4.3), and the
//     label is what lets a reader see they are not the same claim.
//   - `n8 --> n12` is the embedded outpost attached to the proxy provider, unlabelled because the
//     relation has no strength to report.
//   - `n13` and `n14` — `standalone@file` and `twin-blue@file` — are routers that matched nothing this
//     scan found. They are drawn with no edges at all, because §22.5 requires an unmatched record shown
//     **unattached, not hidden**: a router protecting nothing is the finding (§12).
const traefikIdentity = `
%% LabView Identity and auth
graph LR
  n0["crm"]
  n1["docs"]
  n2["metrics"]
  n3["shop"]
  n4["outpost"]
  n5["wiki"]
  n6(["CRM"])
  n7(["crm-proxy"])
  n8(["embedded-outpost"])
  n9(["Shop"])
  n10(["shop-proxy"])
  n11(["Wiki"])
  n12(["wiki-proxy"])
  n13(["standalone@file"])
  n14(["twin-blue@file"])
  n4 --"authentik-forward-auth"--> n1
  n4 --"authentik-forward-auth"--> n2
  n4 --"authentik-forward-auth"--> n5
  n7 --"proxy"--> n6
  n8 --> n7
  n6 --"address"--> n0
  n10 --"proxy"--> n9
  n8 --> n10
  n9 --"address"--> n3
  n12 --"proxy"--> n11
  n8 --> n12
  n11 --"address"--> n5
`

func TestTheIngressAndIdentityExportsOverTheRootsThatHaveRecords(t *testing.T) {
	t.Run("ingress/edge", func(t *testing.T) {
		assertExport(t, diagramOf(t, webui.DiagramIngress), webui.State{}, scanRoot(t, "edge", scanOptions{}), edgeIngress)
	})
	t.Run("identity/traefik", func(t *testing.T) {
		_, out := tfRun(t, tfMode{})
		assertExport(t, diagramOf(t, webui.DiagramIdentity), webui.State{}, out, traefikIdentity)
	})
}

// ---------------------------------------------------------------------------
// The edge rules the literals demonstrate, asserted as rules
// ---------------------------------------------------------------------------

// §23's first named rule: **a `service → service` edge only where `via` is empty** — read as §22.5's
// full sentence, *otherwise requires a dependency, never co-membership*.
//
// So the assertion is that every line between two services is a relation something stated: a
// `depends_on`, a declaration, or a forward-auth middleware. A line that is neither, with two service
// endpoints, could only have come from the two being near each other, which is the invented relation
// §16 forbids.
func TestEveryLineBetweenTwoServicesIsARelationAndNotCoMembership(t *testing.T) {
	// The kinds that may join two services, and what justifies it in each case. Three relations, each
	// one something a file or a provider stated:
	//
	//   - a `depends_on`, or a declaration naming the pair (§14);
	//   - a forward-auth middleware, where one service is the gate on another (§12);
	//   - a tunnel whose origin resolved to another service, which §22.5 requires drawn **through** that
	//     hop rather than as a direct edge — `proxy/gateway → outline/outline` in `apps`, where the
	//     origin `https://10.10.0.5` is another service in the fleet and the path really does go that way.
	//
	// Nothing else. In particular not membership, which is the case below.
	justified := map[payload.GraphEdgeKind]string{
		payload.EdgeDependsOn: "a depends_on or a declared dependency",
		payload.EdgeAuth:      "a forward-auth middleware naming the gate",
		payload.EdgeIngress:   "a tunnel origin that resolved to another service",
	}

	for _, f := range everyFleet(t) {
		for _, d := range webui.Diagrams {
			for _, e := range d.Edges(f.out) {
				if !isService(e.From) || !isService(e.To) {
					continue
				}
				if _, ok := justified[e.Kind]; ok {
					continue
				}
				if e.Kind == payload.EdgeNetwork {
					t.Errorf("%s/%s: %s is a membership edge between two services, which is co-membership "+
						"drawn as a relation (§16)", f.name, d.ID, e.ID)
					continue
				}
				t.Errorf("%s/%s: %s joins two services on a %s edge; a line between two services needs %s",
					f.name, d.ID, e.ID, e.Kind, sortedReasons(justified))
			}
		}
	}
}

// §23's second named rule: **no line from co-membership alone.** The networks diagram is where a
// shortcut would be tempting — four services on one network do look like six connections — so the
// assertion is arithmetic: a network node's drawn degree is its member count, never more.
//
// Four members give four edges. Six would mean the diagram had started drawing pairs, and the count on
// the node is what makes the difference checkable rather than a matter of looking.
func TestANetworkNodesDegreeIsItsMemberCountAndNotItsPairs(t *testing.T) {
	d := diagramOf(t, webui.DiagramNetworks)

	var checked int
	for _, f := range everyFleet(t) {
		dr := d.Draw(webui.State{}, f.out)

		capped := map[string]bool{}
		for _, c := range dr.Caps {
			capped[c.Node] = true
		}

		degree := map[string]int{}
		for _, e := range dr.Edges {
			degree[e.From]++
			degree[e.To]++
			if isService(e.From) == isService(e.To) {
				t.Errorf("%s: %s joins two nodes of the same kind, and membership is service to network",
					f.name, e.ID)
			}
		}

		for _, n := range dr.Nodes {
			if n.Kind != payload.NodeNetwork || capped[n.ID] {
				continue
			}
			if n.MemberCount == nil {
				t.Errorf("%s: network %s carries no member count, which §22.5 requires on the node", f.name, n.ID)
				continue
			}
			checked++
			if degree[n.ID] != *n.MemberCount {
				t.Errorf("%s: network %s has %d member%s and %d edge%s. Membership is one edge per member; "+
					"%d would be the pairs %d members can form",
					f.name, n.ID, *n.MemberCount, suffixOf(*n.MemberCount), degree[n.ID], suffixOf(degree[n.ID]),
					*n.MemberCount*(*n.MemberCount-1)/2, *n.MemberCount)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no network node was checked, so this rule has nothing holding it up")
	}
}

// §22.5's Dependencies row: an empty `via` is drawn direct **and marked**. Two markings, because a
// picture and its export carry it differently — the warn tone on screen, the word in the text.
//
// The export needs its own marking because it outlives the page it came from. Without it a copied
// diagram shows a service → service line with nothing on it saying why that line is allowed to exist,
// which is indistinguishable from the co-membership shortcut the rule above forbids.
func TestADependencyWithNoNetworkToCrossIsMarkedInBothThePictureAndTheExport(t *testing.T) {
	d := diagramOf(t, webui.DiagramDependencies)

	var direct int
	for _, f := range everyFleet(t) {
		export := d.Draw(webui.State{}, f.out).Mermaid()

		for _, e := range d.Edges(f.out) {
			if e.Kind != payload.EdgeDependsOn {
				continue
			}
			if len(e.Via) > 0 {
				if containsTag(e.Tags, webui.EdgeDirect) {
					t.Errorf("%s: %s crosses %v and is tagged direct", f.name, e.ID, e.Via)
				}
				continue
			}
			direct++
			if !containsTag(e.Tags, webui.EdgeDirect) {
				t.Errorf("%s: %s has no network to cross and is not tagged %q", f.name, e.ID, webui.EdgeDirect)
			}
			if e.Tone != webui.ToneWarn {
				t.Errorf("%s: %s is direct and not in the warn tone, so the picture does not mark it",
					f.name, e.ID)
			}
			if !strings.Contains(export, `"`+webui.EdgeDirect+`"`) {
				t.Errorf("%s: %s is direct and the export has no %q on any line, so a copied diagram shows "+
					"a service to service line with nothing saying why", f.name, e.ID, webui.EdgeDirect)
			}
		}
	}
	if direct == 0 {
		t.Fatal("no fixture has a dependency with an empty via, so the marking rule is untested")
	}
}

// The reserved colour is reserved. §22.5 gives it to one thing — a path from outside with no gate this
// scan could find — and a colour that appears anywhere else stops meaning anything.
func TestTheReservedColourGoesToUngatedPathsAndNothingElse(t *testing.T) {
	var ungated int
	for _, f := range everyFleet(t) {
		for _, d := range webui.Diagrams {
			for _, e := range d.Edges(f.out) {
				alert := e.Tone == webui.ToneAlert
				marked := containsTag(e.Tags, webui.EdgeUngated)
				if alert != marked {
					t.Errorf("%s/%s: %s is %s and tagged ungated=%v; the reserved colour and the reading are "+
						"one statement", f.name, d.ID, e.ID, e.Tone, marked)
				}
				if marked {
					ungated++
					if e.Kind != payload.EdgeIngress {
						t.Errorf("%s/%s: %s is a %s edge tagged ungated, and only a path from outside can be",
							f.name, d.ID, e.ID, e.Kind)
					}
				}
			}
		}
	}
	if ungated == 0 {
		t.Fatal("no fixture has an ungated path, so the reserved colour is untested")
	}
}

// ---------------------------------------------------------------------------
// Reading a partial picture: focus, depth, caps, threshold
// ---------------------------------------------------------------------------

// Focus and depth, as literals, because the reason to assert them is the same as for the whole picture:
// a neighbourhood that quietly gained or lost a hop is a wrong answer that looks right.
//
// Depth 1 around `layered/api` is the service and what touches it — `cache`, which it depends on, and
// `web`, which depends on it. Undirected on purpose (§22.5's *neighbourhood*): a reader focusing on a
// service to see its blast radius means both directions. Depth 2 reaches `extra`, which depends on
// `cache` and has nothing to do with `api` — one hop further out, and the picture says so in its header.
func TestAFocusedDiagramDrawsTheNeighbourhoodAndSaysWhereItIsCentred(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})
	d := diagramOf(t, webui.DiagramDependencies)

	assertExport(t, d, webui.State{Focus: "svc:layered/api"}, out, `
%% LabView Dependencies
%% focused on svc:layered/api at depth 1
graph LR
  subgraph "layered"
    n0["api"]
    n1["cache"]
    n2["web"]
  end
  n0 --"layered_inner"--> n1
  n2 --"layered_inner"--> n0
`)

	assertExport(t, d, webui.State{Focus: "svc:layered/api", Depth: 2}, out, `
%% LabView Dependencies
%% focused on svc:layered/api at depth 2
graph LR
  subgraph "layered"
    n0["api"]
    n1["cache"]
    n2["extra"]
    n3["web"]
  end
  n0 --"layered_inner"--> n1
  n2 -."layered_inner".-> n1
  n3 --"layered_inner"--> n0
`)
}

// §22.5: a cap MUST state what it dropped, with a way to see the rest. The export states it in its own
// header, because the export is the copy that leaves the page.
//
// The cap is lowered here rather than waited for. No fixture root is big enough to trip the shipped cap
// of 12 — the biggest hub in the corpus has twelve members exactly — and a rule about what happens at
// the boundary should not be untested because the fixtures are small. Lowering the cap on a copy of the
// real diagram exercises the real code path with a real payload.
func TestACappedDiagramSaysWhatItDroppedAndWhereTheRestIs(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	d := diagramOf(t, webui.DiagramNetworks)
	d.Cap = 2

	// `layered_inner` has five members and `backup` four; both are cut to two, and both say so. The
	// services stranded by the cut are dropped from the picture rather than left floating, because a
	// node whose edges this picture chose not to draw would read as a node that connects to nothing.
	assertExport(t, d, webui.State{}, out, `
%% LabView Networks
%% showing 2 of 5 edges of net:layered_inner; the edge list shows all of them
%% showing 2 of 4 edges of net:backup; the edge list shows all of them
graph LR
  n0["cache"]
  n1["caller"]
  n2["api"]
  n3["cache"]
  n4["edge-facing"]
  n5["db-a"]
  n6["db-b"]
  n7("badref_side (2)")
  n8("layered_inner (5)")
  n9("outside (1)")
  n10("backup (4)")
  n0 -.-> n7
  n1 -.-> n7
  n2 --> n8
  n3 --> n8
  n4 --- n9
  n5 -.-> n10
  n6 -.-> n10
`)

	// The node still carries its true member count — `layered_inner (5)` with two edges drawn — so the
	// picture cannot be read as *this network has two members*. The cap sentence and the count are two
	// independent statements of the same fact, which is why neither is enough alone.
	dr := d.Draw(webui.State{}, out)
	if len(dr.Caps) != 2 {
		t.Fatalf("caps = %v, want two hubs cut", dr.Caps)
	}
	for _, c := range dr.Caps {
		if c.Shown >= c.Total {
			t.Errorf("cap on %s claims %d of %d, which dropped nothing", c.Node, c.Shown, c.Total)
		}
		if !strings.Contains(dr.Mermaid(), c.Sentence("edges")) {
			t.Errorf("the export does not carry %q", c.Sentence("edges"))
		}
	}
}

// §22.5: above a stated node threshold the diagram MUST open focused rather than drawing the whole
// fleet — and the export says it was *opened* focused rather than chosen, with the numbers that forced
// it. The two are different facts for a reader: *you chose this* and *the whole picture would be
// unreadable* need different responses.
//
// The threshold is lowered for the same reason the cap was: no fixture root reaches 60 nodes. The focus
// it picks is not arbitrary — the finding first, then the busiest hub — because the picture has to be
// the same picture on every reload (I7). Here it is `backup-agent`, which three things depend on.
func TestADiagramOverTheThresholdOpensFocusedAndSaysItWasNotAChoice(t *testing.T) {
	out := scanRoot(t, "nets", scanOptions{})

	d := diagramOf(t, webui.DiagramDependencies)
	d.NodeThreshold = 3

	assertExport(t, d, webui.State{}, out, `
%% LabView Dependencies
%% opened focused: 11 nodes is over the threshold of 3 on svc:shared-c/backup-agent at depth 1
graph LR
  subgraph "disjoint"
    n0["back"]
  end
  subgraph "shared-a"
    n1["db-a"]
  end
  subgraph "shared-b"
    n2["db-b"]
  end
  subgraph "shared-c"
    n3["backup-agent"]
  end
  n0 -."direct".-> n3
  n1 -."backup".-> n3
  n2 -."backup".-> n3
`)

	dr := d.Draw(webui.State{}, out)
	if !dr.Forced {
		t.Error("the diagram opened focused without recording that it was forced")
	}
	if dr.Total <= d.NodeThreshold {
		t.Errorf("total %d is not over the threshold %d, so this test forced nothing", dr.Total, d.NodeThreshold)
	}

	// A focus the reader asked for is not marked forced, and that is the whole distinction.
	if chosen := d.Draw(webui.State{Focus: "svc:layered/api"}, out); chosen.Forced {
		t.Error("a focus from the URL was reported as forced")
	}
}

// ---------------------------------------------------------------------------
// Determinism (I7), which is what makes every literal above possible
// ---------------------------------------------------------------------------

// Two draws of one payload, and two independent scans of one root, produce the same bytes.
//
// The second half is the stronger claim and the one a literal actually depends on: the export is stable
// across scans, not merely across calls on a payload already built. Anything read from a map in either
// half would show up here as a diff on some runs and not others, which is why the assertion is over
// every diagram and every root rather than the one that happened to be convenient.
func TestTwoScansOfOneRootExportTheSameDiagramBytes(t *testing.T) {
	for _, name := range []string{"apps", "edge", "nets", "auth"} {
		first, second := scanRoot(t, name, scanOptions{}), scanRoot(t, name, scanOptions{})
		for _, d := range webui.Diagrams {
			s := webui.State{Diagram: d.ID}
			a, b := d.Draw(s, first).Mermaid(), d.Draw(s, second).Mermaid()
			if a != b {
				t.Errorf("%s/%s differs between two scans of the same root:\n%s", name, d.ID, diffLines(a, b))
			}
			if again := d.Draw(s, first).Mermaid(); again != a {
				t.Errorf("%s/%s differs between two draws of one payload:\n%s", name, d.ID, diffLines(a, again))
			}
		}
	}
}

// The diagram set itself is §22.5's four, in its order, each with the caveat the section requires stated
// once per diagram. A fifth diagram is a change to the contract §22.7's `diagram` parameter accepts, and
// a diagram with no Note is a picture offered without the reading it needs to be honest.
func TestTheDiagramSetIsTheFourTheGuideNames(t *testing.T) {
	want := []string{
		webui.DiagramDependencies,
		webui.DiagramNetworks,
		webui.DiagramIngress,
		webui.DiagramIdentity,
	}
	if got := webui.DiagramIDs(); !equalStrings(got, want) {
		t.Errorf("diagram ids = %v, want %v", got, want)
	}

	for _, d := range webui.Diagrams {
		if strings.TrimSpace(d.Note) == "" {
			t.Errorf("%s has no note, and §22.5 requires the caveat once per diagram", d.ID)
		}
		if strings.TrimSpace(d.Shows) == "" {
			t.Errorf("%s does not say what it shows", d.ID)
		}
		if len(d.Kinds) == 0 {
			t.Errorf("%s draws no edge kind, so it is not a selection of the graph", d.ID)
		}
		if d.NodeThreshold <= 0 {
			t.Errorf("%s has no node threshold, so it can never open focused (§22.5)", d.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// assertExport compares one drawing's export against a literal, and says which line first disagreed.
//
// The literals are written starting on the line after the backtick so they read in a test file the way
// they read in a terminal, so the leading newline is trimmed rather than being part of every expectation.
func assertExport(t *testing.T, d webui.Diagram, s webui.State, ov payload.Overview, want string) {
	t.Helper()

	if s.View == "" {
		s.View = webui.SlugDiagrams
	}
	if s.Diagram == "" {
		s.Diagram = d.ID
	}

	got := d.Draw(s, ov).Mermaid()
	want = strings.TrimPrefix(want, "\n")
	if got == want {
		return
	}
	t.Errorf("the %s export is not the literal (§23 check 3).\n%s\n\nWhole export:\n%s",
		d.ID, diffLines(got, want), got)
}

// diffLines is the first line two exports disagree on. A whole-string diff of a thirty-line literal
// makes a reader find the change; naming the line hands it to them.
func diffLines(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("first difference at line %d:\n  got  %q\n  want %q", i+1, gl, wl)
		}
	}
	return "the exports are equal, so this message is a bug in the comparison"
}

func diagramOf(t *testing.T, id string) webui.Diagram {
	t.Helper()
	d, ok := webui.DiagramOf(id)
	if !ok {
		t.Fatalf("§22.5 requires a %s diagram and there is none", id)
	}
	return d
}

func isService(nodeID string) bool {
	return strings.HasPrefix(nodeID, fleet.PrefixService)
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func sortedReasons(m map[payload.GraphEdgeKind]string) string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ", or ")
}
