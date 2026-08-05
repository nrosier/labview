package fleet

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// twoServiceStack is one stack whose `web` depends on `db` twice over: once in compose and once in a
// sidecar that adds a detail. It is the mixed-provenance case, which the fixture corpus deliberately
// splits across two different pairs.
func twoServiceStack(t *testing.T) []payload.AppStack {
	t.Helper()
	return []payload.AppStack{{
		ID: "s", ProjectName: "s",
		DeclaredNetworks: []payload.NetworkDecl{{Name: "default"}},
		Services: []payload.Service{
			{
				Name: "web", Networks: []string{"s_default"}, DependsOn: []string{"db"},
				Declared: &payload.ServiceDeclaration{
					Declaration: payload.Declaration{File: "s/.labview"},
					DependsOn: []payload.DeclaredServiceDependency{
						{Ref: "db", Detail: "and here is why"},
					},
				},
			},
			{Name: "db", Networks: []string{"s_default"}},
		},
	}}
}

// TestBadrefIsFourReferencesAndOneEdge is §14's resolution table over the fixture written for it.
//
// `badref/caller` names four things. One resolves, one resolves to the same pair a second time, and
// two are refused. Each refusal draws nothing: guessing would put a line in a picture whose whole
// point is that a line means something.
func TestBadrefIsFourReferencesAndOneEdge(t *testing.T) {
	a := analyze(t, "nets")

	var edges, refusals int
	for _, d := range a.Deps.Resolved {
		if d.From == "badref/caller" {
			edges++
		}
	}
	for _, r := range a.Deps.Refused {
		if r.From == "badref/caller" {
			refusals++
		}
	}
	if edges != 1 {
		t.Errorf("badref/caller has %d resolved dependencies, want 1", edges)
	}
	if refusals != 2 {
		t.Errorf("badref/caller has %d refusals, want 2", refusals)
	}

	// The bare `cache` resolves to the sibling, not to the `cache` in `layered`: compose's own
	// `depends_on` reaches no further than its project, so a bare name written beside a service of
	// that name means the sibling.
	d := a.dep(t, "badref/caller", "badref/cache")
	if !d.Declared || d.Observed {
		t.Errorf("declared=%v observed=%v, want a declared-only edge", d.Declared, d.Observed)
	}
	if !equalStrings(d.Via, []string{"badref_side"}) {
		t.Errorf("via = %v, want [badref_side]", d.Via)
	}
	// `badref/cache` names the same pair the long way. One dependency, so the repeat is dropped
	// without a word: the file says nothing wrong, it just says it twice.
	if a.hasEdge(edgeID(payload.EdgeDependsOn, PrefixService+"badref/caller", PrefixService+"layered/cache")) {
		t.Error("the bare `cache` was resolved across the fleet instead of to the sibling")
	}
}

// TestRefusalsSayWhichRuleApplied pins the two reasons in `badref`, because a refusal that only said
// "unresolved" would leave a reader with nothing to act on.
func TestRefusalsSayWhichRuleApplied(t *testing.T) {
	a := analyze(t, "nets")

	byRef := map[string]string{}
	for _, r := range a.Deps.Refused {
		byRef[r.From+" → "+r.Ref] = r.Reason
		if r.File == "" {
			t.Errorf("refusal of %q names no file; a drift entry has to say where it was written", r.Ref)
		}
	}

	for ref, want := range map[string]string{
		// A rename nobody carried over here.
		"badref/caller → nope/missing": "names no scanned service",
		// A dependency on itself is not a relation.
		"badref/caller → caller": "names this very service",
		// Two stacks have a service called `probe` and this stack has none, so there is no sibling
		// to prefer and no way to choose.
		"disjoint/front → probe": "and no service of that name in this stack",
	} {
		got, ok := byRef[ref]
		if !ok {
			t.Errorf("%s was not refused; refusals: %v", ref, byRef)
			continue
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s refused because %q, want it to say %q", ref, got, want)
		}
	}
}

// TestAmbiguousReferenceNamesItsCandidates is the answerability rule: a reference naming two services
// is refused *and* both candidates are reported, so the operator knows which two to disambiguate.
func TestAmbiguousReferenceNamesItsCandidates(t *testing.T) {
	a := analyze(t, "nets")

	for _, r := range a.Deps.Refused {
		if r.From != "disjoint/front" {
			continue
		}
		if !equalStrings(r.Considered, []string{"layered/probe", "shared-d/probe"}) {
			t.Errorf("considered = %v, want [layered/probe shared-d/probe]", r.Considered)
		}
		// And the reason says what to write instead.
		if !strings.Contains(r.Reason, "`stack/service`") {
			t.Errorf("reason = %q, want it to say how to write the reference", r.Reason)
		}
		return
	}
	t.Fatalf("disjoint/front's bare `probe` was not refused; refusals: %v", a.Deps.Refused)
}

// TestCrossStackDeclarationsResolveBothWays covers the two forms of a reference that does resolve:
// qualified in `shared-a`, and bare-across-the-fleet in `shared-b`. Both name the one service in
// `shared-c`, whose own file says nothing — which is the whole reason the key lives on the dependent.
func TestCrossStackDeclarationsResolveBothWays(t *testing.T) {
	a := analyze(t, "nets")

	for _, from := range []string{"shared-a/db-a", "shared-b/db-b"} {
		d := a.dep(t, from, "shared-c/backup-agent")
		if !d.DeclaredOnly() {
			t.Errorf("%s: declared=%v observed=%v, want declared-only", from, d.Declared, d.Observed)
		}
		if !equalStrings(d.Via, []string{"backup"}) {
			t.Errorf("%s: via = %v, want [backup]", from, d.Via)
		}
		if d.File == "" {
			t.Errorf("%s: the edge names no file, so the drawer cannot say who declared it", from)
		}
	}

	// The detail travels with the declaration; it is the reason a reader would trust the line.
	if got := a.dep(t, "shared-a/db-a", "shared-c/backup-agent").Detail; !strings.Contains(got, "Nightly dump target") {
		t.Errorf("detail = %q, want shared-a's own sentence", got)
	}
	// `shared-b` wrote no detail, and nothing invents one for it.
	if got := a.dep(t, "shared-b/db-b", "shared-c/backup-agent").Detail; got != "" {
		t.Errorf("detail = %q, want empty: shared-b's sidecar wrote none", got)
	}
}

// TestCoMembershipIsNotAConnection is the trap `shared-d/monitor` exists for. It sits on the shared
// backup network with the two databases and the agent, declares nothing, and nothing declares it. A
// leg from a service to it would claim the monitor needs those databases, or that they need the
// monitor — neither of which anything in this fleet says.
func TestCoMembershipIsNotAConnection(t *testing.T) {
	a := analyze(t, "nets")

	for _, d := range a.Deps.Resolved {
		if d.From == "shared-d/monitor" || d.To == "shared-d/monitor" {
			t.Errorf("shared-d/monitor is in a dependency (%s → %s); co-membership is not a connection",
				d.From, d.To)
		}
	}
	// It is still a member of the network, and reachable from the others — which is the fact
	// co-membership does support.
	if !contains(a.Nets.Of("shared-d/monitor"), "backup") {
		t.Errorf("monitor's networks = %v, want it on backup", a.Nets.Of("shared-d/monitor"))
	}
	if !a.Nets.SharesAny("shared-d/monitor", "shared-a/db-a") {
		t.Error("monitor shares no network with db-a, but both are on `backup`")
	}
	// And its leg to that network carries no arrowhead: nothing crosses it.
	e := a.edge(t, edgeID(payload.EdgeNetwork, PrefixService+"shared-d/monitor", PrefixNetwork+"backup"))
	if e.Flow != "" || e.FlowSource != "" {
		t.Errorf("monitor's leg carries flow=%q source=%q, want both absent", e.Flow, e.FlowSource)
	}
}

// TestEmptyViaIsTheFinding is §8's one case where a straight service-to-service line is the honest
// drawing: compose orders `front` after `back`, and the two are on separate networks, so neither
// container can address the other. A line on a diagram does not say why it is there, so it is also
// a note.
func TestEmptyViaIsTheFinding(t *testing.T) {
	a := analyze(t, "nets")

	d := a.dep(t, "disjoint/front", "disjoint/back")
	if len(d.Via) != 0 {
		t.Errorf("via = %v, want empty: the two are on separate networks", d.Via)
	}
	if !d.Observed {
		t.Error("the compose `depends_on` was not recorded as observed")
	}

	found := false
	for _, note := range a.Index.Service("disjoint/front").Notes {
		if strings.Contains(note, "share no network") &&
			strings.Contains(note, "something this scan cannot see") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note states the finding; notes: %v", a.Index.Service("disjoint/front").Notes)
	}

	// The direct edge is drawn, and carries no network label — there is none to name.
	e := a.edge(t, edgeID(payload.EdgeDependsOn, PrefixService+"disjoint/front", PrefixService+"disjoint/back"))
	if e.Label != "" || len(e.Via) != 0 {
		t.Errorf("edge label = %q via = %v, want both empty", e.Label, e.Via)
	}
}

// TestUnreachableDeclaredDependencyIsStillDrawn is the same rule reached from a declaration rather
// than from compose: `disjoint/back` names a service in another stack it shares no network with, and
// the operator said in the file why. That is a resolved dependency, so it is drawn.
func TestUnreachableDeclaredDependencyIsStillDrawn(t *testing.T) {
	a := analyze(t, "nets")

	d := a.dep(t, "disjoint/back", "shared-c/backup-agent")
	if len(d.Via) != 0 {
		t.Errorf("via = %v, want empty", d.Via)
	}
	if !d.DeclaredOnly() {
		t.Errorf("declared=%v observed=%v, want declared-only", d.Declared, d.Observed)
	}
	if !strings.Contains(d.Detail, "host's cron") {
		t.Errorf("detail = %q, want the operator's own sentence", d.Detail)
	}

	e := a.edge(t, edgeID(payload.EdgeDependsOn, PrefixService+"disjoint/back", PrefixService+"shared-c/backup-agent"))
	if e.DeclaredBy == nil {
		t.Fatal("declaredBy is absent on an edge no compose file states")
	}
	if e.DeclaredBy.File == "" || !strings.Contains(e.DeclaredBy.Detail, "host's cron") {
		t.Errorf("declaredBy = %+v, want the file and the detail", *e.DeclaredBy)
	}
}

// TestObservedAndDeclaredMergeToOneObservedEdge is §14's merge rule. A pair compose already resolved
// is one edge and an observed one, so `declaredBy` is absent and a renderer must not dash it.
func TestObservedAndDeclaredMergeToOneObservedEdge(t *testing.T) {
	a := analyze(t, "nets")

	// `layered/api → layered/cache` is compose's; `layered/extra → layered/cache` is the sidecar's.
	// The two are different pairs, so the merge is tested on the pair `badref` states twice instead:
	// one reference qualified, one bare, both naming `badref/cache`.
	var n int
	for _, d := range a.Deps.Resolved {
		if d.From == "badref/caller" && d.To == "badref/cache" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the pair resolved to %d edges, want 1", n)
	}

	// And the mixed-provenance case as a unit, where compose and a sidecar both state one pair.
	stacks := twoServiceStack(t)
	ix := NewIndex(stacks)
	nets := NewNetworks(stacks)
	deps := Dependencies(ix, nets)

	if len(deps.Resolved) != 1 {
		t.Fatalf("resolved %d dependencies, want 1: %+v", len(deps.Resolved), deps.Resolved)
	}
	d := deps.Resolved[0]
	if !d.Observed || !d.Declared {
		t.Errorf("observed=%v declared=%v, want both", d.Observed, d.Declared)
	}
	if d.DeclaredOnly() {
		t.Error("DeclaredOnly is true on a pair compose also states; a renderer would dash it")
	}
	// The declaration still contributes its detail — that is what it adds.
	if !strings.Contains(d.Detail, "why") {
		t.Errorf("detail = %q, want the declaration's sentence", d.Detail)
	}
}

// TestComposeDependsOnOutsideTheStackIsANote is compose's own limit: `depends_on` names a service in
// the same project, so a name that is not one is a mistake in the file rather than a fleet lookup.
func TestComposeDependsOnOutsideTheStackIsANote(t *testing.T) {
	stacks := twoServiceStack(t)
	stacks[0].Services[0].DependsOn = append(stacks[0].Services[0].DependsOn, "elsewhere")

	ix := NewIndex(stacks)
	deps := Dependencies(ix, NewNetworks(stacks))

	for _, d := range deps.Resolved {
		if d.To == "s/elsewhere" {
			t.Error("a compose `depends_on` resolved outside its own project")
		}
	}
	found := false
	for _, note := range ix.Service("s/web").Notes {
		if strings.Contains(note, "not a service in this stack") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note names the unresolvable `depends_on`; notes: %v", ix.Service("s/web").Notes)
	}
}
