package webui

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// §23's first UI check, and the one the guide says MUST gate CI: **payload-complete.** A field added to
// Appendix A without a place to appear fails here, and the failure names the path so the fix is either a
// column, a drawer section, a card, or a stated reason it needs none.
//
// The test has three parts, because the check has three things that can be wrong: the walk that derives
// the payload's leaves, the tables that declare where fields appear, and the comparison itself.

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

func TestEveryPayloadFieldHasAPlaceToAppear(t *testing.T) {
	uncovered := Uncovered()
	if len(uncovered) == 0 {
		return
	}
	subject := "1 payload field has"
	if n := len(uncovered); n > 1 {
		subject = fmt.Sprintf("%d payload fields have", n)
	}
	t.Errorf("%s nowhere to appear (§22.1). Give each one a view column, a view Field, a drawer section "+
		"or an overview card — the Raw section does not count:\n  %s",
		subject, strings.Join(uncovered, "\n  "))
}

// The other direction: a declared field that is not a payload leaf. Not redundant with the first — a
// misspelling leaves the real field uncovered, and reporting it as *a field nobody shows* sends a reader
// looking for a column that is already written.
func TestEveryDeclaredFieldIsAPayloadLeaf(t *testing.T) {
	unknown := Unknown()
	if len(unknown) == 0 {
		return
	}
	for _, path := range sortedPaths(unknown) {
		t.Errorf("%q is declared by %v but is not a leaf of Appendix A: either it is misspelled, or it "+
			"names a subtree, which would wave through every field beneath it", path, unknown[path])
	}
}

// A path may have several places and that is the good case — the auth method belongs in the Services
// table *and* in the drawer's verdict. What must not happen is a place naming a view, drawer or card
// that does not exist, since such a place satisfies coverage while rendering nothing.
func TestEveryPlaceNamesSomethingThatExists(t *testing.T) {
	views := map[string]bool{"chrome": true}
	for _, v := range Views {
		views[v.Slug] = true
	}
	sections := map[string]bool{}
	for _, d := range Drawers {
		for _, s := range d.Sections {
			sections[d.Kind+":"+s.ID] = true
		}
	}
	cards := map[string]bool{}
	for _, c := range CardTable {
		cards[c.ID] = true
	}

	for path, places := range RenderedPaths() {
		for _, p := range places {
			switch {
			case p.Section != "":
				if !sections[p.Section] {
					t.Errorf("%s declares %q, but no drawer has that section", p, path)
				}
			case p.Card != "":
				if !cards[p.Card] {
					t.Errorf("%s declares %q, but no card has that id", p, path)
				}
			default:
				if !views[p.View] {
					t.Errorf("%s declares %q, but no view has that slug", p, path)
				}
			}
		}
	}
}

// §22.4: the Raw section "MUST NOT be how a field satisfies the coverage rule". The sections in the tree
// declare no fields, so the exclusion currently costs nothing — which is exactly why it is asserted by
// making one declare a field. A subtree dump makes every field technically visible and none of them
// findable, and this is the line that keeps the check from accepting one.
func TestTheRawSectionCannotSatisfyTheCoverageRule(t *testing.T) {
	const field = "stacks.services.auth.method"
	if len(RenderedPaths()[field]) == 0 {
		t.Fatalf("%s is uncovered before this test starts, so it proves nothing", field)
	}

	saved := Drawers
	t.Cleanup(func() { Drawers = saved })
	Drawers = []Drawer{{
		Kind:  "escape",
		Title: "Escape hatch",
		Opens: "nothing — this drawer exists for the length of one test",
		Sections: []Section{
			{ID: "raw", Title: "Raw", Raw: true, Fields: []string{field, "stacks.services.name"}},
			{ID: "real", Title: "Real", Fields: []string{"stacks.services.name"}},
		},
	}}

	places := RenderedPaths()[field]
	for _, p := range places {
		if p.Section == "escape:raw" {
			t.Errorf("the Raw section was counted as a place for %s", field)
		}
	}
	if got := RenderedPaths()["stacks.services.name"]; !hasSection(got, "escape:real") {
		t.Errorf("a non-Raw section was not counted, so this test disabled the wrong thing: %v", got)
	}
}

// Determinism (I7). Both halves are derived from tables and from reflection, and reflection over struct
// fields is ordered — but the sets are built in maps, so the sort is what makes two runs comparable.
func TestBothHalvesAreSortedAndStable(t *testing.T) {
	first, second := PayloadPaths(), PayloadPaths()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("PayloadPaths differs between calls")
	}
	if !sort.StringsAreSorted(first) {
		t.Error("PayloadPaths is not sorted")
	}
	for i := 1; i < len(first); i++ {
		if first[i] == first[i-1] {
			t.Errorf("PayloadPaths repeats %q", first[i])
		}
	}
	if len(first) == 0 {
		t.Fatal("PayloadPaths is empty, so every other assertion here is vacuous")
	}
}

// ---------------------------------------------------------------------------
// The walk: what counts as a leaf
// ---------------------------------------------------------------------------

// Spot checks against the real payload, spelled the way a reader with the JSON in hand would spell them.
// These are the shapes the rules below are about, asserted once on the type they were written for.
func TestThePayloadsLeavesAreSpelledAsTheJSONIs(t *testing.T) {
	leaves := map[string]bool{}
	for _, p := range PayloadPaths() {
		leaves[p] = true
	}

	for _, path := range []string{
		"meta.scannedAt",
		"meta.build.source",
		"meta.connections.target",
		"meta.probe.enabled",
		"stats.stacks",
		"stats.byAuthMethod",
		"stacks.services.auth.method",
		"stacks.services.auth.exposedWithoutAuth",
		"stacks.services.probe.state.refusedAt",
		"stacks.services.declared.data",
		"graph.edges.declaredBy.file",
	} {
		if !leaves[path] {
			t.Errorf("%q is not a leaf, and it is the spelling this check's messages use", path)
		}
	}

	// A subtree is not a leaf. If one were, declaring it would cover everything beneath it — the Raw
	// escape hatch by another name, which is why Unknown reports a subtree declaration as an error.
	for _, subtree := range []string{"meta", "stats", "stacks", "stacks.services", "stacks.services.auth", "graph"} {
		if leaves[subtree] {
			t.Errorf("%q is reported as a leaf, so declaring it would cover its whole subtree", subtree)
		}
	}
}

// A slice of services is the same field as a service, and an optional record is the same field as a
// required one: `stacks.services.auth.method` is one path however many stacks the fleet has.
func TestListsAndPointersAreTransparent(t *testing.T) {
	type inner struct {
		A string `json:"a"`
	}
	type outer struct {
		One   inner    `json:"one"`
		Many  []inner  `json:"many"`
		Maybe *inner   `json:"maybe"`
		Deep  [][]*int `json:"deep"`
	}

	want := []string{"deep", "many.a", "maybe.a", "one.a"}
	if got := walkPaths(reflect.TypeOf(outer{})); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

// A map's keys are members of a closed set, not fields. `stats.byAuthMethod` is one place in the UI
// showing every member, so the map is the leaf — but a map whose values are records is a collection of
// records, and its fields each need a place.
func TestAMapOfCountersIsALeafAndAMapOfRecordsIsNot(t *testing.T) {
	type record struct {
		B string `json:"b"`
	}
	type outer struct {
		Counters map[string]int     `json:"counters"`
		Labels   map[string]string  `json:"labels"`
		Records  map[string]record  `json:"records"`
		Pointers map[string]*record `json:"pointers"`
	}

	want := []string{"counters", "labels", "pointers.b", "records.b"}
	if got := walkPaths(reflect.TypeOf(outer{})); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}

	// And on the payload itself: the distribution is one leaf, with nothing beneath it.
	for _, p := range PayloadPaths() {
		if strings.HasPrefix(p, "stats.byAuthMethod"+PathSeparator) {
			t.Errorf("%q is beneath the distribution, which is one place in the UI", p)
		}
	}
}

// Two values that are structs to Go and single values to a reader: a timestamp is not a wall clock plus
// a monotonic reading, and operator-supplied data (§14) has a shape this program does not define.
func TestATimestampAndAnOperatorsOwnDataAreEachOneLeaf(t *testing.T) {
	type outer struct {
		At   time.Time       `json:"at"`
		Data json.RawMessage `json:"data"`
		Ptr  *time.Time      `json:"ptr"`
	}

	want := []string{"at", "data", "ptr"}
	if got := walkPaths(reflect.TypeOf(outer{})); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}

	// `declared.data` is the payload's own instance of the second rule: a declaration file's contents,
	// carried verbatim, with one place in the drawer to show them.
	for _, p := range PayloadPaths() {
		if strings.HasPrefix(p, "stacks.services.declared.data"+PathSeparator) {
			t.Errorf("%q is beneath operator-supplied data, whose shape LabView does not define", p)
		}
	}
}

// An embedded struct with no JSON name flattens into its parent, so the path must not gain a segment the
// JSON does not have. ServiceDeclaration embeds Declaration, and a reader running `jq` sees one object.
func TestAnEmbeddedStructFlattensIntoItsParent(t *testing.T) {
	type embedded struct {
		Shared string `json:"shared"`
	}
	type named struct {
		Own string `json:"own"`
	}
	type outer struct {
		embedded
		Named named `json:"named"`
	}

	want := []string{"named.own", "shared"}
	if got := walkPaths(reflect.TypeOf(outer{})); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}

	// The payload's own case: nothing under `declared` carries a `declaration` segment.
	for _, p := range PayloadPaths() {
		if strings.Contains(p, ".declaration.") {
			t.Errorf("%q carries a segment the JSON does not have", p)
		}
	}
}

// A field the payload does not serialise is not a field a reader can look for.
func TestUnserialisedFieldsAreNotPaths(t *testing.T) {
	type outer struct {
		Kept     string `json:"kept"`
		Dropped  string `json:"-"`
		Renamed  string `json:"renamed,omitempty"`
		Untagged string
		hidden   string //nolint:unused // deliberately unexported, for this assertion
	}

	want := []string{"Untagged", "kept", "renamed"}
	if got := walkPaths(reflect.TypeOf(outer{})); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

// A payload that ever gained a recursive shape — a graph node holding nodes — must be walked once rather
// than forever. The guard is per path rather than global, because the same type legitimately appears in
// two places and each of them needs its own paths.
func TestARecursiveShapeIsWalkedOnceAndAReusedTypeTwice(t *testing.T) {
	type node struct {
		Name     string  `json:"name"`
		Children []*node `json:"children"`
	}
	type report struct {
		OK bool `json:"ok"`
	}
	type outer struct {
		Root  node   `json:"root"`
		Left  report `json:"left"`
		Right report `json:"right"`
	}

	want := []string{"left.ok", "right.ok", "root.children", "root.name"}
	if got := walkPaths(reflect.TypeOf(outer{})); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// walkPaths is PayloadPaths for an arbitrary type, so the rules above are asserted on the shape each one
// is about rather than on whichever payload field happens to have it today.
func walkPaths(t reflect.Type) []string {
	seen := map[string]bool{}
	walkType(t, "", map[reflect.Type]bool{}, func(path string) { seen[path] = true })
	return sortedKeys(seen)
}

func sortedPaths(m map[string][]Place) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasSection(places []Place, id string) bool {
	for _, p := range places {
		if p.Section == id {
			return true
		}
	}
	return false
}
