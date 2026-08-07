package webui

import (
	"reflect"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// §22.6's tag filtering, which §23 requires asserted as **tables of literals** rather than through
// fixtures. Three tables, because the filtering is three separable things and each fails differently:
//
//  1. **The tri-state grammar** — given a row's tags for one dimension and one filter, does the row
//     survive. Pure set arithmetic, and the one property that has to hold at fleet scale is that
//     exclusion always wins.
//  2. **The condition operators** — the seven weak tests `Holds` evaluates, and the path resolution
//     they run over. Weak on purpose: §22.1 lets the UI relabel and never conclude, so an operator set
//     that could express a heuristic would be an operator set that could invent a finding.
//  3. **The derived readings** — the five dimensions §22.6 says are not a field. Those are the ones a
//     Go switch would have quietly duplicated in JavaScript, so they are the reason the rules are data
//     and the reason a table of literals is the right test for them.
//
// Fixtures cover whether the rules describe the corpus. What they cannot cover is the boundary: a row
// with no tags at all, a filter with excludes and no includes, a path that ends on a nil. Those are
// literals here.

// ---------------------------------------------------------------------------
// 1. The tri-state grammar (§22.6)
// ---------------------------------------------------------------------------

// One row's tags against one filter, as literals. `tags` is what the row carries for the dimension;
// the filter is the state a URL parsed to.
func TestTheTriStateGrammarIsIncludeAnyIncludeAllAndAlwaysAndNotForExclusion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter TagFilter
		tags   []string
		want   bool
	}{
		// Off. A filter that narrows nothing keeps everything, including a row with no tags — I4's
		// *degrade never fail* read as a filter: the least specific filter shows the most rows.
		{"an inactive filter keeps a tagged row", TagFilter{}, []string{"public"}, true},
		{"an inactive filter keeps an untagged row", TagFilter{}, nil, true},

		// Include, Any. The default mode, and the one a reader gets by clicking two chips.
		{"any: one of two matches", TagFilter{Include: []string{"public", "lan"}}, []string{"lan"}, true},
		{"any: both match", TagFilter{Include: []string{"public", "lan"}}, []string{"public", "lan"}, true},
		{"any: neither matches", TagFilter{Include: []string{"public", "lan"}}, []string{"internal"}, false},
		{"any: an untagged row matches no include", TagFilter{Include: []string{"public"}}, nil, false},

		// Include, All. Conjunction over the includes: *both of these*, not *either*.
		{"all: both present", TagFilter{Mode: ModeAll, Include: []string{"public", "lan"}}, []string{"public", "lan", "internal"}, true},
		{"all: only one present", TagFilter{Mode: ModeAll, Include: []string{"public", "lan"}}, []string{"public"}, false},
		{"all: one include behaves like any", TagFilter{Mode: ModeAll, Include: []string{"public"}}, []string{"public"}, true},

		// Exclude. *Everything except this* — so a row with none of the excluded members survives
		// whatever else it carries, including nothing at all.
		{"exclude: the excluded member is out", TagFilter{Exclude: []string{"none"}}, []string{"none"}, false},
		{"exclude: another member is in", TagFilter{Exclude: []string{"none"}}, []string{"public"}, true},
		{"exclude: an untagged row survives an exclusion", TagFilter{Exclude: []string{"none"}}, nil, true},
		{"exclude: any one of several is enough to reject", TagFilter{Exclude: []string{"none", "internal"}}, []string{"lan", "internal"}, false},

		// Both sides. This is the load-bearing pair: the include matches, and the row is still out.
		{
			"exclusion beats a matching include",
			TagFilter{Include: []string{"public"}, Exclude: []string{"lan"}},
			[]string{"public", "lan"},
			false,
		},
		{
			"exclusion beats a matching include under All too",
			TagFilter{Mode: ModeAll, Include: []string{"public", "traefik"}, Exclude: []string{"lan"}},
			[]string{"public", "traefik", "lan"},
			false,
		},
		{
			"the include still has to match when nothing is excluded",
			TagFilter{Include: []string{"public"}, Exclude: []string{"lan"}},
			[]string{"internal"},
			false,
		},
		{
			"include and exclude both satisfied",
			TagFilter{Include: []string{"public"}, Exclude: []string{"lan"}},
			[]string{"public", "internal"},
			true,
		},

		// A member is compared exactly. `Public` is not a member of a closed set containing `public`,
		// and matching it case-insensitively here would make every closed vocabulary open by accident.
		{"a member in the wrong case does not match", TagFilter{Include: []string{"public"}}, []string{"Public"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.Matches(tc.tags); got != tc.want {
				t.Errorf("TagFilter%+v.Matches(%v) = %v, want %v", tc.filter, tc.tags, got, tc.want)
			}
		})
	}
}

// The property behind the table above, stated as a property: **no combination of includes can re-admit
// an excluded row.** It is what makes *everything except this* usable at fleet scale — a reader who
// excludes `none` must be able to trust that nothing they add to the include side brings it back.
func TestNoCombinationOfIncludesCanReAdmitAnExcludedRow(t *testing.T) {
	members := []string{"public", "traefik", "lan", "internal", "none"}
	tags := []string{"public", "traefik", "lan", "internal", "none"}

	// Every subset of the vocabulary as the include side, in both modes, with `lan` excluded.
	for mask := 0; mask < 1<<len(members); mask++ {
		var include []string
		for i, m := range members {
			if mask&(1<<i) != 0 {
				include = append(include, m)
			}
		}
		for _, mode := range []Mode{ModeAny, ModeAll} {
			f := TagFilter{Mode: mode, Include: include, Exclude: []string{"lan"}}
			if f.Matches(tags) {
				t.Fatalf("include %v in mode %q re-admitted a row carrying the excluded member", include, mode)
			}
		}
	}
}

// A dimension the row says nothing about is excluded by any include filter, and that reading is
// deliberate rather than incidental: filtering `probe=gated` must not show a service the probe never
// visited, because *not asked* is not *asked and gated* (§22.8). The absence is expressed as an
// explicit member — `not-probed`, `not-read` — precisely so a reader can filter *for* it.
func TestARowSayingNothingAboutADimensionIsNotAMatchForAnyIncludeFilter(t *testing.T) {
	r := &Row{Kind: "service", ID: "media/jellyfin"}
	r.Tag(DimIngress, "public")

	s := State{View: SlugServices}.Including(DimProbe, OutcomeGated)
	if s.Tag(DimProbe).Matches(r.Tags[DimProbe]) {
		t.Error("a row with no probe tag matched probe=gated")
	}

	// And the absence has a member of its own, so the filter for it exists.
	r.Tag(DimProbe, OutcomeNotProbed)
	if !(State{}).Including(DimProbe, OutcomeNotProbed).Tag(DimProbe).Matches(r.Tags[DimProbe]) {
		t.Error("probe=not-probed did not match a row tagged not-probed")
	}
}

// ---------------------------------------------------------------------------
// 2. The condition operators
// ---------------------------------------------------------------------------

// condSubject is the object the operator table below runs against: one struct carrying every shape a
// path can end on — a string, an empty string, a bool, a number, a nil pointer, a set pointer, a nil
// slice, a populated slice, and a slice of structs a path has to cross.
type condSubject struct {
	Word   string  `json:"word"`
	Blank  string  `json:"blank"`
	Yes    bool    `json:"yes"`
	No     bool    `json:"no"`
	Count  int     `json:"count"`
	Zero   int     `json:"zero"`
	Absent *inner  `json:"absent,omitempty"`
	Set    *inner  `json:"set,omitempty"`
	None   []inner `json:"none"`
	Many   []inner `json:"many"`
}

type inner struct {
	Via   string `json:"via"`
	Depth int    `json:"depth"`
}

var subject = condSubject{
	Word:  "provider",
	Yes:   true,
	Count: 3,
	Set:   &inner{Via: "list", Depth: 1},
	Many:  []inner{{Via: "list", Depth: 1}, {Via: "provider", Depth: 2}},
}

// The seven operators, as literals. `TestPresent` against `TestNonEmpty` is the pair worth reading
// twice: a record that exists carrying an absent status is the `no answer` reading, and telling that
// apart from a record that does not exist at all needs both operators (§13.3).
func TestTheSevenOperatorsAskSevenDifferentQuestions(t *testing.T) {
	for _, tc := range []struct {
		name string
		cond Cond
		want bool
	}{
		// present / absent: does the path reach a value at all.
		{"present on a set field", Cond{Path: "word", Test: TestPresent}, true},
		{"present on an empty string — the field is still there", Cond{Path: "blank", Test: TestPresent}, true},
		{"present on a false bool — the field is still there", Cond{Path: "no", Test: TestPresent}, true},
		{"present on a nil pointer", Cond{Path: "absent", Test: TestPresent}, false},
		{"present through a nil pointer", Cond{Path: "absent.via", Test: TestPresent}, false},
		{"present on a nil slice", Cond{Path: "none", Test: TestPresent}, false},
		{"present on a populated slice", Cond{Path: "many", Test: TestPresent}, true},
		{"present on a field that does not exist", Cond{Path: "invented", Test: TestPresent}, false},
		{"absent is the negation", Cond{Path: "absent", Test: TestAbsent}, true},
		{"absent on a set field", Cond{Path: "word", Test: TestAbsent}, false},

		// nonEmpty / empty: is any value at the path non-zero. A different question from present, and
		// the difference is the whole of §13.3's four-way probe partition.
		{"nonEmpty on a word", Cond{Path: "word", Test: TestNonEmpty}, true},
		{"nonEmpty on an empty string is false where present is true", Cond{Path: "blank", Test: TestNonEmpty}, false},
		{"nonEmpty on a zero number", Cond{Path: "zero", Test: TestNonEmpty}, false},
		{"nonEmpty on a non-zero number", Cond{Path: "count", Test: TestNonEmpty}, true},
		{"nonEmpty on a false bool", Cond{Path: "no", Test: TestNonEmpty}, false},
		{"nonEmpty on a populated slice", Cond{Path: "many", Test: TestNonEmpty}, true},
		{"empty on an empty string", Cond{Path: "blank", Test: TestEmpty}, true},
		{"empty on an absent path — no value is a non-zero value", Cond{Path: "absent.via", Test: TestEmpty}, true},
		{"empty on a word", Cond{Path: "word", Test: TestEmpty}, false},

		// true: the boolean, and only the boolean. A path holding the string "true" is not true.
		{"true on a true bool", Cond{Path: "yes", Test: TestTrue}, true},
		{"true on a false bool", Cond{Path: "no", Test: TestTrue}, false},
		{"true on a non-empty string is not true", Cond{Path: "word", Test: TestTrue}, false},
		{"true on an absent path", Cond{Path: "absent", Test: TestTrue}, false},

		// equals: compared as the string the JSON carries, exactly.
		{"equals a matching word", Cond{Path: "word", Test: TestEquals, Value: "provider"}, true},
		{"equals a different word", Cond{Path: "word", Test: TestEquals, Value: "list"}, false},
		{"equals is case-sensitive", Cond{Path: "word", Test: TestEquals, Value: "Provider"}, false},
		{"equals a number as its rendered spelling", Cond{Path: "count", Test: TestEquals, Value: "3"}, true},
		{"equals on an absent path", Cond{Path: "absent.via", Test: TestEquals, Value: "list"}, false},

		// atLeast: a numeric floor, which is what §8's network predicates are.
		{"atLeast the exact count", Cond{Path: "count", Test: TestAtLeast, N: 3}, true},
		{"atLeast below the count", Cond{Path: "count", Test: TestAtLeast, N: 2}, true},
		{"atLeast above the count", Cond{Path: "count", Test: TestAtLeast, N: 4}, false},
		{"atLeast against a zero", Cond{Path: "zero", Test: TestAtLeast, N: 1}, false},
		{"atLeast on a string is not a number", Cond{Path: "word", Test: TestAtLeast, N: 1}, false},

		// Crossing a slice. The path yields a *set*, so a test over it is existential without needing a
		// quantifier of its own — `many.via equals provider` reads as *some member was via provider*.
		{"a test over a crossed slice holds if any element holds", Cond{Path: "many.via", Test: TestEquals, Value: "provider"}, true},
		{"and fails if none does", Cond{Path: "many.via", Test: TestEquals, Value: "rebuilt"}, false},
		{"atLeast over a crossed slice", Cond{Path: "many.depth", Test: TestAtLeast, N: 2}, true},
		{"a path through a set pointer", Cond{Path: "set.via", Test: TestEquals, Value: "list"}, true},

		// The connectives.
		{"all with both true", Cond{All: []Cond{{Path: "yes", Test: TestTrue}, {Path: "word", Test: TestNonEmpty}}}, true},
		{"all with one false", Cond{All: []Cond{{Path: "yes", Test: TestTrue}, {Path: "blank", Test: TestNonEmpty}}}, false},
		{"any with one true", Cond{Any: []Cond{{Path: "blank", Test: TestNonEmpty}, {Path: "yes", Test: TestTrue}}}, true},
		{"any with none true", Cond{Any: []Cond{{Path: "blank", Test: TestNonEmpty}, {Path: "no", Test: TestTrue}}}, false},
		{"not inverts", Cond{Not: &Cond{Path: "no", Test: TestTrue}}, true},
		{"not nested in all", Cond{All: []Cond{{Path: "yes", Test: TestTrue}, {Not: &Cond{Path: "no", Test: TestTrue}}}}, true},

		// §16's forward-compatibility rule, as an operator: a condition from a later protocol grants
		// nothing rather than reading as true. The wrong default here would hand a row a member it has
		// no claim to — which for `probe=gated` would be the UI concluding a service is protected.
		{"an operator this build does not know grants nothing", Cond{Path: "yes", Test: "impliedBy"}, false},
		{"an empty operator grants nothing", Cond{Path: "yes"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Holds(tc.cond, subject); got != tc.want {
				t.Errorf("Holds(%+v) = %v, want %v", tc.cond, got, tc.want)
			}
		})
	}
}

// embedder has an anonymous embedded struct, which is the shape `ServiceDeclaration` actually is: it
// embeds `Declaration`, so `declared.source` is a path through a field that has no name in the JSON.
// A lookup that only walked named fields would silently miss every promoted one.
type embedder struct {
	inner
	Own string `json:"own"`
}

func TestAPathFollowsAnAnonymousEmbeddedStructTheWayTheJSONReadsIt(t *testing.T) {
	obj := embedder{inner: inner{Via: "list", Depth: 4}, Own: "mine"}

	if !Holds(Cond{Path: "via", Test: TestEquals, Value: "list"}, obj) {
		t.Error("a promoted field was not reachable by its JSON name")
	}
	if !Holds(Cond{Path: "depth", Test: TestAtLeast, N: 4}, obj) {
		t.Error("a promoted numeric field was not reachable")
	}
	if !Holds(Cond{Path: "own", Test: TestNonEmpty}, obj) {
		t.Error("the struct's own field stopped being reachable")
	}
	// And the embedded type's Go name is not a path segment: the path is the JSON's, not Go's.
	if Holds(Cond{Path: "inner.via", Test: TestPresent}, obj) {
		t.Error("the embedded type's Go name resolved as a path segment")
	}
}

// A map key is a path segment, because that is how the JSON reads and how a browser resolves it — a
// property lookup, with no distinction between a field and a key. An absent key yields nothing rather
// than a zero, which is what keeps *not reported* different from *none* (§15).
func TestAMapKeyIsAPathSegmentAndAnAbsentKeyYieldsNothing(t *testing.T) {
	obj := struct {
		By map[payload.AuthMethod]int `json:"by"`
	}{By: map[payload.AuthMethod]int{payload.AuthNone: 4}}

	if !Holds(Cond{Path: "by.none", Test: TestAtLeast, N: 4}, obj) {
		t.Error("a map keyed by a union type was not indexed by the member as the JSON spells it")
	}
	if Holds(Cond{Path: "by.basic-auth", Test: TestPresent}, obj) {
		t.Error("a key the map does not have resolved to a zero instead of to nothing")
	}
}

// §22.8's banner rule, as literals. It is named in the source because three places need the one
// answer — the banner, the Diagnostics ordering and the failing-connections card — and a card
// counting one set while a banner showed another is exactly the defect §22.3 exists to prevent.
//
// The subtlety is that `ok` alone does not answer it. `partial` is a failure whose `ok` is **true**,
// and `disabled` and `not-configured` are settings whose `ok` is false and which are not failures at
// all.
func TestTheBannerRuleIsPartialPlusAnyFailureThatIsNotASetting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report payload.ConnectionReport
		want   bool
	}{
		{"partial gets a banner even though ok is true",
			payload.ConnectionReport{OK: true, Phase: payload.PhasePartial}, true},
		{"a clean read does not",
			payload.ConnectionReport{OK: true, Phase: payload.PhaseConnected}, false},
		{"switched off is a setting, not a failure",
			payload.ConnectionReport{Phase: payload.PhaseDisabled}, false},
		{"nothing to talk to is a setting, not a failure",
			payload.ConnectionReport{Phase: payload.PhaseNotConfigured}, false},
		{"a credential failure gets a banner",
			payload.ConnectionReport{Phase: payload.PhaseCredential}, true},
		{"a not-found gets a banner",
			payload.ConnectionReport{Phase: payload.PhaseNotFound}, true},
		{"a failure with no phase at all still gets one",
			payload.ConnectionReport{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Failing(tc.report); got != tc.want {
				t.Errorf("Failing(%+v) = %v, want %v", tc.report, got, tc.want)
			}
			// Failing is Holds over the named condition. Asserted so the two cannot come apart: the
			// browser reads that tree out of the contract and must reach the same verdict.
			if got := Holds(CondReportFailing, tc.report); got != tc.want {
				t.Errorf("the named condition disagrees with Failing on %+v", tc.report)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. The derived readings (§22.6)
// ---------------------------------------------------------------------------

// The four-way probe partition, as literals over a service. §13.3 counts the same partition, so these
// four readings are also what makes the probe cards' numbers add up to the service count.
//
// It is a partition: every service gets exactly one of the four, and the pair that could collapse is
// `open` against `no answer` — both have an empty gate, and only the presence of a *status* tells them
// apart.
func TestTheProbeOutcomeIsAFourWayPartitionOfTwoFields(t *testing.T) {
	status := func(n int) *int { return &n }

	for _, tc := range []struct {
		name string
		svc  payload.Service
		want string
	}{
		{
			name: "a gate signal fired",
			svc:  payload.Service{Probe: &payload.ServiceProbe{Status: status(200), Gate: payload.GatePasswordForm}},
			want: OutcomeGated,
		},
		{
			name: "answered with no gate signal",
			svc:  payload.Service{Probe: &payload.ServiceProbe{Status: status(200)}},
			want: OutcomeOpen,
		},
		{
			// The record exists — the probe was attempted and is reporting why it got nothing — and the
			// status is absent. Neither gated nor open, and the reading needs both operators to say so.
			name: "a record with no status did not answer",
			svc:  payload.Service{Probe: &payload.ServiceProbe{Phase: payload.PhaseResolve, Detail: "no such host"}},
			want: OutcomeNoAnswer,
		},
		{
			name: "no record at all was not probed",
			svc:  payload.Service{},
			want: OutcomeNotProbed,
		},
		{
			// A gate read on a redirect: the status is a 302 and the gate is set, so it is gated. Worth a
			// row because *gated* must not depend on a 200.
			name: "a gate read off a redirect is still gated",
			svc:  payload.Service{Probe: &payload.ServiceProbe{Status: status(302), Gate: payload.GateRedirectLogin}},
			want: OutcomeGated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := membersFor(tc.svc, DimProbe)
			if !reflect.DeepEqual(got, []string{tc.want}) {
				t.Errorf("probe members = %v, want exactly [%s] — the four readings are a partition", got, tc.want)
			}
		})
	}
}

// Container state, which is the reading §22.8 names in its own row: runtime columns read *not read*
// and **never** *stopped*, because reporting a container LabView could not ask about as one that is
// down is a claim about the fleet that the evidence does not support (I1).
func TestContainerStateSaysNotReadWhereTheEngineWasNeverAskedAndNeverStopped(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  payload.Service
		want []string
	}{
		{
			// The whole record absent: Docker off, or unreachable. This is the corpus's own condition
			// (§23 runs with Docker off), so it is the reading nearly every fixture row carries.
			name: "no Engine reading at all",
			svc:  payload.Service{},
			want: []string{StateNotRead},
		},
		{
			name: "a reading that said nothing",
			svc:  payload.Service{Docker: &payload.DockerState{}},
			want: []string{StateNotRead},
		},
		{
			name: "a running container",
			svc:  payload.Service{Docker: &payload.DockerState{State: "running", Running: true}},
			want: []string{"running"},
		},
		{
			// The Engine's word and the boolean are separate readings, and a paused container is why:
			// its state is `paused` and its running flag is true, and the counter counts it as running.
			// So it carries both, and filtering either way finds it.
			name: "a paused container is paused and running",
			svc:  payload.Service{Docker: &payload.DockerState{State: "paused", Running: true}},
			want: []string{"paused", StateRunning},
		},
		{
			// A container the Engine *did* report as down. `exited` is the Engine's own word, and it is
			// carried verbatim rather than mapped to a member of this protocol (§22.6's open dimension).
			name: "a container the Engine reported as exited",
			svc:  payload.Service{Docker: &payload.DockerState{State: "exited", Running: false}},
			want: []string{"exited"},
		},
		{
			// An Engine status word this build has never heard of survives, because the dimension is
			// open. A closed vocabulary here would drop a real reading on the floor.
			name: "a status word this build never enumerated survives",
			svc:  payload.Service{Docker: &payload.DockerState{State: "restarting", Running: false}},
			want: []string{"restarting"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := membersFor(tc.svc, DimState)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("state members = %v, want %v", got, tc.want)
			}
			for _, m := range got {
				if m == "stopped" {
					t.Error("a service was tagged `stopped`, and §22.8 forbids that word entirely")
				}
			}
		})
	}
}

// The five declaration readings, which are **independent** — a service can carry several at once — and
// where drift and not-confirmed are never merged (§22.2). They are separate because they are different
// statements: *the scan contradicts this* and *the scan could not corroborate this* call for different
// actions, and merging them would make the second look like the first.
func TestTheFiveDeclarationReadingsAreIndependentAndDriftIsNeverMergedWithNotConfirmed(t *testing.T) {
	accepted := &payload.AcceptedExposure{}

	for _, tc := range []struct {
		name string
		svc  payload.Service
		want []string
	}{
		{
			name: "no declaration at all",
			svc:  payload.Service{},
			want: nil,
		},
		{
			name: "a declaration that names a gate",
			svc: payload.Service{Declared: &payload.ServiceDeclaration{
				Auth: []payload.DeclaredAuth{{Mechanism: payload.MechanismExternalProxy}},
			}},
			want: []string{DeclAuth},
		},
		{
			// Rule 2's verdict, read off the agreement rather than recomputed — the agreement is the
			// only place §14 records it.
			name: "a declaration that supplies the only gate",
			svc: payload.Service{Declared: &payload.ServiceDeclaration{
				Auth:          []payload.DeclaredAuth{{Mechanism: payload.MechanismExternalProxy}},
				AuthAgreement: payload.AgreementSupplies,
			}},
			want: []string{DeclAuth, DeclProtected},
		},
		{
			name: "drift alone",
			svc: payload.Service{Declared: &payload.ServiceDeclaration{
				Drift: []string{"declared internal, scanned public"},
			}},
			want: []string{DeclDrift},
		},
		{
			name: "not confirmed alone",
			svc: payload.Service{Declared: &payload.ServiceDeclaration{
				Unconfirmed: []string{"declares external-proxy, no middleware found"},
			}},
			want: []string{DeclNotConfirmed},
		},
		{
			// Both at once, and both members present. This is the row that fails if anyone ever
			// collapses the two into one reading.
			name: "drift and not confirmed are two members, not one",
			svc: payload.Service{Declared: &payload.ServiceDeclaration{
				Drift:       []string{"declared internal, scanned public"},
				Unconfirmed: []string{"declares external-proxy, no middleware found"},
			}},
			want: []string{DeclNotConfirmed, DeclDrift},
		},
		{
			// An accepted exposure is **still an exposure** (§14 rule 3). The member exists so a reader
			// can filter for it; it does not remove anything.
			name: "an accepted exposure",
			svc: payload.Service{Declared: &payload.ServiceDeclaration{
				UnauthenticatedAccepted: accepted,
			}},
			want: []string{DeclAccepted},
		},
		{
			name: "an empty declaration record grants nothing",
			svc:  payload.Service{Declared: &payload.ServiceDeclaration{}},
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := membersFor(tc.svc, DimDecl); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("declaration members = %v, want %v", got, tc.want)
			}
		})
	}
}

// Integration match, which is the reading §11 and §12 require *shown as unattached, never hidden*. A
// record that protects nothing this scan found is the finding, so `unmatched` has to be a member a
// reader can filter for rather than an absence.
func TestTheMatchStateSaysUnmatchedRatherThanSayingNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  payload.Service
		want []string
	}{
		{
			name: "nothing matched",
			svc:  payload.Service{},
			want: []string{MatchUnmatched},
		},
		{
			name: "an identity application matched",
			svc: payload.Service{Authentik: &payload.AuthentikMatch{
				Applications: []payload.AuthentikApplication{{Slug: "jellyfin"}},
			}},
			want: []string{MatchMatched},
		},
		{
			name: "a live router matched",
			svc:  payload.Service{TraefikLive: []payload.TraefikLiveRouter{{Router: "jellyfin@docker", Provider: "docker"}}},
			want: []string{MatchMatched},
		},
		{
			// An empty record is not a match. A provider that answered and listed nothing for this
			// service has told us it protects nothing, which is the unmatched reading.
			name: "an empty identity record is not a match",
			svc:  payload.Service{Authentik: &payload.AuthentikMatch{}},
			want: []string{MatchUnmatched},
		},
		{
			// Rebuilt is additive: the application matched *and* it was reconstructed from a provider
			// because the list withheld it (§11). Both members, because both are true.
			name: "a rebuilt application is matched and rebuilt",
			svc: payload.Service{Authentik: &payload.AuthentikMatch{
				Applications: []payload.AuthentikApplication{{
					Slug:          "jellyfin",
					DiscoveredVia: payload.DiscoveredViaProvider,
				}},
			}},
			want: []string{MatchMatched, MatchRebuilt},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := membersFor(tc.svc, DimMatch); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("match members = %v, want %v", got, tc.want)
			}
		})
	}
}

// §8's three network predicates, as literals over the facts a network row carries. Counts against a
// floor rather than booleans copied from elsewhere, which is what makes them the same statements the
// counters test.
//
// The row that carries the reasoning: an **external** network with one member is not solo-local.
// Something outside the scan may be on it, so *it connects nothing* is a claim the evidence does not
// support (I1) — where the same network declared stack-local really does connect nothing.
func TestTheNetworkPredicatesAreCountsAgainstAFloorAndExternalIsNeverSoloLocal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts NetFacts
		want  []string
	}{
		{
			name:  "one member, stack-local: it connects nothing",
			facts: NetFacts{Name: "solo", Scope: string(payload.ScopeStackLocal), MemberCount: 1, StackCount: 1},
			want:  []string{string(payload.ScopeStackLocal), NetSoloLocal},
		},
		{
			name:  "one member, external: something unseen may be on it",
			facts: NetFacts{Name: "shared", Scope: string(payload.ScopeExternal), MemberCount: 1, StackCount: 1, External: true},
			want:  []string{string(payload.ScopeExternal)},
		},
		{
			name:  "two members in one stack connects",
			facts: NetFacts{Name: "inner", Scope: string(payload.ScopeStackLocal), MemberCount: 2, StackCount: 1},
			want:  []string{string(payload.ScopeStackLocal), NetConnecting},
		},
		{
			name:  "two members across two stacks connects and crosses",
			facts: NetFacts{Name: "proxy", Scope: string(payload.ScopeExternal), MemberCount: 2, StackCount: 2, External: true},
			want:  []string{string(payload.ScopeExternal), NetConnecting, NetCrossStack},
		},
		{
			name:  "no members at all is none of the three",
			facts: NetFacts{Name: "empty", Scope: string(payload.ScopeStackLocal)},
			want:  []string{string(payload.ScopeStackLocal)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Row{Kind: "network", ID: tc.facts.Name}
			r.Apply(RulesNetwork, tc.facts)
			if got := r.Tags[DimState]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("network members = %v, want %v", got, tc.want)
			}
		})
	}
}

// The one rule about the rules: **no rule may ever read an environment variable's value** (I6, §22.6).
// A filter over values would put a secret in a URL, and a URL is the one artifact §22.7 exists to make
// shareable.
func TestNoRuleReadsAnEnvironmentVariableValue(t *testing.T) {
	for _, rule := range RulesEnv.Rules {
		if rule.ValuePath == "value" || pathTouchesValue(rule.When) {
			t.Errorf("a rule on the env shape reads `value`: %+v — I6 forbids it reaching a filter", rule)
		}
	}

	// And the reading that is allowed in its place: *masked*, which says a value was withheld without
	// saying what it was.
	r := &Row{Kind: "config", ID: "media/jellyfin:JELLYFIN_API_KEY"}
	r.Apply(RulesEnv, struct {
		Source string `json:"source"`
		Masked bool   `json:"masked"`
		Value  string `json:"value"`
	}{Source: "compose", Masked: true, Value: "s3cr3t"})

	if want := []string{ConfigEnv, "compose", ConfigMasked}; !reflect.DeepEqual(r.Tags[DimState], want) {
		t.Errorf("config members = %v, want %v", r.Tags[DimState], want)
	}
}

// Every rule in every table grants a member of its dimension's vocabulary, or names a path whose
// values are the members. A rule granting a member no vocabulary lists would produce a chip with no
// label and a filter a reader cannot construct from the UI (§22.6).
func TestEveryFixedMemberARuleGrantsIsInItsDimensionsVocabulary(t *testing.T) {
	for _, set := range RuleSets {
		for _, rule := range set.Rules {
			if rule.Member == "" {
				continue
			}
			dim, ok := DimensionOf(rule.Dim)
			if !ok {
				t.Errorf("%s: a rule names dimension %q, which is not one of §22.6's eight", set.Shape, rule.Dim)
				continue
			}
			// The open dimension has no vocabulary to check against, and that is its definition: the
			// members are the Engine's, the mount type's, the phase's — collected from the rows.
			if dim.Set == "" {
				continue
			}
			if !containsString(Members(dim.Set), rule.Member) {
				t.Errorf("%s: a rule grants %q to %s, which its vocabulary %q does not list",
					set.Shape, rule.Member, rule.Dim, dim.Set)
			}
		}
	}
}

// Every rule table has a shape and every rule does something, because a rule that grants no member and
// names no path is a row in the contract the browser would evaluate to nothing.
func TestEveryRuleGrantsSomething(t *testing.T) {
	shapes := map[string]bool{}
	for _, set := range RuleSets {
		if set.Shape == "" {
			t.Error("a rule set has no shape, so a failure cannot say which object it was about")
		}
		if shapes[set.Shape] {
			t.Errorf("two rule sets share the shape %q", set.Shape)
		}
		shapes[set.Shape] = true

		for _, rule := range set.Rules {
			if rule.Member == "" && rule.ValuePath == "" {
				t.Errorf("%s: a rule grants no member and names no path: %+v", set.Shape, rule)
			}
			if rule.Default != "" && rule.ValuePath == "" {
				t.Errorf("%s: a rule has a default with no path to fall back from: %+v", set.Shape, rule)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// membersFor applies the service rules and returns one dimension's members, in the order the rules
// granted them. The order is asserted rather than sorted away: it is the order the chips appear in.
func membersFor(svc payload.Service, d Dim) []string {
	r := &Row{Kind: "service", ID: svc.Name}
	r.Apply(RulesService, svc)
	return r.Tags[d]
}

// pathTouchesValue reports whether a condition tree reads `value` anywhere.
func pathTouchesValue(c *Cond) bool {
	if c == nil {
		return false
	}
	if c.Path == "value" {
		return true
	}
	for _, sub := range append(append([]Cond{}, c.All...), c.Any...) {
		if pathTouchesValue(&sub) {
			return true
		}
	}
	return pathTouchesValue(c.Not)
}
