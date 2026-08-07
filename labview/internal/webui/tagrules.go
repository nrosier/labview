package webui

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// The derived readings of §22.6, **as data**.
//
// Most filter dimensions are a field: `ingress` is the ingress set, `health` is the health member,
// `conf` is the confidence. Five are not. *Probe outcome* is a three-way reading of two fields,
// *declaration state* is five independent readings, *match state* asks whether anything matched,
// *container state* has to say `not read` where the Engine was never asked, and the network
// predicates are counts compared against a threshold. Those five are rules.
//
// They are expressed here as a table of conditions over payload paths rather than as Go switches,
// for one reason: **the browser needs the same readings and must not hold a second copy of them.**
// §22.1 requires the UI to hold no fleet knowledge of its own, and §16 requires a pure rule to exist
// once. A Go switch would have to be restated in JavaScript to filter a row in the browser, and the
// two would then agree only until someone changed one of them. A condition tree is data: this file
// evaluates it, contract.js carries it verbatim, and the browser's evaluator applies it.
//
// The conditions are deliberately weak — presence, emptiness, equality, a numeric floor, and the
// three connectives. That is enough for every reading §22.6 lists and not enough to express a
// heuristic, which is the point: a UI that could compute anything could conclude something, and
// §22.1 says it may relabel and never conclude. Anything that cannot be said with these operators
// is an analysis rule and belongs upstream, in the payload.

// Test is one condition operator.
type Test string

const (
	// TestPresent holds when the path yields at least one value: a non-nil pointer, or a slice with
	// something in it. *Present* and *non-empty* differ — a probe record that exists with an absent
	// status is the `no answer` reading, and it needs both.
	TestPresent Test = "present"
	// TestAbsent is the negation of TestPresent, spelled as its own operator because *the Engine was
	// never asked* is a reading the UI shows in its own words (§22.8).
	TestAbsent Test = "absent"
	// TestNonEmpty holds when some value at the path is a non-zero string or a non-empty list.
	TestNonEmpty Test = "nonEmpty"
	// TestEmpty holds when no value at the path is non-zero.
	TestEmpty Test = "empty"
	// TestTrue holds when some value at the path is the boolean true.
	TestTrue Test = "true"
	// TestEquals holds when some value at the path equals Value, compared as the string the JSON
	// carries. Members are compared exactly: a case-insensitive match would make `Public` a member
	// of a closed set that does not contain it.
	TestEquals Test = "equals"
	// TestAtLeast holds when some numeric value at the path is >= N. It is what the network
	// predicates of §8 are: *two or more members*, *two or more stacks*.
	TestAtLeast Test = "atLeast"
)

// Cond is one condition. Exactly one of Test, All, Any or Not is set.
//
// A path crosses slices transparently and yields a *set* of values, so `authentik.applications
// .discoveredVia equals provider` reads as *some application was rebuilt* without a quantifier of
// its own — the same rule coverage.go's walk uses for field paths, and the reading a person with the
// JSON in hand would give it.
type Cond struct {
	Path  string `json:"path,omitempty"`
	Test  Test   `json:"test,omitempty"`
	Value string `json:"value,omitempty"`
	N     int    `json:"n,omitempty"`

	All []Cond `json:"all,omitempty"`
	Any []Cond `json:"any,omitempty"`
	Not *Cond  `json:"not,omitempty"`
}

// TagRule assigns members of one dimension to an object.
//
// Either Member is a fixed member the rule grants when When holds, or ValuePath names a path whose
// values *are* the members. The second form is what keeps a dimension open: `state` takes whatever
// the Engine's status word was, and no table here has to enumerate the Engine's vocabulary (§22.6).
type TagRule struct {
	Dim    Dim    `json:"dim"`
	Member string `json:"member,omitempty"`

	ValuePath string `json:"valuePath,omitempty"`
	// Default is the member ValuePath falls back to when the path yields nothing. `auth.method` uses
	// it: an absent method is `none`, which is exactly how the counter reads it (§22.3) — and a card
	// and its destination that disagreed about that would be the defect §22.3 forbids.
	Default string `json:"default,omitempty"`

	When *Cond  `json:"when,omitempty"`
	Note string `json:"note,omitempty"`
}

// Rules is one object shape's rule set, named so the contract and a failure message can say which
// shape a rule belongs to.
type Rules struct {
	// Shape is the object the paths are relative to: a service, a mount, a connection report.
	Shape string    `json:"shape"`
	Rules []TagRule `json:"rules"`
}

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------

// RulesService is every dimension a service answers (§22.6), in the order the tags come out.
//
// Read it beside internal/fleet/stats.go: each rule here is the same reading the counter it
// corresponds to is counted from, which is what makes `len(Rows(dest)) == count` hold for the
// cards rather than nearly hold (§22.3).
var RulesService = Rules{
	Shape: "service",
	Rules: []TagRule{
		{Dim: DimIngress, ValuePath: "ingress", Note: "the whole set: a service both public and on the LAN carries both members"},
		{Dim: DimAuth, ValuePath: "auth.method", Default: string(payload.AuthNone), Note: "an absent method is `none`, as the counters read it"},
		{Dim: DimConf, ValuePath: "auth.confidence"},
		{Dim: DimHealth, ValuePath: "docker.health"},

		// Container state. The Engine's own status word, plus `running` from the boolean the
		// counter is counted off, plus `not read` where there was no reading at all — never
		// `stopped`, which would report a container LabView could not ask about as one that is down
		// (§22.8).
		{Dim: DimState, ValuePath: "docker.state"},
		{Dim: DimState, Member: StateRunning, When: &Cond{Path: "docker.running", Test: TestTrue},
			Note: "the boolean, not the word: a paused container reports state `paused` and running true, and the counter counts it"},
		{Dim: DimState, Member: StateNotRead, When: &Cond{Any: []Cond{
			{Path: "docker", Test: TestAbsent},
			{All: []Cond{
				{Path: "docker.state", Test: TestEmpty},
				{Not: &Cond{Path: "docker.running", Test: TestTrue}},
			}},
		}}, Note: "no Engine reading, or one that said nothing"},

		// Probe outcome: a gate, or an answer with no gate, or an answer that never came, or no
		// probe at all. Four readings of two fields, and the same partition §13.3 counts.
		{Dim: DimProbe, Member: OutcomeGated, When: &Cond{Path: "probe.gate", Test: TestNonEmpty}},
		{Dim: DimProbe, Member: OutcomeOpen, When: &Cond{All: []Cond{
			{Path: "probe.gate", Test: TestEmpty},
			{Path: "probe.status", Test: TestPresent},
		}}, Note: "answered, no gate signal — a finding, not a verdict about the application"},
		{Dim: DimProbe, Member: OutcomeNoAnswer, When: &Cond{All: []Cond{
			{Path: "probe", Test: TestPresent},
			{Path: "probe.gate", Test: TestEmpty},
			{Path: "probe.status", Test: TestAbsent},
		}}, Note: "no response, so neither gated nor open (§13.3)"},
		{Dim: DimProbe, Member: OutcomeNotProbed, When: &Cond{Path: "probe", Test: TestAbsent}},

		// Declaration state: five independent readings, and drift and not-confirmed are never
		// merged (§22.2).
		{Dim: DimDecl, Member: DeclAuth, When: &Cond{Path: "declared.auth", Test: TestNonEmpty}},
		{Dim: DimDecl, Member: DeclProtected, When: &Cond{Path: "declared.authAgreement", Test: TestEquals, Value: string(payload.AgreementSupplies)},
			Note: "read off the agreement, which is the only place rule 2's verdict is recorded (§14)"},
		{Dim: DimDecl, Member: DeclNotConfirmed, When: &Cond{Path: "declared.unconfirmed", Test: TestNonEmpty}},
		{Dim: DimDecl, Member: DeclDrift, When: &Cond{Path: "declared.drift", Test: TestNonEmpty}},
		{Dim: DimDecl, Member: DeclAccepted, When: &Cond{Path: "declared.unauthenticatedAccepted", Test: TestPresent},
			Note: "an accepted exposure is still an exposure (§14 rule 3)"},

		// Integration match: whether an enrichment record found this service, and whether the
		// record that found it was rebuilt from a provider rather than listed (§11).
		{Dim: DimMatch, Member: MatchMatched, When: &Cond{Any: []Cond{
			{Path: "authentik.applications", Test: TestNonEmpty},
			{Path: "traefikLive", Test: TestNonEmpty},
		}}},
		{Dim: DimMatch, Member: MatchUnmatched, When: &Cond{Not: &Cond{Any: []Cond{
			{Path: "authentik.applications", Test: TestNonEmpty},
			{Path: "traefikLive", Test: TestNonEmpty},
		}}}},
		{Dim: DimMatch, Member: MatchRebuilt,
			When: &Cond{Path: "authentik.applications.discoveredVia", Test: TestEquals, Value: string(payload.DiscoveredViaProvider)},
			Note: "some application behind this service was reconstructed because the list withheld it"},
	},
}

// RulesMount is a storage row's readings.
var RulesMount = Rules{
	Shape: "mount",
	Rules: []TagRule{
		{Dim: DimState, ValuePath: "type"},
		{Dim: DimState, Member: StorageReadOnly, When: &Cond{Path: "readOnly", Test: TestTrue}},
		{Dim: DimState, Member: StorageWritable, When: &Cond{Not: &Cond{Path: "readOnly", Test: TestTrue}}},
	},
}

// RulesEnv is a config row's readings for an environment variable.
//
// There is no rule reading `value` and there never may be: the value is shown on the row and is not
// a filterable reading, because a filter over values would put a secret in a URL (I6, §22.6).
var RulesEnv = Rules{
	Shape: "env",
	Rules: []TagRule{
		{Dim: DimState, Member: ConfigEnv},
		{Dim: DimState, ValuePath: "source"},
		{Dim: DimState, Member: ConfigMasked, When: &Cond{Path: "masked", Test: TestTrue}},
	},
}

// RulesReport is a connection report's readings, including §22.8's banner test.
//
// `disabled` and `not-configured` are settings rather than failures, and `partial` is a failure
// whose OK is true — which is why the condition names all three rather than reading `ok` alone.
var RulesReport = Rules{
	Shape: "report",
	Rules: []TagRule{
		{Dim: DimState, ValuePath: "phase"},
		{Dim: DimState, Member: ReportFailing, When: &CondReportFailing,
			Note: "what gets a banner: partial, and any failure that is not a setting (§22.8)"},
	},
}

// CondReportFailing is §22.8's rule for which connection reports get a banner: `partial`, and any
// failure whose phase is neither `disabled` nor `not-configured`.
//
// Named, because three places need this one answer — the banner, the Diagnostics ordering and the
// failing-connections card — and a card counting one set while a banner showed another is the defect
// §22.3 exists to prevent. Go reads it through Failing; the browser reads the same tree out of the
// contract.
var CondReportFailing = Cond{Any: []Cond{
	{Path: "phase", Test: TestEquals, Value: string(payload.PhasePartial)},
	{All: []Cond{
		{Not: &Cond{Path: "ok", Test: TestTrue}},
		{Not: &Cond{Path: "phase", Test: TestEquals, Value: string(payload.PhaseDisabled)}},
		{Not: &Cond{Path: "phase", Test: TestEquals, Value: string(payload.PhaseNotConfigured)}},
	}},
}}

// RulesLiveRouter is a proxy row's readings.
var RulesLiveRouter = Rules{
	Shape: "liveRouter",
	Rules: []TagRule{
		{Dim: DimState, ValuePath: "status"},
		{Dim: DimState, Member: RouterErrored, When: &Cond{Path: "errors", Test: TestNonEmpty}},
		{Dim: DimMatch, Member: MatchMatched},
	},
}

// RulesUnmatched is the readings of an unmatched application or router. Both records have the same
// shape here — a reason, a detail and a trace — so one rule set serves both (§11, §12).
var RulesUnmatched = Rules{
	Shape: "unmatched",
	Rules: []TagRule{
		{Dim: DimMatch, Member: MatchUnmatched},
		{Dim: DimMatch, Member: MatchAmbiguous, When: &Cond{Path: "reason", Test: TestEquals, Value: string(payload.UnmatchedAmbiguous)}},
	},
}

// RulesNetwork is §8's three network predicates, over the facts a network row carries.
//
// Counts compared against a floor, not booleans copied from somewhere: *connecting* is two or more
// members and *cross-stack* is two or more stacks, which is exactly what the counters test. An
// external network with one member is **not** solo-local — something outside the scan may be on it,
// and that is a real statement about what its member can reach.
var RulesNetwork = Rules{
	Shape: "network",
	Rules: []TagRule{
		{Dim: DimState, ValuePath: "scope"},
		{Dim: DimState, Member: NetConnecting, When: &Cond{Path: "memberCount", Test: TestAtLeast, N: 2}},
		{Dim: DimState, Member: NetCrossStack, When: &Cond{Path: "stackCount", Test: TestAtLeast, N: 2}},
		{Dim: DimState, Member: NetSoloLocal, When: &Cond{All: []Cond{
			{Not: &Cond{Path: "external", Test: TestTrue}},
			{Path: "memberCount", Test: TestAtLeast, N: 1},
			{Not: &Cond{Path: "memberCount", Test: TestAtLeast, N: 2}},
		}}, Note: "one member and no outside: it connects nothing, and the graph draws no node for it (§8)"},
	},
}

// RuleSets is every table, for the contract and for a test that no dimension is granted a member
// outside its vocabulary.
var RuleSets = []Rules{
	RulesService, RulesMount, RulesEnv, RulesReport, RulesLiveRouter, RulesUnmatched, RulesNetwork,
}

// NetFacts is the object RulesNetwork reads: what the fleet knows about one network, in the same
// spelling the graph's network node carries it in (§8).
type NetFacts struct {
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	MemberCount int    `json:"memberCount"`
	StackCount  int    `json:"stackCount"`
	External    bool   `json:"external"`
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// Apply grants a rule set's members to a row.
func (r *Row) Apply(rules Rules, obj any) {
	for _, rule := range rules.Rules {
		if rule.When != nil && !Holds(*rule.When, obj) {
			continue
		}
		if rule.ValuePath == "" {
			r.Tag(rule.Dim, rule.Member)
			continue
		}
		values := stringsAt(obj, rule.ValuePath)
		if len(values) == 0 && rule.Default != "" {
			values = []string{rule.Default}
		}
		r.Tag(rule.Dim, values...)
	}
}

// Holds evaluates one condition against an object.
func Holds(c Cond, obj any) bool {
	switch {
	case len(c.All) > 0:
		for _, sub := range c.All {
			if !Holds(sub, obj) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for _, sub := range c.Any {
			if Holds(sub, obj) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !Holds(*c.Not, obj)
	}

	values := valuesAt(obj, c.Path)
	switch c.Test {
	case TestPresent:
		return len(values) > 0
	case TestAbsent:
		return len(values) == 0
	case TestNonEmpty:
		return anyValue(values, func(v reflect.Value) bool { return !isZero(v) })
	case TestEmpty:
		return !anyValue(values, func(v reflect.Value) bool { return !isZero(v) })
	case TestTrue:
		return anyValue(values, func(v reflect.Value) bool { return v.Kind() == reflect.Bool && v.Bool() })
	case TestEquals:
		return anyValue(values, func(v reflect.Value) bool { return asString(v) == c.Value })
	case TestAtLeast:
		return anyValue(values, func(v reflect.Value) bool { n, ok := asInt(v); return ok && n >= c.N })
	default:
		// An operator this build does not know grants nothing. A condition from a later protocol
		// (§16) must not accidentally read as *true* and hand a row a member it has no claim to.
		return false
	}
}

func anyValue(values []reflect.Value, pred func(reflect.Value) bool) bool {
	for _, v := range values {
		if pred(v) {
			return true
		}
	}
	return false
}

// stringsAt is the values at a path as members, skipping empties: a union member that is absent is
// not a member spelled "".
func stringsAt(obj any, path string) []string {
	var out []string
	for _, v := range valuesAt(obj, path) {
		if s := asString(v); s != "" {
			out = appendOnceString(out, s)
		}
	}
	return out
}

// valuesAt resolves a dotted path against an object and returns every value it reaches.
//
// Pointers are followed, slices are crossed, and a nil anywhere on the way ends that branch — so an
// absent record yields nothing rather than a zero value, which is what lets TestAbsent and TestEmpty
// be different questions. Fields are matched by their **JSON name**, because the path in a rule is
// the path a reader would use against the JSON and the path coverage.go checks against Appendix A.
func valuesAt(obj any, path string) []reflect.Value {
	v := reflect.ValueOf(obj)
	if !v.IsValid() {
		return nil
	}
	current := []reflect.Value{v}
	if path == "" {
		return deref(current)
	}

	for _, segment := range strings.Split(path, PathSeparator) {
		current = deref(current)
		next := make([]reflect.Value, 0, len(current))
		for _, item := range current {
			switch item.Kind() {
			case reflect.Struct:
				if field, ok := fieldByJSON(item, segment); ok {
					next = append(next, field)
				}
			case reflect.Map:
				// A map's keys are members, and a member is a path segment: `stats.byAuthMethod.oauth2`
				// is that member's count, which is exactly how the JSON reads and how a browser
				// resolves it — a property lookup, with no distinction between a field and a key. An
				// absent key yields nothing rather than a zero, so a distribution that never counted a
				// member reads as *not reported* rather than as none (§15).
				if v := mapValue(item, segment); v.IsValid() {
					next = append(next, v)
				}
			}
		}
		current = next
		if len(current) == 0 {
			return nil
		}
	}
	return deref(current)
}

// mapValue looks a key up by its rendered spelling, so a map keyed by a union type — `byAuthMethod`
// is keyed by AuthMethod — is indexed by the member as the JSON spells it.
func mapValue(m reflect.Value, key string) reflect.Value {
	for _, k := range m.MapKeys() {
		if asString(k) == key {
			return m.MapIndex(k)
		}
	}
	return reflect.Value{}
}

// deref follows pointers and expands slices, dropping nils.
func deref(in []reflect.Value) []reflect.Value {
	out := make([]reflect.Value, 0, len(in))
	for _, v := range in {
		for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				v = reflect.Value{}
				break
			}
			v = v.Elem()
		}
		if !v.IsValid() {
			continue
		}
		if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
			for i := 0; i < v.Len(); i++ {
				out = append(out, deref([]reflect.Value{v.Index(i)})...)
			}
			continue
		}
		out = append(out, v)
	}
	return out
}

// fieldByJSON finds a struct field by its JSON name, following embedded structs that flatten into
// their parent — the shape ServiceDeclaration has, where the declared fields are the parent's.
func fieldByJSON(v reflect.Value, name string) (reflect.Value, bool) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "-" {
			continue
		}
		if f.Anonymous && tag == "" {
			inner := v.Field(i)
			for inner.Kind() == reflect.Pointer {
				if inner.IsNil() {
					return reflect.Value{}, false
				}
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct {
				if found, ok := fieldByJSON(inner, name); ok {
					return found, true
				}
			}
			continue
		}
		if tag == name || (tag == "" && f.Name == name) {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	default:
		return v.IsZero()
	}
}

// asString renders a value the way the JSON carries it, so a rule's Value is written in the
// spelling a reader sees rather than in Go's.
func asString(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	default:
		return ""
	}
}

func asInt(v reflect.Value) (int, bool) {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(v.Uint()), true
	case reflect.Float32, reflect.Float64:
		return int(v.Float()), true
	default:
		return 0, false
	}
}
