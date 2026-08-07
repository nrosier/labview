package webui

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// §22.7: **view state is a shareable URL.** Every view, filter, diagram selection, drawer and panel
// MUST be expressible as a query string, and reading one back MUST reproduce that state.
//
// The grammar is contract even though the view set is not, which is why the parameter names and the
// tri-state spelling below are constants and why the round trip is asserted as a table of literals
// (§23). Two properties are load-bearing:
//
//   - **Parsing degrades, never fails** (I4). Everything read out of a URL is attacker-supplied, so
//     enumerations are checked against their literals and anything else is dropped: an unknown view
//     is the overview, an unknown panel is closed, and a member outside a dimension's vocabulary is
//     gone. §22.7 states the reason for dropping rather than keeping — *a filter with no chip is a
//     view with no way back*. There is no such thing as an invalid LabView URL, only one that
//     describes less than it meant to.
//   - **Writing is canonical.** Members come out in their set's own order, defaults are omitted, and
//     only `all:` is ever written, so two readers who built the same state by different routes
//     produce the same link (I7).

// Parameter names. The whole grammar of §22.7's table, and nothing beyond it: a state that needed
// a parameter this list does not have would be a state a shared link cannot carry.
const (
	ParamView     = "view"
	ParamQuery    = "q"
	ParamStack    = "stack"
	ParamNet      = "net"
	ParamExposed  = "exposed"
	ParamAccepted = "accepted"
	ParamDrift    = "drift"
	ParamDiagram  = "diagram"
	ParamFocus    = "focus"
	ParamDepth    = "depth"
	ParamPanel    = "panel"
	ParamSvc      = "svc"
)

// Dim is a tag-filter dimension, and its value is the query parameter it is carried in (§22.7).
type Dim string

const (
	DimIngress Dim = "ingress"
	DimAuth    Dim = "auth"
	DimConf    Dim = "conf"
	DimState   Dim = "state"
	DimHealth  Dim = "health"
	DimProbe   Dim = "probe"
	DimDecl    Dim = "decl"
	DimMatch   Dim = "match"
)

// Dimension describes one filterable dimension (§22.6).
type Dimension struct {
	Param Dim
	Label string
	// Set is the vocabulary the members come from, or "" when the members are open — container
	// state is the Engine's own status string and is not a closed set of this protocol, so its
	// values are collected from the rows rather than offered from a table.
	Set Set
	// Multi says the dimension takes the tri-state grammar with an Any/All mode. Auth method is
	// the one that does not: a service has one posture, so Any/All would be a mode over a single
	// value (§22.6).
	Multi bool
	// Note is the sentence beside the control.
	Note string
}

// Dimensions is §22.6's list, in the order the filter bar shows them.
var Dimensions = []Dimension{
	{Param: DimIngress, Label: "Ingress", Set: SetIngressKind, Multi: true, Note: "tri-state: include, exclude, off — exclusion always wins"},
	{Param: DimAuth, Label: "Auth method", Set: SetAuthMethod, Multi: false, Note: "single-valued: a service has one posture"},
	{Param: DimConf, Label: "Confidence", Set: SetAuthConfidence, Multi: true, Note: "how the gate was established, never how severe it is"},
	{Param: DimState, Label: "Container state", Set: "", Multi: true, Note: "the Engine's own status, plus running as the boolean reports it"},
	{Param: DimHealth, Label: "Health", Set: SetHealth, Multi: true},
	{Param: DimProbe, Label: "Probe", Set: SetProbeOutcome, Multi: true},
	{Param: DimDecl, Label: "Declaration", Set: SetDeclState, Multi: true, Note: "drift and not-confirmed are separate readings"},
	{Param: DimMatch, Label: "Integration match", Set: SetMatchState, Multi: true},
}

// DimensionOf returns one dimension's descriptor.
func DimensionOf(d Dim) (Dimension, bool) {
	for _, dim := range Dimensions {
		if dim.Param == d {
			return dim, true
		}
	}
	return Dimension{}, false
}

// Mode is the Any/All mode over a dimension's includes (§22.6).
type Mode string

const (
	// ModeAny is the default and is never written into a URL: a filter whose common case spelled
	// itself out would make every shared link longer for nothing.
	ModeAny Mode = "any"
	ModeAll Mode = "all"
)

// The tri-state spelling. A member is included bare and excluded with a leading `-`; the mode is a
// prefix on the whole value. `ingress=all:public,traefik,-lan` reads: on every service that is both
// public and proxy-routed, and not on the LAN.
//
// Both mode prefixes are read and only `all:` is ever written (§22.7). `any:` is accepted because a
// reader who types the default explicitly has said something true, and refusing it would make a
// hand-written link describe less than it meant to.
const (
	excludePrefix = "-"
	modeAllPrefix = "all:"
	modeAnyPrefix = "any:"
)

// TagFilter is one dimension's state: off (both lists empty), include, exclude, or both.
type TagFilter struct {
	Mode    Mode
	Include []string
	Exclude []string
}

// Active reports whether this filter narrows anything.
func (f TagFilter) Active() bool { return len(f.Include) > 0 || len(f.Exclude) > 0 }

// Matches evaluates the tri-state grammar of §22.6 against one row's tags for this dimension.
//
// **Exclusion is always AND-NOT and always wins.** It is tested first and returns immediately, so
// no combination of includes can re-admit an excluded row — which is the property that makes
// *everything except this* a usable filter at fleet scale.
func (f TagFilter) Matches(tags []string) bool {
	for _, ex := range f.Exclude {
		if containsString(tags, ex) {
			return false
		}
	}
	if len(f.Include) == 0 {
		return true
	}
	if f.Mode == ModeAll {
		for _, in := range f.Include {
			if !containsString(tags, in) {
				return false
			}
		}
		return true
	}
	for _, in := range f.Include {
		if containsString(tags, in) {
			return true
		}
	}
	return false
}

// State is one view of one payload: §22.7's whole table, and nothing that is not in it.
type State struct {
	// View is the view slug, empty for the overview (§22.7: omitted for the overview).
	View string
	Q    string

	Tags map[Dim]TagFilter

	Stack string
	Net   string

	// The three boolean narrowings of §22.7. Plain booleans, and deliberately not tri-state
	// pointers: the parameter is *written as `1`, and only the exact string `"1"` reads back as
	// true*, so `exposed=0` is not a third state — it is a narrowing that is off, spelled the long
	// way. Off means *do not narrow*, which shows the most rows rather than the fewest (I4).
	Exposed  bool
	Accepted bool
	Drift    bool

	Diagram string
	Focus   string
	Depth   int

	Panel string
	Svc   string
}

// The view slugs of §22.2, as constants.
//
// Constants rather than literals because three tables spell them: the view itself (views.go), every
// card's destination (§22.3) and every drawer's Opens list (§22.4). A card pointing at a misspelled
// slug is a dead link that still renders, so the spelling is stated once and the compiler checks the
// rest.
const (
	// SlugOverview is the view an empty `view` parameter means (§22.7).
	SlugOverview     = "overview"
	SlugStacks       = "stacks"
	SlugServices     = "services"
	SlugIngress      = "ingress"
	SlugNetworks     = "networks"
	SlugDiagrams     = "diagrams"
	SlugContainers   = "containers"
	SlugStorage      = "storage"
	SlugConfig       = "config"
	SlugIdentity     = "identity"
	SlugProxy        = "proxy"
	SlugProbe        = "probe"
	SlugDeclarations = "declarations"
	SlugDiagnostics  = "diagnostics"
)

// ViewSlug is the resolved view: the overview when the parameter is absent.
func (s State) ViewSlug() string {
	if s.View == "" {
		return SlugOverview
	}
	return s.View
}

// Tag returns one dimension's filter, zero when it is off.
func (s State) Tag(d Dim) TagFilter { return s.Tags[d] }

// With returns a copy carrying one dimension's filter. Copies rather than mutates, so a card's
// destination cannot be edited by whatever renders it — the cards are a package-level table (§22.3)
// and a shared map would let one reader's click change another's link.
func (s State) With(d Dim, f TagFilter) State {
	out := s.clone()
	if !f.Active() {
		delete(out.Tags, d)
		return out
	}
	out.Tags[d] = f
	return out
}

// Including is With for the common case: narrow to one member.
func (s State) Including(d Dim, members ...string) State {
	return s.With(d, TagFilter{Include: canonicalMembers(d, members)})
}

// Excluding is With for the other common case: everything but these members.
func (s State) Excluding(d Dim, members ...string) State {
	f := s.Tag(d)
	f.Exclude = canonicalMembers(d, append(append([]string{}, f.Exclude...), members...))
	return s.With(d, f)
}

func (s State) clone() State {
	out := s
	out.Tags = map[Dim]TagFilter{}
	for d, f := range s.Tags {
		out.Tags[d] = TagFilter{
			Mode:    f.Mode,
			Include: append([]string{}, f.Include...),
			Exclude: append([]string{}, f.Exclude...),
		}
	}
	return out
}

// Active reports whether anything narrows the row set. It is what tells the UI to show a clear-all,
// and what tells an empty result to name a filter to remove rather than to say the fleet is empty
// (§22.6).
func (s State) Active() bool {
	if s.Q != "" || s.Stack != "" || s.Net != "" {
		return true
	}
	if s.Exposed || s.Accepted || s.Drift {
		return true
	}
	for _, f := range s.Tags {
		if f.Active() {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// Parse reads a state back from a query string (§22.7).
//
// It takes url.Values rather than a string so the caller decides where the parameters came from,
// and so a fragment or a form body would work the same way.
func Parse(q url.Values) State {
	s := State{Tags: map[Dim]TagFilter{}}

	// The three enumerations of §22.7, checked against their literals. An unknown view is the
	// overview, an unknown diagram is none, an unknown panel is closed — each the reading that shows
	// the reader something rather than nothing.
	s.View = parseEnum(q.Get(ParamView), ViewSlugs())
	if s.View == SlugOverview {
		// Both spellings mean the overview, and writing it back would produce a link that differs
		// from the one the navigation produces for the same view. Normalised on the way in so the
		// round trip has one canonical form.
		s.View = ""
	}
	s.Diagram = parseEnum(q.Get(ParamDiagram), DiagramIDs())
	s.Panel = parseEnum(q.Get(ParamPanel), PanelIDs())

	// The free-text parameters. Every one of them is capped and stripped: `q` because §22.7 says so,
	// and the four identifiers by the same rule, because a service key, a stack id and a focus
	// target are read from a URL exactly as attacker-supplied as the search box (§22.7). None of
	// them is an enumeration — the values are the fleet's own names, and a build that rejected a
	// name it had not seen would reject every link shared before a service was added.
	s.Q = Text(q.Get(ParamQuery))
	s.Stack = Text(q.Get(ParamStack))
	s.Net = Text(q.Get(ParamNet))
	s.Focus = Text(q.Get(ParamFocus))
	s.Svc = Text(q.Get(ParamSvc))

	s.Exposed = parseFlag(q.Get(ParamExposed))
	s.Accepted = parseFlag(q.Get(ParamAccepted))
	s.Drift = parseFlag(q.Get(ParamDrift))

	s.Depth = parseDepth(q.Get(ParamDepth))

	for _, dim := range Dimensions {
		if f := parseTagFilter(dim, q.Get(string(dim.Param))); f.Active() {
			s.Tags[dim.Param] = f
		}
	}
	return s
}

// ParseQuery is Parse over a raw query string, with or without a leading `?`.
func ParseQuery(raw string) State {
	raw = strings.TrimPrefix(raw, "?")
	q, err := url.ParseQuery(raw)
	if err != nil {
		// A query string that will not parse is not a reason to refuse to show a dashboard (I4).
		// url.ParseQuery returns what it managed to read alongside the error, so the readable half
		// is kept and the unreadable half is dropped.
		if q == nil {
			return State{Tags: map[Dim]TagFilter{}}
		}
	}
	return Parse(q)
}

// parseTagFilter reads one dimension's tri-state value.
func parseTagFilter(dim Dimension, raw string) TagFilter {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return TagFilter{}
	}

	f := TagFilter{}
	if rest, ok := cutPrefixFold(raw, modeAllPrefix); ok {
		f.Mode, raw = ModeAll, rest
	} else if rest, ok := cutPrefixFold(raw, modeAnyPrefix); ok {
		f.Mode, raw = ModeAny, rest
	}

	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if member, ok := cutPrefixFold(part, excludePrefix); ok {
			if member = strings.TrimSpace(member); member != "" {
				f.Exclude = appendOnceString(f.Exclude, member)
			}
			continue
		}
		f.Include = appendOnceString(f.Include, part)
	}

	// Exclusion wins, so a member on both sides is only an exclusion. Resolved here rather than at
	// evaluation time so the chips a reader sees and the rows they get agree.
	kept := f.Include[:0]
	for _, in := range f.Include {
		if !containsString(f.Exclude, in) {
			kept = append(kept, in)
		}
	}
	f.Include = kept

	if !dim.Multi {
		// Single-valued: one member on each side at most, and no mode. A URL asking for two
		// postures is not refused — it is read as the first, because a service has one (§22.6).
		f.Mode = ModeAny
		f.Include = firstOnly(f.Include)
		f.Exclude = firstOnly(f.Exclude)
	}
	if f.Mode != ModeAll {
		f.Mode = ModeAny
	}

	// A member outside the dimension's vocabulary is **dropped** (§22.7), and the spec states the
	// reason: a filter with no chip is a view with no way back. A tag that survived into the state
	// but matched no row and appeared in no control would show an empty table with a full filter bar
	// and nothing to click to undo it.
	//
	// The open dimension keeps everything, because it has no vocabulary to check against: container
	// state is the Engine's own status word (§22.6), so `state=restarting` is a member this build
	// never enumerated and a reading the payload may well contain.
	f.Include = knownMembers(dim, f.Include)
	f.Exclude = knownMembers(dim, f.Exclude)

	f.Include = canonicalMembers(dim.Param, f.Include)
	f.Exclude = canonicalMembers(dim.Param, f.Exclude)
	return f
}

// knownMembers drops members outside a closed vocabulary.
func knownMembers(dim Dimension, members []string) []string {
	if dim.Set == "" {
		return members
	}
	vocab := Members(dim.Set)
	out := members[:0]
	for _, m := range members {
		if containsString(vocab, m) {
			out = append(out, m)
		}
	}
	return out
}

// parseEnum is §22.7's rule for an enumerated parameter: the value if it is one of the literals,
// otherwise nothing.
func parseEnum(raw string, allowed []string) string {
	raw = strings.TrimSpace(raw)
	if raw != "" && containsString(allowed, raw) {
		return raw
	}
	return ""
}

// parseFlag is §22.7's boolean rule: **only the exact string `"1"`** reads back as true.
//
// Exact, so `exposed=true`, `exposed=TRUE` and `exposed=01` are all off. That looks unhelpful and is
// the point: one spelling in and one spelling out is what makes the round trip an identity, and a
// grammar that accepted four spellings of true would let two links describing the same state fail to
// compare equal (I7).
func parseFlag(raw string) bool { return raw == flagTrue }

// flagTrue is the only value a boolean narrowing is ever written as, and the only one that reads
// back as true.
const flagTrue = "1"

// TextLimit is §22.7's cap on free text: 200 characters.
//
// Characters, not bytes. A 200-byte cap would cut a multi-byte name mid-rune and hand the renderer an
// invalid string, and the reason the cap exists — a bounded URL — is served either way.
const TextLimit = 200

// Text is §22.7's free-text rule: capped at 200 characters and stripped of control code points —
// **everything below `0x20` plus `0x7f`, and nothing else.**
//
// Nothing else is the load-bearing half. The obvious implementation strips anything
// non-alphanumeric, or anything unicode.IsControl reports, and both of them delete a Cyrillic
// container name or an emoji in a label — text the fleet legitimately contains and a reader must be
// able to search for. So the test is the code point range and only that range.
func Text(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	n := 0
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if n == TextLimit {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func parseDepth(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// Query is the state as parameters, canonical and complete.
func (s State) Query() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}

	set(ParamView, s.View)
	set(ParamQuery, s.Q)
	for _, dim := range Dimensions {
		set(string(dim.Param), s.Tags[dim.Param].String())
	}
	set(ParamStack, s.Stack)
	set(ParamNet, s.Net)
	set(ParamExposed, flagParam(s.Exposed))
	set(ParamAccepted, flagParam(s.Accepted))
	set(ParamDrift, flagParam(s.Drift))
	set(ParamDiagram, s.Diagram)
	set(ParamFocus, s.Focus)
	if s.Depth > 0 {
		set(ParamDepth, strconv.Itoa(s.Depth))
	}
	set(ParamPanel, s.Panel)
	set(ParamSvc, s.Svc)
	return q
}

// String is the query string a link carries: the parameters in the order of §22.7's table rather
// than sorted alphabetically.
//
// The order is presentational and the round trip does not depend on it — but a shared link is read
// by people, and `view=services&exposed=1` reads as a sentence where the alphabetical form
// (`exposed=1&view=services`) reads as a form submission.
func (s State) String() string {
	q := s.Query()
	var b strings.Builder
	for _, key := range paramOrder() {
		v := q.Get(key)
		if v == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(v))
	}
	return b.String()
}

// Link is String as an href a browser can follow: `?` and the query, or `.` when the state is the
// bare overview.
//
// `.` rather than `/` because §2.2 requires relative URLs so a path-prefixed mount works — an href
// of `/` would leave the mount point and answer with somebody else's dashboard.
func (s State) Link() string {
	if q := s.String(); q != "" {
		return "?" + q
	}
	return "."
}

// GrammarParams is §22.7's table: every parameter, in the order String writes it, with the kind Parse
// reads it as and — for an enumeration — the literals it is checked against.
//
// It lives next to Parse because it describes Parse, and it is a table rather than prose because the
// browser has to do the same reading. The kinds are the five ways a parameter is read, so the bundle
// parses a URL by walking this list instead of holding a second copy of the decisions above (§16).
// Adding a parameter means adding a row here, which is what puts it in the canonical write order, in
// the contract, and in the round-trip test at once.
func GrammarParams() []GrammarParam {
	out := []GrammarParam{
		{Name: ParamView, Kind: KindEnum, Values: ViewSlugs()},
		{Name: ParamQuery, Kind: KindText},
	}
	for _, dim := range Dimensions {
		out = append(out, GrammarParam{Name: string(dim.Param), Kind: KindTags, Dim: dim.Param})
	}
	return append(out,
		GrammarParam{Name: ParamStack, Kind: KindText},
		GrammarParam{Name: ParamNet, Kind: KindText},
		GrammarParam{Name: ParamExposed, Kind: KindFlag},
		GrammarParam{Name: ParamAccepted, Kind: KindFlag},
		GrammarParam{Name: ParamDrift, Kind: KindFlag},
		GrammarParam{Name: ParamDiagram, Kind: KindEnum, Values: DiagramIDs()},
		GrammarParam{Name: ParamFocus, Kind: KindText},
		GrammarParam{Name: ParamDepth, Kind: KindCount},
		GrammarParam{Name: ParamPanel, Kind: KindEnum, Values: PanelIDs()},
		GrammarParam{Name: ParamSvc, Kind: KindText},
	)
}

// paramOrder is the order String writes in, read off the one table above so the written order and the
// contract's order cannot drift apart.
func paramOrder() []string {
	params := GrammarParams()
	out := make([]string, 0, len(params))
	for _, p := range params {
		out = append(out, p.Name)
	}
	return out
}

// String is one dimension's value: the mode prefix, then includes, then excludes.
func (f TagFilter) String() string {
	if !f.Active() {
		return ""
	}
	parts := make([]string, 0, len(f.Include)+len(f.Exclude))
	parts = append(parts, f.Include...)
	for _, ex := range f.Exclude {
		parts = append(parts, excludePrefix+ex)
	}
	value := strings.Join(parts, ",")
	if f.Mode == ModeAll {
		return modeAllPrefix + value
	}
	return value
}

// flagParam writes a boolean narrowing: `1` when it is on, and **absent** when it is off.
//
// Absent rather than `0`, because §22.7 requires defaults to be omitted so an untouched dashboard has
// an empty query. `exposed=0` and no `exposed` at all are the same state, and only one of them is the
// canonical spelling of it.
func flagParam(v bool) string {
	if v {
		return flagTrue
	}
	return ""
}

// NavParams are §22.7's navigation-scale parameters: the ones whose change pushes a history entry.
//
// *A keystroke in the search box is not something Back should undo* — so `q` and the filter
// dimensions are not here, and a filter change replaces the history entry instead. Stated as data
// because the browser side needs the same list and must not keep its own copy of it (§22 contract).
var NavParams = []string{ParamView, ParamDiagram, ParamFocus, ParamPanel, ParamSvc}

// Navigational reports whether moving from one state to another is a navigation-scale change and so
// pushes a history entry rather than replacing one (§22.7).
func Navigational(from, to State) bool {
	a, b := from.Query(), to.Query()
	for _, p := range NavParams {
		if a.Get(p) != b.Get(p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Canonical order
// ---------------------------------------------------------------------------

// canonicalMembers sorts a dimension's members into the order §22.1 requires chips to be shown in:
// the vocabulary's own order, which is the payload's precedence order, with members this build does
// not know last and alphabetical among themselves.
//
// Sorting here rather than at render time is what makes a link canonical: two readers who reached
// the same filter by clicking in different orders share the same URL (I7).
func canonicalMembers(d Dim, members []string) []string {
	dim, ok := DimensionOf(d)
	if !ok {
		return sortedUnique(members)
	}
	rank := map[string]int{}
	for i, m := range Members(dim.Set) {
		rank[m] = i
	}

	out := sortedUnique(members)
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := rank[out[i]]
		rj, okj := rank[out[j]]
		switch {
		case oki && okj:
			return ri < rj
		case oki != okj:
			return oki
		default:
			// Both unknown: already alphabetical from sortedUnique, so keep that order.
			return false
		}
	})
	return out
}

func sortedUnique(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = appendOnceString(out, v)
	}
	sort.Strings(out)
	return out
}

func firstOnly(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return in[:1]
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(s), prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

func containsString(list []string, v string) bool {
	for _, existing := range list {
		if existing == v {
			return true
		}
	}
	return false
}

func appendOnceString(list []string, v string) []string {
	if containsString(list, v) {
		return list
	}
	return append(list, v)
}

// sortStrings sorts in place. Used where an order came out of a map and has to become deterministic
// before anyone can see it (§22.1).
func sortStrings(list []string) { sort.Strings(list) }
