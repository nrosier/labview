package webui

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// §22.7's view-state round trip, which §23 requires asserted as a **table of literals** rather than
// through fixtures. The grammar is contract even though the view set is not, so the assertions are
// query strings written out by hand: exactly what a reader pastes, and exactly what LabView writes
// back.
//
// The round trip has two halves and they fail differently.
//
//   - **Reading degrades, never fails** (I4). Everything in a URL is attacker-supplied, so an unknown
//     view is the overview, an unknown member is gone, and a depth of `-1` is no depth. §22.7 gives the
//     reason for dropping rather than keeping: *a filter with no chip is a view with no way back*.
//   - **Writing is canonical.** One spelling per state, so two readers who reached the same filter by
//     different routes share the same link (I7). That is what makes the table below a table: the third
//     column is the state's only spelling, and reading it back must produce it again.

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

// roundTrips is the grammar as literals. `raw` is what arrives; `canonical` is what §22.7 writes for
// the state it read. Where the two differ, the difference is the rule being asserted.
var roundTrips = []struct {
	name      string
	raw       string
	canonical string
}{
	{
		// The untouched dashboard: §22.7 requires defaults omitted, so the overview has no query at all.
		name:      "the overview is the empty query",
		raw:       "",
		canonical: "",
	},
	{
		// Both spellings of the overview mean the overview, and only one of them is written. Otherwise
		// the navigation's link and a hand-written one would differ for the same view.
		name:      "the overview named explicitly is still the empty query",
		raw:       "view=overview",
		canonical: "",
	},
	{
		name:      "a view is its slug",
		raw:       "view=services",
		canonical: "view=services",
	},
	{
		// A slug this build does not have is the overview, not an error and not an empty table. §22.2's
		// view set is explicitly not contract, so a link from a later version names a view that may not
		// exist here — and showing the overview is showing something.
		name:      "a view this build does not have is the overview",
		raw:       "view=quantum-tunnels",
		canonical: "",
	},
	{
		// The tri-state, in the spelling §22.7 gives it. Include bare, exclude with a leading `-`.
		name:      "include and exclude in one dimension",
		raw:       "ingress=public,-lan",
		canonical: "ingress=public%2C-lan",
	},
	{
		// `all:` is the only mode ever written, and it is written whenever it was asked for.
		name:      "the All mode is carried",
		raw:       "ingress=all:public,traefik,-lan",
		canonical: "ingress=all%3Apublic%2Ctraefik%2C-lan",
	},
	{
		// `any:` is read — a reader who typed the default has said something true — and never written,
		// because a filter whose common case spelled itself out makes every shared link longer.
		name:      "the Any mode is read and not written",
		raw:       "ingress=any:public,traefik",
		canonical: "ingress=public%2Ctraefik",
	},
	{
		// Members come out in the vocabulary's own order, which is the payload's precedence order
		// (§22.1). Two readers clicking the same chips in different orders get the same link.
		name:      "members are written in the vocabulary's order, not the order they were typed",
		raw:       "ingress=internal,public,lan",
		canonical: "ingress=public%2Clan%2Cinternal",
	},
	{
		// A member outside the dimension's vocabulary is dropped (§22.7), and dropping the only member
		// leaves the dimension off rather than present-and-empty.
		name:      "a member outside the vocabulary is dropped",
		raw:       "ingress=public,teleport",
		canonical: "ingress=public",
	},
	{
		name:      "a dimension whose every member was dropped is off",
		raw:       "ingress=teleport,wormhole",
		canonical: "",
	},
	{
		// Exclusion always wins (§22.6), and it wins at parse time so the chips a reader sees and the
		// rows they get agree. A member on both sides is one chip, an exclusion.
		name:      "a member on both sides is only an exclusion",
		raw:       "ingress=public,lan,-public",
		canonical: "ingress=lan%2C-public",
	},
	{
		// Auth method is single-valued: a service has one posture, so Any/All would be a mode over one
		// value. A URL asking for two is not refused — it is read as the first (§22.6).
		name:      "the single-valued dimension keeps one member and no mode",
		raw:       "auth=all:none,basic-auth",
		canonical: "auth=none",
	},
	{
		// Container state is the open dimension: the Engine's own status word, which this build never
		// enumerated. `restarting` is a reading the payload may well contain, so it survives.
		name:      "the open dimension keeps a member no table lists",
		raw:       "state=restarting",
		canonical: "state=restarting",
	},
	{
		// A boolean narrowing is written `1` and **only** the exact string `1` reads back as true.
		name:      "a boolean narrowing is 1",
		raw:       "view=services&exposed=1",
		canonical: "view=services&exposed=1",
	},
	{
		// `exposed=0` is not a third state. It is a narrowing that is off, spelled the long way, and off
		// means *do not narrow* — which shows the most rows rather than the fewest (I4).
		name:      "a boolean narrowing spelled 0 is off and vanishes",
		raw:       "view=services&exposed=0",
		canonical: "view=services",
	},
	{
		// Four spellings of true that are not `1`. This looks unhelpful and is the point: one spelling in
		// and one out is what lets two links describing the same state compare equal (I7).
		name:      "true, TRUE, yes and 01 are all off",
		raw:       "exposed=true&accepted=TRUE&drift=yes",
		canonical: "",
	},
	{
		name:      "all three narrowings at once",
		raw:       "view=declarations&accepted=1&drift=1",
		canonical: "view=declarations&accepted=1&drift=1",
	},
	{
		name:      "a diagram with a focus and a depth",
		raw:       "view=diagrams&diagram=networks&focus=net:backup&depth=2",
		canonical: "view=diagrams&diagram=networks&focus=net%3Abackup&depth=2",
	},
	{
		// An unknown diagram is none — the view still renders, with its diagram picker.
		name:      "a diagram this build does not have is none",
		raw:       "view=diagrams&diagram=sankey",
		canonical: "view=diagrams",
	},
	{
		// Depth 0 is the default and is omitted; DefaultDepth is applied when the diagram draws, not
		// when the URL is read, so *no depth in the link* and *depth 1* stay one state.
		name:      "depth zero is the default and is not written",
		raw:       "view=diagrams&diagram=networks&depth=0",
		canonical: "view=diagrams&diagram=networks",
	},
	{
		name:      "a negative depth is no depth",
		raw:       "view=diagrams&diagram=networks&depth=-3",
		canonical: "view=diagrams&diagram=networks",
	},
	{
		name:      "a depth that is not a number is no depth",
		raw:       "view=diagrams&diagram=networks&depth=deep",
		canonical: "view=diagrams&diagram=networks",
	},
	{
		// §22.7's table ends `panel`, `svc` — in that order — so the panel is written first even though
		// the drawer is what contains it. The order is the table's, not the nesting's.
		name:      "an open drawer at a section",
		raw:       "view=services&svc=media/jellyfin&panel=service:verdict",
		canonical: "view=services&panel=service%3Averdict&svc=media%2Fjellyfin",
	},
	{
		// An unknown panel is closed, and the drawer it was on stays open: the reader asked for a
		// service and gets the service, scrolled to the top instead of to a section that is not there.
		name:      "an unknown panel is closed and the drawer stays open",
		raw:       "view=services&svc=media/jellyfin&panel=service:telemetry",
		canonical: "view=services&svc=media%2Fjellyfin",
	},
	{
		name:      "the edge list panel",
		raw:       "view=diagrams&diagram=dependencies&panel=edges",
		canonical: "view=diagrams&diagram=dependencies&panel=edges",
	},
	{
		// Every parameter of §22.7's table at once, which is also the assertion about **write order**:
		// the table's order, not alphabetical. `view=services&exposed=1` reads as a sentence where
		// `exposed=1&view=services` reads as a form submission.
		name: "the whole grammar in the table's order",
		raw: "svc=media/jellyfin&panel=service:verdict&depth=2&focus=svc:media/jellyfin&diagram=dependencies" +
			"&drift=1&accepted=1&exposed=1&net=proxy&stack=media&match=unmatched&decl=drift&probe=gated" +
			"&health=healthy&state=running&conf=inferred&auth=none&ingress=public&q=jellyfin&view=services",
		canonical: "view=services&q=jellyfin&ingress=public&auth=none&conf=inferred&state=running&health=healthy" +
			"&probe=gated&decl=drift&match=unmatched&stack=media&net=proxy&exposed=1&accepted=1&drift=1" +
			"&diagram=dependencies&focus=svc%3Amedia%2Fjellyfin&depth=2&panel=service%3Averdict&svc=media%2Fjellyfin",
	},
	{
		// Free text is kept verbatim apart from §22.7's stripping, and it is escaped on the way out
		// rather than sanitised: a search for `a&b` is a search for `a&b`.
		name:      "free text carrying the separator",
		raw:       "q=" + url.QueryEscape("a&b=c"),
		canonical: "q=a%26b%3Dc",
	},
	{
		// A query string that will not parse is not a reason to refuse a dashboard (I4). `%zz` is not an
		// escape; the readable half of the query survives it.
		name:      "an unparseable escape does not lose the rest of the query",
		raw:       "view=services&q=%zz&exposed=1",
		canonical: "view=services&exposed=1",
	},
	{
		// A parameter that is not in §22.7's table is not carried. A state that needed one would be a
		// state a shared link cannot express, so the grammar is closed and the extra is dropped.
		name:      "a parameter outside the grammar is dropped",
		raw:       "view=services&sort=name&page=3",
		canonical: "view=services",
	},
	{
		name:      "a parameter present and empty is a parameter absent",
		raw:       "view=&q=&ingress=&depth=&panel=",
		canonical: "",
	},
	{
		// Whitespace around a value is not part of it, and a dimension of nothing but commas is off.
		name:      "whitespace and empty members are trimmed away",
		raw:       "view=%20services%20&ingress=" + url.QueryEscape(" public , , -lan "),
		canonical: "view=services&ingress=public%2C-lan",
	},
	{
		name:      "a dimension of only separators is off",
		raw:       "ingress=" + url.QueryEscape(",,,"),
		canonical: "",
	},
	{
		// A member repeated is one member. Two chips saying the same thing is two ways to remove one
		// filter, and the second does nothing.
		name:      "a repeated member appears once",
		raw:       "ingress=public,public,lan,public",
		canonical: "ingress=public%2Clan",
	},
	{
		// The mode prefix is matched case-insensitively, because a reader typing a URL by hand types
		// `ALL:` as readily as `all:` and both say the same thing.
		name:      "the mode prefix is read regardless of case",
		raw:       "ingress=ALL:public,lan",
		canonical: "ingress=all%3Apublic%2Clan",
	},
	{
		// The **member** is not, and that is deliberate: `Public` is not a member of a closed set that
		// contains `public`, and accepting it would make the set open by accident (§16).
		name:      "a member in the wrong case is not a member",
		raw:       "ingress=Public,lan",
		canonical: "ingress=lan",
	},
	{
		// A dimension with an exclusion and no include is a filter: *everything except this*. It is the
		// case the tri-state exists for and it must survive the round trip on its own.
		name:      "an exclusion with no include",
		raw:       "ingress=-none",
		canonical: "ingress=-none",
	},
	{
		// Mode with excludes only. The mode has nothing to quantify over — Any/All is over the includes
		// — but it is what the reader wrote, and a link that quietly dropped it would come back
		// different from the one that was shared.
		name:      "the All mode with only exclusions is kept",
		raw:       "ingress=all:-public,-lan",
		canonical: "ingress=all%3A-public%2C-lan",
	},
}

// The round trip itself, in both directions, over every literal above.
//
// Three assertions per row, and the third is the one that makes the other two mean something: the
// canonical spelling must be a **fixed point**. Reading it back and writing it again must produce it
// unchanged, or two shares of one state would drift apart with each hop.
func TestTheViewStateRoundTripsThroughItsQueryString(t *testing.T) {
	for _, tc := range roundTrips {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseQuery(tc.raw).String()
			if got != tc.canonical {
				t.Errorf("reading %q and writing it gives\n  %q\nwant\n  %q", tc.raw, got, tc.canonical)
			}

			again := ParseQuery(tc.canonical)
			if s := again.String(); s != tc.canonical {
				t.Errorf("the canonical spelling is not a fixed point: %q reads back and writes as %q",
					tc.canonical, s)
			}

			// And the states themselves are equal, not merely their spellings. A state carrying
			// something String does not write would round-trip as a string and lose data.
			if first := ParseQuery(tc.raw); !reflect.DeepEqual(first, again) {
				t.Errorf("the state read from %q is not the state read from its own spelling %q:\n  %+v\n  %+v",
					tc.raw, tc.canonical, first, again)
			}
		})
	}
}

// The other direction: a state built in Go, spelled once. A card's destination is built this way
// (§22.3), so if With and Including did not produce the canonical spelling, two cards pointing at the
// same rows would render different links.
func TestAStateBuiltInGoSpellsItselfTheSameWayAsOneReadFromAURL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State
		want  string
	}{
		{
			name:  "the bare overview",
			state: State{},
			want:  "",
		},
		{
			name:  "a view with one member",
			state: State{View: SlugServices}.Including(DimAuth, "none"),
			want:  "view=services&auth=none",
		},
		{
			name:  "Including sorts into the vocabulary's order",
			state: State{View: SlugServices}.Including(DimIngress, "internal", "public", "lan"),
			want:  "view=services&ingress=public%2Clan%2Cinternal",
		},
		{
			name:  "Excluding keeps the include it was applied to",
			state: State{View: SlugServices}.Including(DimIngress, "public").Excluding(DimIngress, "internal"),
			want:  "view=services&ingress=public%2C-internal",
		},
		{
			name:  "the All mode written out",
			state: State{View: SlugServices}.With(DimIngress, TagFilter{Mode: ModeAll, Include: []string{"public", "traefik"}}),
			want:  "view=services&ingress=all%3Apublic%2Ctraefik",
		},
		{
			name:  "a narrowing and a scope",
			state: State{View: SlugServices, Stack: "media", Exposed: true},
			want:  "view=services&stack=media&exposed=1",
		},
		{
			name:  "a focused diagram",
			state: State{View: SlugDiagrams, Diagram: DiagramNetworks, Focus: "net:proxy", Depth: 2},
			want:  "view=diagrams&diagram=networks&focus=net%3Aproxy&depth=2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
			// And the state survives its own spelling. This is the assertion that catches a builder
			// setting a field String does not write.
			if got := ParseQuery(tc.state.String()).String(); got != tc.want {
				t.Errorf("the state does not survive its own spelling: %q", got)
			}
		})
	}
}

// §22.7 requires a link, and §2.2 requires it relative so a path-prefixed mount works. `.` rather than
// `/`, because an href of `/` leaves the mount point and answers with somebody else's dashboard.
func TestALinkIsRelativeSoAPathPrefixedMountKeepsWorking(t *testing.T) {
	if got := (State{}).Link(); got != "." {
		t.Errorf("the bare overview links to %q, want %q", got, ".")
	}
	for _, tc := range roundTrips {
		s := ParseQuery(tc.raw)
		link := s.Link()
		if strings.HasPrefix(link, "/") || strings.Contains(link, "://") {
			t.Errorf("%q links to %q, which leaves the mount point (§2.2)", tc.raw, link)
		}
		if tc.canonical == "" {
			continue
		}
		if link != "?"+tc.canonical {
			t.Errorf("%q links to %q, want %q", tc.raw, link, "?"+tc.canonical)
		}
	}
}

// ---------------------------------------------------------------------------
// Free text (§22.7)
// ---------------------------------------------------------------------------

// The free-text rule, as a table, because its second half is the load-bearing one.
//
// Strip **everything below `0x20` plus `0x7f`, and nothing else.** The obvious implementation strips
// anything non-alphanumeric, or anything `unicode.IsControl` reports — and both of those delete a
// Cyrillic container name or an emoji in a label, which is text the fleet legitimately contains and a
// reader must be able to search for. So the assertions are the code point range and only that range.
func TestFreeTextKeepsEveryPrintableRuneAndStripsOnlyTheControlRange(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"plain text is unchanged", "jellyfin", "jellyfin"},
		{"a newline is stripped", "jelly\nfin", "jellyfin"},
		{"a tab is stripped", "jelly\tfin", "jellyfin"},
		{"a NUL is stripped", "jelly\x00fin", "jellyfin"},
		{"an escape is stripped", "jelly\x1bfin", "jellyfin"},
		{"delete is stripped", "jelly\x7ffin", "jellyfin"},
		{"the space above the range is kept", "jelly fin", "jelly fin"},
		{"leading and trailing space go", "  jellyfin  ", "jellyfin"},
		{"a Cyrillic name survives", "контейнер", "контейнер"},
		{"a CJK name survives", "媒体服务器", "媒体服务器"},
		{"an emoji survives", "media 📺", "media 📺"},
		{"a combining mark survives", "café", "café"},
		{"punctuation the shell would hate survives", `a&b=c;d|e$f`, `a&b=c;d|e$f`},
		{"an image reference survives", "ghcr.io/org/app:1.2", "ghcr.io/org/app:1.2"},
		{"a label key survives", "traefik.http.routers.x.rule", "traefik.http.routers.x.rule"},
		{"a lone high surrogate replacement survives", "a\uFFFDb", "a\uFFFDb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Text(tc.raw); got != tc.want {
				t.Errorf("Text(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// The cap is 200 **characters**, not bytes. A byte cap would cut a multi-byte name mid-rune and hand
// the renderer an invalid string, and the reason the cap exists — a bounded URL — is served either way.
func TestTheTextCapCountsCharactersRatherThanBytes(t *testing.T) {
	long := strings.Repeat("a", TextLimit+50)
	if got := Text(long); len(got) != TextLimit {
		t.Errorf("a %d-character string capped to %d, want %d", len(long), len(got), TextLimit)
	}

	// Three bytes each, so a byte cap would keep a third as many and could split the last one.
	wide := strings.Repeat("媒", TextLimit+50)
	got := Text(wide)
	if runes := len([]rune(got)); runes != TextLimit {
		t.Errorf("a wide string capped to %d characters, want %d", runes, TextLimit)
	}
	if !utf8.ValidString(got) {
		t.Error("the cap cut a character in half")
	}

	// Stripped code points do not count toward the cap: a string of newlines and one word is one word.
	if got := Text(strings.Repeat("\n", 500) + "jellyfin"); got != "jellyfin" {
		t.Errorf("control code points counted toward the cap: %q", got)
	}

	// And the cap holds through the round trip, which is the reason it exists.
	s := ParseQuery("q=" + url.QueryEscape(long))
	if len(s.Q) != TextLimit {
		t.Errorf("a long q survived parsing at %d characters", len(s.Q))
	}
	if len(ParseQuery(s.String()).Q) != TextLimit {
		t.Error("the cap did not survive the round trip")
	}
}

// Every free-text parameter is capped and stripped, not just `q`. A service key, a stack id and a focus
// target are read from a URL exactly as attacker-supplied as the search box, and one of them reaching a
// renderer with a control code point in it would be the same defect in a less obvious place.
func TestEveryFreeTextParameterIsStrippedAndNotJustTheSearchBox(t *testing.T) {
	dirty := "med\x00ia\x1b"
	q := url.Values{}
	for _, p := range GrammarParams() {
		if p.Kind == KindText {
			q.Set(p.Name, dirty)
		}
	}
	if len(q) < 5 {
		t.Fatalf("only %d text parameters found, and §22.7's table has five", len(q))
	}

	s := Parse(q)
	for name, got := range map[string]string{
		ParamQuery: s.Q, ParamStack: s.Stack, ParamNet: s.Net, ParamFocus: s.Focus, ParamSvc: s.Svc,
	} {
		if got != "media" {
			t.Errorf("%s = %q, want %q — every text parameter takes the same rule", name, got, "media")
		}
	}
}

// ---------------------------------------------------------------------------
// The grammar table
// ---------------------------------------------------------------------------

// §22.7's parameter table, as literals. It is contract: the browser parses a URL by walking this list
// instead of holding a second copy of Parse's decisions (§16), so a parameter added to Parse without a
// row here is a parameter the bundle cannot read.
func TestTheGrammarIsTheTwelveParametersPlusTheEightDimensions(t *testing.T) {
	want := []string{
		"view", "q",
		"ingress", "auth", "conf", "state", "health", "probe", "decl", "match",
		"stack", "net",
		"exposed", "accepted", "drift",
		"diagram", "focus", "depth",
		"panel", "svc",
	}

	var got []string
	for _, p := range GrammarParams() {
		got = append(got, p.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the grammar is\n  %v\nwant\n  %v", got, want)
	}

	// The write order is the table's order. Asserted here rather than trusted, because paramOrder reads
	// the same table and a change to one is meant to be a change to both.
	if !reflect.DeepEqual(paramOrder(), want) {
		t.Errorf("the write order is %v, want the table's order", paramOrder())
	}

	// Every enumerated parameter states the literals it is checked against, or Parse would have nothing
	// to check and the browser nothing to offer.
	for _, p := range GrammarParams() {
		if p.Kind == KindEnum && len(p.Values) == 0 {
			t.Errorf("%s is an enumeration with no values", p.Name)
		}
		if p.Kind == KindTags && p.Dim == "" {
			t.Errorf("%s is a tag filter naming no dimension", p.Name)
		}
	}
}

// §22.6's dimensions, as literals, with the one that is not multi-valued named. Auth method is
// single-valued because a service has one posture — Any/All over one value is a mode with nothing to
// quantify — and container state is the one open dimension, because the Engine's status word is not a
// closed set of this protocol.
func TestTheDimensionsAreTheEightAndOnlyAuthIsSingleValued(t *testing.T) {
	var got, multi, open []string
	for _, d := range Dimensions {
		got = append(got, string(d.Param))
		if d.Multi {
			multi = append(multi, string(d.Param))
		}
		if d.Set == "" {
			open = append(open, string(d.Param))
		}
		if strings.TrimSpace(d.Label) == "" {
			t.Errorf("dimension %s has no label", d.Param)
		}
	}

	wantAll := []string{"ingress", "auth", "conf", "state", "health", "probe", "decl", "match"}
	if !reflect.DeepEqual(got, wantAll) {
		t.Errorf("dimensions = %v, want %v", got, wantAll)
	}
	if want := []string{"ingress", "conf", "state", "health", "probe", "decl", "match"}; !reflect.DeepEqual(multi, want) {
		t.Errorf("multi-valued dimensions = %v, want %v — only auth is single-valued (§22.6)", multi, want)
	}
	if want := []string{"state"}; !reflect.DeepEqual(open, want) {
		t.Errorf("open dimensions = %v, want %v — container state is the Engine's own word (§22.6)", open, want)
	}
}

// ---------------------------------------------------------------------------
// History (§22.7)
// ---------------------------------------------------------------------------

// *A keystroke in the search box is not something Back should undo.* So a filter or a search replaces
// the history entry and a navigation pushes one, and which is which is stated as data because the
// browser needs the same list.
func TestOnlyNavigationScaleChangesPushAHistoryEntry(t *testing.T) {
	base := ParseQuery("view=services&ingress=public")

	for _, tc := range []struct {
		name string
		to   string
		want bool
	}{
		{"the same state is not a navigation", "view=services&ingress=public", false},
		{"a different view is", "view=networks&ingress=public", true},
		{"opening a drawer is", "view=services&ingress=public&svc=media/jellyfin", true},
		{"opening a panel is", "view=services&ingress=public&panel=list:warnings", true},
		{"choosing a diagram is", "view=diagrams&diagram=networks", true},
		{"moving the focus is", "view=diagrams&diagram=networks&focus=net:proxy", true},

		{"changing a filter is not", "view=services&ingress=lan", false},
		{"adding a filter is not", "view=services&ingress=public&health=healthy", false},
		{"typing in the search box is not", "view=services&ingress=public&q=jelly", false},
		{"a boolean narrowing is not", "view=services&ingress=public&exposed=1", false},
		{"scoping to a stack is not", "view=services&ingress=public&stack=media", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Navigational(base, ParseQuery(tc.to)); got != tc.want {
				t.Errorf("Navigational(base, %q) = %v, want %v", tc.to, got, tc.want)
			}
			// Symmetric: going back is the same size of change as going forward.
			if got := Navigational(ParseQuery(tc.to), base); got != tc.want {
				t.Errorf("the reverse move reports %v, want %v", got, tc.want)
			}
		})
	}

	// Changing the depth is not navigation either, but it is worth stating why it is in neither list
	// above: `depth` is not in NavParams, so zooming a diagram in and out does not fill the history with
	// steps a reader has to walk back through.
	if Navigational(ParseQuery("view=diagrams&diagram=networks"), ParseQuery("view=diagrams&diagram=networks&depth=3")) {
		t.Error("changing the depth pushed a history entry")
	}
}
