package webui

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// The UI contract: every table in this package, as one JSON document the browser reads.
//
// §18's route table is closed — there is no rows endpoint and no figure endpoint — so the browser is
// given `/api/overview` and has to build the views itself. That is the situation §16 warns about: the
// vocabulary, the readings of §22.6, the card destinations and the diagram selections would all exist
// twice, once in Go and once in JavaScript, and the two copies would agree only until someone edited
// one of them.
//
// So they exist once, here, as data. This file serialises the tables; `dist/assets/contract.js` is
// that serialisation, generated and committed; and the bundled script evaluates it. What stays in
// JavaScript is the evaluator and the rendering — no member spelling, no threshold, no reading, no
// destination.
//
// Two consequences worth being explicit about:
//
//   - **The Go side is the tested reference.** Rows, Cards and the diagrams are asserted against
//     fixtures (§23); the browser's evaluation of the same tables is not. What the contract removes is
//     the class of drift where the two hold *different rules*. It does not remove the need for the
//     browser's evaluator to be correct.
//   - **The contract is checked for drift.** A test regenerates it and compares against the committed
//     asset, so a table edited in Go without regenerating fails the build rather than shipping a UI
//     that filters by last release's vocabulary.

// ContractVersion is the shape of this document, not the version of LabView.
//
// The browser refuses a contract it does not know how to read rather than guessing at a field it has
// never seen — the same rule §16 gives for a payload from a later version, applied to the UI's own
// input.
const ContractVersion = 1

// Contract is the whole document.
type Contract struct {
	Version int `json:"version"`

	// Grammar is §22.7's URL grammar: enough for the browser to write a state the same way Go writes
	// it, so a link built in the browser and a link built in a test are the same string.
	Grammar Grammar `json:"grammar"`

	Groups     []string            `json:"groups"`
	Views      []ContractView      `json:"views"`
	Chrome     ContractChrome      `json:"chrome"`
	Dimensions []ContractDimension `json:"dimensions"`
	Sets       []ContractSet       `json:"sets"`

	// Unknown is the fallback term for a member this build has no term for (§22.1's *defined
	// fallback*). It is in the contract because the browser needs the same fallback, and a chip that
	// rendered as nothing would make a payload from a later version look like a payload with a gap.
	Unknown Term `json:"unknown"`

	// Rules are §22.6's derived readings, and Conds are the named conditions a reading is shared
	// under.
	Rules []Rules           `json:"rules"`
	Conds []ContractCond    `json:"conds"`
	Cards []ContractCard    `json:"cards"`
	Draws []Drawer          `json:"drawers"`
	Panel []string          `json:"panels"`
	Diags []ContractDiagram `json:"diagrams"`

	// Names are the member spellings a *projection* needs by name rather than through a rule table.
	//
	// Most of §22.6's readings are rules and arrive above as data. A few are not: a route row is
	// tagged `public` because it is a tunnel route, an entry row is tagged `drift` because it came
	// out of the drift list, a diagram edge is tagged `ungated` because nothing stands on the path.
	// Those are facts about which list the row was built from, and there is no condition to evaluate.
	//
	// They are still spellings, and a browser holding its own copy of them would be §16's second
	// implementation with the vocabulary split across two languages. So they are named here and the
	// bundle refers to them by name — `M.ingressPublic`, never `"public"`.
	Names []ContractName `json:"names"`
}

// ContractName is one named spelling.
type ContractName struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ParamKind is how one parameter of §22.7 is read.
//
// Five kinds and no more, because §22.7's parameter list is closed: an enumeration checked against its
// literals, free text capped and stripped, a boolean with one true spelling, a count, and a
// dimension's tri-state filter.
type ParamKind string

const (
	KindEnum  ParamKind = "enum"
	KindText  ParamKind = "text"
	KindFlag  ParamKind = "flag"
	KindCount ParamKind = "count"
	KindTags  ParamKind = "tags"
)

// GrammarParam is one parameter and how it is read.
//
// Carried in the contract with its kind and, for an enumeration, its literals — so the browser parses
// a URL by walking this table rather than by holding a second copy of §22.7. An unknown view being
// the overview and an unknown panel being closed are then one rule evaluated from data, in both
// languages, rather than the same twelve decisions written twice (§16).
type GrammarParam struct {
	Name string    `json:"name"`
	Kind ParamKind `json:"kind"`

	// Dim is the dimension a `tags` parameter filters, so the browser finds its vocabulary and its
	// single-valued rule without matching on the name.
	Dim Dim `json:"dim,omitempty"`

	// Values is the closed set an `enum` parameter is checked against. A value outside it is dropped
	// (§22.7), which is why the set has to travel with the parameter.
	Values []string `json:"values,omitempty"`
}

// Grammar is the closed part of §22.7: the parameters with their kinds, the two prefixes, the
// exclusion marker, the boolean spelling and the free-text cap.
type Grammar struct {
	// Params is the fixed order parameters are written in. §22.7: *the table's order*, so the same
	// state always spells the same string.
	Params []GrammarParam `json:"params"`

	// Flag is the only string that reads back as true.
	Flag string `json:"flag"`

	// TextLimit is the free-text cap in characters.
	TextLimit int `json:"textLimit"`

	// ExcludePrefix marks an excluded member; AllPrefix and AnyPrefix are the mode prefixes. Only
	// AllPrefix is ever written out.
	ExcludePrefix string `json:"excludePrefix"`
	AllPrefix     string `json:"allPrefix"`
	AnyPrefix     string `json:"anyPrefix"`

	// NavParams are the parameters whose change pushes a history entry (§22.7: navigation-scale
	// change only — a keystroke in the search box is not something Back should undo).
	NavParams []string `json:"navParams"`

	// DefaultView is the slug an absent `view` means, and DefaultDepth the depth an absent `depth`
	// means.
	DefaultView  string `json:"defaultView"`
	DefaultDepth int    `json:"defaultDepth"`
}

// ContractView is one view: §22.2's row, plus the projection the browser builds for it.
type ContractView struct {
	Slug     string   `json:"slug"`
	Title    string   `json:"title"`
	Group    string   `json:"group"`
	Icon     string   `json:"icon,omitempty"`
	Question string   `json:"question"`
	RowNoun  string   `json:"rowNoun"`
	Kind     string   `json:"kind"`
	Columns  []Column `json:"columns"`
	Fields   []string `json:"fields,omitempty"`
	Order    string   `json:"order"`
	Empty    string   `json:"empty"`
	Dims     []Dim    `json:"dims,omitempty"`
}

// ContractChrome is the frame's fields and what it shows (§22.2's last rule, §22.8's banners).
type ContractChrome struct {
	Fields []string `json:"fields"`
	Note   string   `json:"note"`
}

// ContractDimension is one filter dimension and its vocabulary reference.
type ContractDimension struct {
	Param Dim    `json:"param"`
	Label string `json:"label"`
	Set   Set    `json:"set,omitempty"`
	Multi bool   `json:"multi"`
	Note  string `json:"note,omitempty"`
}

// ContractSet is one closed vocabulary, in its canonical order.
type ContractSet struct {
	Name  Set    `json:"name"`
	Terms []Term `json:"terms"`
}

// ContractCond is a named condition, so the browser can reference the one the banner test uses
// (§22.8) rather than carry a second copy inline.
type ContractCond struct {
	Name string `json:"name"`
	Cond Cond   `json:"cond"`
}

// ContractCard is one card, with its destination as the query string it links to.
//
// The destination is a **string**, not a structure, on purpose: the browser navigates by setting the
// query, and giving it the finished string means a card's link is written by the same code a test
// asserts. A structure would let the browser assemble it a second, slightly different way.
type ContractCard struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Unit     string `json:"unit,omitempty"`
	Note     string `json:"note,omitempty"`
	Path     string `json:"path,omitempty"`
	Dest     string `json:"dest"`
	View     string `json:"view"`
	Exact    bool   `json:"exact"`
	Optional bool   `json:"optional,omitempty"`
	Lead     bool   `json:"lead,omitempty"`
	Tone     Tone   `json:"tone"`
	Segments bool   `json:"segments,omitempty"`
	Set      Set    `json:"set,omitempty"`
}

// ContractDiagram is one diagram: its edge kinds, its caveat, and its limits.
type ContractDiagram struct {
	ID            string               `json:"id"`
	Title         string               `json:"title"`
	Shows         string               `json:"shows"`
	Kinds         []string             `json:"kinds"`
	Note          string               `json:"note"`
	NodeThreshold int                  `json:"nodeThreshold"`
	Cap           int                  `json:"cap"`
	GroupByStack  bool                 `json:"groupByStack,omitempty"`
	Tags          []ContractDiagramTag `json:"tags"`
}

// ContractDiagramTag is one edge reading and what it means, so the legend is generated from the same
// list the edges are tagged from.
type ContractDiagramTag struct {
	Member string `json:"member"`
	Label  string `json:"label"`
	Tone   Tone   `json:"tone"`
	Note   string `json:"note"`
}

// TheContract builds the document.
//
// Deterministic by construction: every field is a slice in a declared order, and no map is
// serialised. That is what makes the drift test a byte comparison rather than a semantic one (I7).
func TheContract() Contract {
	c := Contract{
		Version: ContractVersion,
		Grammar: Grammar{
			Params:        GrammarParams(),
			Flag:          flagTrue,
			TextLimit:     TextLimit,
			ExcludePrefix: excludePrefix,
			AllPrefix:     modeAllPrefix,
			AnyPrefix:     modeAnyPrefix,
			NavParams:     NavParams,
			DefaultView:   SlugOverview,
			DefaultDepth:  DefaultDepth,
		},
		Chrome:  ContractChrome{Fields: Chrome.Fields, Note: Chrome.Note},
		Unknown: UnknownTerm(""),
		Rules:   RuleSets,
		Conds: []ContractCond{
			{Name: "reportFailing", Cond: CondReportFailing},
		},
		Draws: Drawers,
		Panel: PanelIDs(),
		Names: names(),
	}

	for _, g := range Groups {
		c.Groups = append(c.Groups, string(g))
	}
	for _, v := range Views {
		c.Views = append(c.Views, ContractView{
			Slug: v.Slug, Title: v.Title, Group: string(v.Group), Icon: v.Icon, Question: v.Question,
			RowNoun: v.RowNoun, Kind: string(v.Kind), Columns: v.Columns, Fields: v.Fields,
			Order: v.Order, Empty: v.Empty, Dims: v.Dims,
		})
	}
	for _, d := range Dimensions {
		c.Dimensions = append(c.Dimensions, ContractDimension{
			Param: d.Param, Label: d.Label, Set: d.Set, Multi: d.Multi, Note: d.Note,
		})
	}
	for _, set := range Sets() {
		c.Sets = append(c.Sets, ContractSet{Name: set, Terms: Terms(set)})
	}

	// The cards are the table, not an expanded payload: a distribution is carried as `segments` with
	// its set, and the browser expands it against the payload it holds — which is the only way the
	// contract can be a static asset and still show a member the payload carries that this build does
	// not know (§16).
	for _, card := range CardTable {
		c.Cards = append(c.Cards, ContractCard{
			ID: card.ID, Label: card.Label, Unit: card.Unit, Note: card.Note, Path: card.Path,
			Dest: card.Dest.String(), View: card.Dest.ViewSlug(), Exact: card.Exact,
			Optional: card.Optional, Lead: card.Lead, Tone: card.Tone,
			Segments: card.Segments, Set: card.Set,
		})
	}

	for _, d := range Diagrams {
		cd := ContractDiagram{
			ID: d.ID, Title: d.Title, Shows: d.Shows, Note: d.Note,
			NodeThreshold: d.NodeThreshold, Cap: d.Cap, GroupByStack: d.GroupByStack,
			Tags: diagramTags(d),
		}
		for _, k := range d.Kinds {
			cd.Kinds = append(cd.Kinds, string(k))
		}
		c.Diags = append(c.Diags, cd)
	}
	return c
}

// names is the named-spelling table.
//
// Every value is a constant from this package or from payload, so a spelling changed in one place
// changes here too and the bundle follows without being edited. The names are the browser's
// vocabulary for facts it cannot derive: which list a row came from, and which payload member a
// projection compares against.
func names() []ContractName {
	return []ContractName{
		// The parameters, by the name the code refers to them by. The grammar table above carries the
		// order and the kinds, which is enough to parse and write a URL; these are for the handful of
		// parameters a control addresses directly — the nav writes the view, a diagram control writes the
		// focus and the depth, a row opens a drawer by writing the panel and the subject.
		{"paramView", ParamView},
		{"paramQuery", ParamQuery},
		{"paramStack", ParamStack},
		{"paramNet", ParamNet},
		{"paramExposed", ParamExposed},
		{"paramAccepted", ParamAccepted},
		{"paramDrift", ParamDrift},
		{"paramDiagram", ParamDiagram},
		{"paramFocus", ParamFocus},
		{"paramDepth", ParamDepth},
		{"paramPanel", ParamPanel},
		{"paramSvc", ParamSvc},

		// The five ways a parameter is read, so the browser's parser switches on the kind the table gave
		// it. A kind it does not know leaves the parameter unread, which is the degradation §22.7 asks
		// for rather than a broken parse (I4).
		{"kindEnum", string(KindEnum)},
		{"kindText", string(KindText)},
		{"kindFlag", string(KindFlag)},
		{"kindCount", string(KindCount)},
		{"kindTags", string(KindTags)},

		// The dimensions, because a projection tags a row into a named dimension: a probe phase goes to
		// `state`, an Authentik match strength to `conf`. The vocabularies and the labels travel in the
		// dimensions table; these are the keys into it.
		{"dimIngress", string(DimIngress)},
		{"dimAuth", string(DimAuth)},
		{"dimConf", string(DimConf)},
		{"dimState", string(DimState)},
		{"dimHealth", string(DimHealth)},
		{"dimProbe", string(DimProbe)},
		{"dimDecl", string(DimDecl)},
		{"dimMatch", string(DimMatch)},

		// The row kinds. The browser keys its projections and its cell renderers off the kind a view
		// declares, never off a view slug — §22.2 gives Storage and Configuration the same shape from
		// different lists, and a renderer keyed by slug would be a table of special cases.
		{"rowStat", string(RowStat)},
		{"rowStack", string(RowStack)},
		{"rowService", string(RowService)},
		{"rowRoute", string(RowRoute)},
		{"rowNetwork", string(RowNetwork)},
		{"rowDiagram", string(RowDiagram)},
		{"rowContainer", string(RowContainer)},
		{"rowStorage", string(RowStorage)},
		{"rowConfig", string(RowConfig)},
		{"rowApplication", string(RowApplication)},
		{"rowRouter", string(RowRouter)},
		{"rowProbe", string(RowProbe)},
		{"rowDeclaration", string(RowDeclaration)},
		{"rowReport", string(RowReport)},

		// The kinds a boolean narrowing or a panel switches the projection to (§22.7).
		{"rowDrift", string(RowDrift)},
		{"rowUnconfirmed", string(RowUnconfirmed)},
		{"rowAccepted", string(RowAccepted)},
		{"rowEdge", string(RowEdge)},
		{"rowWarning", string(RowWarning)},
		{"panelEdges", PanelEdges},
		{"panelWarnings", PanelWarnings},

		// Ingress and posture members a projection asserts about a row it built from one list.
		{"ingressPublic", string(payload.IngressPublic)},
		{"ingressTraefik", string(payload.IngressTraefik)},
		{"ingressNone", string(payload.IngressNone)},
		{"authNone", string(payload.AuthNone)},

		// Runtime.
		{"stateRunning", StateRunning},
		{"stateNotRead", StateNotRead},
		{"healthUnhealthy", string(payload.HealthUnhealthy)},

		// Storage and configuration.
		{"mountVolume", string(payload.MountVolume)},
		{"storageWritable", StorageWritable},
		{"storageReadOnly", StorageReadOnly},
		{"storageExternal", StorageExternal},
		{"storageUnused", StorageUnused},
		{"configEnv", ConfigEnv},
		{"configLabel", ConfigLabel},
		{"configMasked", ConfigMasked},

		// Enrichment.
		{"matchMatched", MatchMatched},
		{"matchUnmatched", MatchUnmatched},
		{"matchRebuilt", MatchRebuilt},
		{"discoveredViaProvider", string(payload.DiscoveredViaProvider)},
		{"routerErrored", RouterErrored},

		// Declarations.
		{"declDrift", DeclDrift},
		{"declNotConfirmed", DeclNotConfirmed},
		{"declAccepted", DeclAccepted},

		// The finding vocabulary. The browser relabels a service's own exposure fields into these
		// members — the Overview's exposure cards and the Stacks roll-up read them — so it must not
		// hold the spellings itself.
		{"findingExposed", FindingExposed},
		{"findingGated", FindingGated},
		{"findingAccepted", FindingAccepted},
		{"findingNone", FindingNone},

		// Probe outcomes the Probe view's stated order reads (§22.2).
		{"outcomeOpen", OutcomeOpen},
		{"outcomeGated", OutcomeGated},

		// Networks. The two scopes are here because a network with one local member has no node in the
		// graph (§8): the browser has to build a node-shaped record for it, and a scope it spelled itself
		// would be a second vocabulary.
		{"netScopeExternal", string(payload.ScopeExternal)},
		{"netScopeStackLocal", string(payload.ScopeStackLocal)},
		{"netConnecting", NetConnecting},
		{"netCrossStack", NetCrossStack},
		{"netSoloLocal", NetSoloLocal},

		// Diagnostics.
		{"reportFailing", ReportFailing},

		// The graph: edge kinds, the readings a diagram grants, and the node kinds the shapes key off.
		{"edgeDependsOn", string(payload.EdgeDependsOn)},
		{"edgeNetworkKind", string(payload.EdgeNetwork)},
		{"edgeIngressKind", string(payload.EdgeIngress)},
		{"edgeAuthKind", string(payload.EdgeAuth)},
		{"edgeDeclared", EdgeDeclared},
		{"edgeObserved", EdgeObserved},
		{"edgeDirect", EdgeDirect},
		{"edgeUngated", EdgeUngated},
		{"edgeUnattached", EdgeUnattached},
		{"flowSourceDeclared", string(payload.FlowSourceDeclared)},
		{"flowSourceObserved", string(payload.FlowSourceObserved)},
		{"nodeService", string(payload.NodeService)},
		{"nodeNetwork", string(payload.NodeNetwork)},
		{"nodeExternal", string(payload.NodeExternal)},
		{"roleProxy", string(payload.RoleProxy)},
		{"flowBoth", string(payload.FlowBoth)},
		{"flowToNetwork", string(payload.FlowToNetwork)},
		{"flowToService", string(payload.FlowToService)},

		// The node-id spellings (§9). A diagram reads them to say which service a node is, and the
		// browser opens a drawer from a node by the same key the rows are identified with.
		{"prefixService", fleet.PrefixService},
		{"prefixNetwork", fleet.PrefixNetwork},
		{"prefixHostname", fleet.PrefixHostname},
		{"prefixApp", fleet.PrefixApp},
		{"prefixRouter", fleet.PrefixRouter},
		{"keySeparator", "/"},

		// LabView's own sign-in methods (§19), for the form the browser shows on a 401.
		{"methodPasswd", string(payload.MethodPasswd)},
		{"methodOIDC", string(payload.MethodOIDC)},

		// The condition operators, read off the tests themselves so the browser's evaluator switches on
		// this table rather than on its own copy of the spellings. An operator not named here is one the
		// browser does not know, and an unknown operator holds false rather than true (I4).
		{"testPresent", string(TestPresent)},
		{"testAbsent", string(TestAbsent)},
		{"testNonEmpty", string(TestNonEmpty)},
		{"testEmpty", string(TestEmpty)},
		{"testTrue", string(TestTrue)},
		{"testEquals", string(TestEquals)},
		{"testAtLeast", string(TestAtLeast)},

		// The rule-set shapes, read off the sets, so a projection asks for the rules of the object it
		// holds by the name the table gives itself.
		{"shapeService", RulesService.Shape},
		{"shapeMount", RulesMount.Shape},
		{"shapeEnv", RulesEnv.Shape},
		{"shapeReport", RulesReport.Shape},
		{"shapeLiveRouter", RulesLiveRouter.Shape},
		{"shapeUnmatched", RulesUnmatched.Shape},
		{"shapeNetwork", RulesNetwork.Shape},
	}
}

// diagramTags is the readings a diagram's edges can carry, with the words the legend uses.
//
// Per diagram rather than one global list, because a reading only means something on the diagram that
// grants it: `direct` is a statement about a dependency and `ungated` about a path from outside, and a
// legend offering both on the identity diagram would be offering two filters that match nothing.
func diagramTags(d Diagram) []ContractDiagramTag {
	var out []ContractDiagramTag
	add := func(member, label string, tone Tone, note string) {
		out = append(out, ContractDiagramTag{Member: member, Label: label, Tone: tone, Note: note})
	}
	if d.draws(payload.EdgeDependsOn) {
		add(EdgeDeclared, "Declared", ToneInfo, "an operator said this dependency exists (§14 rule 1)")
		add(EdgeObserved, "Observed", ToneNeutral, "the scan resolved it from the compose file")
		add(EdgeDirect, "No shared network", ToneWarn,
			"the dependency is real and no network in this scan explains how it is reached (§8)")
	}
	if d.draws(payload.EdgeNetwork) {
		for _, t := range Terms(SetEdgeFlow) {
			add(t.Member, t.Label, t.Tone, t.Note)
		}
		for _, t := range Terms(SetEdgeFlowSource) {
			add(t.Member, t.Label, t.Tone, t.Note)
		}
	}
	if d.draws(payload.EdgeIngress) {
		add(EdgeUngated, "No gate found", ToneAlert,
			"reachable from outside with nothing in front of it — the one reserved colour (§22.1)")
	}
	if d.draws(payload.EdgeAuth) {
		for _, t := range Terms(SetMatchStrength) {
			add(t.Member, t.Label, t.Tone, t.Note)
		}
		add(EdgeUnattached, "Unattached", ToneWarn,
			"a provider record that matched nothing in this fleet, drawn rather than hidden (§11, §12)")
	}
	return out
}

// ContractJSON is the contract as indented JSON, deterministic for a build.
func ContractJSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// HTML escaping off: the document is assigned to a variable in a script, never interpolated into
	// markup, and `<` in a note would make the committed asset unreadable in review for nothing.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(TheContract()); err != nil {
		return nil, fmt.Errorf("encode contract: %w", err)
	}
	return buf.Bytes(), nil
}

// ContractJS is the generated asset: the contract as a frozen global.
//
// A plain script rather than a module, and a global rather than an import, because the bundle is three
// static files served from an embedded FS with no build step (§2.2) — and frozen because the browser's
// evaluator reads it on every keystroke and must not be able to edit the rules it is evaluating.
func ContractJS() ([]byte, error) {
	doc, err := ContractJSON()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("// Generated by internal/webui: go test ./internal/webui -run TestContractAsset -update\n")
	buf.WriteString("// Every table in §22 lives in Go; this file is that table set, and the bundled\n")
	buf.WriteString("// script evaluates it. Do not edit by hand — a drift test compares this against\n")
	buf.WriteString("// the tables and fails the build if they disagree.\n")
	buf.WriteString("window.LABVIEW_CONTRACT = Object.freeze(")
	buf.Write(bytes.TrimRight(doc, "\n"))
	buf.WriteString(");\n")
	return buf.Bytes(), nil
}

// ContractAsset is the path of the generated file inside the bundle.
const ContractAsset = "assets/contract.js"
