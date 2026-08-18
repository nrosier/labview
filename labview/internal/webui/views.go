package webui

// §22.2: fourteen views, grouped Fleet · Reachability · Runtime · Enrichment · Operator · System.
// Each is one row per object, filterable (§22.6) and addressable (§22.7).
//
// The table below is the whole declaration. Three things depend on it, which is why it is data rather
// than fourteen render functions:
//
//   - **The coverage check** (§22.1, §23). A column's Fields are the payload leaves it shows, so the
//     answer to *where does this field appear* is derived from the same statement that draws it. A
//     column that stops showing a field stops covering it in the same edit.
//   - **The generated contract** (contract.go). The browser is given this table; it holds no view
//     slug, header or column key of its own.
//   - **The card destinations** (§22.3). A card resolves to a view slug and a filter, and the check
//     that a card's destination shows exactly the rows it counted needs both halves in Go.
//
// Question and RowNoun are §22.2's own two columns, kept verbatim rather than paraphrased: they are
// what the view puts at the top of the page, and a view whose heading disagrees with the spec's
// question is answering something nobody asked for.

// Group is a navigation group (§22.2).
type Group string

const (
	GroupFleet        Group = "Fleet"
	GroupReachability Group = "Reachability"
	GroupRuntime      Group = "Runtime"
	GroupEnrichment   Group = "Enrichment"
	GroupOperator     Group = "Operator"
	GroupSystem       Group = "System"
)

// Groups is the navigation order.
var Groups = []Group{GroupFleet, GroupReachability, GroupRuntime, GroupEnrichment, GroupOperator, GroupSystem}

// RowKind is what one row of a view is: which projection of the payload Rows returns (§22.2's *one
// row is* column, as something the code can dispatch on).
type RowKind string

const (
	RowStat        RowKind = "stat"
	RowStack       RowKind = "stack"
	RowService     RowKind = "service"
	RowRoute       RowKind = "route"
	RowNetwork     RowKind = "network"
	RowDiagram     RowKind = "diagram"
	RowContainer   RowKind = "container"
	RowStorage     RowKind = "storage"
	RowConfig      RowKind = "config"
	RowApplication RowKind = "application"
	RowRouter      RowKind = "router"
	RowProbe       RowKind = "probe"
	RowDeclaration RowKind = "declaration"
	RowReport      RowKind = "report"

	// The three projections a boolean narrowing switches to (§22.7). They are separate kinds rather
	// than a filtered declaration row because the number they must agree with counts entries, not
	// services: `stats.declarationDrift` is the sum of every drift string in the fleet, and a view
	// showing one row per service could not display that count truthfully (§22.3).
	RowDrift       RowKind = "drift"
	RowUnconfirmed RowKind = "unconfirmed"
	RowAccepted    RowKind = "accepted"

	// The two projections a `panel` switches to. §22.5 requires every diagram to have a tabular
	// equivalent *reachable from it*, and §22.3's warning list is a bounded list a card links to —
	// both are row sets of a view that otherwise shows something else, which is what `panel` selects
	// (§22.7).
	RowEdge    RowKind = "edge"
	RowWarning RowKind = "warning"
)

// Column is one column of one view.
type Column struct {
	// Key is the stable identifier: what the URL, the generated contract and the tests call this
	// column. Independent of Header, so wording can change without breaking a shared link.
	Key string `json:"key"`

	// Header is the label shown.
	Header string `json:"header"`

	// Fields are the payload leaves this column shows, as dotted JSON paths relative to the root of
	// Appendix A (coverage.go). This is the coverage map of §22.1.
	Fields []string `json:"fields,omitempty"`

	// Set is the vocabulary when the cell is a union member, so the tone and the label come from one
	// place (§22.1). Empty when the cell is free text or a number.
	Set Set `json:"set,omitempty"`

	// Dim is the filter dimension this column's value belongs to, so a cell can offer *filter to
	// this* without a second table saying which column filters what (§22.6). Empty when the column
	// is not filterable.
	Dim Dim `json:"dim,omitempty"`

	// Numeric right-aligns and sorts as a number.
	Numeric bool `json:"numeric,omitempty"`

	// Icon is a glyph drawn beside a numeric cell whose count is not zero, as a token rather than as
	// drawing instructions — the same arrangement as View.Icon, and for the same reason: the bundle's
	// icon table turns a token into a path, and the choice of which count is worth marking is this
	// file's.
	//
	// Only on a count, and only when the count is nonzero: the icon is there to make a row with
	// something to report findable at a glance, and one drawn beside every zero would mark every row
	// and therefore none. It is not a colour — §22.1 reserves those — so it carries its own
	// distinction and takes nothing from the two emphasis tones (tone.go).
	Icon string `json:"icon,omitempty"`

	// Evidence marks a column whose cell carries the evidence, detail or notes that produced it —
	// §22.1: *evidence is never more than one interaction away*.
	Evidence bool `json:"evidence,omitempty"`

	// Note is the sentence under the header, for a column whose honest reading is not obvious.
	Note string `json:"note,omitempty"`
}

// View is one of §22.2's fourteen.
type View struct {
	// Slug is the `view` parameter (§22.7). The overview's is the one that is omitted.
	Slug  string
	Title string
	Group Group

	// Icon is the navigation glyph, as a token rather than as drawing instructions.
	//
	// It is here, in the view table, for the same reason the title is: the bundle holds no view slug of
	// its own (contract.go), so a browser that picked its own icon per view would be keying off a
	// spelling this file owns. The token names the shape; the bundle's icon table turns it into a path.
	// A token the bundle has no shape for draws the fallback dot rather than nothing, so adding a view
	// here without drawing it is a plain navigation entry, not an invisible one.
	Icon string

	// Question is §22.2's *question it answers*, shown as the view's subtitle.
	Question string

	// RowNoun is §22.2's *one row is*, singular. It is what the row count is counted in, so a view
	// that says *31 routes* rather than *31 rows* is reading its own noun.
	RowNoun string

	// Kind is the projection Rows returns for this view.
	Kind RowKind

	Columns []Column

	// Fields are payload leaves this view shows outside any column: a banner, a summary header, an
	// expandable list under the table. They count for coverage exactly as a column's do — §22.1 asks
	// for a *place to appear*, not for a cell.
	Fields []string

	// Order is the stated sort. §22.1 requires determinism and §22.2 requires findings to lead, so
	// the ordering rule is written down beside the view rather than left to whatever the renderer
	// does with equal keys.
	Order string

	// Empty is what the reader sees when there are no rows (§22.8). Never a bare empty table: either
	// the setting that would populate it, or the filter to remove.
	Empty string

	// Dims are the filter dimensions that apply here. A dimension a view cannot honour is not
	// offered, because a chip that narrows nothing is a filter with no way back (§22.6).
	Dims []Dim
}

// Views is §22.2's table. Order is navigation order.
var Views = []View{
	{
		Slug:     SlugOverview,
		Title:    "Overview",
		Group:    GroupFleet,
		Icon:     "layout-dashboard",
		Question: "what is here, and what needs attention",
		RowNoun:  "statistic",
		Kind:     RowStat,
		Columns: []Column{
			{Key: "card", Header: "Statistic"},
			{Key: "count", Header: "Count", Numeric: true, Note: "an absent optional count reads not reported, never 0"},
			{Key: "destination", Header: "Shows", Note: "every card is a link, and the destination shows exactly these rows"},
		},
		Order: "§22.3's card order: the exposure finding first and above the fold, then the fleet, reachability, declarations, probe, networks and integrations",
		Empty: "No payload yet. The first scan is in flight; the health route never waits on it (§18).",
	},
	{
		Slug:     SlugStacks,
		Title:    "Stacks",
		Group:    GroupFleet,
		Icon:     "layers",
		Question: "how the tree is laid out",
		RowNoun:  "stack",
		Kind:     RowStack,
		// Six columns: what a stack *is* and what about it needs attention. The tree — directory,
		// compose file, project name, env file, declared networks and volumes, the stack's own
		// declaration — is in the drawer this view's rows open (drawer.go), which is where a reader who
		// is asking about one stack goes rather than a reader who is scanning thirty of them. §22.1 is
		// satisfied either way: a drawer section is a place to appear, and the coverage check counts it
		// (coverage.go). What the split changes is the width of the table, which was thirteen columns of
		// mostly paths.
		Columns: []Column{
			{Key: "name", Header: "Stack", Fields: []string{"stacks.id", "stacks.name"}},
			{Key: "services", Header: "Services", Numeric: true, Note: "the count links to them"},
			{Key: "ingressRollup", Header: "Ingress", Set: SetIngressKind, Dim: DimIngress, Note: "every distinct kind in the stack; none rolls up to nothing"},
			{Key: "authRollup", Header: "Auth", Set: SetAuthMethod, Dim: DimAuth, Note: "every distinct mechanism in the stack — a roll-up, and filtering is still service-level"},
			{Key: "exposed", Header: "Exposed", Numeric: true, Set: SetFinding, Note: "services reachable from outside with no gate"},
			{Key: "warnings", Header: "Warnings", Fields: []string{"stacks.warnings"}, Numeric: true, Icon: "alert-triangle", Evidence: true, Note: "the drawer has the scan's own words"},
		},
		// Two conditions, in the order §22.1 ranks them: the reserved finding outranks a scan warning,
		// and a warning outranks nothing at all. The emphasis follows the same ranking — the row wash
		// belongs to the exposure, and the warning count carries a glyph instead (Icon above).
		Order: "exposed stacks first, then stacks with warnings, then by name",
		Empty: "No stacks under the apps root. The Diagnostics view states the root that was read.",
		Dims:  []Dim{DimIngress, DimAuth},
	},
	{
		Slug:     SlugServices,
		Title:    "Services",
		Group:    GroupFleet,
		Icon:     "boxes",
		Question: "everything about one service, comparably",
		RowNoun:  "service",
		Kind:     RowService,
		// Where the service is, what state it is in, how it is reached, what stands in front of it, what
		// that adds up to, and whether the operator's description of it still holds. The image, the
		// declaration agreement, the probe verdict and the cross-check notes moved into the service
		// drawer's identity, declaration, probe and authentication-detail sections (drawer.go) — every
		// one of them was already there, so this view is narrower and covers the same payload.
		//
		// Filtering is unchanged: `decl` and `probe` still narrow this view (Dims below), and a
		// dimension can be filtered without having a column of its own — that is what the chips and the
		// controls are for (§22.6).
		Columns: []Column{
			{Key: "stack", Header: "Stack"},
			{Key: "name", Header: "Service", Fields: []string{"stacks.services.name", "stacks.services.containerName"}},
			{Key: "state", Header: "State", Fields: []string{"stacks.services.docker.state", "stacks.services.docker.running"}, Dim: DimState, Note: "not read when the Engine was not read — never stopped (§22.8)"},
			{Key: "ingress", Header: "Ingress", Fields: []string{"stacks.services.ingress"}, Set: SetIngressKind, Dim: DimIngress, Note: "a set, not a category: the three external kinds overlap"},
			{Key: "auth", Header: "Auth", Fields: []string{"stacks.services.auth.method", "stacks.services.auth.confidence", "stacks.services.auth.detail", "stacks.services.auth.evidence"}, Set: SetAuthMethod, Dim: DimAuth, Evidence: true, Note: "confidence is how the gate was established, never how strong it is"},
			{Key: "exposure", Header: "Exposure", Fields: []string{"stacks.services.auth.exposedWithoutAuth"}, Set: SetFinding, Evidence: true},
			{Key: "drift", Header: "Drift", Fields: []string{"stacks.services.declared.drift"}, Numeric: true, Icon: "alert-triangle", Evidence: true, Note: "declarations this scan contradicts, never merely unconfirmed (§22.2)"},
		},
		Order: "exposed without auth first, then by stack and service name",
		Empty: "No service matches. Remove a filter chip to widen it.",
		Dims:  []Dim{DimIngress, DimAuth, DimConf, DimState, DimHealth, DimProbe, DimDecl, DimMatch},
	},
	{
		Slug:     SlugIngress,
		Title:    "Ingress",
		Group:    GroupReachability,
		Icon:     "globe",
		Question: "how each hostname reaches a container",
		RowNoun:  "route",
		Kind:     RowRoute,
		Columns: []Column{
			{Key: "hostname", Header: "Hostname", Fields: []string{"stacks.services.cloudflare.hostname", "stacks.services.traefik.hosts"}},
			{Key: "path", Header: "Path", Fields: []string{"stacks.services.cloudflare.path", "stacks.services.traefik.pathPrefixes"}},
			// Filterable, and by the dimension the row is already tagged with: a route row carries
			// `public` because it is a tunnel ingress and `traefik` because it is a proxy router, so the
			// cell showing the mechanism and the filter narrowing to it are one reading (§22.6).
			{Key: "kind", Header: "Kind", Set: SetIngressKind, Dim: DimIngress,
				Note: "tunnel ingress or proxy router — the mechanism, never the provider (I3)"},
			{Key: "tls", Header: "TLS", Fields: []string{"stacks.services.traefik.tls", "stacks.services.traefik.certResolver", "stacks.services.cloudflare.noTlsVerify"}},
			{Key: "entrypoints", Header: "Entrypoints", Fields: []string{"stacks.services.traefik.entrypoints"}},
			{Key: "middleware", Header: "Middleware", Fields: []string{"stacks.services.traefik.middlewares"}, Evidence: true},
			{Key: "router", Header: "Router", Fields: []string{"stacks.services.traefik.router", "stacks.services.traefik.rule"}},
			{Key: "origin", Header: "Origin", Fields: []string{"stacks.services.cloudflare.service", "stacks.services.cloudflare.origin.address", "stacks.services.cloudflare.origin.host", "stacks.services.cloudflare.origin.port", "stacks.services.cloudflare.origin.kind", "stacks.services.cloudflare.origin.hopKey", "stacks.services.cloudflare.origin.evidence", "stacks.services.cloudflare.raw"}, Set: SetOriginKind, Evidence: true, Note: "how the address resolved, and the hop it resolved through"},
			{Key: "target", Header: "Target service", Fields: []string{"stacks.services.traefik.service", "stacks.services.traefik.servicePort"}},
			{Key: "gate", Header: "Gate on this path", Fields: []string{"stacks.services.cloudflare.access.group", "stacks.services.cloudflare.access.policy", "stacks.services.cloudflare.access.emails"}, Set: SetAuthMethod, Dim: DimAuth, Evidence: true, Note: "the gate on this route, which is not always the service's overall posture"},
		},
		Order: "ungated external paths first, then by hostname and path",
		Empty: "No route reaches a container in this fleet, or none matches the filter.",
		Dims:  []Dim{DimIngress, DimAuth, DimConf},
	},
	{
		Slug:     SlugNetworks,
		Title:    "Networks",
		Group:    GroupReachability,
		Icon:     "network",
		Question: "what connects services and what merely co-locates them",
		RowNoun:  "network",
		Kind:     RowNetwork,
		Columns: []Column{
			{Key: "name", Header: "Network"},
			{Key: "scope", Header: "Scope", Fields: []string{"graph.nodes.scope"}, Set: SetNetworkScope},
			{Key: "driver", Header: "Driver"},
			{Key: "members", Header: "Members", Fields: []string{"graph.nodes.memberCount"}, Numeric: true},
			{Key: "stacks", Header: "Stacks", Fields: []string{"graph.nodes.stackCount"}, Numeric: true},
			{Key: "connects", Header: "Connects", Note: "a network with one member connects nothing, and co-membership is never a dependency (§16)"},
			{Key: "crossing", Header: "Dependencies across it", Fields: []string{"graph.edges.via"}, Numeric: true, Evidence: true},
		},
		Order: "cross-stack networks first, then connecting, then by name",
		Empty: "No network is declared or joined in this fleet.",
		Dims:  []Dim{DimIngress, DimAuth},
	},
	{
		Slug:     SlugDiagrams,
		Title:    "Diagrams",
		Group:    GroupReachability,
		Icon:     "share",
		Question: "the shape of the fleet",
		RowNoun:  "diagram",
		Kind:     RowDiagram,
		Columns: []Column{
			{Key: "diagram", Header: "Diagram"},
			{Key: "shows", Header: "What it draws"},
			{Key: "nodes", Header: "Nodes", Fields: []string{"graph.nodes.id", "graph.nodes.label", "graph.nodes.kind", "graph.nodes.stack", "graph.nodes.role", "graph.nodes.auth", "graph.nodes.ingress", "graph.nodes.running"}, Numeric: true, Set: SetNodeKind},
			{Key: "edges", Header: "Edges", Fields: []string{"graph.edges.id", "graph.edges.source", "graph.edges.target", "graph.edges.kind", "graph.edges.label", "graph.edges.flow", "graph.edges.flowSource", "graph.edges.declaredBy.file", "graph.edges.declaredBy.detail"}, Numeric: true, Set: SetEdgeKind, Evidence: true},
			{Key: "export", Header: "Text export", Note: "the diagram's own source, copyable and deterministic for a payload (§22.5)"},
		},
		Order: "§22.5's order: dependencies, networks, ingress paths, identity and auth",
		Empty: "Nothing to draw: the payload carries no nodes.",
	},
	{
		Slug:     SlugContainers,
		Title:    "Containers",
		Group:    GroupRuntime,
		Icon:     "box",
		Question: "what is actually running",
		RowNoun:  "container",
		Kind:     RowContainer,
		Columns: []Column{
			{Key: "id", Header: "ID", Fields: []string{"stacks.services.docker.id"}},
			{Key: "name", Header: "Name", Fields: []string{"stacks.services.docker.name"}},
			{Key: "image", Header: "Image", Fields: []string{"stacks.services.docker.image", "stacks.services.docker.imageDigest"}, Note: "the digest is what is running, where the tag is only what was asked for"},
			{Key: "state", Header: "State", Fields: []string{"stacks.services.docker.status"}, Dim: DimState},
			{Key: "health", Header: "Health", Fields: []string{"stacks.services.docker.health"}, Set: SetHealth, Dim: DimHealth},
			{Key: "restarts", Header: "Restarts", Fields: []string{"stacks.services.docker.restartCount"}, Numeric: true, Note: "not reported when the Engine did not say — never 0"},
			{Key: "created", Header: "Created", Fields: []string{"stacks.services.docker.createdAt"}},
			{Key: "started", Header: "Started", Fields: []string{"stacks.services.docker.startedAt"}},
			{Key: "ips", Header: "Addresses", Fields: []string{"stacks.services.docker.networks", "stacks.services.docker.ipAddresses"}},
			{Key: "ports", Header: "Published ports", Fields: []string{"stacks.services.docker.publishedPorts.published", "stacks.services.docker.publishedPorts.target", "stacks.services.docker.publishedPorts.protocol", "stacks.services.docker.publishedPorts.raw"}, Note: "what the Engine reports as published, which is the reading that decides LAN reachability"},
		},
		Fields: []string{"meta.dockerAvailable", "meta.dockerError"},
		Order:  "unhealthy first, then not running, then by name",
		Empty:  "The container Engine was not read. Runtime columns read not read rather than stopped; mount the socket read-only to populate them, and Diagnostics states what failed.",
		Dims:   []Dim{DimState, DimHealth},
	},
	{
		Slug:     SlugStorage,
		Title:    "Storage",
		Group:    GroupRuntime,
		Icon:     "hard-drive",
		Question: "where data lives",
		RowNoun:  "mount or volume",
		Kind:     RowStorage,
		Columns: []Column{
			{Key: "type", Header: "Type", Fields: []string{"stacks.services.mounts.type"}, Set: SetMountType},
			{Key: "source", Header: "Source", Fields: []string{"stacks.services.mounts.source", "stacks.services.mounts.raw"}},
			{Key: "target", Header: "Target", Fields: []string{"stacks.services.mounts.target"}},
			{Key: "readOnly", Header: "Read-only", Fields: []string{"stacks.services.mounts.readOnly"}},
			{Key: "service", Header: "Declared by"},
			{Key: "external", Header: "External"},
			{Key: "shared", Header: "Shared with", Numeric: true, Note: "other services mounting the same source — shared storage is a relation the compose files state"},
		},
		Order: "shared sources first, then writable before read-only, then by target",
		Empty: "No service declares a mount or a volume.",
	},
	{
		Slug:     SlugConfig,
		Title:    "Config",
		Group:    GroupRuntime,
		Icon:     "sliders",
		Question: "what each service is configured with",
		RowNoun:  "environment variable or label",
		Kind:     RowConfig,
		Columns: []Column{
			{Key: "key", Header: "Key", Fields: []string{"stacks.services.env.key", "stacks.services.labels"}},
			{Key: "value", Header: "Value", Fields: []string{"stacks.services.env.value", "stacks.services.env.masked"}, Note: "masked values are absent, not starred — a mask that carried the length would carry the secret (I6)"},
			{Key: "source", Header: "Source", Fields: []string{"stacks.services.env.source"}, Set: SetEnvSource, Note: "which file the value came from, or that it was interpolated"},
			{Key: "service", Header: "Service"},
			{Key: "prefix", Header: "Group", Note: "labels grouped by prefix, so one proxy's labels read as one block"},
			{Key: "conclusion", Header: "Produced", Evidence: true, Note: "which conclusion this label produced, quoted from the evidence that cites it"},
		},
		Order: "labels that produced a conclusion first, then by service, then by key",
		Empty: "No environment variable or label matches.",
	},
	{
		Slug:     SlugIdentity,
		Title:    "Identity",
		Group:    GroupEnrichment,
		Icon:     "key",
		Question: "what the identity provider reported",
		RowNoun:  "application",
		Kind:     RowApplication,
		Columns: []Column{
			{Key: "slug", Header: "Slug", Fields: []string{"stacks.services.authentik.applications.slug"}},
			{Key: "name", Header: "Name", Fields: []string{"stacks.services.authentik.applications.name"}},
			{Key: "group", Header: "Group", Fields: []string{"stacks.services.authentik.applications.group"}},
			{Key: "launch", Header: "Launch URL", Fields: []string{"stacks.services.authentik.applications.launchUrl"}},
			{Key: "providers", Header: "Providers", Fields: []string{"stacks.services.authentik.applications.providers.name", "stacks.services.authentik.applications.providers.kind", "stacks.services.authentik.applications.providers.rawKind", "stacks.services.authentik.applications.providers.mode", "stacks.services.authentik.applications.providers.internalHost", "stacks.services.authentik.applications.providers.externalHost", "stacks.services.authentik.applications.providers.redirectUris", "stacks.services.authentik.applications.providers.backchannel"}, Set: SetProviderKind, Note: "kind and mode, with the raw kind kept so an unknown one is readable rather than dropped"},
			{Key: "outposts", Header: "Outposts", Fields: []string{"stacks.services.authentik.applications.providers.outposts"}},
			{Key: "match", Header: "Matched service", Fields: []string{"stacks.services.authentik.strength", "stacks.services.authentik.evidence"}, Set: SetMatchStrength, Dim: DimMatch, Evidence: true, Note: "per-match strength, and what matched"},
			{Key: "via", Header: "Discovered via", Fields: []string{"stacks.services.authentik.applications.discoveredVia"}, Set: SetDiscoveredVia, Dim: DimMatch, Note: "a record rebuilt from a provider is tagged rebuilt, because it is not what the applications endpoint returned"},
		},
		Fields: []string{
			"meta.authentik.enabled", "meta.authentik.configured", "meta.authentik.reachable",
			"meta.authentik.endpoint", "meta.authentik.endpointSource", "meta.authentik.error",
			"meta.authentik.applications", "meta.authentik.applicationsConfigured",
			"meta.authentik.applicationsWithheld", "meta.authentik.applicationsRecovered",
			"meta.authentik.providers", "meta.authentik.outposts", "meta.authentik.matchedServices",
			"meta.authentik.unmatchedApplications.reason", "meta.authentik.unmatchedApplications.detail",
			"meta.authentik.unmatchedApplications.considered",
			"meta.authentik.unmatchedApplications.application.name",
			"meta.authentik.unmatchedApplications.application.slug",
			"meta.authentik.unmatchedApplications.application.group",
			"meta.authentik.unmatchedApplications.application.launchUrl",
			"meta.authentik.unmatchedApplications.application.discoveredVia",
			"meta.authentik.unmatchedApplications.application.providers.name",
			"meta.authentik.unmatchedApplications.application.providers.kind",
			"meta.authentik.unmatchedApplications.application.providers.rawKind",
			"meta.authentik.unmatchedApplications.application.providers.mode",
			"meta.authentik.unmatchedApplications.application.providers.internalHost",
			"meta.authentik.unmatchedApplications.application.providers.externalHost",
			"meta.authentik.unmatchedApplications.application.providers.redirectUris",
			"meta.authentik.unmatchedApplications.application.providers.backchannel",
			"meta.authentik.unmatchedApplications.application.providers.outposts",
		},
		Order: "unmatched applications first with reason, detail and trace, then matched by slug",
		Empty: "The identity integration is off or not configured. It adds applications, providers, outposts and the service they protect; the withheld and recovered counts sit beside each other because the partial rule is their difference.",
		Dims:  []Dim{DimMatch, DimAuth},
	},
	{
		Slug:     SlugProxy,
		Title:    "Proxy",
		Group:    GroupEnrichment,
		Icon:     "route",
		Question: "what the reverse proxy is actually serving",
		RowNoun:  "live router",
		Kind:     RowRouter,
		Columns: []Column{
			{Key: "router", Header: "Router", Fields: []string{"stacks.services.traefikLive.router", "stacks.services.traefikLive.provider"}},
			{Key: "rule", Header: "Rule", Fields: []string{"stacks.services.traefikLive.rule"}},
			{Key: "hosts", Header: "Hosts", Fields: []string{"stacks.services.traefikLive.hosts"}},
			{Key: "entrypoints", Header: "Entrypoints", Fields: []string{"stacks.services.traefikLive.entryPoints"}},
			{Key: "tls", Header: "TLS", Fields: []string{"stacks.services.traefikLive.tls"}},
			{Key: "status", Header: "Status", Fields: []string{"stacks.services.traefikLive.status", "stacks.services.traefikLive.errors"}, Evidence: true, Note: "the proxy's own words, verbatim"},
			{Key: "middleware", Header: "Middleware chain", Fields: []string{"stacks.services.traefikLive.middlewares.name", "stacks.services.traefikLive.middlewares.type", "stacks.services.traefikLive.middlewares.address", "stacks.services.traefikLive.middlewares.errors", "stacks.services.traefikLive.middlewares.viaChain", "stacks.services.traefikLive.middlewares.viaEntrypoint"}, Evidence: true, Note: "where each entry came from: named on the router, reached through a chain, or applied by the entrypoint"},
			{Key: "servers", Header: "Backend servers", Fields: []string{"stacks.services.traefikLive.servers.url", "stacks.services.traefikLive.servers.status"}},
			{Key: "match", Header: "Matched service", Fields: []string{"stacks.services.traefikLive.service", "stacks.services.traefikLive.evidence"}, Dim: DimMatch, Evidence: true},
		},
		Fields: []string{
			"meta.traefik.enabled", "meta.traefik.configured", "meta.traefik.reachable",
			"meta.traefik.endpoint", "meta.traefik.endpointSource", "meta.traefik.credential",
			"meta.traefik.version", "meta.traefik.entrypointsRead", "meta.traefik.error",
			"meta.traefik.routers", "meta.traefik.middlewares", "meta.traefik.services",
			"meta.traefik.matchedServices",
			"meta.traefik.unmatchedRouters.reason", "meta.traefik.unmatchedRouters.detail",
			"meta.traefik.unmatchedRouters.considered",
			"meta.traefik.unmatchedRouters.router.router", "meta.traefik.unmatchedRouters.router.provider",
			"meta.traefik.unmatchedRouters.router.status", "meta.traefik.unmatchedRouters.router.errors",
			"meta.traefik.unmatchedRouters.router.rule", "meta.traefik.unmatchedRouters.router.hosts",
			"meta.traefik.unmatchedRouters.router.entryPoints", "meta.traefik.unmatchedRouters.router.service",
			"meta.traefik.unmatchedRouters.router.tls", "meta.traefik.unmatchedRouters.router.evidence",
			"meta.traefik.unmatchedRouters.router.middlewares.name",
			"meta.traefik.unmatchedRouters.router.middlewares.type",
			"meta.traefik.unmatchedRouters.router.middlewares.address",
			"meta.traefik.unmatchedRouters.router.middlewares.errors",
			"meta.traefik.unmatchedRouters.router.middlewares.viaChain",
			"meta.traefik.unmatchedRouters.router.middlewares.viaEntrypoint",
			"meta.traefik.unmatchedRouters.router.servers.url",
			"meta.traefik.unmatchedRouters.router.servers.status",
		},
		Order: "unmatched routers first with reason, detail and trace, then by router name",
		Empty: "The proxy integration is off or not configured. It adds the routers actually serving, their middleware chains and their backends; a read-only API credential is enough.",
		Dims:  []Dim{DimMatch, DimAuth, DimIngress},
	},
	{
		Slug:     SlugProbe,
		Title:    "Probe",
		Group:    GroupEnrichment,
		Icon:     "radar",
		Question: "what answered when asked",
		RowNoun:  "probed service",
		Kind:     RowProbe,
		Columns: []Column{
			{Key: "service", Header: "Service"},
			{Key: "vantage", Header: "Vantage", Fields: []string{"stacks.services.probe.vantage"}, Set: SetProbeVantage, Note: "where it was asked from, which is what the answer is about"},
			{Key: "address", Header: "Address", Fields: []string{"stacks.services.probe.endpoint"}},
			{Key: "phase", Header: "Phase", Fields: []string{"stacks.services.probe.phase"}, Set: SetConnectionPhase},
			{Key: "status", Header: "Status", Fields: []string{"stacks.services.probe.status", "stacks.services.probe.mediaType"}, Numeric: true},
			{Key: "verdict", Header: "Verdict", Fields: []string{"stacks.services.probe.gate"}, Set: SetProbeGate, Dim: DimProbe},
			{Key: "fact", Header: "Rested on", Fields: []string{"stacks.services.probe.detail"}, Evidence: true, Note: "the one fact the verdict rested on"},
			{Key: "form", Header: "Form shape", Fields: []string{"stacks.services.probe.form.password", "stacks.services.probe.form.username", "stacks.services.probe.form.submit", "stacks.services.probe.form.otp", "stacks.services.probe.form.action"}},
			{Key: "state", Header: "State challenge", Fields: []string{"stacks.services.probe.state.asked", "stacks.services.probe.state.refusedAt", "stacks.services.probe.state.status", "stacks.services.probe.state.challenge"}, Evidence: true},
			{Key: "anon", Header: "Anonymous reading", Fields: []string{"stacks.services.probe.anon.textChars", "stacks.services.probe.anon.links", "stacks.services.probe.anon.loginHref", "stacks.services.probe.anon.loginLabel"}},
			{Key: "redirect", Header: "Redirect", Fields: []string{"stacks.services.probe.redirect.to", "stacks.services.probe.redirect.crossOrigin", "stacks.services.probe.refresh.to", "stacks.services.probe.refresh.crossOrigin", "stacks.services.probe.truncated"}},
			{Key: "attempts", Header: "Attempts", Fields: []string{"stacks.services.probe.attempts.endpoint", "stacks.services.probe.attempts.why", "stacks.services.probe.attempts.phase", "stacks.services.probe.attempts.code", "stacks.services.probe.attempts.detail"}, Evidence: true},
		},
		Fields: []string{"meta.probe.enabled", "meta.probe.source", "meta.probe.skipped"},
		Order:  "§22.2: answered with no login page, then answered with a login page, then did not answer",
		Empty:  "The probe is off, or nothing was eligible. The switch beside Rescan turns it on for one scan; a service with a detected gate is deliberately not asked.",
		Dims:   []Dim{DimProbe, DimIngress, DimAuth},
	},
	{
		Slug:     SlugDeclarations,
		Title:    "Declarations",
		Group:    GroupOperator,
		Icon:     "file-check",
		Question: "where the operator and the scan disagree",
		RowNoun:  "declaration",
		Kind:     RowDeclaration,
		Columns: []Column{
			{Key: "service", Header: "Service"},
			{Key: "owner", Header: "Owner", Fields: []string{"stacks.services.declared.owner"}},
			{Key: "criticality", Header: "Criticality", Fields: []string{"stacks.services.declared.criticality"}},
			{Key: "description", Header: "Description", Fields: []string{"stacks.services.declared.description", "stacks.services.declared.notes"}},
			{Key: "data", Header: "Data", Fields: []string{"stacks.services.declared.data", "stacks.services.declared.file"}, Note: "the operator's own fields, kept as written"},
			{Key: "links", Header: "Links", Fields: []string{"stacks.services.declared.links.label", "stacks.services.declared.links.url"}},
			{Key: "declaredAuth", Header: "Declared auth", Fields: []string{"stacks.services.declared.auth.mechanism", "stacks.services.declared.auth.detail", "stacks.services.declared.authAgreement"}, Set: SetMechanism, Dim: DimDecl, Evidence: true, Note: "the mechanism the operator declared, and whether the scan agrees"},
			{Key: "dependencies", Header: "Declared dependencies", Fields: []string{"stacks.services.declared.dependsOn.ref", "stacks.services.declared.dependsOn.detail", "stacks.services.declared.dependencies.name", "stacks.services.declared.dependencies.detail"}},
			{Key: "accepted", Header: "Accepted exposure", Fields: []string{"stacks.services.declared.unauthenticatedAccepted.reason"}, Set: SetFinding, Note: "still exposed: an acceptance records a decision and changes nothing about reachability"},
			{Key: "expected", Header: "Expected ingress", Fields: []string{"stacks.services.declared.expectedIngress"}, Set: SetIngressKind},
			{Key: "drift", Header: "Drift", Fields: []string{"stacks.services.declared.drift"}, Numeric: true, Set: SetDeclState, Evidence: true, Note: "the declaration and the scan disagree"},
			{Key: "unconfirmed", Header: "Not confirmed", Fields: []string{"stacks.services.declared.unconfirmed"}, Numeric: true, Set: SetDeclState, Evidence: true, Note: "nothing contradicts the declaration and nothing corroborates it — never merged with drift"},
		},
		Fields: []string{"stacks.services.declared.description", "stacks.services.declared.dependencies.name"},
		Order:  "drift first, then not confirmed, then accepted exposures, then by service",
		Empty:  "No declaration file was found. A declaration states what the operator intends; drift is where the scan disagrees with it.",
		Dims:   []Dim{DimDecl, DimIngress, DimAuth},
	},
	{
		Slug:     SlugDiagnostics,
		Title:    "Diagnostics",
		Group:    GroupSystem,
		Icon:     "activity",
		Question: "what LabView could not do",
		RowNoun:  "connection report",
		Kind:     RowReport,
		Columns: []Column{
			{Key: "target", Header: "Target", Fields: []string{"meta.connections.target"}, Note: "the mechanism read, not the vendor behind it (I3)"},
			{Key: "phase", Header: "Phase", Fields: []string{"meta.connections.ok", "meta.connections.phase"}, Set: SetConnectionPhase, Note: "how far it got: disabled and not-configured are settings, everything after them is a failure"},
			{Key: "endpoint", Header: "Endpoint", Fields: []string{"meta.connections.endpoint", "meta.connections.source"}, Set: SetEndpointSource},
			{Key: "detail", Header: "Detail", Fields: []string{"meta.connections.detail", "meta.connections.code"}, Evidence: true},
			{Key: "hint", Header: "Fix", Fields: []string{"meta.connections.hint"}, Note: "what would make it work"},
			{Key: "read", Header: "What was read", Fields: []string{"meta.connections.read"}, Note: "on a partial read, the half that arrived"},
			{Key: "attempts", Header: "Rejected candidates", Fields: []string{"meta.connections.attempts.endpoint", "meta.connections.attempts.why", "meta.connections.attempts.phase", "meta.connections.attempts.code", "meta.connections.attempts.detail"}, Evidence: true, Note: "every endpoint considered and why it was not used"},
		},
		Fields: []string{
			"meta.warnings", "meta.durationMs", "meta.scannedAt", "meta.appsRoot",
			"meta.build.version", "meta.build.commit", "meta.build.source",
			"meta.dockerAvailable", "meta.dockerError",
		},
		Order: "failures and partial first, then by target",
		Empty: "Every integration that was asked for answered, and the scan reported no warning.",
	},
}

// ViewOf resolves a slug (§22.7). The overview answers to both its slug and the empty string, which
// is what makes `?view=overview` and an empty query the same state.
func ViewOf(slug string) (View, bool) {
	if slug == "" {
		slug = SlugOverview
	}
	for _, v := range Views {
		if v.Slug == slug {
			return v, true
		}
	}
	return View{}, false
}

// ViewSlugs is every slug, in navigation order.
func ViewSlugs() []string {
	out := make([]string, 0, len(Views))
	for _, v := range Views {
		out = append(out, v.Slug)
	}
	return out
}

// ViewsIn is one navigation group's views.
func ViewsIn(g Group) []View {
	var out []View
	for _, v := range Views {
		if v.Group == g {
			out = append(out, v)
		}
	}
	return out
}

// ColumnOf finds a column by key.
func (v View) ColumnOf(key string) (Column, bool) {
	for _, c := range v.Columns {
		if c.Key == key {
			return c, true
		}
	}
	return Column{}, false
}

// Has reports whether a dimension applies to this view (§22.6).
func (v View) Has(d Dim) bool {
	for _, dim := range v.Dims {
		if dim == d {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The frame around every view
// ---------------------------------------------------------------------------

// Chrome is what the persistent frame shows on every view: §22.2's last rule (a rescan control, with
// the change note, the scanned-at time and the probe switch re-synced from the payload) and §22.8's
// banners.
//
// It is declared as a place fields can appear because it is one: `meta.scannedAt` has no column
// anywhere and needs none — it belongs in the frame, and the coverage check should be satisfied by
// saying so rather than by wedging a column into a view to hold it.
var Chrome = struct {
	Fields []string
	Note   string
}{
	Fields: []string{
		"meta.scannedAt",
		"meta.probe.enabled",
		"meta.probe.source",
		"meta.durationMs",
		"meta.build.version",
		"meta.build.commit",
		"meta.build.source",
		"meta.warnings",
		"meta.dockerAvailable",
		"meta.dockerError",
	},
	Note: "the rescan control with the change note and the probe switch, re-synced from meta.probe.enabled on every payload; the connection banner; the build stamp",
}
