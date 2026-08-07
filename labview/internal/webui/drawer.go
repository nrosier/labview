package webui

// §22.4: one service, everything known about it, **findings first and raw last** — then equivalent
// drawers for networks, routes, applications, routers and probed services. One panel or drawer is
// open at a time (§22.1: Escape closes the topmost layer only).
//
// The order is the argument. A drawer that opened on the image name and the restart policy would put
// the reader's attention on the least consequential thing known about the service; a drawer that
// opens on the verdict and keeps the payload subtree at the bottom answers *is this exposed* before
// it answers *what is it*. §22.4 fixes that order, so it is a table here rather than a layout
// decision in whatever renders it.
//
// Two sections carry rules that are easy to lose and are stated on the section itself:
//
//   - **Connections reads the uncapped relation set.** A diagram may drop a spoke and say so
//     (§22.5); the drawer may not, because the drawer is where the reader goes to find the spoke the
//     diagram dropped.
//   - **Raw contributes no coverage.** §22.4 says it plainly: the subtree dump "MUST NOT be how a
//     field satisfies the §22.1 coverage rule". coverage.go skips any section with Raw set, so a new
//     payload field cannot be waved through by the escape hatch.

// Section is one section of one drawer.
type Section struct {
	// ID is the stable identifier; `panel` and the generated contract use it (§22.7).
	ID    string `json:"id"`
	Title string `json:"title"`

	// Fields are the payload leaves this section shows (coverage.go).
	Fields []string `json:"fields,omitempty"`

	// Raw marks the escape-hatch section. Its Fields are ignored by the coverage check.
	Raw bool `json:"raw,omitempty"`

	// Uncapped marks a section that MUST show the whole relation set rather than a capped view
	// (§22.4 rule 6).
	Uncapped bool `json:"uncapped,omitempty"`

	// Note is the sentence under the section heading.
	Note string `json:"note,omitempty"`
}

// Drawer is one object's drawer.
type Drawer struct {
	// Kind is the object: the `panel` value that opens it, and the prefix a section is named by in a
	// coverage failure (`service:verdict`).
	Kind string `json:"kind"`

	Title string `json:"title"`

	// Opens states what click opens this drawer, so every drawer has a stated way in — a drawer
	// reachable from nowhere is a section of the payload with no place to appear.
	Opens string `json:"opens"`

	Sections []Section `json:"sections"`
}

// Drawers is §22.4's set: the service drawer in §22.4's order, then the equivalents.
var Drawers = []Drawer{
	{
		Kind:  "service",
		Title: "Service",
		Opens: "a row in Services, a node in any diagram, or the svc parameter",
		Sections: []Section{
			{
				ID:    "identity",
				Title: "Identity",
				Fields: []string{
					"stacks.services.name", "stacks.services.containerName", "stacks.services.image",
					"stacks.services.docker.imageDigest", "stacks.services.command", "stacks.services.restart",
				},
				Note: "stack, service and container name, image with digest, command, restart policy",
			},
			{
				ID:    "verdict",
				Title: "Verdict",
				Fields: []string{
					"stacks.services.ingress",
					"stacks.services.auth.method", "stacks.services.auth.confidence",
					"stacks.services.auth.evidence", "stacks.services.auth.detail",
					"stacks.services.auth.exposedWithoutAuth",
				},
				Note: "the ingress set, the method with its confidence and evidence, the exposure state, and the no-auth reason in its own words",
			},
			{
				ID:    "reachability",
				Title: "Reachability",
				Fields: []string{
					"stacks.services.cloudflare.hostname", "stacks.services.cloudflare.path",
					"stacks.services.cloudflare.service", "stacks.services.cloudflare.noTlsVerify",
					"stacks.services.cloudflare.raw",
					"stacks.services.cloudflare.access.group", "stacks.services.cloudflare.access.policy",
					"stacks.services.cloudflare.access.emails",
					"stacks.services.cloudflare.origin.address", "stacks.services.cloudflare.origin.host",
					"stacks.services.cloudflare.origin.port", "stacks.services.cloudflare.origin.kind",
					"stacks.services.cloudflare.origin.hopKey", "stacks.services.cloudflare.origin.evidence",
					"stacks.services.traefik.router", "stacks.services.traefik.rule",
					"stacks.services.traefik.hosts", "stacks.services.traefik.pathPrefixes",
					"stacks.services.traefik.entrypoints", "stacks.services.traefik.tls",
					"stacks.services.traefik.certResolver", "stacks.services.traefik.middlewares",
					"stacks.services.traefik.service", "stacks.services.traefik.servicePort",
					"stacks.services.ports.published", "stacks.services.ports.target",
					"stacks.services.ports.protocol", "stacks.services.ports.raw",
					"stacks.services.expose",
				},
				Note: "every route reaching it with its origin resolution and the gate on that path; published and exposed ports — exposed is container-to-container only, and is not a LAN reading",
			},
			{
				ID:    "auth-detail",
				Title: "Authentication detail",
				Fields: []string{
					"stacks.services.authentik.applications.name", "stacks.services.authentik.applications.slug",
					"stacks.services.authentik.applications.group", "stacks.services.authentik.applications.launchUrl",
					"stacks.services.authentik.applications.discoveredVia",
					"stacks.services.authentik.applications.providers.name",
					"stacks.services.authentik.applications.providers.kind",
					"stacks.services.authentik.applications.providers.rawKind",
					"stacks.services.authentik.applications.providers.mode",
					"stacks.services.authentik.applications.providers.internalHost",
					"stacks.services.authentik.applications.providers.externalHost",
					"stacks.services.authentik.applications.providers.redirectUris",
					"stacks.services.authentik.applications.providers.backchannel",
					"stacks.services.authentik.applications.providers.outposts",
					"stacks.services.authentik.strength", "stacks.services.authentik.evidence",
					"stacks.services.traefikLive.router", "stacks.services.traefikLive.provider",
					"stacks.services.traefikLive.status", "stacks.services.traefikLive.errors",
					"stacks.services.traefikLive.rule", "stacks.services.traefikLive.hosts",
					"stacks.services.traefikLive.entryPoints", "stacks.services.traefikLive.tls",
					"stacks.services.traefikLive.service", "stacks.services.traefikLive.evidence",
					"stacks.services.traefikLive.middlewares.name", "stacks.services.traefikLive.middlewares.type",
					"stacks.services.traefikLive.middlewares.address", "stacks.services.traefikLive.middlewares.errors",
					"stacks.services.traefikLive.middlewares.viaChain",
					"stacks.services.traefikLive.middlewares.viaEntrypoint",
					"stacks.services.traefikLive.servers.url", "stacks.services.traefikLive.servers.status",
					"stacks.services.notes",
				},
				Note: "identity-provider applications with per-match strength, the live middleware chain with where each entry came from, and any three-way cross-check note",
			},
			{
				ID:    "probe",
				Title: "Probe",
				Fields: []string{
					"stacks.services.probe.endpoint", "stacks.services.probe.vantage",
					"stacks.services.probe.phase", "stacks.services.probe.status",
					"stacks.services.probe.gate", "stacks.services.probe.mediaType",
					"stacks.services.probe.detail", "stacks.services.probe.truncated",
					"stacks.services.probe.redirect.to", "stacks.services.probe.redirect.crossOrigin",
					"stacks.services.probe.refresh.to", "stacks.services.probe.refresh.crossOrigin",
					"stacks.services.probe.form.password", "stacks.services.probe.form.username",
					"stacks.services.probe.form.submit", "stacks.services.probe.form.otp",
					"stacks.services.probe.form.action",
					"stacks.services.probe.state.asked", "stacks.services.probe.state.refusedAt",
					"stacks.services.probe.state.status", "stacks.services.probe.state.challenge",
					"stacks.services.probe.anon.textChars", "stacks.services.probe.anon.links",
					"stacks.services.probe.anon.loginHref", "stacks.services.probe.anon.loginLabel",
					"stacks.services.probe.attempts.endpoint", "stacks.services.probe.attempts.why",
					"stacks.services.probe.attempts.phase", "stacks.services.probe.attempts.code",
					"stacks.services.probe.attempts.detail",
				},
				Note: "what was asked, what answered, the fact the verdict rested on — or why it was not asked",
			},
			{
				ID:       "connections",
				Title:    "Connections",
				Uncapped: true,
				Fields: []string{
					"stacks.services.dependsOn", "stacks.services.networks",
					"graph.edges.source", "graph.edges.target", "graph.edges.kind",
					"graph.edges.via", "graph.edges.label", "graph.edges.flow",
					"graph.edges.flowSource", "graph.edges.declaredBy.file", "graph.edges.declaredBy.detail",
				},
				Note: "dependencies in both directions with the network each crosses, co-members kept distinct from dependencies, and an empty via shown as the finding it is; read from the uncapped set, so a spoke a diagram dropped is still answerable here",
			},
			{
				ID:    "storage",
				Title: "Storage",
				Fields: []string{
					"stacks.services.mounts.type", "stacks.services.mounts.source",
					"stacks.services.mounts.target", "stacks.services.mounts.readOnly",
					"stacks.services.mounts.raw",
				},
			},
			{
				ID:    "config",
				Title: "Configuration",
				Fields: []string{
					"stacks.services.env.key", "stacks.services.env.value",
					"stacks.services.env.masked", "stacks.services.env.source",
					"stacks.services.labels",
				},
				Note: "env vars with source and masked values, labels grouped by prefix — a masked value is absent, not starred (I6)",
			},
			{
				ID:    "declaration",
				Title: "Declaration",
				Fields: []string{
					"stacks.services.declared.file", "stacks.services.declared.description",
					"stacks.services.declared.owner", "stacks.services.declared.criticality",
					"stacks.services.declared.notes", "stacks.services.declared.data",
					"stacks.services.declared.links.label", "stacks.services.declared.links.url",
					"stacks.services.declared.dependencies.name", "stacks.services.declared.dependencies.detail",
					"stacks.services.declared.auth.mechanism", "stacks.services.declared.auth.detail",
					"stacks.services.declared.authAgreement",
					"stacks.services.declared.dependsOn.ref", "stacks.services.declared.dependsOn.detail",
					"stacks.services.declared.unauthenticatedAccepted.reason",
					"stacks.services.declared.expectedIngress",
					"stacks.services.declared.drift", "stacks.services.declared.unconfirmed",
				},
				Note: "every declared field, the agreement, and this service's drift and not-confirmed entries",
			},
			{
				ID:    "raw",
				Title: "Raw",
				Raw:   true,
				Note:  "the service's payload subtree, copyable. An escape hatch — and explicitly not how a field satisfies the coverage rule (§22.4)",
			},
		},
	},
	{
		Kind:  "network",
		Title: "Network",
		Opens: "a row in Networks, a network node in the networks diagram, or the net parameter",
		Sections: []Section{
			{
				ID:     "identity",
				Title:  "Identity",
				Fields: []string{"graph.nodes.id", "graph.nodes.label", "graph.nodes.kind", "graph.nodes.scope", "graph.nodes.stack"},
				Note:   "name, scope and the stack that declared it",
			},
			{
				ID:     "members",
				Title:  "Members",
				Fields: []string{"graph.nodes.memberCount", "graph.nodes.stackCount"},
				Note:   "who is joined to it, and from how many stacks — membership is not a dependency (§16)",
			},
			{
				ID:       "crossing",
				Title:    "Dependencies across it",
				Uncapped: true,
				Fields:   []string{"graph.edges.id", "graph.edges.via"},
				Note:     "the dependencies that actually cross this network, uncapped",
			},
			{ID: "raw", Title: "Raw", Raw: true},
		},
	},
	{
		Kind:  "route",
		Title: "Route",
		Opens: "a row in Ingress, or a hostname node in the ingress-paths diagram",
		Sections: []Section{
			{
				ID:     "path",
				Title:  "The path",
				Fields: []string{"graph.nodes.ingress", "graph.nodes.role"},
				Note:   "outside → hostname → tunnel or router → origin → service, with the gate on the path",
			},
			{
				ID:    "gate",
				Title: "The gate",
				Note:  "what stands on this path, and the evidence for it — which is not always the service's overall posture",
			},
			{ID: "raw", Title: "Raw", Raw: true},
		},
	},
	{
		Kind:  "application",
		Title: "Application",
		Opens: "a row in Identity, or an application node in the identity diagram",
		Sections: []Section{
			{ID: "identity", Title: "Application", Note: "slug, name, group and launch URL as the provider reported them"},
			{ID: "providers", Title: "Providers", Note: "kind, mode, hosts and outposts; an unknown kind keeps its raw spelling"},
			{ID: "match", Title: "Match", Note: "the service it protects and at what strength, or the reason it matched nothing with the trace of what was considered"},
			{ID: "raw", Title: "Raw", Raw: true},
		},
	},
	{
		Kind:  "router",
		Title: "Live router",
		Opens: "a row in Proxy, or a router node in the ingress-paths diagram",
		Sections: []Section{
			{ID: "router", Title: "Router", Note: "provider, rule, hosts, entrypoints and TLS as the proxy reports them"},
			{ID: "chain", Title: "Middleware chain", Note: "each entry with where it came from: named, reached through a chain, or applied by the entrypoint"},
			{ID: "backends", Title: "Backends", Note: "the servers and their status, and the proxy's errors verbatim"},
			{ID: "raw", Title: "Raw", Raw: true},
		},
	},
	{
		Kind:  "probe",
		Title: "Probe result",
		Opens: "a row in Probe, or the probe section of a service drawer",
		Sections: []Section{
			{ID: "asked", Title: "What was asked", Note: "the vantage and the address — the vantage is what the answer is about"},
			{ID: "answered", Title: "What answered", Note: "phase, status, media type, redirects and whether the body was truncated"},
			{ID: "verdict", Title: "Verdict", Note: "the gate reading and the one fact it rested on"},
			{ID: "raw", Title: "Raw", Raw: true},
		},
	},
	{
		Kind:  "report",
		Title: "Connection report",
		Opens: "a row in Diagnostics, or the banner on an affected view",
		Sections: []Section{
			{ID: "outcome", Title: "Outcome", Note: "target, phase and what was read — disabled and not-configured are settings, not failures"},
			{ID: "fix", Title: "Fix", Note: "the detail, the code and the hint that says what would make it work"},
			{ID: "candidates", Title: "Rejected candidates", Note: "every endpoint considered and its why"},
			{ID: "raw", Title: "Raw", Raw: true},
		},
	},
	{
		Kind:  "build",
		Title: "Build stamp",
		Opens: "the build-stamp card on the overview (§22.3)",
		Sections: []Section{
			{
				ID:     "stamp",
				Title:  "This build",
				Fields: []string{"meta.build.version", "meta.build.commit", "meta.build.source"},
				Note:   "version, commit, source — and what that source means: stamped at link time, read from the module's own build info, or unknown (§3.4)",
			},
		},
	},
}

// DrawerOf finds a drawer by kind.
func DrawerOf(kind string) (Drawer, bool) {
	for _, d := range Drawers {
		if d.Kind == kind {
			return d, true
		}
	}
	return Drawer{}, false
}

// PanelIDs is every `panel` value §22.7 can carry: one per drawer section, prefixed by its kind, plus
// the bounded lists a card opens instead of a view (§22.3).
//
// Derived from the table rather than listed, so a section added without a way to address it is
// impossible — §22.7 requires every drawer and panel to be expressible in the URL.
func PanelIDs() []string {
	out := make([]string, 0, 48)
	for _, d := range Drawers {
		for _, s := range d.Sections {
			out = append(out, d.Kind+":"+s.ID)
		}
	}
	return append(out, ListPanels...)
}

// The two panels that select a **row set** rather than a place to scroll to.
//
// A `panel` naming a drawer section says *open this drawer, at this section*. These two say *this
// view, showing its other rows*: the Diagrams view's edge list, which §22.5 requires to exist and be
// reachable from the diagram, and the Diagnostics view's scan warnings, which are a different list
// from its connection reports and are what §22.3's warning card links to.
//
// There are only two because everything else a card counts is a view with a filter, and a filter is
// already addressable. A panel for *unmatched applications* would be a second way to say
// `view=applications&match=unmatched` — and two spellings of one destination is how a card and its
// view start to disagree (§22.3).
const (
	PanelEdges    = "edges"
	PanelWarnings = "list:warnings"
)

// ListPanels are the panels that are not drawer sections.
var ListPanels = []string{PanelEdges, PanelWarnings}
