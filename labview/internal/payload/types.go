package payload

// Appendix A, in order. The JSON tag on every field is the contract; the Go name is not.
//
// Optional fields follow one rule (§16). Where "present and zero" says something
// different from "absent" — a false noTlsVerify label as against no such label, a
// restart count of 0 as against a container that never reported one — the field is a
// pointer with no omitempty, so nil is the absence and false or 0 is a reading. Where
// empty and absent mean the same thing, as with every optional string, the field is a
// plain value with omitempty.
//
// A required list or map is a plain slice or map, which Go would marshal as null when
// nil. Normalize (normalize.go) is what guarantees they go out as [] and {} instead, so
// a consumer never has to treat null as an empty list.

// Overview is the whole payload: one scan, complete.
type Overview struct {
	Meta   ScanMeta      `json:"meta"`
	Stats  OverviewStats `json:"stats"`
	Stacks []AppStack    `json:"stacks"`
	Graph  Graph         `json:"graph"`
}

// ScanRequest is the body of POST /api/rescan (§18). Probe absent means "whatever
// configuration says"; present means this request overrides it for this build (§13.7).
type ScanRequest struct {
	Probe *bool `json:"probe,omitempty"`
}

// Health is the body of GET /api/healthz (§18). It runs no scan, so it reports only that
// the process is answering.
type Health struct {
	OK bool `json:"ok"`
}

// ---------------------------------------------------------------------------
// Scan metadata
// ---------------------------------------------------------------------------

// ScanMeta is everything about the scan itself rather than about the fleet.
type ScanMeta struct {
	ScannedAt       string `json:"scannedAt"`
	AppsRoot        string `json:"appsRoot"`
	DockerAvailable bool   `json:"dockerAvailable"`
	DockerError     string `json:"dockerError,omitempty"`
	// Authentik and Traefik are absent when that integration produced no summary at
	// all. A disabled or unconfigured integration still produces one — with enabled or
	// configured false — because "switched off" is a reading the Diagnostics view has
	// to be able to show (§15).
	Authentik   *AuthentikSummary  `json:"authentik,omitempty"`
	Traefik     *TraefikSummary    `json:"traefik,omitempty"`
	Connections []ConnectionReport `json:"connections"`
	Probe       ProbeRun           `json:"probe"`
	DurationMs  int                `json:"durationMs"`
	Warnings    []string           `json:"warnings"`
	Build       BuildStamp         `json:"build"`
}

// ProbeRun describes the probe's mode for this build. Never optional: a payload that
// omitted it would leave a reader unable to tell a probe that found nothing from a probe
// that never ran (§13.7).
type ProbeRun struct {
	Enabled bool           `json:"enabled"`
	Source  ProbeRunSource `json:"source"`
	// Skipped counts services the probe declined to ask about — no external ingress, or
	// no address it could form.
	Skipped int `json:"skipped"`
}

// BuildStamp identifies the running build (§3.4). Source is never optional; Commit is
// absent entirely when Source is BuildUnknown, rather than being an empty string.
type BuildStamp struct {
	Version string           `json:"version"`
	Commit  string           `json:"commit,omitempty"`
	Source  BuildStampSource `json:"source"`
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// OverviewStats is every counter the Overview view draws. Each one is a card that links
// to a view showing exactly that many rows (§22.3), so a counter that cannot be
// reproduced by filtering is a defect in this struct rather than in the UI.
//
// The three external ingress counters overlap — one service can be public and lan at
// once — so they must never be drawn as a partition. ByAuthMethod does partition (§22.1).
type OverviewStats struct {
	Stacks   int `json:"stacks"`
	Services int `json:"services"`
	Running  int `json:"running"`

	PublicServices    int `json:"publicServices"`
	TraefikServices   int `json:"traefikServices"`
	LanServices       int `json:"lanServices"`
	InternalServices  int `json:"internalServices"`
	NoIngressServices int `json:"noIngressServices"`

	AuthProtected      int                `json:"authProtected"`
	ExposedWithoutAuth int                `json:"exposedWithoutAuth"`
	ByAuthMethod       map[AuthMethod]int `json:"byAuthMethod"`

	DeclaredAuth            int `json:"declaredAuth"`
	DeclaredAuthProtected   int `json:"declaredAuthProtected"`
	DeclaredAuthUnconfirmed int `json:"declaredAuthUnconfirmed"`

	ExposureAccepted     int `json:"exposureAccepted"`
	DeclarationDrift     int `json:"declarationDrift"`
	DeclaredDependencies int `json:"declaredDependencies"`

	ProbeGated int `json:"probeGated"`
	ProbeOpen  int `json:"probeOpen"`

	Networks int `json:"networks"`
	// ConnectingNetworks carry something between services; CrossStackNetworks join two
	// or more stacks; SoloLocalNetworks have one member and are drawn nowhere, which is
	// why drawn network nodes plus SoloLocalNetworks must equal Networks (§8).
	ConnectingNetworks int `json:"connectingNetworks"`
	CrossStackNetworks int `json:"crossStackNetworks"`
	SoloLocalNetworks  int `json:"soloLocalNetworks"`
}

// ---------------------------------------------------------------------------
// Stacks and services
// ---------------------------------------------------------------------------

// AppStack is one directory holding one compose file.
type AppStack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Dir         string `json:"dir"`
	ComposeFile string `json:"composeFile"`
	HasEnvFile  bool   `json:"hasEnvFile"`
	ProjectName string `json:"projectName"`

	Services         []Service     `json:"services"`
	DeclaredNetworks []NetworkDecl `json:"declaredNetworks"`
	DeclaredVolumes  []VolumeDecl  `json:"declaredVolumes"`
	Declared         *Declaration  `json:"declared,omitempty"`
	Warnings         []string      `json:"warnings"`
}

// NetworkDecl is a networks: entry in a compose file. External decides scope: a network
// any stack declared external can carry containers this scan never saw (§8).
type NetworkDecl struct {
	Name     string `json:"name"`
	External bool   `json:"external"`
	Driver   string `json:"driver,omitempty"`
}

// VolumeDecl is a volumes: entry in a compose file.
type VolumeDecl struct {
	Name     string `json:"name"`
	External bool   `json:"external"`
	Driver   string `json:"driver,omitempty"`
}

// Service is one service in one stack, with everything every later stage attached to it.
//
// The scanned fields come first, then the two conclusions Ingress and Auth, then the
// five enrichments — each absent when its source said nothing about this service.
type Service struct {
	Name          string `json:"name"`
	ContainerName string `json:"containerName"`
	Image         string `json:"image,omitempty"`
	Restart       string `json:"restart,omitempty"`
	Command       string `json:"command,omitempty"`

	DependsOn []string          `json:"dependsOn"`
	Networks  []string          `json:"networks"`
	Ports     []PortMapping     `json:"ports"`
	Expose    []string          `json:"expose"`
	Mounts    []MountSpec       `json:"mounts"`
	Env       []EnvVar          `json:"env"`
	Labels    map[string]string `json:"labels"`

	Cloudflare []CloudflareRoute `json:"cloudflare"`
	Traefik    []TraefikRoute    `json:"traefik"`

	Ingress []IngressKind `json:"ingress"`
	Auth    AuthPosture   `json:"auth"`

	Docker      *DockerState        `json:"docker,omitempty"`
	Authentik   *AuthentikMatch     `json:"authentik,omitempty"`
	TraefikLive []TraefikLiveRouter `json:"traefikLive,omitempty"`
	Declared    *ServiceDeclaration `json:"declared,omitempty"`
	Probe       *ServiceProbe       `json:"probe,omitempty"`

	Notes []string `json:"notes"`
}

// EnvVar is one resolved environment entry. Value is a required field that may be null:
// null is a variable declared with no value at all, which is a different reading from a
// variable set to the empty string (§6). Masked says the value was withheld, never that
// it was absent (§20) — a masked entry still carries its key.
type EnvVar struct {
	Key    string       `json:"key"`
	Value  *string      `json:"value"`
	Masked bool         `json:"masked"`
	Source EnvVarSource `json:"source"`
}

// PortMapping is a ports: or an Engine-reported publication. Raw is kept because the
// presence of a published port is the signal, and the exact text is the evidence — no
// rule may depend on a parsed port number (§6).
type PortMapping struct {
	Published string `json:"published,omitempty"`
	Target    string `json:"target"`
	Protocol  string `json:"protocol"`
	Raw       string `json:"raw"`
}

// MountSpec is a volumes: entry on a service.
type MountSpec struct {
	Type     MountType `json:"type"`
	Source   string    `json:"source,omitempty"`
	Target   string    `json:"target"`
	ReadOnly bool      `json:"readOnly"`
	Raw      string    `json:"raw"`
}

// DockerState is what the Engine reported about one container (§10). Health is absent
// when the container declares no health check; RestartCount is a pointer because zero
// restarts and no report are different facts.
type DockerState struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Image       string      `json:"image"`
	ImageDigest string      `json:"imageDigest,omitempty"`
	State       string      `json:"state"`
	Status      string      `json:"status"`
	Health      HealthState `json:"health,omitempty"`

	Running      bool   `json:"running"`
	RestartCount *int   `json:"restartCount,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
	StartedAt    string `json:"startedAt,omitempty"`

	Networks       []string          `json:"networks"`
	IPAddresses    map[string]string `json:"ipAddresses"`
	PublishedPorts []PortMapping     `json:"publishedPorts"`
}

// ---------------------------------------------------------------------------
// Reachability and posture
// ---------------------------------------------------------------------------

// AuthPosture is the one verdict about a service's gate, with the evidence it rests on.
//
// ExposedWithoutAuth is stored rather than derived so that the finding a reader sees and
// the number the counter reports cannot come apart. Confidence is how the gate was
// established, never how severe it is (§4.2).
type AuthPosture struct {
	Method             AuthMethod     `json:"method"`
	Detail             string         `json:"detail"`
	Evidence           []string       `json:"evidence"`
	Confidence         AuthConfidence `json:"confidence"`
	ExposedWithoutAuth bool           `json:"exposedWithoutAuth"`
}

// CloudflareRoute is one tunnel route read from labels (§7). NoTLSVerify is a pointer:
// absent means no such label, false means a label that said false.
type CloudflareRoute struct {
	Hostname string            `json:"hostname"`
	Service  string            `json:"service"`
	Path     string            `json:"path,omitempty"`
	Access   *CloudflareAccess `json:"access,omitempty"`

	NoTLSVerify *bool             `json:"noTlsVerify,omitempty"`
	Raw         map[string]string `json:"raw"`
	Origin      *OriginTarget     `json:"origin,omitempty"`
}

// CloudflareAccess is the access policy a route declared, if any.
type CloudflareAccess struct {
	Group  string   `json:"group,omitempty"`
	Policy string   `json:"policy,omitempty"`
	Emails []string `json:"emails,omitempty"`
}

// OriginTarget is what a route's declared origin address resolved to (§9). HopKey is the
// service key of the hop when Kind is OriginFleetService, and absent otherwise.
type OriginTarget struct {
	Address  string     `json:"address"`
	Host     string     `json:"host"`
	Port     string     `json:"port"`
	Kind     OriginKind `json:"kind"`
	HopKey   string     `json:"hopKey,omitempty"`
	Evidence string     `json:"evidence"`
}

// TraefikRoute is one router read from labels (§7).
//
// Its entrypoints tag is lower-case, while TraefikLiveRouter's is entryPoints. That
// asymmetry is deliberate: the live shape mirrors the proxy's own API spelling, the
// label shape mirrors the label key. Both are contract (Appendix A).
type TraefikRoute struct {
	Router       string   `json:"router"`
	Rule         string   `json:"rule,omitempty"`
	Hosts        []string `json:"hosts"`
	PathPrefixes []string `json:"pathPrefixes"`
	Entrypoints  []string `json:"entrypoints"`
	TLS          bool     `json:"tls"`
	CertResolver string   `json:"certResolver,omitempty"`
	Middlewares  []string `json:"middlewares"`
	ServicePort  string   `json:"servicePort,omitempty"`
	Service      string   `json:"service,omitempty"`
}

// ---------------------------------------------------------------------------
// Identity provider
// ---------------------------------------------------------------------------

// AuthentikProvider is one provider record. RawKind keeps what the API actually said, so
// a kind normalised to ProviderOther is still answerable (I3).
type AuthentikProvider struct {
	Name    string                `json:"name"`
	Kind    AuthentikProviderKind `json:"kind"`
	RawKind string                `json:"rawKind"`
	Mode    string                `json:"mode,omitempty"`

	InternalHost string   `json:"internalHost,omitempty"`
	ExternalHost string   `json:"externalHost,omitempty"`
	RedirectURIs []string `json:"redirectUris,omitempty"`
	Backchannel  bool     `json:"backchannel"`
	Outposts     []string `json:"outposts"`
}

// AuthentikApplication is one application record. DiscoveredVia says whether the list
// returned it or it was rebuilt from a provider — a rebuilt record is thinner, and the
// UI must say so (§11).
type AuthentikApplication struct {
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Group     string `json:"group,omitempty"`
	LaunchURL string `json:"launchUrl,omitempty"`

	Providers     []AuthentikProvider `json:"providers"`
	DiscoveredVia DiscoveredVia       `json:"discoveredVia"`
}

// AuthentikMatch ties applications to one service. The three lists are parallel: entry i
// of Strength is how entry i of Applications was matched, and entry i of Evidence says
// on what. A Strength shorter than Applications reads as StrengthName for the remainder,
// never as the strongest (§4.3).
type AuthentikMatch struct {
	Applications []AuthentikApplication   `json:"applications"`
	Evidence     []string                 `json:"evidence"`
	Strength     []AuthentikMatchStrength `json:"strength"`
}

// UnmatchedApplication is an application no service could be tied to. Considered lists
// what was weighed, so an ambiguous match is answerable rather than merely reported
// (§22, requirement 4).
type UnmatchedApplication struct {
	Application AuthentikApplication `json:"application"`
	Reason      UnmatchedReason      `json:"reason"`
	Detail      string               `json:"detail"`
	Considered  []string             `json:"considered"`
}

// AuthentikSummary is the identity-provider read as a whole (§11).
//
// ApplicationsConfigured is the count the API itself claimed, absent when it claimed
// none. Withheld minus Recovered is what stayed invisible — the reason both counts are
// carried rather than a single difference.
//
// EndpointSource here is only SourceConfig or SourceDiscovered: there is no default
// identity-provider address to fall back to.
type AuthentikSummary struct {
	Enabled    bool   `json:"enabled"`
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Endpoint   string `json:"endpoint,omitempty"`

	EndpointSource EndpointSource `json:"endpointSource,omitempty"`
	Error          string         `json:"error,omitempty"`

	Applications           int  `json:"applications"`
	ApplicationsConfigured *int `json:"applicationsConfigured,omitempty"`
	ApplicationsWithheld   int  `json:"applicationsWithheld"`
	ApplicationsRecovered  int  `json:"applicationsRecovered"`

	Providers       int `json:"providers"`
	Outposts        int `json:"outposts"`
	MatchedServices int `json:"matchedServices"`

	UnmatchedApplications []UnmatchedApplication `json:"unmatchedApplications"`
}

// ---------------------------------------------------------------------------
// Reverse proxy
// ---------------------------------------------------------------------------

// TraefikLiveMiddleware is one middleware on a live router. ViaChain names the chain that
// pulled it in; ViaEntrypoint is a pointer because "added by the entrypoint" and "not
// stated" are different readings of the same absent field (§12).
type TraefikLiveMiddleware struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Address string   `json:"address,omitempty"`
	Errors  []string `json:"errors"`

	ViaChain      string `json:"viaChain,omitempty"`
	ViaEntrypoint *bool  `json:"viaEntrypoint,omitempty"`
}

// TraefikLiveServer is one backend address the proxy holds for a service. An absent
// Status means nothing is known about it, not that it is down (Appendix A).
type TraefikLiveServer struct {
	URL    string `json:"url"`
	Status string `json:"status,omitempty"`
}

// TraefikLiveRouter is one router the proxy's API reported (§12).
type TraefikLiveRouter struct {
	Router   string   `json:"router"`
	Provider string   `json:"provider"`
	Status   string   `json:"status,omitempty"`
	Errors   []string `json:"errors"`
	Rule     string   `json:"rule,omitempty"`

	Hosts       []string                `json:"hosts"`
	EntryPoints []string                `json:"entryPoints"`
	Middlewares []TraefikLiveMiddleware `json:"middlewares"`
	Service     string                  `json:"service,omitempty"`
	Servers     []TraefikLiveServer     `json:"servers"`
	TLS         bool                    `json:"tls"`
	Evidence    []string                `json:"evidence"`
}

// UnmatchedRouter is a live router no service could be tied to.
type UnmatchedRouter struct {
	Router     TraefikLiveRouter `json:"router"`
	Reason     UnmatchedReason   `json:"reason"`
	Detail     string            `json:"detail"`
	Considered []string          `json:"considered"`
}

// TraefikSummary is the proxy read as a whole (§12). Credential CredentialNone means the
// API answered without one, which is itself evidence about how that API is exposed.
// EntrypointsRead says whether the entrypoint list was obtained, because a middleware
// attributed to an entrypoint is only assertable when it was.
type TraefikSummary struct {
	Enabled    bool   `json:"enabled"`
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Endpoint   string `json:"endpoint,omitempty"`

	EndpointSource  EndpointSource    `json:"endpointSource,omitempty"`
	Credential      TraefikCredential `json:"credential"`
	Version         string            `json:"version,omitempty"`
	EntrypointsRead bool              `json:"entrypointsRead"`
	Error           string            `json:"error,omitempty"`

	Routers         int `json:"routers"`
	Middlewares     int `json:"middlewares"`
	Services        int `json:"services"`
	MatchedServices int `json:"matchedServices"`

	UnmatchedRouters []UnmatchedRouter `json:"unmatchedRouters"`
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

// ConnectionAttempt is one address tried. Why says what made it a candidate, so a
// reader can tell a configured address from one the scan guessed (§15).
type ConnectionAttempt struct {
	Endpoint string          `json:"endpoint"`
	Why      string          `json:"why"`
	Phase    ConnectionPhase `json:"phase"`
	Code     string          `json:"code,omitempty"`
	Detail   string          `json:"detail"`
}

// ConnectionReport is one outbound target's whole story (§15).
//
// OK is true for PhaseConnected and for PhasePartial — a partial read is useful, and
// treating it as a failure would hide what was read. Hint is the one action to take;
// Read says what was obtained when the read was partial.
type ConnectionReport struct {
	Target   string          `json:"target"`
	OK       bool            `json:"ok"`
	Phase    ConnectionPhase `json:"phase"`
	Endpoint string          `json:"endpoint,omitempty"`
	Source   EndpointSource  `json:"source,omitempty"`
	Detail   string          `json:"detail,omitempty"`
	Code     string          `json:"code,omitempty"`
	Hint     string          `json:"hint,omitempty"`
	Read     string          `json:"read,omitempty"`

	Attempts []ConnectionAttempt `json:"attempts"`
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

// ProbeRedirect is where an answer pointed. CrossOrigin is what separates
// GateRedirectOrigin from GateRedirectLogin (§13.3).
type ProbeRedirect struct {
	To          string `json:"to"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// ProbeState is the second request of §13.4: the page's own client asking for state.
// Asked counts the addresses tried. RefusedAt, Status and Challenge describe the refusal
// that fired GateStateChallenge — Status and Challenge are pointers because a status of 0
// and an absent header are not the same as no second request having happened.
type ProbeState struct {
	Asked     int    `json:"asked"`
	RefusedAt string `json:"refusedAt,omitempty"`
	Status    *int   `json:"status,omitempty"`
	Challenge *bool  `json:"challenge,omitempty"`
}

// ProbeAnon is the anonymous reading of a page that answered without gating: how much
// text and how many links it carried, and the login link it offered if any. It is
// structurally incapable of gating anything — it exists to describe what a reader would
// see (§13.5).
type ProbeAnon struct {
	TextChars  int    `json:"textChars"`
	Links      int    `json:"links"`
	LoginHref  string `json:"loginHref,omitempty"`
	LoginLabel string `json:"loginLabel,omitempty"`
}

// LoginFormShape is one form's fields. Composition is per-form, never per-page: a
// password input in one form and a username input in another do not make a login form
// (§13.3).
type LoginFormShape struct {
	Password bool   `json:"password"`
	Username bool   `json:"username"`
	Submit   bool   `json:"submit"`
	OTP      bool   `json:"otp"`
	Action   string `json:"action,omitempty"`
}

// ServiceProbe is what one service's probe asked and what answered (§13).
//
// There is deliberately no WWW-Authenticate field: a 401 without GateChallenge already
// means the header was absent (Appendix A). Truncated is a pointer so that "the body hit
// the cap" stays distinct from "nothing is known about the body".
type ServiceProbe struct {
	Endpoint string          `json:"endpoint"`
	Vantage  ProbeVantage    `json:"vantage"`
	Phase    ConnectionPhase `json:"phase"`
	Status   *int            `json:"status,omitempty"`

	Gate      ProbeGate      `json:"gate,omitempty"`
	MediaType string         `json:"mediaType,omitempty"`
	Redirect  *ProbeRedirect `json:"redirect,omitempty"`
	Refresh   *ProbeRedirect `json:"refresh,omitempty"`
	Truncated *bool          `json:"truncated,omitempty"`

	Form  *LoginFormShape `json:"form,omitempty"`
	State *ProbeState     `json:"state,omitempty"`
	Anon  *ProbeAnon      `json:"anon,omitempty"`

	Detail   string              `json:"detail"`
	Attempts []ConnectionAttempt `json:"attempts"`
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

// DeclaredAuth is one mechanism an operator claimed. MechanismOther must carry a Detail
// (§4.5).
type DeclaredAuth struct {
	Mechanism DeclaredAuthMechanism `json:"mechanism"`
	Detail    string                `json:"detail,omitempty"`
}

// DeclaredLink is a link an operator attached.
type DeclaredLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// DeclaredDependency is a free-text dependency on something outside the fleet.
type DeclaredDependency struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
}

// DeclaredServiceDependency is a dependency on a scanned service, by reference. Ref is
// kept as written even when it resolves to nothing, so a broken reference is visible
// rather than dropped (§14).
type DeclaredServiceDependency struct {
	Ref    string `json:"ref"`
	Detail string `json:"detail,omitempty"`
}

// Declaration is a sidecar file's contents, at stack level or shared by a service.
// File is the path it was read from — the evidence for everything in it (I1).
type Declaration struct {
	File        string `json:"file"`
	Description string `json:"description,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	Notes       string `json:"notes,omitempty"`
	Data        string `json:"data,omitempty"`

	Links        []DeclaredLink       `json:"links"`
	Dependencies []DeclaredDependency `json:"dependencies"`
}

// AcceptedExposure is an operator's statement that being reachable with no gate is
// intended. The reason is required: an acceptance with no reason is not one (§14).
type AcceptedExposure struct {
	Reason string `json:"reason"`
}

// ServiceDeclaration is a Declaration plus everything only a service can declare.
// Declaration is embedded, so its fields sit flat in the JSON exactly as Appendix A
// writes them.
//
// Drift and Unconfirmed are two separate readings and must never be merged (§22,
// requirement 5): drift is a declaration the scan contradicts, unconfirmed is one the
// scan simply could not corroborate.
type ServiceDeclaration struct {
	Declaration

	Auth      []DeclaredAuth              `json:"auth"`
	DependsOn []DeclaredServiceDependency `json:"dependsOn"`

	UnauthenticatedAccepted *AcceptedExposure `json:"unauthenticatedAccepted,omitempty"`
	ExpectedIngress         []IngressKind     `json:"expectedIngress,omitempty"`

	Drift         []string              `json:"drift"`
	Unconfirmed   []string              `json:"unconfirmed"`
	AuthAgreement DeclaredAuthAgreement `json:"authAgreement,omitempty"`
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

// GraphNode is a service, a network, a volume or something outside the fleet.
//
// Stack, Auth, Ingress and Running are service facts; Scope, MemberCount and StackCount
// are network facts. Running is a pointer because a stopped service and a node that is
// not a service are different things.
type GraphNode struct {
	ID    string        `json:"id"`
	Label string        `json:"label"`
	Kind  GraphNodeKind `json:"kind"`

	Stack   string        `json:"stack,omitempty"`
	Auth    AuthMethod    `json:"auth,omitempty"`
	Ingress IngressKind   `json:"ingress,omitempty"`
	Running *bool         `json:"running,omitempty"`
	Role    GraphNodeRole `json:"role,omitempty"`

	Scope       NetworkScope `json:"scope,omitempty"`
	MemberCount *int         `json:"memberCount,omitempty"`
	StackCount  *int         `json:"stackCount,omitempty"`
}

// EdgeDeclaredBy is the sidecar file an edge came from, when it came from one.
type EdgeDeclaredBy struct {
	File   string `json:"file"`
	Detail string `json:"detail,omitempty"`
}

// GraphEdge is one relation. The graph is service → network → service; a direct
// service → service edge survives only where Via is empty (§8, §22).
//
// Flow is the arrowhead on a membership edge, absent in the common case where the
// service is merely on the network. FlowSource separates an observed dependency from a
// declared one, and a leg whose dependencies were all declared renders dashed.
type GraphEdge struct {
	ID     string        `json:"id"`
	Source string        `json:"source"`
	Target string        `json:"target"`
	Kind   GraphEdgeKind `json:"kind"`
	Label  string        `json:"label,omitempty"`

	Flow       EdgeFlow       `json:"flow,omitempty"`
	FlowSource EdgeFlowSource `json:"flowSource,omitempty"`

	DeclaredBy *EdgeDeclaredBy `json:"declaredBy,omitempty"`
	Via        []string        `json:"via,omitempty"`
}

// Graph is the one graph object every view reads. The service drawer reads the unpruned
// relation set, so a spoke a cap dropped from a diagram is still answerable there (§22).
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// ---------------------------------------------------------------------------
// LabView's own access control
// ---------------------------------------------------------------------------

// AccessMode is whether LabView requires a login, and by which methods (§19).
// Enforced is true exactly when Methods is non-empty; Consistent asserts it.
type AccessMode struct {
	Enforced bool          `json:"enforced"`
	Methods  []LoginMethod `json:"methods"`
	Notes    []string      `json:"notes"`
}

// Consistent reports the invariant of Appendix A: enforced is non-empty methods.
func (m AccessMode) Consistent() bool { return m.Enforced == (len(m.Methods) > 0) }

// SessionUser is who is signed in, and by which method.
type SessionUser struct {
	Name string      `json:"name"`
	Via  LoginMethod `json:"via"`
}

// SessionInfo is the body of GET /api/session: the posture, plus the signed-in reader if
// there is one. AccessMode is embedded, so the three posture fields sit flat in the JSON
// exactly as Appendix A writes them.
type SessionInfo struct {
	AccessMode

	User      *SessionUser `json:"user,omitempty"`
	OIDCLabel string       `json:"oidcLabel,omitempty"`
}
