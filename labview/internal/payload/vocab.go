// Package payload is the wire contract of Appendix A: every type the JSON payload
// carries, and every closed vocabulary those types are built from.
//
// Two rules govern the whole package.
//
// Field names and union member spellings are exact. They appear in the JSON, they key
// the UI's colours and labels, and a filter in a shared URL is written from them, so
// adding or renaming a member is a breaking change to both the payload and the UI (§16).
//
// An optional field is optional because its absence is a fact (§16). A fact about one
// response — a media type, a redirect, a truncation — is a pointer or an omitempty
// slice, so "not present" and "present and empty" stay different answers. A field
// describing the build is never optional: the probe mode, the build stamp and the
// skipped counts are always written, so an unknown build says "unknown" rather than
// going missing.
package payload

// ---------------------------------------------------------------------------
// §4.1 Reachability
// ---------------------------------------------------------------------------

// IngressKind is how a service can be reached, most to least exposed. A service
// carries a set of these, never one (§8).
type IngressKind string

const (
	IngressPublic   IngressKind = "public"   // a Cloudflare tunnel route with a hostname
	IngressTraefik  IngressKind = "traefik"  // a Traefik route with hosts or a rule
	IngressLan      IngressKind = "lan"      // ports: is non-empty — published on the host
	IngressInternal IngressKind = "internal" // expose:, or a real network shared with another scanned service
	IngressNone     IngressKind = "none"     // none of the above
)

// IngressKinds is the canonical order of §4.1, which is the order every ingress set
// is written in.
var IngressKinds = []IngressKind{IngressPublic, IngressTraefik, IngressLan, IngressInternal, IngressNone}

// ExternalIngressKinds are the kinds that mean something outside the container network
// can answer. §4.1 requires this grouping to be its own question over its own three
// kinds rather than "not internal", so that the exposure finding and the
// stale-acceptance check are provably asking the same thing.
var ExternalIngressKinds = []IngressKind{IngressPublic, IngressTraefik, IngressLan}

// IsExternal reports whether this kind means something outside the container network
// can answer.
func (k IngressKind) IsExternal() bool {
	return k == IngressPublic || k == IngressTraefik || k == IngressLan
}

// ValidIngressKind reports whether s is a member of the closed set.
func ValidIngressKind(s string) bool { return validMember(s, IngressKinds) }

// NetworkScope says who can be on a network — not how severe it is (§4.1).
type NetworkScope string

const (
	// ScopeExternal: declared external: by at least one stack, so it can carry stacks
	// and containers this scan never saw.
	ScopeExternal NetworkScope = "external"
	// ScopeStackLocal: created by one compose project, so only that project's services
	// can ever join.
	ScopeStackLocal NetworkScope = "stack-local"
)

// NetworkRelation is what one service is to another across a named shared network.
//
// RelationPeer is the absence of a relation — a co-member, reachable and no more — so
// nothing is ever labelled with it and no rule returns it (§4.1). It exists as a
// member so that the three cases can be named in prose and in tests.
type NetworkRelation string

const (
	RelationDependsOn  NetworkRelation = "depends-on"
	RelationRequiredBy NetworkRelation = "required-by"
	RelationPeer       NetworkRelation = "peer"
)

// OriginKind is what a tunnel's declared origin resolved to (§9).
type OriginKind string

const (
	OriginSelfNetwork  OriginKind = "self-network"   // the origin host is this service's own name or container_name
	OriginSelfHostPort OriginKind = "self-host-port" // the origin port is a host port this service publishes
	OriginFleetService OriginKind = "fleet-service"  // another scanned service sharing a network, named as the hop
	OriginUnresolved   OriginKind = "unresolved"     // no match, an FQDN, or a tie between reachable candidates
)

// ---------------------------------------------------------------------------
// §4.2 Authentication
// ---------------------------------------------------------------------------

// AuthMethod is the gate in front of a service. The order of the constants is the
// precedence order of §4.2.
type AuthMethod string

const (
	AuthAuthentikForwardAuth AuthMethod = "authentik-forward-auth"
	AuthAuthentikOAuth       AuthMethod = "authentik-oauth"
	AuthAuthentikLDAP        AuthMethod = "authentik-ldap"
	AuthForwardAuth          AuthMethod = "forward-auth"
	AuthOtherOAuth           AuthMethod = "other-oauth"
	AuthLDAP                 AuthMethod = "ldap"
	AuthBasicAuth            AuthMethod = "basic-auth"
	AuthNone                 AuthMethod = "none"
)

// AuthMethods is the precedence order of §4.2, strongest first. AuthNone is last, so
// index order is also the order the posture roll-up resolves ties in.
var AuthMethods = []AuthMethod{
	AuthAuthentikForwardAuth,
	AuthAuthentikOAuth,
	AuthAuthentikLDAP,
	AuthForwardAuth,
	AuthOtherOAuth,
	AuthLDAP,
	AuthBasicAuth,
	AuthNone,
}

// Rank is the method's position in the precedence order; lower is stronger. An
// unlisted member ranks after every known one rather than before, so a member added
// to the payload by a future version cannot silently outrank a real gate.
func (m AuthMethod) Rank() int {
	for i, k := range AuthMethods {
		if k == m {
			return i
		}
	}
	return len(AuthMethods)
}

// Detected reports whether this method names a gate. It is the one place the
// distinction lives, so eligibility for the probe and the exposure verdict cannot
// come apart (§13.1).
func (m AuthMethod) Detected() bool { return m != AuthNone && m != "" }

// ValidAuthMethod reports whether s is a member of the closed set.
func ValidAuthMethod(s string) bool { return validMember(s, AuthMethods) }

// AuthConfidence is how the gate was established, and never a severity (§4.2).
type AuthConfidence string

const (
	// ConfidenceConfirmed: an API reported the gate and named the service.
	ConfidenceConfirmed AuthConfidence = "confirmed"
	// ConfidenceObserved: a scanned configuration value states it, or an API tied it
	// to the service by name alone.
	ConfidenceObserved AuthConfidence = "observed"
	// ConfidenceInferred: it rests on a middleware name — and a service note must say so.
	ConfidenceInferred AuthConfidence = "inferred"
)

// AuthConfidences is the rank order of §4.2: confirmed < observed < inferred.
var AuthConfidences = []AuthConfidence{ConfidenceConfirmed, ConfidenceObserved, ConfidenceInferred}

// Rank is the confidence's position in the rank order; lower is stronger. When two
// accounts of one service disagree the stronger is reported and the weaker kept as
// evidence (§4.2).
func (c AuthConfidence) Rank() int {
	for i, k := range AuthConfidences {
		if k == c {
			return i
		}
	}
	return len(AuthConfidences)
}

// ValidAuthConfidence reports whether s is a member of the closed set.
func ValidAuthConfidence(s string) bool { return validMember(s, AuthConfidences) }

// NoAuthReason explains why no method is named. It is derived for display and is not
// stored in the payload (§4.2) — it appears here because §14, §16 and §19 assert
// conclusions in its terms.
type NoAuthReason string

const (
	NoAuthGap          NoAuthReason = "gap"           // "No proxy auth" — the only finding in this set
	NoAuthNotReachable NoAuthReason = "not-reachable" // "None expected"
	NoAuthDeclared     NoAuthReason = "declared"      // "Declared, not detected" (§14)
	NoAuthUnnamedGate  NoAuthReason = "unnamed-gate"  // "None named — gate confirmed"
	NoAuthProbedGate   NoAuthReason = "probed-gate"   // a login page answered (§13)
)

// ---------------------------------------------------------------------------
// §4.3 Integrations
// ---------------------------------------------------------------------------

// AuthentikProviderKind is the provider kind Authentik reported, normalised.
type AuthentikProviderKind string

const (
	ProviderProxy  AuthentikProviderKind = "proxy"
	ProviderOAuth2 AuthentikProviderKind = "oauth2"
	ProviderLDAP   AuthentikProviderKind = "ldap"
	ProviderSAML   AuthentikProviderKind = "saml"
	ProviderRADIUS AuthentikProviderKind = "radius"
	ProviderSCIM   AuthentikProviderKind = "scim"
	ProviderOther  AuthentikProviderKind = "other"
)

// AuthentikProviderKinds is the closed set of §4.3.
var AuthentikProviderKinds = []AuthentikProviderKind{
	ProviderProxy, ProviderOAuth2, ProviderLDAP, ProviderSAML, ProviderRADIUS, ProviderSCIM, ProviderOther,
}

// AuthentikMatchStrength is how firmly an application was tied to a service. Absent
// must read as StrengthName, never as the strongest (§4.3).
type AuthentikMatchStrength string

const (
	StrengthAddress  AuthentikMatchStrength = "address"
	StrengthHostname AuthentikMatchStrength = "hostname"
	StrengthName     AuthentikMatchStrength = "name"
)

// UnmatchedReason is why an application or a router could not be tied to a service.
type UnmatchedReason string

const (
	UnmatchedAmbiguous   UnmatchedReason = "ambiguous"    // more than one candidate
	UnmatchedNoCandidate UnmatchedReason = "no-candidate" //
	UnmatchedInternal    UnmatchedReason = "internal"     //
)

// DiscoveredVia records which read produced an application record (§11).
type DiscoveredVia string

const (
	// DiscoveredViaList: the application list returned it.
	DiscoveredViaList DiscoveredVia = "list"
	// DiscoveredViaProvider: it was rebuilt from a provider record because the list
	// withheld it. A rebuilt record is thinner and must be tagged "rebuilt" in the UI.
	DiscoveredViaProvider DiscoveredVia = "provider"
)

// EndpointSource says who chose an endpoint. The built-in default socket path must
// stay distinguishable from an operator-supplied one, which is the whole reason this
// set has three members rather than two (§3.1).
type EndpointSource string

const (
	SourceConfig     EndpointSource = "config"     // the operator named it
	SourceDiscovered EndpointSource = "discovered" // the scan found it
	SourceDefault    EndpointSource = "default"    // a built-in fallback path
)

// TraefikCredential is which credential the proxy's API needed.
type TraefikCredential string

const (
	// CredentialNone: the API answered without one, which is itself evidence about how
	// that API is exposed on that network (§12).
	CredentialNone  TraefikCredential = "none"
	CredentialBasic TraefikCredential = "basic"
)

// ---------------------------------------------------------------------------
// §4.4 The probe
// ---------------------------------------------------------------------------

// ProbeVantage is where the request was sent from, in the same order as the external
// ingress kinds — walked most-exposed first (§4.4).
type ProbeVantage string

const (
	VantagePublic  ProbeVantage = "public"
	VantageTraefik ProbeVantage = "traefik"
	VantageLan     ProbeVantage = "lan"
)

// ProbeVantages is the walk order of §13.2.
var ProbeVantages = []ProbeVantage{VantagePublic, VantageTraefik, VantageLan}

// ProbeGate is one of the eight signals, strongest first (§4.4). Firing conditions
// are in §13.3 and §13.4.
type ProbeGate string

const (
	GateChallenge        ProbeGate = "challenge"          // 401 or 407 with a WWW-Authenticate header
	GateRedirectOrigin   ProbeGate = "redirect-origin"    // a 3xx whose Location resolves to a different origin
	GateRedirectLogin    ProbeGate = "redirect-login"     // a 3xx that stayed on the origin, landing on a login path
	GateMetaRefreshLogin ProbeGate = "meta-refresh-login" // a 200 whose meta refresh resolves the same way
	GateSSOForm          ProbeGate = "sso-form"           // a hidden SAMLRequest or SAMLResponse input
	GatePasswordForm     ProbeGate = "password-form"      // a password input anywhere on the page
	GateCredentialForm   ProbeGate = "credential-form"    // username + submit + login intent, no password
	GateStateChallenge   ProbeGate = "state-challenge"    // the page's own client was refused with a scheme (§13.4)
)

// ProbeGates is the precedence order of §4.4, strongest first. The reason sentence
// branches in this order, and the mapping from signal to wording must be exhaustive
// over it (§13.6).
var ProbeGates = []ProbeGate{
	GateChallenge,
	GateRedirectOrigin,
	GateRedirectLogin,
	GateMetaRefreshLogin,
	GateSSOForm,
	GatePasswordForm,
	GateCredentialForm,
	GateStateChallenge,
}

// ---------------------------------------------------------------------------
// §4.5 Declarations
// ---------------------------------------------------------------------------

// DeclaredAuthMechanism is what an operator may claim in a sidecar file. MechanismOther
// must carry a detail (§4.5).
type DeclaredAuthMechanism string

const (
	MechanismAppLocalAccounts  DeclaredAuthMechanism = "app-local-accounts"
	MechanismAppLDAP           DeclaredAuthMechanism = "app-ldap"
	MechanismAppOIDC           DeclaredAuthMechanism = "app-oidc"
	MechanismAppSAML           DeclaredAuthMechanism = "app-saml"
	MechanismAppToken          DeclaredAuthMechanism = "app-token"
	MechanismMTLS              DeclaredAuthMechanism = "mtls"
	MechanismNetworkRestricted DeclaredAuthMechanism = "network-restricted"
	MechanismExternalProxy     DeclaredAuthMechanism = "external-proxy"
	MechanismOther             DeclaredAuthMechanism = "other"
)

// DeclaredAuthMechanisms is the closed set of §4.5, in the order a validation warning
// lists them.
var DeclaredAuthMechanisms = []DeclaredAuthMechanism{
	MechanismAppLocalAccounts,
	MechanismAppLDAP,
	MechanismAppOIDC,
	MechanismAppSAML,
	MechanismAppToken,
	MechanismMTLS,
	MechanismNetworkRestricted,
	MechanismExternalProxy,
	MechanismOther,
}

// ValidDeclaredAuthMechanism reports whether s is a member of the closed set.
func ValidDeclaredAuthMechanism(s string) bool { return validMember(s, DeclaredAuthMechanisms) }

// AuthFamily is one of the three families a declared and a detected mechanism can be
// compared within (§14). Both mappings into it are partial, so an unmapped mechanism
// has no family and cannot conflict.
type AuthFamily string

const (
	FamilyOIDC  AuthFamily = "oidc"
	FamilyLDAP  AuthFamily = "ldap"
	FamilyProxy AuthFamily = "proxy"
)

// DeclaredAuthAgreement is what the comparison of §14 concluded.
type DeclaredAuthAgreement string

const (
	// AgreementSupplies: the service would be exposed and a declaration is the only
	// protection. This is the one verdict a declaration may change.
	AgreementSupplies DeclaredAuthAgreement = "supplies"
	// AgreementRedundant: declared and detected in the same family. Rendered nowhere.
	AgreementRedundant DeclaredAuthAgreement = "redundant"
	// AgreementConflicts: same layer, different family. A drift entry.
	AgreementConflicts DeclaredAuthAgreement = "conflicts"
	// AgreementSupplements: declared in a layer with nothing detected in it, while the
	// other layer has a gate. Noted, not drift.
	AgreementSupplements DeclaredAuthAgreement = "supplements"
)

// ---------------------------------------------------------------------------
// §4.6 Connections
// ---------------------------------------------------------------------------

// ConnectionPhase is one taxonomy for every outbound target, in the order of §4.6.
// The first four stop before the network and are outcomes rather than faults.
type ConnectionPhase string

const (
	PhaseDisabled      ConnectionPhase = "disabled"       // switched off in configuration
	PhaseNotConfigured ConnectionPhase = "not-configured" // nothing to talk to
	PhaseNotFound      ConnectionPhase = "not-found"      // the thing to talk to does not exist
	PhaseCredential    ConnectionPhase = "credential"     // a credential was needed and was absent or blank
	PhaseResolve       ConnectionPhase = "resolve"        // DNS said no
	PhaseConnect       ConnectionPhase = "connect"        // refused, unreachable, or no route
	PhaseTLS           ConnectionPhase = "tls"            // handshake failed
	PhaseTimeout       ConnectionPhase = "timeout"        // no answer inside the budget, established by the clock
	PhaseAuthenticate  ConnectionPhase = "authenticate"   // answered 401
	PhaseAuthorize     ConnectionPhase = "authorize"      // answered 403
	PhasePath          ConnectionPhase = "path"           // answered 404 or 405 — right host, wrong route
	PhaseStatus        ConnectionPhase = "status"         // answered with any other non-2xx
	PhaseProtocol      ConnectionPhase = "protocol"       // answered, but not as this API
	PhasePartial       ConnectionPhase = "partial"        // read enough to be useful, not all of it; ok stays true
	PhaseConnected     ConnectionPhase = "connected"      // full read
)

// ConnectionPhases is the order of §4.6.
var ConnectionPhases = []ConnectionPhase{
	PhaseDisabled, PhaseNotConfigured, PhaseNotFound, PhaseCredential,
	PhaseResolve, PhaseConnect, PhaseTLS, PhaseTimeout,
	PhaseAuthenticate, PhaseAuthorize, PhasePath, PhaseStatus, PhaseProtocol,
	PhasePartial, PhaseConnected,
}

// BeforeTheNetwork reports whether this phase stopped before any request was sent, and
// is therefore an outcome rather than a fault. It is what the banner rule of §15 tests:
// a banner is shown for partial and for any failure whose phase is neither disabled nor
// not-configured.
func (p ConnectionPhase) BeforeTheNetwork() bool {
	return p == PhaseDisabled || p == PhaseNotConfigured
}

// ValidConnectionPhase reports whether s is a member of the closed set.
func ValidConnectionPhase(s string) bool { return validMember(s, ConnectionPhases) }

// ---------------------------------------------------------------------------
// §4.7 LabView's own login
// ---------------------------------------------------------------------------

// LoginMethod is how a reader signs in to LabView itself.
//
// Naming hazard, stated once (§4.7): MethodPasswd is a file of bcrypt hashes and has
// nothing to do with HTTP Basic authentication. No identifier in this program may call
// it "basic".
type LoginMethod string

const (
	MethodPasswd LoginMethod = "passwd"
	MethodOIDC   LoginMethod = "oidc"
)

// LoginMethods is the order the login screen offers them in.
var LoginMethods = []LoginMethod{MethodPasswd, MethodOIDC}

// LoginFailureReason is one of the eight codes a failed login redirect may carry. A
// redirect carrying anything else must be rejected rather than displayed (§4.7).
type LoginFailureReason string

const (
	FailCredentials       LoginFailureReason = "credentials"
	FailThrottled         LoginFailureReason = "throttled"
	FailMethodUnavailable LoginFailureReason = "method-unavailable"
	FailSessionExpired    LoginFailureReason = "session-expired"
	FailOIDCState         LoginFailureReason = "oidc-state"
	FailOIDCProvider      LoginFailureReason = "oidc-provider"
	FailOIDCToken         LoginFailureReason = "oidc-token"
	FailOIDCIdentity      LoginFailureReason = "oidc-identity"
)

// LoginFailureReasons is the closed set of §4.7.
var LoginFailureReasons = []LoginFailureReason{
	FailCredentials, FailThrottled, FailMethodUnavailable, FailSessionExpired,
	FailOIDCState, FailOIDCProvider, FailOIDCToken, FailOIDCIdentity,
}

// ValidLoginFailureReason reports whether s is a member of the closed set.
func ValidLoginFailureReason(s string) bool { return validMember(s, LoginFailureReasons) }

// SessionRejection is why a session was refused. It is internal: logged, never served
// (§4.7).
type SessionRejection string

const (
	RejectMalformed SessionRejection = "malformed"
	RejectSignature SessionRejection = "signature"
	RejectExpired   SessionRejection = "expired"
	RejectRevoked   SessionRejection = "revoked"
)

// ---------------------------------------------------------------------------
// §4.8 Scan detail
// ---------------------------------------------------------------------------

// EnvVarSource is where a resolved environment value came from.
type EnvVarSource string

const (
	EnvFromEnvFile      EnvVarSource = "env_file"
	EnvFromEnvironment  EnvVarSource = "environment"
	EnvFromShellDefault EnvVarSource = "shell-default"
)

// MountType is the kind of mount a compose entry described.
type MountType string

const (
	MountBind    MountType = "bind"
	MountVolume  MountType = "volume"
	MountTmpfs   MountType = "tmpfs"
	MountNpipe   MountType = "npipe"
	MountUnknown MountType = "unknown"
)

// HealthState is what the Engine reported about a container's health check.
type HealthState string

const (
	HealthHealthy   HealthState = "healthy"
	HealthUnhealthy HealthState = "unhealthy"
	HealthStarting  HealthState = "starting"
	HealthNone      HealthState = "none"
)

// BuildStampSource is where the build identity came from (§3.4).
type BuildStampSource string

const (
	BuildFromImage    BuildStampSource = "image"    // LABVIEW_BUILD_SHA was set at build time
	BuildFromCheckout BuildStampSource = "checkout" // read from a .git directory at startup
	BuildUnknown      BuildStampSource = "unknown"  // neither; commit is then absent entirely
)

// GraphNodeKind is what a graph node stands for.
type GraphNodeKind string

const (
	NodeService  GraphNodeKind = "service"
	NodeNetwork  GraphNodeKind = "network"
	NodeVolume   GraphNodeKind = "volume"
	NodeExternal GraphNodeKind = "external"
)

// GraphNodeRole is the only role a node may carry. A service another service's origin
// resolved to, or the service whose Traefik API answered, gets RoleProxy — it stays an
// ordinary service node, and the role only lets the UI colour it as infrastructure (§9).
type GraphNodeRole string

const RoleProxy GraphNodeRole = "proxy"

// GraphEdgeKind is what a graph edge stands for.
type GraphEdgeKind string

const (
	EdgeNetwork   GraphEdgeKind = "network"
	EdgeDependsOn GraphEdgeKind = "depends_on"
	EdgeVolume    GraphEdgeKind = "volume"
	EdgeIngress   GraphEdgeKind = "ingress"
	EdgeAuth      GraphEdgeKind = "auth"
)

// EdgeFlow is where the dependency arrowhead sits on a membership edge. Absent — the
// common case — means the service is on the network and nothing crosses it (§8).
type EdgeFlow string

const (
	FlowToNetwork EdgeFlow = "to-network" // this service is the dependent
	FlowToService EdgeFlow = "to-service" // something else on that network depends on it
	FlowBoth      EdgeFlow = "both"
)

// EdgeFlowSource distinguishes an observed dependency from a declared one. A leg every
// one of whose dependencies was declared renders dashed; FlowSourceBoth stays solid (§8).
type EdgeFlowSource string

const (
	FlowSourceObserved EdgeFlowSource = "observed"
	FlowSourceDeclared EdgeFlowSource = "declared"
	FlowSourceBoth     EdgeFlowSource = "both"
)

// ProbeRunSource says whether the probe's on/off state for this build came from
// configuration or from the request that started it (§13.7).
type ProbeRunSource string

const (
	ProbeSourceConfig  ProbeRunSource = "config"
	ProbeSourceRequest ProbeRunSource = "request"
)

// validMember is the one membership test behind every Valid* function, so a closed set
// is checked against its own canonical slice rather than against a second list that
// could fall out of step.
func validMember[T ~string](s string, members []T) bool {
	for _, m := range members {
		if string(m) == s {
			return true
		}
	}
	return false
}
