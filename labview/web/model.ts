/** Re-export the shared backend model so the UI has a single import surface. */
export type {
  Overview,
  OverviewStats,
  ScanMeta,
  AppStack,
  Service,
  EnvVar,
  PortMapping,
  MountSpec,
  CloudflareRoute,
  OriginTarget,
  OriginKind,
  TraefikRoute,
  TraefikLiveRouter,
  TraefikLiveMiddleware,
  TraefikLiveServer,
  TraefikSummary,
  AuthMethod,
  AuthConfidence,
  AuthPosture,
  Declaration,
  DeclaredAuth,
  DeclaredAuthAgreement,
  DeclaredAuthMechanism,
  DeclaredDependency,
  DeclaredLink,
  ServiceDeclaration,
  AuthentikApplication,
  AuthentikMatch,
  AuthentikMatchStrength,
  AuthentikProvider,
  AuthentikProviderKind,
  AuthentikSummary,
  UnmatchedApplication,
  UnmatchedReason,
  UnmatchedRouter,
  DockerState,
  NetworkDecl,
  NetworkScope,
  VolumeDecl,
  Graph,
  GraphNode,
  GraphEdge,
  IngressKind,
  ConnectionPhase,
  ConnectionAttempt,
  ConnectionReport,
  AccessMode,
  LoginFailureReason,
  LoginMethod,
  SessionInfo,
} from "../src/model/types";

/**
 * The wording and the show/hide rule for connection reports, from the same module the
 * server logs through — so the banner cannot describe a phase differently from the log
 * line about the same failure, and adding a phase updates both at once.
 */
export { phaseText, shouldBanner } from "../src/model/connections";

/**
 * What a rescan found, compared and worded by the same module the server logs through —
 * so the note beside `scanned <time>` and the line in the log can never disagree about
 * the same rescan.
 *
 * Two diffs, because a rescan does two things: it re-reads the compose files, and it
 * re-runs the Authentik and Traefik exchanges. An API that answered differently is not an
 * edit, so the second is reported beside the first rather than inside it.
 */
/**
 * How a declared mechanism is worded, from the same module the analyzer's note is built
 * from — so a badge and the note beside it cannot describe one `.labview` entry in two
 * different ways. `formatExposureCount` is here for the same reason: the tile and the
 * CLI line print the same figure.
 */
export {
  declaredAuthLabel,
  declaredAuthSummary,
  formatExposureCount,
  showsDeclaredAuth,
} from "../src/model/declarations";

/**
 * The ingress vocabulary and the operations on it, from the same module the analyzer
 * classifies with — so the badge order, the bar order and the classification can never
 * disagree about which kinds exist or which one is most exposed.
 */
export {
  INGRESS_KINDS,
  diffIngress,
  externalIngress,
  formatIngress,
  ingressMatchesExpectation,
  isExternallyReachable,
  isIngressKind,
  normalizeIngress,
  primaryIngress,
  rollUpIngress,
} from "../src/model/ingress";

/**
 * How services connected by a shared network are drawn and worded.
 *
 * In `src/` for the reason every rule here is a rule and not a rendering detail: which
 * network nodes are worth drawing, how many spokes one may have, when a dependency is
 * drawn straight between two services instead of through the network that carries it, and
 * who counts as a peer. The fleet graph, the drawer diagram and the Networks section all
 * read the same complete graph through these functions, so none of them can claim a
 * connection the others do not.
 */
export {
  MAX_DRAWER_PEERS,
  MAX_GRAPH_SPOKES,
  MAX_LIST_PEERS,
  NETWORK_SCOPES,
  graphServiceId,
  hiddenNetworksNote,
  networkGroups,
  networkLinks,
  networkNodeLabel,
  networkScopeMeta,
  peerlessNetworkText,
  relationLabel,
  serviceConnections,
  showsDirectDependency,
  showsNetworkNode,
  visibleSpokes,
} from "../src/model/networks";
export type {
  NetworkGroup,
  NetworkLink,
  NetworkPeerView,
  NetworkRelation,
  NetworkScopeMeta,
  ServiceConnections,
  ServiceRefView,
  SpokeSelection,
} from "../src/model/networks";

/**
 * When the absence of an authentication mechanism may be reported, and how it is worded.
 * In `src/` because it is a rule about the fleet rather than a rendering detail: a
 * missing gate is only a finding where a gate was expected, and the four reasons a
 * service has no mechanism have to be told apart before anything can be said about it.
 */
export { NO_AUTH_REASONS, noAuthReason, noAuthText, showsAuthMethod } from "../src/model/auth";
export type { NoAuthReason, NoAuthText } from "../src/model/auth";

/**
 * The tri-state tag filter. In `src/` rather than here because the web bundle is never
 * rendered by the smoke pass: what a reader sees after clicking three chips is decided
 * by pure functions the test can call, and this module only holds the state.
 */
export {
  EMPTY_TAG_FILTER,
  cycleTag,
  describeTagFilter,
  matchesTagFilter,
  tagFilterActive,
} from "../src/model/filter";
export type { TagFilter, TagMode } from "../src/model/filter";

/**
 * The wording of LabView's own access control, from the same module the server logs and
 * the routes redirect through — so a failure code cannot mean one thing in a log line and
 * another on the login screen, and the closed set of codes is validated in one place.
 *
 * `parseLoginFailure` matters most: the OIDC callback can only hand the UI a query
 * parameter, so `?login_error=…` is attacker-supplied by definition and is checked
 * against the union here rather than rendered.
 */
export {
  isValidUsername,
  loginFailureText,
  methodLabel,
  oidcButtonLabel,
  parseLoginFailure,
} from "../src/model/access";

export { diffStacks, scanDiffText, scanDiffDetails } from "../src/model/changes";
export { diffIntegrations, integrationDiffText, integrationDiffDetails } from "../src/model/changes";
export type { ScanDiff, StackChange, IntegrationDiff, IntegrationChange } from "../src/model/changes";
