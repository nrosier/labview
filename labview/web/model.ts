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
  VolumeDecl,
  Graph,
  GraphNode,
  GraphEdge,
  IngressKind,
  ConnectionPhase,
  ConnectionAttempt,
  ConnectionReport,
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
 * different ways.
 */
export { declaredAuthLabel, declaredAuthSummary } from "../src/model/declarations";

export { diffStacks, scanDiffText, scanDiffDetails } from "../src/model/changes";
export { diffIntegrations, integrationDiffText, integrationDiffDetails } from "../src/model/changes";
export type { ScanDiff, StackChange, IntegrationDiff, IntegrationChange } from "../src/model/changes";
