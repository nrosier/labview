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
  AuthentikApplication,
  AuthentikMatch,
  AuthentikProvider,
  AuthentikProviderKind,
  AuthentikSummary,
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
