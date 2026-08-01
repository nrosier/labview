import type { AppStack, AuthentikProviderKind, IngressKind, OriginTarget, Service } from "../model";
import { declaredAuthLabel, diffIngress } from "../model";
import { fmtTime, shortImage, statusView } from "../lib/format";
import { ingressLabel } from "../lib/palette";
import { buildServiceMermaid } from "../lib/mermaidDef";
import { AcceptedBadge, AuthBadge, DeclaredAuthBadge, ExposedBadge, IngressBadge, StatusDot } from "./badges";
import { Mermaid } from "./Mermaid";
import { Section } from "./Section";

/**
 * Where a tunnel origin was found to lead, in a few words. The full reasoning is
 * listed as evidence under the table, so this only has to say which of the four
 * conclusions was reached.
 */
/**
 * Whether a declared expectation and the classification agree, from the same diff the
 * analyzer words its drift note with — so the pill and the note cannot disagree about
 * whether the two match.
 */
function expectedMatches(expected: readonly IngressKind[], actual: readonly IngressKind[]): boolean {
  const { missing, unexpected } = diffIngress(expected, actual);
  return missing.length === 0 && unexpected.length === 0;
}

function originLabel(o: OriginTarget): string {
  switch (o.kind) {
    case "fleet-service":
      return `via ${o.hopKey}`;
    case "self-host-port":
      return "direct — own host port";
    case "self-network":
      return "direct — own network";
    default:
      return "hop unresolved";
  }
}

/**
 * Whether an empty outpost list is worth flagging for this provider kind. OAuth2 and
 * SAML are served by the Authentik server itself, and SCIM provisions outbound rather
 * than gating anything, so "no outpost" is only a finding for the three kinds an
 * outpost actually enforces.
 */
function needsOutpost(kind: AuthentikProviderKind): boolean {
  return kind === "proxy" || kind === "ldap" || kind === "radius";
}

function originEvidence(svc: Service): string[] {
  return [...new Set(svc.cloudflare.map((r) => r.origin?.evidence).filter(Boolean))] as string[];
}

/**
 * A declared value together with where it came from: this service's own sidecar entry,
 * or the stack's.
 *
 * The fallback is the drawer's alone — the model keeps the two levels apart, and
 * nothing in the scan or the stats inherits. It exists because a reader who opens one
 * service should not have to go back to the stack card to find out who owns it, and
 * the marker exists because an inherited value must never read as if it had been
 * written about this service specifically.
 */
function declaredValue<T>(own: T | undefined, fromStack: T | undefined): { value: T; inherited: boolean } | null {
  if (own !== undefined) return { value: own, inherited: false };
  if (fromStack !== undefined) return { value: fromStack, inherited: true };
  return null;
}

/** `declaredValue` for the list-valued fields, where empty means absent. */
function declaredList<T>(own: T[] | undefined, fromStack: T[] | undefined): { value: T[]; inherited: boolean } | null {
  return declaredValue(own?.length ? own : undefined, fromStack?.length ? fromStack : undefined);
}

/**
 * Whether a declared criticality is one of the values worth marking.
 *
 * The field is free text, so this recognises the two conventional words that mean "look
 * here first" and leaves everything else plain — better than inventing a scale the
 * operator never agreed to.
 */
function criticalHint(value: string): boolean {
  const v = value.trim().toLowerCase();
  return v === "critical" || v === "high";
}

/** "from the stack", when it was. */
function InheritedMark({ shown }: { shown: boolean }) {
  return shown ? (
    <span class="pill" title="Declared for the stack, not for this service">
      from the stack
    </span>
  ) : null;
}

export function AppDetail({ stack, svc, onClose }: { stack: AppStack; svc: Service; onClose: () => void }) {
  const s = statusView(svc.docker);
  const def = buildServiceMermaid(svc, stack);
  const declared = svc.declared;
  const accepted = declared?.unauthenticatedAccepted;
  // The stack's own declarations, used only as the fallback for a field this service
  // did not declare itself.
  const stackDecl = stack.declared;
  const declaredFile = declared?.file ?? stackDecl?.file;
  const description = declaredValue(declared?.description, stackDecl?.description);
  const owner = declaredValue(declared?.owner, stackDecl?.owner);
  const criticality = declaredValue(declared?.criticality, stackDecl?.criticality);
  const data = declaredValue(declared?.data, stackDecl?.data);
  const notes = declaredValue(declared?.notes, stackDecl?.notes);
  const links = declaredList(declared?.links, stackDecl?.links);
  const dependencies = declaredList(declared?.dependencies, stackDecl?.dependencies);

  return (
    <>
      <div class="drawer-scrim" onClick={onClose} />
      <aside class="drawer" role="dialog" aria-label={`${svc.name} details`}>
        <div class="dhead">
          <StatusDot docker={svc.docker} />
          <div class="title">
            <h2>{svc.name}</h2>
            <div class="sub">
              {stack.name} · <span class="mono">{shortImage(svc.image)}</span> · {s.label}
            </div>
          </div>
          <button class="btn icon" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div class="dbody">
          <div class="badges" style="display:flex;gap:6px;flex-wrap:wrap;">
            {/* Every way in, one badge each: this is the one view with room to list
                them, and the drawer is where a reader comes to see all of them. */}
            {svc.ingress.map((k) => (
              <IngressBadge key={k} kind={k} />
            ))}
            <AuthBadge method={svc.auth.method} />
            {/* Detected first, declared second, and the detected posture is never
                replaced: a service the operator says authenticates itself still shows
                "No proxy auth" beside the declaration, because that is what the scan
                found and it stays true. */}
            {svc.auth.exposedWithoutAuth &&
              (declared && accepted ? (
                <AcceptedBadge reason={accepted.reason} file={declared.file} />
              ) : (
                <ExposedBadge />
              ))}
            {declared && <DeclaredAuthBadge auth={declared.auth} file={declared.file} />}
          </div>

          {svc.notes.length > 0 && (
            <div style="margin-top:12px;">
              {/* An accepted exposure drops the alarm styling and keeps the note: the
                  finding is unchanged, but it no longer competes for attention with the
                  exposures nobody has looked at yet. */}
              {svc.notes.map((note) => (
                <div class={`note${svc.auth.exposedWithoutAuth && !accepted ? " crit" : ""}`}>{note}</div>
              ))}
            </div>
          )}

          <Section title="Connections">
            <Mermaid def={def} />
          </Section>

          <Section title="Overview">
            <dl class="kv">
              <dt>Container</dt>
              <dd class="mono">{svc.containerName}</dd>
              <dt>Image</dt>
              <dd class="mono">{svc.image ?? "—"}</dd>
              {svc.restart && (
                <>
                  <dt>Restart</dt>
                  <dd>{svc.restart}</dd>
                </>
              )}
              {svc.command && (
                <>
                  <dt>Command</dt>
                  <dd class="mono">{svc.command}</dd>
                </>
              )}
              {svc.dependsOn.length > 0 && (
                <>
                  <dt>Depends on</dt>
                  <dd>
                    {svc.dependsOn.map((d) => (
                      <span class="pill">{d}</span>
                    ))}
                  </dd>
                </>
              )}
            </dl>
          </Section>

          {svc.cloudflare.length > 0 && (
            <Section title="Public ingress — Cloudflare tunnel (DockFlare)">
              <table class="data">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Origin service</th>
                    <th>Access</th>
                  </tr>
                </thead>
                <tbody>
                  {svc.cloudflare.map((r) => (
                    <tr>
                      <td>
                        {r.hostname ? (
                          <a href={`https://${r.hostname}${r.path ?? ""}`} target="_blank" rel="noreferrer">
                            {r.hostname}
                            {r.path}
                          </a>
                        ) : (
                          <span class="masked">unresolved</span>
                        )}
                      </td>
                      <td class="mono">
                        {r.service}
                        {r.noTlsVerify ? " (no-tls-verify)" : ""}
                        {/* Where that address leads. A tunnel usually terminates at a
                            reverse proxy rather than at this container, so the path is
                            reported rather than assumed. */}
                        {r.origin && (
                          <div>
                            <span class="pill" title={r.origin.evidence}>
                              {originLabel(r.origin)}
                            </span>
                          </div>
                        )}
                      </td>
                      <td>
                        {r.access
                          ? [r.access.policy, r.access.group, r.access.emails?.join(", ")]
                              .filter(Boolean)
                              .join(" / ") || "policy"
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* One line per distinct conclusion: several hostnames routinely share
                  a single origin, and repeating its reasoning adds nothing. */}
              {originEvidence(svc).length > 0 && (
                <ul class="evidence" style="margin-top:8px;">
                  {originEvidence(svc).map((e) => (
                    <li>{e}</li>
                  ))}
                </ul>
              )}
            </Section>
          )}

          {svc.traefik.length > 0 && (
            <Section title="Traefik ingress — from the compose labels">
              {svc.traefik.map((r) => (
                <div style="margin-bottom:10px;">
                  <div style="font-weight:600;">{r.router}</div>
                  <dl class="kv" style="grid-template-columns:120px 1fr;margin-top:4px;">
                    {r.rule && (
                      <>
                        <dt>Rule</dt>
                        <dd class="mono">{r.rule}</dd>
                      </>
                    )}
                    {r.hosts.length > 0 && (
                      <>
                        <dt>Hosts</dt>
                        <dd>
                          {r.hosts.map((h) => (
                            <a class="pill" href={`https://${h}`} target="_blank" rel="noreferrer">
                              {h}
                            </a>
                          ))}
                        </dd>
                      </>
                    )}
                    {r.entrypoints.length > 0 && (
                      <>
                        <dt>Entrypoints</dt>
                        <dd>{r.entrypoints.join(", ")}</dd>
                      </>
                    )}
                    <>
                      <dt>TLS</dt>
                      <dd>{r.tls ? `yes${r.certResolver ? ` (${r.certResolver})` : ""}` : "no"}</dd>
                    </>
                    {r.servicePort && (
                      <>
                        <dt>Service port</dt>
                        <dd>{r.servicePort}</dd>
                      </>
                    )}
                    {r.middlewares.length > 0 && (
                      <>
                        <dt>Middlewares</dt>
                        <dd>
                          {r.middlewares.map((m) => (
                            <span class="pill">{m}</span>
                          ))}
                        </dd>
                      </>
                    )}
                  </dl>
                </div>
              ))}
            </Section>
          )}

          {/* The live counterpart of the section above: same subject, different source.
              Kept adjacent to it deliberately — the two accounts of one router are only
              useful side by side, and any difference between them is what the notes at
              the top of the drawer are about. */}
          {svc.traefikLive && svc.traefikLive.length > 0 && (
            <Section title="Traefik ingress — live, from its API">
              {svc.traefikLive.map((r) => (
                <div style="margin-bottom:10px;">
                  <div style="font-weight:600;">
                    {r.router}
                    <span class="mono masked">@{r.provider}</span>
                    {/* Traefik's own verdict on the router. Anything but a clean
                        `enabled` means it is not in a request path at all. */}
                    {r.status && r.status.toLowerCase() !== "enabled" ? (
                      <span class="pill crit">{r.status}</span>
                    ) : (
                      <span class="pill">{r.status ?? "enabled"}</span>
                    )}
                  </div>
                  <dl class="kv" style="grid-template-columns:120px 1fr;margin-top:4px;">
                    {r.rule && (
                      <>
                        <dt>Rule</dt>
                        <dd class="mono">{r.rule}</dd>
                      </>
                    )}
                    {r.hosts.length > 0 && (
                      <>
                        <dt>Hosts</dt>
                        <dd>
                          {r.hosts.map((h) => (
                            <a class="pill" href={`https://${h}`} target="_blank" rel="noreferrer">
                              {h}
                            </a>
                          ))}
                        </dd>
                      </>
                    )}
                    {r.entryPoints.length > 0 && (
                      <>
                        <dt>Entrypoints</dt>
                        <dd>{r.entryPoints.join(", ")}</dd>
                      </>
                    )}
                    <>
                      <dt>TLS</dt>
                      <dd>{r.tls ? "yes" : "no"}</dd>
                    </>
                    <>
                      {/* The chain as built, not as asked for: chains expanded,
                          entrypoint middlewares merged in, each entry saying where it
                          came from. An empty chain on a router whose labels name one is
                          exactly the discrepancy worth seeing. */}
                      <dt>Chain</dt>
                      <dd>
                        {r.middlewares.length === 0 ? (
                          <span class="masked">none</span>
                        ) : (
                          r.middlewares.map((m) => (
                            <div>
                              <span class={`pill${m.errors.length ? " crit" : ""}`}>{m.name}</span>
                              <span class="mono masked">{m.type}</span>
                              {m.viaEntrypoint && <span class="pill">via entrypoint</span>}
                              {m.viaChain && <span class="pill">via {m.viaChain}</span>}
                              {m.address && <span class="mono masked">→ {m.address}</span>}
                              {m.errors.map((e) => (
                                <div class="mono">{e}</div>
                              ))}
                            </div>
                          ))
                        )}
                      </dd>
                    </>
                    {r.service && (
                      <>
                        <dt>Service</dt>
                        <dd class="mono">{r.service}</dd>
                      </>
                    )}
                    {r.servers.length > 0 && (
                      <>
                        {/* Backend health as the proxy last observed it — the one part
                            of this section no configuration file can state. */}
                        <dt>Backends</dt>
                        <dd>
                          {r.servers.map((sv) => (
                            <div>
                              <span class="mono">{sv.url}</span>
                              {sv.status && (
                                <span
                                  class={`pill${sv.status.toUpperCase() === "DOWN" ? " crit" : ""}`}
                                >
                                  {sv.status}
                                </span>
                              )}
                            </div>
                          ))}
                        </dd>
                      </>
                    )}
                    {r.errors.length > 0 && (
                      <>
                        <dt>Errors</dt>
                        <dd class="mono">{r.errors.join("; ")}</dd>
                      </>
                    )}
                  </dl>
                  {/* Why this router was tied to this service. A match is a conclusion,
                      in the same voice as the origin and Authentik evidence. */}
                  {r.evidence.length > 0 && (
                    <ul class="evidence" style="margin-top:4px;">
                      {r.evidence.map((e) => (
                        <li>{e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </Section>
          )}

          <Section title="Authentication">
            <dl class="kv">
              <dt>Method</dt>
              <dd>
                <AuthBadge method={svc.auth.method} />
                {/* A conclusion drawn from a middleware name alone is labelled as
                    such, so a reader never has to re-derive whether the evidence
                    below is a definition or a guess. */}
                {svc.auth.confidence === "inferred" && (
                  <span class="pill" title="No middleware definition was found in the scanned stacks">
                    inferred from name
                  </span>
                )}
                {/* The other direction: a responsible system's own API reported this
                    gate — the identity provider's records, or the chain the proxy
                    actually built — so it states what will be enforced rather than what
                    the labels asked for. */}
                {svc.auth.confidence === "confirmed" && (
                  <span
                    class="pill"
                    title="Reported by the Authentik API or the proxy's live configuration, not derived from labels"
                  >
                    confirmed by API
                  </span>
                )}
              </dd>
              <dt>Detail</dt>
              <dd>{svc.auth.detail}</dd>
            </dl>
            {svc.auth.evidence.length > 0 && (
              <ul class="evidence" style="margin-top:8px;">
                {svc.auth.evidence.map((e) => (
                  <li class="mono">{e}</li>
                ))}
              </ul>
            )}
          </Section>

          {/* Placed after Authentication on purpose: the evidence is read first, and this
              is read as what the operator says about the same service. Nothing in here
              was observed, and nothing in here changed anything above it. */}
          {declaredFile && (
            <Section title={`Declared by the operator (${declaredFile})`}>
              {/* Where the file and the scan disagree, first — a stale declaration is
                  worth more attention than the declaration itself. */}
              {declared?.drift.map((d) => (
                <div class="note crit">{d}</div>
              ))}
              <dl class="kv">
                {description && (
                  <>
                    <dt>Description</dt>
                    <dd>
                      {description.value}
                      <InheritedMark shown={description.inherited} />
                    </dd>
                  </>
                )}
                {declared && declared.auth.length > 0 && (
                  <>
                    <dt>Authentication</dt>
                    <dd>
                      {declared.auth.map((a) => (
                        <div>
                          <span class="pill">{declaredAuthLabel(a.mechanism)}</span>
                          {a.detail && <span> {a.detail}</span>}
                        </div>
                      ))}
                      <div class="muted-inline">
                        Declared here, not detected by the scan — the posture above is what
                        LabView could observe.
                      </div>
                    </dd>
                  </>
                )}
                {accepted && (
                  <>
                    <dt>Unauthenticated</dt>
                    <dd>
                      Intentional — {accepted.reason}
                      <div class="muted-inline">
                        Still counted as exposed. The acceptance records that it was
                        reviewed, and lets the "hide accepted" filter put it aside.
                      </div>
                    </dd>
                  </>
                )}
                {declared?.expectedIngress && (
                  <>
                    <dt>Expected ingress</dt>
                    <dd>
                      {declared.expectedIngress.map(ingressLabel).join(", ")}
                      {/* Compared as sets, because the expectation and the scan are both
                          lists now: agreement means the same kinds, in any order. */}
                      {expectedMatches(declared.expectedIngress, svc.ingress) ? (
                        <span class="pill">matches the scan</span>
                      ) : (
                        <span class="pill crit">
                          scan says {svc.ingress.map(ingressLabel).join(", ")}
                        </span>
                      )}
                    </dd>
                  </>
                )}
                {owner && (
                  <>
                    <dt>Owner</dt>
                    <dd>
                      {owner.value}
                      <InheritedMark shown={owner.inherited} />
                    </dd>
                  </>
                )}
                {criticality && (
                  <>
                    <dt>Criticality</dt>
                    <dd>
                      <span class={`pill${criticalHint(criticality.value) ? " crit" : ""}`}>
                        {criticality.value}
                      </span>
                      <InheritedMark shown={criticality.inherited} />
                    </dd>
                  </>
                )}
                {data && (
                  <>
                    <dt>Data</dt>
                    <dd>
                      {data.value}
                      <InheritedMark shown={data.inherited} />
                    </dd>
                  </>
                )}
                {dependencies && (
                  <>
                    <dt>Dependencies</dt>
                    <dd>
                      {dependencies.value.map((d) => (
                        <div>
                          {d.name}
                          {d.detail && <span class="muted-inline"> — {d.detail}</span>}
                        </div>
                      ))}
                      <InheritedMark shown={dependencies.inherited} />
                    </dd>
                  </>
                )}
                {links && (
                  <>
                    <dt>Links</dt>
                    <dd>
                      {links.value.map((l) => (
                        <div>
                          {/* rel is not optional here: these URLs come from a file LabView
                              does not control, and a target=_blank without it hands the
                              opened page a handle on this one. */}
                          <a href={l.url} target="_blank" rel="noopener noreferrer">
                            {l.label}
                          </a>
                        </div>
                      ))}
                      <InheritedMark shown={links.inherited} />
                    </dd>
                  </>
                )}
                {notes && (
                  <>
                    <dt>Notes</dt>
                    <dd>
                      {notes.value}
                      <InheritedMark shown={notes.inherited} />
                    </dd>
                  </>
                )}
              </dl>
            </Section>
          )}

          {svc.authentik && svc.authentik.applications.length > 0 && (
            <Section title="Identity provider — Authentik (from its API)">
              {svc.authentik.applications.map((app) => (
                <div style="margin-bottom:10px;">
                  <div style="font-weight:600;">
                    {app.name} <span class="mono masked">{app.slug}</span>
                    {app.group && <span class="pill">{app.group}</span>}
                  </div>
                  <dl class="kv" style="grid-template-columns:120px 1fr;margin-top:4px;">
                    {app.launchUrl && (
                      <>
                        <dt>Launch URL</dt>
                        <dd class="mono">{app.launchUrl}</dd>
                      </>
                    )}
                    {app.providers.map((p) => (
                      <>
                        <dt>{p.kind === "other" ? "Provider" : `${p.kind} provider`}</dt>
                        <dd>
                          {p.name}
                          {p.mode && <span class="pill">{p.mode}</span>}
                          {p.backchannel && <span class="pill">backchannel</span>}
                          {/* An outpost is what puts a proxy, LDAP or RADIUS provider in
                              the request path. None means the gate is configured but
                              standing nowhere — which the notes above spell out. */}
                          {p.outposts.length > 0 ? (
                            p.outposts.map((o) => <span class="pill">outpost: {o}</span>)
                          ) : needsOutpost(p.kind) ? (
                            <span class="pill crit">no outpost</span>
                          ) : null}
                          {p.internalHost && <div class="mono masked">→ {p.internalHost}</div>}
                        </dd>
                      </>
                    ))}
                  </dl>
                </div>
              ))}
              {/* Why each application was tied to this service, in the same voice as the
                  auth and origin evidence: a match is a conclusion, not a given. */}
              {svc.authentik.evidence.length > 0 && (
                <ul class="evidence" style="margin-top:8px;">
                  {svc.authentik.evidence.map((e) => (
                    <li>{e}</li>
                  ))}
                </ul>
              )}
            </Section>
          )}

          {svc.networks.length > 0 && (
            <Section title="Networks">
              {svc.networks.map((nw) => (
                <span class="pill">{nw}</span>
              ))}
            </Section>
          )}

          {svc.ports.length > 0 && (
            <Section title="Ports">
              <table class="data">
                <thead>
                  <tr>
                    <th>Published</th>
                    <th>Container</th>
                    <th>Proto</th>
                  </tr>
                </thead>
                <tbody>
                  {svc.ports.map((p) => (
                    <tr>
                      <td class="mono">{p.published ?? "—"}</td>
                      <td class="mono">{p.target}</td>
                      <td>{p.protocol}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}

          {svc.mounts.length > 0 && (
            <Section title="Volumes & mounts">
              <table class="data">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Container path</th>
                    <th>Mode</th>
                  </tr>
                </thead>
                <tbody>
                  {svc.mounts.map((m) => (
                    <tr>
                      <td>{m.type}</td>
                      <td class="mono">{m.source ?? "—"}</td>
                      <td class="mono">{m.target}</td>
                      <td>{m.readOnly ? "ro" : "rw"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}

          {svc.env.length > 0 && (
            <Section title={`Environment (${svc.env.length})`}>
              <table class="data">
                <thead>
                  <tr>
                    <th>Key</th>
                    <th>Value</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {svc.env.map((e) => (
                    <tr>
                      <td class="mono">{e.key}</td>
                      <td class="mono">
                        {/* A masked entry either has no value at all (key matched a
                            secret pattern) or a partially redacted one (an inline
                            URI password was stripped) — show the latter. */}
                        {e.masked && e.value === null ? (
                          <span class="masked">•••••• (masked)</span>
                        ) : e.masked && e.value !== null ? (
                          <span title="password redacted">{e.value}</span>
                        ) : (
                          e.value ?? <span class="masked">∅</span>
                        )}
                      </td>
                      <td>{e.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}

          {svc.docker && (
            <Section title="Live container state">
              <dl class="kv">
                <dt>Status</dt>
                <dd>{svc.docker.status}</dd>
                <dt>State</dt>
                <dd>{svc.docker.state}</dd>
                {svc.docker.health && svc.docker.health !== "none" && (
                  <>
                    <dt>Health</dt>
                    <dd>{svc.docker.health}</dd>
                  </>
                )}
                {typeof svc.docker.restartCount === "number" && (
                  <>
                    <dt>Restarts</dt>
                    <dd>{svc.docker.restartCount}</dd>
                  </>
                )}
                {svc.docker.startedAt && (
                  <>
                    <dt>Started</dt>
                    <dd>{fmtTime(svc.docker.startedAt)}</dd>
                  </>
                )}
                {svc.docker.imageDigest && (
                  <>
                    <dt>Image digest</dt>
                    <dd class="mono" style="word-break:break-all;">{svc.docker.imageDigest}</dd>
                  </>
                )}
                {Object.keys(svc.docker.ipAddresses).length > 0 && (
                  <>
                    <dt>IP addresses</dt>
                    <dd class="mono">
                      {Object.entries(svc.docker.ipAddresses).map(([net, ip]) => (
                        <div>
                          {net}: {ip}
                        </div>
                      ))}
                    </dd>
                  </>
                )}
              </dl>
            </Section>
          )}
        </div>
      </aside>
    </>
  );
}
