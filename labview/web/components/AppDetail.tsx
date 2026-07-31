import type { AppStack, AuthentikProviderKind, OriginTarget, Service } from "../model";
import { fmtTime, shortImage, statusView } from "../lib/format";
import { buildServiceMermaid } from "../lib/mermaidDef";
import { AuthBadge, ExposedBadge, IngressBadge, StatusDot } from "./badges";
import { Mermaid } from "./Mermaid";

function Section({ title, children }: { title: string; children: preact.ComponentChildren }) {
  return (
    <div class="section">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

/**
 * Where a tunnel origin was found to lead, in a few words. The full reasoning is
 * listed as evidence under the table, so this only has to say which of the four
 * conclusions was reached.
 */
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

export function AppDetail({ stack, svc, onClose }: { stack: AppStack; svc: Service; onClose: () => void }) {
  const s = statusView(svc.docker);
  const def = buildServiceMermaid(svc, stack);

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
            <IngressBadge kind={svc.ingress} />
            <AuthBadge method={svc.auth.method} />
            {svc.auth.exposedWithoutAuth && <ExposedBadge />}
          </div>

          {svc.notes.length > 0 && (
            <div style="margin-top:12px;">
              {svc.notes.map((note) => (
                <div class={`note${svc.auth.exposedWithoutAuth ? " crit" : ""}`}>{note}</div>
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
            <Section title="Local ingress — Traefik">
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
                {/* The other direction: the identity provider's own API reported this
                    gate, so it states what will be enforced rather than what the
                    labels asked for. */}
                {svc.auth.confidence === "confirmed" && (
                  <span class="pill" title="Reported by the Authentik API, not derived from labels">
                    confirmed by provider
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
