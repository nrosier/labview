# probe-lab

See what LabView's login rule reads at a URL, and what it would take to read more.

A diagnostic, not part of the scan. Nothing in `src/` imports it, no scan consults it, and the
`Dockerfile` COPYs named paths so it never enters the image.

## Why it exists

A service LabView reports as **open** — reachable, no authentication found, no login page
observed — is one of two completely different things:

1. a genuinely unprotected application, which is a finding worth acting on; or
2. an application with a login screen this rule cannot see.

Both appear as the same row on the dashboard, and there was no way to look at the page and find
out which. That is what this is for. Point it at the address and it reports the verdict, then
**every one of the seven signals and why each did not fire**, then all the evidence no signal
reads yet, then what an eighth signal would have to be.

**Two of those misses are not about the page at all.** Pointed at a real fleet, the reports came
back saying "no `<form>` in the served markup" for service after service whose operator sees a
sign-in screen in a browser — and in every case the login was somewhere the scan does not look
rather than something the scan misread:

- **Further down a redirect chain.** A same-origin 3xx to a path the login list does not have,
  then another, and the sign-in screen is on the third response. `readGate` reads the first.
- **At a different address entirely.** A single-page application serves one shell at every path
  and routes in the browser, so there is no redirect and no form — but whatever the shell draws
  has to fetch state, and that fetch is refused when nobody is signed in. The refusal is real,
  HTTP-level, and one path away from where the scan asks.

So the tool follows the chain and asks a fixed list of current-user addresses. Both are reported
as evidence, and **neither can change the verdict**: what a report says LabView concluded is what
LabView would conclude from the one response it reads.

The rule being sharpened lives in [`src/model/probe.ts`](../../src/model/probe.ts). It is strict
on purpose: everything it does not recognise reads as "answered, no gate observed", which leaves
the exposure finding standing. A finding a reader dismisses costs them a look; false comfort is
the thing LabView exists to remove. So the useful change is almost never "loosen a clause" — it
is "here is a fact this response carries that no clause reads."

## Running it

```sh
npm run probe-lab -- https://app.example.com
npm run probe-lab -- --urls targets.txt
npm run probe-lab -- --from-scan overview.json --lan-host 192.168.1.10
```

| Option | |
| --- | --- |
| `--urls <file>` | one URL per line; blank lines and `#` comments ignored |
| `--from-scan <file>` | a saved `GET /api/overview` — see below |
| `--lan-host <host>` | host address for `--from-scan`'s LAN vantage (default: none) |
| `--paths a,b` | also ask these paths on each origin (default: only the URL given) |
| `--no-follow` | stop at the first answer (default: follow the redirect chain) |
| `--max-hops <n>` | how far to follow a chain (default: 5) |
| `--sweep` | ask the auth-state addresses on every target that answered |
| `--no-sweep` | never ask them (default: only where a page had no gate and no form) |
| `--timeout <ms>` | per request (default: 8000) |
| `--concurrency <n>` | targets in flight (default: 1) |
| `--out <dir>` | report directory (default: `tools/probe-lab/reports`, gitignored) |
| `--raw-headers` | do not redact header values (default: redacted) |

A bare host is read as `https://host/`. Query and fragment are dropped from every address, for
the same reason `readRedirect` drops them: neither changes whether a page is a login page, and
either can carry a token that has no business in a file.

### `--from-scan`

The one that answers the question directly: *the services for which LabView detected neither
authentication nor a login page.* It reads a saved overview payload and selects services with

- no detected authentication — `hasDetectedAuth(svc)` is false, the same predicate the scan uses
  to decide which services to probe at all; and
- no gate found by the probe, if the payload was produced with probing on.

Addresses come from **`probeTargets`**, the same function the scan uses, so the lab asks the
addresses the scan asked. Save a payload with:

```sh
npm run scan > overview.json          # or: curl -s localhost:3000/api/overview > overview.json
```

The LAN vantage needs `--lan-host` here for the reason the scan needs `probe.lanHost`: a
container cannot see its host's LAN address, and a saved payload does not carry the one it was
given.

## What it will and will not request

Invariant **I8** applies here with full force — this sends requests at somebody's services, at
addresses a person typed.

- **`GET`**, and nothing else. There is no method flag.
- **No credential, ever.** Nothing on the call path has one in scope and no option supplies one.
  What an unauthenticated visitor gets is the whole measurement — and for the auth-state sweep
  below it is not merely a bound but the entire point, since a 401 is only evidence when nothing
  was sent that could have earned a 200.
- **A redirect chain is followed to its end, while no gate has been found.** `--max-hops` bounds
  it (default 5), a repeated address ends it, and `--no-follow` turns it off. The gate condition
  is what matters: an off-origin `Location` *is* `redirect-origin`, so a hand-off to an identity
  provider is recognised at the first response and **never walked into**. Nothing is sent to
  somebody's SSO endpoint by this tool. The chain's end gets a report of its own, built from the
  answer already in hand rather than from a second request.
- **The auth-state sweep is the one place it asks for more than it was given.** Where a page came
  back with no gate and no `<form>` at all — the client-rendered shell, the one case where reading
  the body cannot work even in principle — the addresses in `AUTH_STATE_PATHS` are asked as well:
  a **fixed list of eight**, the same eight every run, reviewed in the source rather than derived
  at runtime. Sequential regardless of `--concurrency`, because eight requests at once is a burst
  a rate limiter is entitled to read as an attack. `--no-sweep` restores the older bound of one
  address per target; `--sweep` asks everywhere, for a page that is not obviously a shell.
- **Nothing a page suggests is ever fetched** — not an asset, not a form action, not a link. Every
  address asked is one of four things: given on the command line, listed in `--urls` or `--paths`,
  named by the *service* in a `Location` header, or a constant in this tool's source. None of them
  is parsed out of a page's markup.
- **Every run says what it sent.** The closing lines report hops followed and sweep requests made,
  so the bounds above are checkable against the output and not only against the source.
- **Sequential by default**, each request with a timeout.
- **The body is read only when it is HTML**, and only to `MAX_BODY_BYTES` (64 KiB).
- **Header values are redacted by default.** `Set-Cookie` is reduced to cookie *names* — the
  value is never read at all, since a session cookie's value is a credential and a report is a
  file somebody pastes into an issue. Anything whose name matches `authorization`, `token`,
  `secret`, `password`, `credential`, `api-key` or `signature` is replaced by its length.
  `--raw-headers` opts out. `WWW-Authenticate` is deliberately *not* redacted: its value is a
  challenge rather than a secret, and it is the fact the `challenge` clause turns on.
- **Writes only under `--out`**, and nothing anywhere else.

None of those bounds is restated in this tool's own code. `cli.ts` calls
[`getResponse`](../../src/enrich/http.ts) — the same function `enrich/probe.ts` calls — through a
`FetchLike` wrapper whose only job is to keep the response headers `getResponse` discards. The
transport is inherited, so tightening a bound in the pipeline tightens it here in the same
commit.

## What comes out

Two files per target under `--out`, plus an `index.md` with one row per target. The index's
**Chain** and **Auth-state** columns are the two to scan first — either one filled in is a row
whose verdict is not the whole story.

The `.md` is for reading while changing `readGate`. Four sections, plus two that appear only when
there was something to put in them:

1. **Verdict** — the gate or none, in the dashboard's own words (`probeOutcome`,
   `probeReasonText`), and whether it would take the service out of the exposed count.
2. **What the rule read** — status, `Location` and its resolution, `WWW-Authenticate`,
   `Content-Type` → media type → whether that is HTML at all, body size and truncation, the
   strongest form's shape. Then **one row per signal**, fired or not, naming the fact that
   decided it. Rows are in `readGate`'s precedence order and the deciding one is marked, so a
   page satisfying two clauses shows which one won.
2b. **Where the chain went** — one row per followed hop, with the address, the status, the
   `Location` and its resolution, and **what `readGate` would have found there**. Present only
   when the first answer was a redirect the rule found nothing in. A signal on any row is a
   signal the scan does not see, and the heading says so above the table.
3. **What the rule did not consider** — the evidence an eighth signal would be built from:
   every `<form>` with every `<input>`'s `type`/`name`/`id`/`placeholder`/`autocomplete`/
   `aria-label` and every button label, `<title>`, first `<h1>`, `lang`,
   `<meta name="generator">`, every `<script src>` and `<link>`, all surviving response headers,
   and `Set-Cookie` names. Then, when the sweep ran, **Auth-state addresses**: each path with its
   status, content type, `WWW-Authenticate` and body size — or the note that its body was the same
   bytes as the page, which is a catch-all router rather than an endpoint that served an anonymous
   caller. A `SweepStep` has no header field at all, so nothing set on a swept response can reach
   a report by any route.
4. **What would have to change** — one line per thing standing between this page and a verdict.
   A gate found down the chain, or a refusal at a current-user address, leads it: those settle
   what everything below them only raises.

The `.json` is the actual deliverable. It is a structured observation that can be dropped into
`scripts/smoke.ts` as a fixture, so a proposed rule is replayed against the real page offline,
with no network and nobody's service involved.

## The one guarantee worth knowing

**The verdict in a report *is* the pipeline's verdict.** `report.ts` imports `readGate`,
`readLoginForm`, `readRedirect`, `readRefresh`, `readMediaType`, `isHtmlMediaType`,
`probeGateText`, `probeOutcome`, `probeReasonText` and the four clause predicates
(`isLoginPath`, `pointsAtLogin`, `hasPasswordField`, `hasSamlField`) from
[`src/model/probe.ts`](../../src/model/probe.ts) and reimplements none of them. A report that
described a decision LabView would not make would be worse than no report — it would send
somebody to change a rule that was never the problem — so the smoke pass asserts the equality
directly: every canned body in `scripts/smoke.ts` goes through `buildReport`, and the report's
gate must equal `readGate`'s on the same input.

Which means: the questions are shared, the *patterns* are not. `LOGIN_PATHS`, `USERNAME_WORDS`,
`SAML_FIELD` and `PASSWORD_INPUT` stay private to `src/model/probe.ts`. What this tool can ask
is what the rule asks; it can never ask it differently.

## Reading a report

Three patterns are worth knowing by sight, and the first two are the common ones.

**A 200 with no `<form>` and one bundle.** Section 4 says so explicitly. This is the known blind
spot: a login screen drawn by JavaScript is not in the served markup, so no body-only signal can
see it, at any body size and after any number of redirects. **Read the auth-state table.** A 401
or 403 at a current-user address, from a request carrying no credential, is the application saying
it does not know who is calling — the service is gated, and the gate is simply not at the address
the scan asks. That is the strongest evidence available short of rendering the page, and rendering
is a different tool with different bounds. If nothing there refuses either, the shell probably is
what it looks like, and section 4 says that too.

Acting on a refusal is a bigger change than it looks, which is why the report says so in those
words. Every one of the seven clauses reads *a response*; this one needs a **second request per
service** — a request budget, a list of addresses to argue about, and an I8 case to make. It is a
change to what the probe asks, not to how the rule reads, and the two should not be confused
because one needs a fixture and the other needs a decision.

**A same-origin 3xx to a path that is not in the login list.** LabView reads it as routing, and
the chain section says where it actually went. If a hop carries a signal, the service is gated and
the scan looked one response too early — but the fix is still not "follow redirects in the scan".
The first `Location` is a string the scan already holds, so recognising that path costs nothing and
needs no extra request, while following costs a request per service and a second address to be
wrong about. Adding the name to `LOGIN_PATHS` needs a fixture, because the list only ever *adds* a
gate to a same-origin redirect, so a wrong entry costs a false gate rather than a missed one.

**A chain that ends on another shell.** Both patterns at once, and the one to be most careful
with: the sign-in screen is at the end of the chain *and* drawn in the browser, so the chain
section proves where the service sends an anonymous visitor while the served markup there proves
nothing either way. The path names in the chain are the evidence — not the page at the end of it.

Anything added to the rule needs a fixture under `fixtures/probe/`, and by the fixture-revert
contract that fixture must fail the smoke pass when the rule is backed out. Two existing
fixtures are there to keep the rule honest in the other direction — `meta-refresh/home` and
`passwordless/news` — and a loosened clause is most likely to break them first. That is the
signal to design the change differently, not to change the fixtures.
