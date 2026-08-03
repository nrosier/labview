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
| `--follow` | follow one hop of a 3xx, as its own target (default: off) |
| `--timeout <ms>` | per request (default: 8000) |
| `--concurrency <n>` | requests in flight (default: 1) |
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

- **`GET`**, at the address given, and nothing else. There is no method flag.
- **No credential, ever.** Nothing on the call path has one in scope and no option supplies one.
  What an unauthenticated visitor gets is the whole measurement, so a credential would destroy
  it as surely as following a redirect would.
- **No redirect followed** unless `--follow`, and then exactly one hop, reported as its own
  target with its own report.
- **Nothing a page suggests is ever fetched** — not an asset, not a form action, not a link.
  `--paths` exists so an extra address is something the operator typed.
- One request per target, **sequential by default**, each with a timeout.
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

Two files per target under `--out`, plus an `index.md` with one row per target.

The `.md` is for reading while changing `readGate`. Four sections:

1. **Verdict** — the gate or none, in the dashboard's own words (`probeOutcome`,
   `probeReasonText`), and whether it would take the service out of the exposed count.
2. **What the rule read** — status, `Location` and its resolution, `WWW-Authenticate`,
   `Content-Type` → media type → whether that is HTML at all, body size and truncation, the
   strongest form's shape. Then **one row per signal**, fired or not, naming the fact that
   decided it. Rows are in `readGate`'s precedence order and the deciding one is marked, so a
   page satisfying two clauses shows which one won.
3. **What the rule did not consider** — the evidence an eighth signal would be built from:
   every `<form>` with every `<input>`'s `type`/`name`/`id`/`placeholder`/`autocomplete`/
   `aria-label` and every button label, `<title>`, first `<h1>`, `lang`,
   `<meta name="generator">`, every `<script src>` and `<link>`, all surviving response headers,
   and `Set-Cookie` names.
4. **What would have to change** — one line per thing standing between this page and a verdict.

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

Two patterns are worth knowing by sight.

**A 200 with no `<form>` and one bundle.** Section 4 says so explicitly. This is the known blind
spot: a login screen drawn by JavaScript is not in the served markup, so no body-only signal can
see it. Recognising it needs either a rendered page — which the probe will not do, since running
a browser against a scanned service is a different tool with different bounds — or a marker the
shell itself carries, which is why section 3 lists cookie names and vendor headers.

**A same-origin 3xx to a path that is not in the login list.** LabView reads it as routing. If
that path is the sign-in screen under a name `LOGIN_PATHS` does not have, adding the name is a
one-word change — and it needs a fixture, because the list only ever *adds* a gate to a
same-origin redirect, so a wrong entry costs a false gate rather than a missed one. Check with
`--paths` first: ask the target directly and see whether it serves a login form.

Anything added to the rule needs a fixture under `fixtures/probe/`, and by the fixture-revert
contract that fixture must fail the smoke pass when the rule is backed out. Two existing
fixtures are there to keep the rule honest in the other direction — `meta-refresh/home` and
`passwordless/news` — and a loosened clause is most likely to break them first. That is the
signal to design the change differently, not to change the fixtures.
