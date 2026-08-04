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
**every one of the eight signals and why each did not fire**, then all the evidence no signal
reads yet, then what a ninth signal would have to be.

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

So the tool follows the chain and asks a list of current-user addresses. Both are reported as
evidence, and the report's verdict stays the pipeline's: what a report says LabView concluded is
what LabView would conclude from what the scan itself would have seen.

**Both of those findings have since become rules, which is this tool having worked.** Neither
needed the rule loosened:

- The first one turned out not to need a chain at all. The services in question were Authentik,
  and their **first** `Location` was already the evidence — a flow-executor path that
  `LOGIN_PATHS` simply did not have. Two list entries and a fixture, no new signal, no second
  request, and the chain-walking the report suggested was never needed.
- The second became the eighth signal, `state-challenge` (see
  [§3.6b](../../../IMPLEMENTATION.md)). The scan now asks four current-user addresses itself
  when — and only when — it got back a 200 of HTML with no `<form>` in it, and a refusal
  carrying `WWW-Authenticate` is a gate.

The lab still sweeps **eight** addresses where the scan asks four, so a refusal it finds at one
of the other four remains a finding. What changed is the size of the change it implies: it is now
*one entry missing from a list*, which is a commit with a fixture and no new rule in it, and the
report says so in those words.

It also makes the chain and the sweep **asymmetrical**, which they were not before. The chain
still cannot move a verdict — the scan follows no redirect, so nothing past the first `Location`
is something the pipeline could have seen. The sweep now can, but only for the four paths the
pipeline shares and only under the pipeline's own eligibility test: `report.ts` reconstructs a
`ProbeState` from `STATE_PATHS` alone and hands it to the real `readStateGate`. That is not this
tool acquiring a rule of its own; it is the same construction as before, following a rule that
moved.

**The third finding was about this tool, not about the rule.** Eight reports later, three of them
described twenty-four kilobytes of fully rendered page as "no `<form>` element in the served
markup" — and they were right, and it did not matter, because the proof the operator could see in
a browser was a plain `<a href="/login">Sign in</a>` next to four paragraphs of public content.
Nothing here had ever read an anchor. `readUnread` captured forms, scripts and the `<title>`; no
`<a href>`, no anchor text, no `<button>` outside a form, no visible text, no inline script. So
the reports were describing a page by everything it happened not to have.

Two things came out of that, and the split between them is the point:

- **The extraction grew to the whole of what a page shows**, and [section
  3a](#what-comes-out) now says what those facts *prove* about a visitor's view rather than leaving
  a reader to weigh a dump. Six detectors, none of which can move a verdict — the type that carries
  a finding has no way to say "gated".
- **One of the six was promoted into the pipeline**, and only one could be: `content-served` beside
  a sign-in offer is proof the service is **open**, so acting on it can only ever leave a service in
  the exposed count. That is `readAnonAccess` (see [§3.6c](../../../IMPLEMENTATION.md)), and the
  scan now says so in the page's own words on the dashboard. The candidate that would move a count
  the other way — a title saying login, no form, one bundle — is still only *proposed*, in section
  4, which is where a change to a gate rule belongs.

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
| `--try-login-paths` | also GET the ten names in the pipeline's own `LOGIN_PATHS` on a form-less shell's origin (default: off — these are guesses, not addresses anything named) |
| `--timeout <ms>` | per request (default: 8000) |
| `--concurrency <n>` | targets in flight (default: 1) |
| `--out <dir>` | report directory (default: `tools/probe-lab/reports`, gitignored) |
| `--raw-headers` | do not redact header values (default: redacted) |
| `--save-body` | also write the served HTML verbatim (default: off — it is the one file this tool writes that is **not** safe to paste into an issue) |

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
- **The auth-state sweep asks four addresses more than the scan does.** Where a page came back
  with no gate and no `<form>` at all — the client-rendered shell, the one case where reading the
  body cannot work even in principle — the addresses in `AUTH_STATE_PATHS` are asked as well: a
  **fixed list of eight**, the same eight every run, reviewed in the source rather than derived at
  runtime. Four of them are `STATE_PATHS`, which the scan now asks itself under the same
  eligibility test, so the sweep is *four* addresses beyond the pipeline rather than eight beyond
  nothing. Sequential regardless of `--concurrency`, because eight requests at once is a burst a
  rate limiter is entitled to read as an attack. `--sweep` asks everywhere, for a page that is not
  obviously a shell.
- **`--no-sweep` now makes the lab ask *less* than a scan would**, which is worth knowing before
  using it. It is still the tightest setting and still bounds the run to one address per target —
  but with no sweep there is nothing to reconstruct a `ProbeState` from, so `pipelineState`
  withholds the eighth signal instead of guessing at it: *a short prefix understates the walk,
  which at worst withholds a gate; it can never invent one.* A `--no-sweep` report is therefore a
  floor on the verdict, not the verdict. Section 4 says which addresses went unasked.
- **The guessed login addresses are asked only if you ask for them.** `--try-login-paths` is off
  by default, and it is the only thing this tool sends that nothing named. The chain follows a
  `Location` the *service* gave; the sweep asks a convention the pipeline already trusts enough to
  spend a scan's second request on. This guesses — the ten entries of the pipeline's own
  `LOGIN_PATHS`, on the same form-less-shell eligibility as the sweep, sequential, `GET`, no
  credential — and a guess at ten addresses on somebody's service is a different kind of act, so it
  waits for the flag. There is no `--try-login-paths always`: the flag's whole case is the shell,
  and asking ten addresses of a page that already answered readably buys nothing.
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
- **The body is described, never dumped** — inline scripts are reported as a size, a type, the
  login-shaped path literals in them and the names of the globals they assign, and the visible text
  as a capped sample. `--save-body` is the exception and the one flag with a warning attached: it
  writes a third file per target, the served HTML verbatim, and **that file is not safe to paste
  into an issue** the way the `.md` and `.json` beside it are. An anonymous body carries no session,
  but it carries whatever its bootstrap script was handed — one real report listed a
  `/__config.js` — so this is off by default and the run's own closing lines say so every time it
  is used, not only here (I6).
- **Writes only under `--out`**, and nothing anywhere else.

None of those bounds is restated in this tool's own code. `cli.ts` calls
[`getResponse`](../../src/enrich/http.ts) — the same function `enrich/probe.ts` calls — through a
`FetchLike` wrapper whose only job is to keep the response headers `getResponse` discards. The
transport is inherited, so tightening a bound in the pipeline tightens it here in the same
commit.

## What comes out

Two files per target under `--out` — three with `--save-body` — plus an `index.md` with one row per
target. The index's **Chain** and **Auth-state** columns are the two to scan first: either one
filled in is a row whose verdict is not the whole story. A **Login paths** column joins them on a
run that passed `--try-login-paths`, and a column of dashes there is itself a finding — a service
that answers nothing at any of the ten names is a service whose login is somewhere else entirely.

The `.md` is for reading while changing `readGate`. Four sections, plus three that appear only when
there was something to put in them:

1. **Verdict** — the gate or none, in the dashboard's own words (`probeOutcome`,
   `probeReasonText`), and whether it would take the service out of the exposed count.
2. **What the rule read** — status, `Location` and its resolution, `WWW-Authenticate`,
   `Content-Type` → media type → whether that is HTML at all, body size and truncation, the
   strongest form's shape. Then **one row per signal**, fired or not, naming the fact that
   decided it. Rows are in `PROBE_GATES`' order — `readGate`'s precedence for its seven, with
   `readStateGate`'s `state-challenge` last — and the deciding one is marked, so a page
   satisfying two clauses shows which one won. The last row is the only one that can cite a
   *second* response, so it is the only one that has to say whether that request went out at all:
   it reads either "the served page was readable" — no second question warranted, the common case
   — or how many addresses were asked and what the one that refused answered.
2b. **Where the chain went** — one row per followed hop, with the address, the status, the
   `Location` and its resolution, and **what `readGate` would have found there**. Present only
   when the first answer was a redirect the rule found nothing in. A signal on any row is a
   signal the scan does not see, and the heading says so above the table.
3a. **What a visitor was shown** — the section that answers *this service has a sign-in page, so
   why does the tool say it found nothing?* The signal table above can only report which of eight
   clauses failed; this reports what the page **did**, one row per finding, each with the fact
   quoted from the page and why that fact points where it does. Six kinds: a login link, a
   form-less login control, a login route named in a bundle or an inline script, a login-shaped
   heading with no form, a session cookie on an anonymous GET, and `content-served` — the
   anti-gate, and the one this section was added for: *N characters of text and M links were
   served to a caller carrying no credential.* Each points at **open**, at **open with an optional
   account**, or at **worth another look**, and there is no fourth option — a finding here can
   never conclude a gate, because deciding gates is `readGate`'s and `readGate` cannot see any of
   this. So a `look-closer` row beside a "No login page" verdict is not the report contradicting
   itself; it is the report saying what a rule change would have to be built from. Read this
   before the dumps below it: it is the same evidence, already weighed.
3. **What the rule did not consider** — the evidence a ninth signal would be built from:
   every `<form>` with every `<input>`'s `type`/`name`/`id`/`placeholder`/`autocomplete`/
   `aria-label` and every button label; **every `<a href>`** with its resolved path, its text, its
   `aria-label` and the pipeline's own reading of each (`isLoginPath`, `saysLogin`, `saysLogout`);
   every **control outside every form**, which is where a single-page application keeps its
   sign-in; `<title>`, first `<h1>`, `lang`, every `<meta>`, the mount points and custom elements
   that fingerprint a shell, every `<script src>` and `<link>`, every inline script *described*
   rather than dumped, `<noscript>` contents, a capped sample of the **visible text**, all
   surviving response headers, and `Set-Cookie` names. Every list is bounded and every bound is
   reported as an `…Omitted` count, because a truncated anchor list that does not say it was
   truncated is how a reader concludes a page had no sign-in link. Anchors inside a `<template>`,
   `<noscript>`, `<script>` or `<svg>` are kept and marked `hidden`: worth knowing, since a
   client-side router ships its sign-in screen in one, but not evidence about what this response
   showed anybody. Then, when the sweep ran, **Auth-state addresses**: each path with its
   status, content type, `WWW-Authenticate` and body size — or the note that its body was the same
   bytes as the page, which is a catch-all router rather than an endpoint that served an anonymous
   caller. A `SweepStep` has no header field at all, so nothing set on a swept response can reach
   a report by any route. And, on a `--try-login-paths` run, **Guessed login addresses**: each of
   the ten `LOGIN_PATHS` names with its status, `readGate`'s reading of that answer, the page's
   own title and its size — or the same catch-all note, which matters more here, since every one
   of those paths is *expected* to 404 on a service that has no login.
4. **What would have to change** — one line per thing standing between this page and a verdict.
   A gate found down the chain, or a refusal at a current-user address, leads it: those settle
   what everything below them only raises.

The `.json` is the actual deliverable. It is a structured observation that can be dropped into
`scripts/smoke.ts` as a fixture, so a proposed rule is replayed against the real page offline,
with no network and nobody's service involved.

## The one guarantee worth knowing

**The verdict in a report *is* the pipeline's verdict.** `report.ts` imports `readGate`,
`readLoginForm`, `readRedirect`, `readRefresh`, `readMediaType`, `isHtmlMediaType`,
`probeGateText`, `probeOutcome`, `probeReasonText`, the four clause predicates
(`isLoginPath`, `pointsAtLogin`, `hasPasswordField`, `hasSamlField`), for the eighth
signal `wantsStateProbe`, `readState`, `readStateGate` and `STATE_PATHS` itself, and for the page
a visitor was shown `readAnonAccess`, `saysLogin`, `saysLogout`, `servedAnonContent`,
`LOGIN_LABEL_MAX` and `LOGIN_PATHS` — all from
[`src/model/probe.ts`](../../src/model/probe.ts), and it reimplements none of them. A report that
described a decision LabView would not make would be worse than no report — it would send
somebody to change a rule that was never the problem — so the smoke pass asserts the equality
directly: every canned body in `scripts/smoke.ts` goes through `buildReport`, and the report's
gate must equal `readGate`'s on the same input.

**Section 3a is asserted as a *non*-effect, which is the same guarantee read backwards.** Every row
of the detector table in `scripts/smoke.ts` is put through `buildReport` and must leave
`verdict.gate` exactly as `readGate` alone decided it, and `EvidenceFinding.direction` has no
`"gated"` member — so a detector cannot express the conclusion it must not reach, and cannot reach
it by accident either. The same holds for `--try-login-paths` across all three of its answer
shapes. A finding here is worth what a paragraph in a diagnostic file is worth, and never a
service's place in the exposed count.

Which means: the questions are shared, the *patterns* are not. `USERNAME_WORDS`, `SAML_FIELD`,
`PASSWORD_INPUT`, `LOGIN_LABEL` and `NOT_LOGIN_LABEL` stay private to `src/model/probe.ts`, and so
do the two content thresholds behind `servedAnonContent` — the tool asks the question and is told
the answer, rather than comparing two numbers of its own that would eventually disagree with the
sentence the dashboard shows for the same page. What this tool can ask is what the rule asks; it
can never ask it differently.

## Reading a report

Four patterns are worth knowing by sight. Check the first one before any of the others, because it
is the one that **settles** the question instead of deepening it.

**A page that served you content.** Section 3a leads with `content-served`, and if a login link or
a form-less sign-in control is there beside it, the two together are the answer: the service is
open and has an optional account. Nothing is missing from the rule, nothing needs a ninth signal,
and the scan's own verdict already says as much in the reason line at the top of the report — this
is the one finding in the tool that was promoted into the pipeline, precisely because it can only
ever leave a service **in** the exposed count. Two things to check before believing it, and the
report gives you both: that the text and links are the *application's* content and not a cookie
banner with a nav bar, which the visible-text sample in section 3 shows you directly; and that the
sign-in row is not `hidden`, since an anchor found inside a `<template>` was served but never
drawn. Content with **no** offer is the weaker, still-useful half — it rules out the shell below.
An offer with no content is not this pattern at all; it is the next one.

**A 200 with no `<form>` and one bundle.** Section 4 says so explicitly. This is the known blind
spot: a login screen drawn by JavaScript is not in the served markup, so no body-only signal can
see it, at any body size and after any number of redirects. **Read the auth-state table.** A 401
at a current-user address, from a request carrying no credential, is the application saying it
does not know who is calling. That is the strongest evidence available short of rendering the
page, and rendering is a different tool with different bounds. If nothing there refuses either,
the shell probably is what it looks like, and section 4 says that too.

This is also the one pattern `--try-login-paths` was added for, and it is worth a second run rather
than a first: with the flag on, the report gains **Guessed login addresses**, one row per name in
the pipeline's own `LOGIN_PATHS`, and each row reads one of three ways. A login page at one of them
means the sign-in screen exists at a path the scan already trusts as a *name* — a redirect to it
would have been caught, so what is missing is the redirect, not the rule. The same bytes as the
root means a catch-all router, which is positive proof the login is drawn client-side and closes
the question this pattern opens. A 404 rules the path out. None of it can move the verdict, because
the scan sends none of these requests — the rows land in section 4 as a sized change.

What to do about a refusal depends on **which** address it came from, and that is the one thing to
read carefully here:

- **At one of the four in `STATE_PATHS`** — the scan already asks it. If the refusal carried
  `WWW-Authenticate`, the verdict at the top of the report is already `state-challenge` and there
  is nothing to change. If it did not, that is deliberate: a bare 401 is what an anonymous-enabled
  Grafana and a world-readable Gitea answer, so counting it would clear services that really are
  open. Changing that is a one-line change to `readStateGate` and a decision about which error you
  would rather make — not a missing rule. If a ninth signal ever settles this one, this is the shape
  it would need: not a looser reading of the refusal, but a *second fact beside it* — whether the API
  serves anything at all to a caller with no credential, as well as refusing its current-user
  address. An application that refuses everything anonymously is not the anonymous-enabled Grafana
  the bare 401 has to stay safe for, and unlike a login route literal in a bundle that fact is
  specific to *this* deployment rather than shipped with the application. It would have to be
  measured here first — enough real bodies to know what it clears wrongly — before it became a rule,
  a fixture and a revert trap, which is the road `state-challenge` took.
- **At one of the other four the lab sweeps** — that is a finding, and section 4 sizes it: one
  entry added to `STATE_PATHS`, a fixture under `fixtures/probe/`, and no new rule. The list is
  the request budget, so an entry is not free; but it is a much smaller change than the one this
  paragraph used to describe, back when the scan asked a single address per service and reading a
  refusal at a second one was a new *kind* of request.

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
