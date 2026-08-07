/* LabView's browser bundle.
 *
 * §22.1: the interface derives everything from the payload it was given. It holds no fleet knowledge,
 * no threshold, no member spelling and no view slug of its own — every one of those is a table in Go,
 * serialised into assets/contract.js by internal/webui/contract.go. This file is an *evaluator* of
 * those tables. Read that literally: there is no `if (view === 'services')` anywhere below, because a
 * view is a row of a table and a slug is data.
 *
 * It may relabel and it must never conclude. Relabelling here means: rendering a stored member as its
 * term's label, a boolean finding as the member of the `finding` vocabulary the contract carries for
 * it, and an absent optional number as *not reported*. Concluding would mean deciding that a service
 * is reachable, that two things are the same, or that a number is zero because nothing said otherwise
 * — none of which happens below.
 *
 * Colour: every colour comes from a `tone-*` class, and the tone comes from the term. A member this
 * build has no term for renders with the contract's `unknown` template — neutral, with a mark and the
 * sentence saying the payload is a later protocol (§16). Nothing here keys off a member name.
 *
 * Stated limitations, so that nobody has to discover them:
 *
 *   1. **This is a second evaluator of the shared tables.** The Go side is the tested reference: it
 *      builds the same rows, the same cards and the same diagrams and its results are asserted. When
 *      the two disagree, Go is right and this file has the bug. The tables cannot drift (a build step
 *      regenerates contract.js and a test fails when it is stale), but two evaluators of one table can.
 *   2. **Sort order is JavaScript's.** `Array.sort` compares UTF-16 code units where Go compares bytes;
 *      the two agree for the ASCII member names and identifiers this payload uses and can differ for
 *      non-ASCII service names. The row order is cosmetic, never a reading.
 *   3. **Only three drawers are addressable** (§22.7 gives parameters for a service, a network and the
 *      build stamp). The others open from the row that was clicked and close on reload rather than
 *      restoring — degraded, never broken (I4).
 *   4. **A drawer section the contract gives no field list for** is rendered as the clicked subject's
 *      own subtree, once, rather than as several empty headings.
 *   5. **A value a column's vocabulary does not contain renders as text**, not as an unknown chip: the
 *      same member arriving as a *tag* does get the fallback chip, and the filter controls list it, so
 *      §16's "read a later payload as far as it can be read" is carried by the tags.
 *   6. **The row kinds behind the drift and not-confirmed entry lists** are reached through the boolean
 *      narrowings §22.7 states (`drift=1`, `accepted=1`); a not-confirmed *entry* list has no parameter
 *      of its own in the grammar, so this build shows the service-level rows for it, as Go does.
 *
 * There is no build step for this file and no dependency: it is loaded after contract.js and reads
 * `window.LABVIEW_CONTRACT`.
 */
(function () {
  'use strict';

  var C = window.LABVIEW_CONTRACT;
  if (!C) {
    document.getElementById('boot').textContent =
      'The contract asset did not load. assets/contract.js is generated from internal/webui and this ' +
      'page cannot read a payload without it.';
    return;
  }

  // ---------------------------------------------------------------------------
  // The contract, indexed
  //
  // Every spelling this file needs is looked up by *name* from the contract's name table, so a member
  // renamed in Go arrives here without an edit. `M.paramView` is the parameter's name; the string
  // "view" appears nowhere below.
  // ---------------------------------------------------------------------------

  var M = {};
  C.names.forEach(function (n) { M[n.name] = n.value; });

  var SETS = {};
  (C.sets || []).forEach(function (s) {
    var by = {};
    s.terms.forEach(function (t) { by[t.member] = t; });
    SETS[s.name] = { terms: s.terms, by: by };
  });

  var VIEWS = {}, VIEW_ORDER = [];
  C.views.forEach(function (v) { VIEWS[v.slug] = v; VIEW_ORDER.push(v.slug); });

  var DIMS = {};
  C.dimensions.forEach(function (d) { DIMS[d.param] = d; });

  var RULES = {};
  C.rules.forEach(function (r) { RULES[r.shape] = r.rules; });

  var CONDS = {};
  C.conds.forEach(function (c) { CONDS[c.name] = c.cond; });

  var DIAGS = {};
  C.diagrams.forEach(function (d) { DIAGS[d.id] = d; });

  var PARAMS = C.grammar.params;
  var G = C.grammar;

  // FIELD maps a grammar parameter to the field it occupies on a state object. The parameter names
  // come from the contract; the field names are this file's own and never leave it.
  var FIELD = {};
  FIELD[M.paramView] = 'view';
  FIELD[M.paramQuery] = 'q';
  FIELD[M.paramStack] = 'stack';
  FIELD[M.paramNet] = 'net';
  FIELD[M.paramExposed] = 'exposed';
  FIELD[M.paramAccepted] = 'accepted';
  FIELD[M.paramDrift] = 'drift';
  FIELD[M.paramDiagram] = 'diagram';
  FIELD[M.paramFocus] = 'focus';
  FIELD[M.paramDepth] = 'depth';
  FIELD[M.paramPanel] = 'panel';
  FIELD[M.paramSvc] = 'svc';

  // The one piece of payload *structure* this file holds: which object each field prefix is rooted at.
  // The prefixes are the contract's own field paths, cut at the object they address. A field whose
  // prefix a row has no base for resolves to nothing and renders as *not reported* rather than
  // throwing (I4).
  var PRE = {
    stack: 'stacks.',
    svc: 'stacks.services.',
    mount: 'stacks.services.mounts.',
    env: 'stacks.services.env.',
    cf: 'stacks.services.cloudflare.',
    tf: 'stacks.services.traefik.',
    live: 'stacks.services.traefikLive.',
    ak: 'stacks.services.authentik.',
    app: 'stacks.services.authentik.applications.',
    probe: 'stacks.services.probe.',
    decl: 'stacks.services.declared.',
    conn: 'meta.connections.',
    node: 'graph.nodes.',
    edge: 'graph.edges.',
    unApp: 'meta.authentik.unmatchedApplications.',
    unRouter: 'meta.traefik.unmatchedRouters.'
  };

  function termOf(set, member) {
    var s = SETS[set];
    if (s && s.by[member]) return s.by[member];
    var t = {};
    Object.keys(C.unknown).forEach(function (k) { t[k] = C.unknown[k]; });
    t.member = member;
    t.label = member;
    return t;
  }

  function setMembers(set) {
    var s = SETS[set];
    return s ? s.terms.map(function (t) { return t.member; }) : [];
  }

  function isMember(set, member) {
    var s = SETS[set];
    return !!(s && Object.prototype.hasOwnProperty.call(s.by, member));
  }

  // ---------------------------------------------------------------------------
  // Payload primitives
  //
  // The Go originals are valuesAt/asString/asInt/isZero in internal/webui/tagrules.go. A path follows
  // pointers, crosses slices and matches by JSON name — which in a browser means: cross arrays, read
  // own properties, drop nulls.
  // ---------------------------------------------------------------------------

  function flatten(vals) {
    var out = [];
    for (var i = 0; i < vals.length; i++) {
      var v = vals[i];
      if (v === null || v === undefined) continue;
      if (Array.isArray(v)) { out = out.concat(flatten(v)); continue; }
      out.push(v);
    }
    return out;
  }

  // valuesAt resolves a dotted path to every value it reaches, flattened.
  function valuesAt(obj, path) {
    return resolve(obj, path, true);
  }

  // nodesAt resolves a path without flattening the *final* value, so a list stays a list and can be
  // counted. Go's numeric columns read a length this way.
  function nodesAt(obj, path) {
    return resolve(obj, path, false);
  }

  function resolve(obj, path, flat) {
    if (obj === null || obj === undefined) return [];
    var cur = [obj];
    if (!path) return flatten(cur);
    var segs = path.split('.');
    for (var i = 0; i < segs.length; i++) {
      cur = flatten(cur);
      var next = [];
      for (var j = 0; j < cur.length; j++) {
        var item = cur[j];
        if (item === null || typeof item !== 'object') continue;
        if (Object.prototype.hasOwnProperty.call(item, segs[i])) next.push(item[segs[i]]);
      }
      cur = next;
      if (!cur.length) return [];
    }
    if (flat) return flatten(cur);
    return cur.filter(function (v) { return v !== null && v !== undefined; });
  }

  function stringsAt(obj, path) {
    var out = [];
    valuesAt(obj, path).forEach(function (v) {
      var s = asString(v);
      if (s) out.push(s);
    });
    return out;
  }

  // asString mirrors Go's: strings and booleans and whole numbers have a spelling, and anything else
  // has none — an object rendered through a member's spelling would be a fiction.
  function asString(v) {
    if (typeof v === 'string') return v;
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number' && isFinite(v) && Math.floor(v) === v) return String(v);
    return '';
  }

  function asInt(v) {
    if (typeof v === 'number' && isFinite(v)) return Math.trunc(v);
    return null;
  }

  function isZero(v) {
    if (v === null || v === undefined) return true;
    if (Array.isArray(v)) return v.length === 0;
    if (typeof v === 'object') return Object.keys(v).length === 0;
    return v === '' || v === 0 || v === false;
  }

  // holds is §22.6's condition evaluator (Go: Cond.Holds). An unknown test is false, never true: a
  // rule this build cannot evaluate must not tag.
  function holds(c, obj) {
    if (!c) return false;
    if (c.all && c.all.length) return c.all.every(function (s) { return holds(s, obj); });
    if (c.any && c.any.length) return c.any.some(function (s) { return holds(s, obj); });
    if (c.not) return !holds(c.not, obj);
    var vals = valuesAt(obj, c.path || '');
    switch (c.test) {
      case M.testPresent: return vals.length > 0;
      case M.testAbsent: return vals.length === 0;
      case M.testNonEmpty: return vals.some(function (v) { return !isZero(v); });
      case M.testEmpty: return !vals.some(function (v) { return !isZero(v); });
      case M.testTrue: return vals.some(function (v) { return v === true; });
      case M.testEquals: return vals.some(function (v) { return asString(v) === (c.value || ''); });
      case M.testAtLeast: return vals.some(function (v) {
        var n = asInt(v);
        return n !== null && n >= (c.n || 0);
      });
      default: return false;
    }
  }

  // applyRules runs a shape's tag table over one object (Go: TagRule.Apply).
  function applyRules(shape, row, obj) {
    (RULES[shape] || []).forEach(function (rule) {
      if (rule.when && !holds(rule.when, obj)) return;
      if (!rule.valuePath) { tag(row, rule.dim, rule.member); return; }
      var vals = stringsAt(obj, rule.valuePath);
      if (!vals.length && rule.default) vals = [rule.default];
      tag.apply(null, [row, rule.dim].concat(vals));
    });
  }

  // ---------------------------------------------------------------------------
  // §22.7: the URL is the state
  //
  // One loop over the grammar, switching on the parameter's kind. A parameter this build does not know
  // the kind of is left unread rather than guessed.
  // ---------------------------------------------------------------------------

  function newState() {
    var s = { view: '', q: '', stack: '', net: '', exposed: false, accepted: false, drift: false,
      diagram: '', focus: '', depth: 0, panel: '', svc: '', tags: {} };
    return s;
  }

  function parseState(search) {
    var q = new URLSearchParams(search || '');
    var s = newState();
    PARAMS.forEach(function (p) {
      // First value only: a repeated parameter is a rewritten link, and reading the first is what Go's
      // q.Get does.
      var raw = q.get(p.name);
      raw = raw === null ? '' : raw;
      switch (p.kind) {
        case M.kindEnum:
          s[FIELD[p.name]] = (p.values || []).indexOf(raw) >= 0 ? raw : '';
          break;
        case M.kindText:
          s[FIELD[p.name]] = text(raw);
          break;
        case M.kindFlag:
          s[FIELD[p.name]] = raw === G.flag;
          break;
        case M.kindCount:
          s[FIELD[p.name]] = parseDepth(raw);
          break;
        case M.kindTags:
          var f = parseFilter(DIMS[p.dim], raw);
          if (f.include.length || f.exclude.length) s.tags[p.dim] = f;
          break;
        default:
          break;
      }
    });
    // The default view is written as the empty string, so that the overview's URL is `.`.
    if (s.view === G.defaultView) s.view = '';
    return s;
  }

  // text is §22.7's sanitiser: control characters dropped, capped in code points, trimmed.
  function text(raw) {
    var out = '', n = 0;
    var chars = Array.from(String(raw));
    for (var i = 0; i < chars.length; i++) {
      var cp = chars[i].codePointAt(0);
      if (cp < 0x20 || cp === 0x7f) continue;
      if (n >= G.textLimit) break;
      out += chars[i];
      n++;
    }
    return out.trim();
  }

  function parseDepth(raw) {
    if (!raw) return 0;
    if (!/^-?[0-9]+$/.test(raw)) return 0;
    var n = parseInt(raw, 10);
    return n < 0 ? 0 : n;
  }

  function cutFold(s, prefix) {
    if (s.length < prefix.length) return null;
    if (s.slice(0, prefix.length).toLowerCase() !== prefix.toLowerCase()) return null;
    return s.slice(prefix.length);
  }

  // parseFilter reads one dimension's tri-state filter. Exclusion always wins, a single-valued
  // dimension keeps one member per side, and a member outside a closed vocabulary is dropped.
  function parseFilter(dim, raw) {
    var f = { all: false, include: [], exclude: [] };
    raw = String(raw || '').trim();
    if (!raw) return f;
    var cut = cutFold(raw, G.allPrefix);
    if (cut !== null) { f.all = true; raw = cut; }
    else {
      cut = cutFold(raw, G.anyPrefix);
      if (cut !== null) raw = cut;
    }
    raw.split(',').forEach(function (part) {
      part = part.trim();
      if (!part) return;
      var ex = cutFold(part, G.excludePrefix);
      if (ex !== null) {
        ex = ex.trim();
        if (ex) once(f.exclude, ex);
        return;
      }
      once(f.include, part);
    });
    f.include = f.include.filter(function (m) { return f.exclude.indexOf(m) < 0; });
    if (dim && !dim.multi) {
      f.all = false;
      f.include = f.include.slice(0, 1);
      f.exclude = f.exclude.slice(0, 1);
    }
    if (dim && dim.set) {
      var vocab = setMembers(dim.set);
      f.include = f.include.filter(function (m) { return vocab.indexOf(m) >= 0; });
      f.exclude = f.exclude.filter(function (m) { return vocab.indexOf(m) >= 0; });
    }
    f.include = canonical(dim, f.include);
    f.exclude = canonical(dim, f.exclude);
    return f;
  }

  // canonical is the vocabulary's order for known members, alphabetical for the rest, known first —
  // so that two links with the same meaning are the same string.
  function canonical(dim, list) {
    var out = list.slice().sort();
    var uniq = [];
    out.forEach(function (m) { once(uniq, m); });
    var vocab = dim && dim.set ? setMembers(dim.set) : [];
    return uniq.map(function (m, i) { return { m: m, i: i, rank: vocab.indexOf(m) }; })
      .sort(function (a, b) {
        if (a.rank >= 0 && b.rank >= 0) return a.rank - b.rank;
        if ((a.rank >= 0) !== (b.rank >= 0)) return a.rank >= 0 ? -1 : 1;
        return a.i - b.i;
      })
      .map(function (e) { return e.m; });
  }

  function filterString(f) {
    if (!f || (!f.include.length && !f.exclude.length)) return '';
    var parts = f.include.slice();
    f.exclude.forEach(function (m) { parts.push(G.excludePrefix + m); });
    var v = parts.join(',');
    return f.all ? G.allPrefix + v : v;
  }

  function filterMatches(f, tags) {
    tags = tags || [];
    for (var i = 0; i < f.exclude.length; i++) {
      if (tags.indexOf(f.exclude[i]) >= 0) return false;
    }
    if (!f.include.length) return true;
    if (f.all) {
      return f.include.every(function (m) { return tags.indexOf(m) >= 0; });
    }
    return f.include.some(function (m) { return tags.indexOf(m) >= 0; });
  }

  // pairsOf writes the state back out, in the grammar's order — the round trip §22.7 requires.
  function pairsOf(s) {
    var out = [];
    PARAMS.forEach(function (p) {
      var v = '';
      if (p.kind === M.kindTags) v = filterString(s.tags[p.dim]);
      else {
        var raw = s[FIELD[p.name]];
        if (p.kind === M.kindFlag) v = raw ? G.flag : '';
        else if (p.kind === M.kindCount) v = raw > 0 ? String(raw) : '';
        else v = raw || '';
      }
      if (v) out.push([p.name, v]);
    });
    return out;
  }

  // queryEscape mirrors Go's url.QueryEscape, so the same state is the same URL on both sides.
  function queryEscape(v) {
    return encodeURIComponent(v)
      .replace(/[!'()*]/g, function (ch) {
        return '%' + ch.charCodeAt(0).toString(16).toUpperCase();
      })
      .replace(/%20/g, '+');
  }

  function queryOf(s) {
    return pairsOf(s).map(function (p) { return p[0] + '=' + queryEscape(p[1]); }).join('&');
  }

  function linkOf(s) {
    var q = queryOf(s);
    return q ? '?' + q : '.';
  }

  function copyState(s) {
    var out = newState();
    Object.keys(s).forEach(function (k) { out[k] = s[k]; });
    out.tags = {};
    Object.keys(s.tags).forEach(function (d) {
      out.tags[d] = { all: s.tags[d].all, include: s.tags[d].include.slice(), exclude: s.tags[d].exclude.slice() };
    });
    return out;
  }

  // with returns a copy with one field replaced, and clears whatever a change of that field invalidates.
  function withField(s, field, value) {
    var out = copyState(s);
    out[field] = value;
    if (field === 'view') {
      // A view change drops the other view's panel, focus and depth: a panel id names a drawer section
      // that the new view has no row for.
      out.panel = ''; out.focus = ''; out.depth = 0;
    }
    if (field === 'diagram' || field === 'focus') out.depth = s.depth;
    return out;
  }

  function withFilter(s, dim, f) {
    var out = copyState(s);
    if (!f || (!f.include.length && !f.exclude.length)) delete out.tags[dim];
    else out.tags[dim] = f;
    return out;
  }

  // sameNav reports whether two states differ only in ways that do not need a re-read of the drawer's
  // subject — the navigational parameters the contract names.
  function sameNav(a, b) {
    return G.navParams.every(function (p) {
      var f = FIELD[p];
      return (a[f] || '') === (b[f] || '');
    });
  }

  function viewOf(s) {
    return VIEWS[s.view || G.defaultView] || VIEWS[G.defaultView];
  }

  // ---------------------------------------------------------------------------
  // Rows
  //
  // One projection per row kind, mirroring internal/webui/rows.go. Each row carries:
  //
  //   bases   [prefix, object] pairs — a column's field path is resolved against the longest matching
  //           prefix, which is how a generic renderer reads a specific record.
  //   cells   values the payload does not hold in a single field (a row's stack, a roll-up, an export).
  //   numbers numeric columns whose count is a projection rather than a field.
  //   tags    the dimensions of §22.6, from the shared rule tables.
  //   text    the free-text haystack. **Never an environment value** (I6) — keys only.
  // ---------------------------------------------------------------------------

  function once(list, v) {
    if (list.indexOf(v) < 0) list.push(v);
    return list;
  }

  function pad(i) {
    var s = String(i);
    while (s.length < 6) s = '0' + s;
    return s;
  }

  function padDesc(n) {
    return pad(999999 - n);
  }

  function newRow(kind, id, label) {
    return { kind: kind, id: id, label: label, stack: '', service: '', networks: [],
      exposed: false, accepted: false, drift: false, lead: 3, sort: [], tags: {}, text: [],
      bases: [], cells: {}, numbers: {}, raw: null, open: null };
  }

  function tag(row, dim) {
    for (var i = 2; i < arguments.length; i++) {
      var v = arguments[i];
      if (!v) continue;
      if (!row.tags[dim]) row.tags[dim] = [];
      once(row.tags[dim], v);
    }
  }

  function say(row) {
    for (var i = 1; i < arguments.length; i++) {
      var v = arguments[i];
      if (typeof v !== 'string') continue;
      var t = v.trim();
      if (t) once(row.text, t);
    }
  }

  function leadIf(cond) { return cond ? 0 : 1; }

  function keyOf(stackID, name) { return stackID + M.keySeparator + name; }

  function eachService(ov, fn) {
    (ov.stacks || []).forEach(function (stack) {
      (stack.services || []).forEach(function (svc) {
        fn(stack, svc, keyOf(stack.id, svc.name));
      });
    });
  }

  // methodOf normalises an absent method the way the counters read it: `none`.
  function methodOf(svc) {
    var m = svc && svc.auth ? asString(svc.auth.method) : '';
    return m || M.authNone;
  }

  function detected(method) {
    return method !== '' && method !== M.authNone;
  }

  // sayService is the service haystack. Label KEYS and env KEYS, never an env value (I6).
  function sayService(row, svc) {
    say(row, svc.name, svc.containerName, svc.image);
    (svc.cloudflare || []).forEach(function (r) { say(row, r.hostname); });
    (svc.traefik || []).forEach(function (r) {
      say(row, r.router);
      (r.hosts || []).forEach(function (h) { say(row, h); });
    });
    (svc.traefikLive || []).forEach(function (r) {
      say(row, r.router);
      (r.hosts || []).forEach(function (h) { say(row, h); });
    });
    Object.keys(svc.labels || {}).forEach(function (k) { say(row, k); });
    (svc.env || []).forEach(function (e) { say(row, e.key); });
  }

  function serviceBases(stack, svc) {
    return [[PRE.stack, stack], [PRE.svc, svc]];
  }

  function serviceRowBase(kind, stack, svc, key) {
    var r = newRow(kind, key, svc.name);
    r.stack = stack.id;
    r.service = key;
    r.networks = (svc.networks || []).slice();
    r.exposed = !!(svc.auth && svc.auth.exposedWithoutAuth);
    r.accepted = !!(svc.declared && svc.declared.unauthenticatedAccepted);
    r.drift = !!(svc.declared && (svc.declared.drift || []).length);
    r.bases = serviceBases(stack, svc);
    r.raw = svc;
    r.open = { kind: M.rowService, svc: key, title: svc.name, subject: svc, bases: r.bases };
    applyRules(M.shapeService, r, svc);
    sayService(r, svc);
    r.cells.stack = { text: [stack.name || stack.id], link: withField(newState(), 'stack', stack.id) };
    r.cells.service = { text: [svc.name] };
    return r;
  }

  // findingOf relabels a service's stored exposure fields into the `finding` vocabulary. It is a
  // relabel, not a conclusion: every branch reads a field the scan already decided (§4.2).
  function findingOf(svc) {
    var out = [];
    var ingress = stringsAt(svc, 'ingress').filter(function (k) { return k !== M.ingressNone; });
    if (svc.auth && svc.auth.exposedWithoutAuth) {
      out.push(M.findingExposed);
      if (svc.declared && svc.declared.unauthenticatedAccepted) out.push(M.findingAccepted);
      return out;
    }
    if (!ingress.length) return [M.findingNone];
    return [M.findingGated];
  }

  function statRows(ov) {
    var out = [];
    cardsOf(ov).forEach(function (card, i) {
      var r = newRow(M.rowStat, card.id, card.label);
      var count = countOf(card, ov);
      r.lead = card.lead ? 0 : 1;
      r.sort = [pad(i)];
      say(r, card.label, card.note, card.unit);
      r.cells.card = { text: [card.label], note: card.note, tone: card.tone, member: card.member, set: card.set };
      r.cells.count = count.ok ? { number: count.n, unit: card.unit, tone: card.tone } : { absent: true };
      r.cells.destination = { text: [destinationOf(card)], href: '?' + card.dest, exact: card.exact };
      r.open = card.path ? null : { kind: M.rowReport, title: card.label, subject: null };
      r.card = card;
      out.push(r);
    });
    return out;
  }

  function destinationOf(card) {
    var view = VIEWS[card.view];
    var title = view ? view.title : card.view;
    if (card.exact) return title + ' — exactly these ' + (card.unit ? card.unit + 's' : 'rows');
    return title + ' — the records it can show';
  }

  function stackRows(ov) {
    var out = [];
    (ov.stacks || []).forEach(function (stack) {
      var r = newRow(M.rowStack, stack.id, stack.name || stack.id);
      r.stack = stack.id;
      r.bases = [[PRE.stack, stack]];
      r.raw = stack;
      r.lead = leadIf((stack.warnings || []).length > 0);
      r.sort = [(stack.name || '').toLowerCase(), stack.id];
      say(r, stack.name, stack.id, stack.dir, stack.composeFile, stack.projectName);
      var exposed = 0;
      (stack.services || []).forEach(function (svc) {
        say(r, svc.name);
        // The roll-up is every distinct member in the stack. `none` is not rolled up into the
        // ingress column: a stack with one internal service does not read as an exposed stack.
        stringsAt(svc, 'ingress').forEach(function (k) {
          if (k !== M.ingressNone) tag(r, M.dimIngress, k);
        });
        tag(r, M.dimAuth, methodOf(svc));
        if (svc.auth && svc.auth.exposedWithoutAuth) exposed++;
      });
      r.numbers.services = (stack.services || []).length;
      r.numbers.exposed = exposed;
      r.numbers.warnings = (stack.warnings || []).length;
      r.cells.name = { text: [stack.name || stack.id], link: withField(newState(), 'stack', stack.id) };
      out.push(r);
    });
    return out;
  }

  function serviceRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      var r = serviceRowBase(M.rowService, stack, svc, key);
      r.lead = leadIf(r.exposed);
      r.sort = [(stack.name || '').toLowerCase(), (svc.name || '').toLowerCase()];
      r.cells.exposure = { members: findingOf(svc), set: 'finding' };
      out.push(r);
    });
    return out;
  }

  function routeRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      var method = methodOf(svc);
      (svc.cloudflare || []).forEach(function (route, i) {
        var r = serviceRowBase(M.rowRoute, stack, svc, key);
        r.id = key + '#tunnel/' + pad(i);
        r.label = route.hostname || key;
        r.bases = serviceBases(stack, svc).concat([[PRE.cf, route], [PRE.tf, null]]);
        r.raw = route;
        r.open = { kind: M.rowRoute, title: r.label, subject: route, bases: r.bases };
        // The gate on this path, which is not the same statement as the service's posture.
        var gated = !!route.access || detected(method);
        r.lead = leadIf(!gated);
        r.sort = [(route.hostname || '').toLowerCase(), pad(i)];
        say(r, route.hostname, route.path, route.service);
        out.push(r);
      });
      (svc.traefik || []).forEach(function (route, i) {
        var r = serviceRowBase(M.rowRoute, stack, svc, key);
        r.id = key + '#router/' + pad(i);
        r.label = (route.hosts || []).join(', ') || route.router || key;
        r.bases = serviceBases(stack, svc).concat([[PRE.tf, route], [PRE.cf, null]]);
        r.raw = route;
        r.open = { kind: M.rowRoute, title: r.label, subject: route, bases: r.bases };
        var gated = detected(method) || (route.middlewares || []).length > 0;
        r.lead = leadIf(!gated);
        r.sort = [((route.hosts || [])[0] || route.router || '').toLowerCase(), pad(i)];
        say(r, route.router, route.rule);
        (route.hosts || []).forEach(function (h) { say(r, h); });
        out.push(r);
      });
    });
    return out;
  }

  // networksOf mirrors fleet.NewNetworks: one record per declared or joined network, with the members
  // and the stacks that hold them. A network with one member is still a network — it just connects
  // nothing, and co-membership is never a dependency (§16).
  function networksOf(ov) {
    var order = [], by = {};
    function get(name) {
      if (!by[name]) {
        by[name] = { name: name, external: false, scope: '', driver: '', members: [], stacks: [] };
        order.push(name);
      }
      return by[name];
    }
    (ov.stacks || []).forEach(function (stack) {
      (stack.declaredNetworks || []).forEach(function (dn) {
        var n = get(dn.name);
        if (dn.external) n.external = true;
        if (!n.driver) n.driver = dn.driver || '';
        once(n.stacks, stack.id);
      });
      (stack.services || []).forEach(function (svc) {
        (svc.networks || []).forEach(function (name) {
          var n = get(name);
          once(n.members, keyOf(stack.id, svc.name));
          once(n.stacks, stack.id);
        });
      });
    });
    return order.map(function (name) { return by[name]; });
  }

  function networkRows(ov) {
    var out = [];
    var nodes = {};
    (ov.graph && ov.graph.nodes ? ov.graph.nodes : []).forEach(function (n) {
      if (n.kind === M.nodeNetwork) nodes[n.label] = n;
    });
    var crossing = {};
    (ov.graph && ov.graph.edges ? ov.graph.edges : []).forEach(function (e) {
      (e.via || []).forEach(function (name) { crossing[name] = (crossing[name] || 0) + 1; });
    });
    networksOf(ov).forEach(function (net) {
      var r = newRow(M.rowNetwork, M.prefixNetwork + net.name, net.name);
      // A network with one local member has no node in the graph (§8), so the node-rooted columns are
      // resolved against a record shaped like one rather than left blank.
      var node = nodes[net.name] || {
        id: M.prefixNetwork + net.name, label: net.name, kind: M.nodeNetwork,
        scope: net.external ? 'external' : 'local',
        memberCount: net.members.length, stackCount: net.stacks.length
      };
      var facts = { name: net.name, scope: node.scope, memberCount: net.members.length,
        stackCount: net.stacks.length, external: net.external };
      r.bases = [[PRE.node, node]];
      r.raw = node;
      r.networks = [net.name];
      r.stack = net.stacks.length === 1 ? net.stacks[0] : '';
      r.lead = leadIf(net.stacks.length > 1);
      r.sort = [padDesc(net.stacks.length), padDesc(net.members.length), net.name.toLowerCase()];
      r.numbers.members = net.members.length;
      r.numbers.stacks = net.stacks.length;
      r.numbers.crossing = crossing[net.name] || 0;
      applyRules(M.shapeNetwork, r, facts);
      say(r, net.name, net.driver, node.scope);
      net.members.forEach(function (m) { say(r, m); });
      r.cells.name = { text: [net.name], link: withField(newState(), 'net', net.name) };
      r.cells.driver = { text: [net.driver || node.scope] };
      r.cells.connects = net.members.length > 1
        ? { text: [net.members.length + ' services across ' + net.stacks.length +
            (net.stacks.length === 1 ? ' stack' : ' stacks')] }
        : { text: ['nothing — one member'] };
      r.open = { kind: M.rowNetwork, net: net.name, title: net.name, subject: node, bases: r.bases };
      out.push(r);
    });
    return out;
  }

  function diagramRows(ov) {
    return C.diagrams.map(function (d, i) {
      var r = newRow(M.rowDiagram, d.id, d.title);
      var dr = draw(d, newState(), ov);
      r.sort = [pad(i)];
      r.numbers.nodes = dr.total;
      r.numbers.edges = dr.edges.length;
      say(r, d.title, d.shows, d.note);
      r.cells.diagram = { text: [d.title], note: d.note, link: diagramState(newState(), d.id) };
      r.cells.shows = { text: [d.shows] };
      r.cells.export = { text: ['Mermaid'], export: mermaid(d, dr) };
      r.open = null;
      r.diagram = d;
      out_push(r);
      return r;
    });
    function out_push() {}
  }

  function containerRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      var r = serviceRowBase(M.rowContainer, stack, svc, key);
      var d = svc.docker || null;
      var health = d ? asString(d.health) : '';
      var running = !!(d && d.running);
      r.lead = health === M.healthUnhealthy ? 0 : (running ? 2 : 1);
      r.sort = [(stack.name || '').toLowerCase(), (svc.name || '').toLowerCase()];
      if (d) say(r, d.name, d.image, d.status, d.id);
      out.push(r);
    });
    return out;
  }

  function storageRows(ov) {
    var out = [];
    // Shared storage is a relation the compose files state: the same source mounted by another service.
    var mounted = {};
    eachService(ov, function (stack, svc) {
      (svc.mounts || []).forEach(function (m) {
        var k = stack.id + ' ' + (m.source || '');
        mounted[k] = (mounted[k] || 0) + 1;
      });
    });
    eachService(ov, function (stack, svc, key) {
      (svc.mounts || []).forEach(function (m, i) {
        var r = serviceRowBase(M.rowStorage, stack, svc, key);
        r.id = key + '#mount/' + pad(i);
        r.label = m.source || m.target || pad(i);
        r.bases = serviceBases(stack, svc).concat([[PRE.mount, m]]);
        r.raw = m;
        r.tags = {};
        applyRules(M.shapeMount, r, m);
        r.lead = leadIf(!m.readOnly);
        r.sort = [(m.source || '').toLowerCase(), (svc.name || '').toLowerCase(), pad(i)];
        say(r, m.source, m.target, m.raw, svc.name);
        var shared = (mounted[stack.id + ' ' + (m.source || '')] || 1) - 1;
        r.numbers.shared = shared;
        r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
        r.cells.external = { text: [externalSource(stack, m) ? 'yes' : 'no'] };
        r.open = { kind: M.rowService, svc: key, title: svc.name, subject: svc, bases: serviceBases(stack, svc) };
        out.push(r);
      });
    });
    // A declared volume nothing mounts is a row of its own: the declaration is there and no service
    // uses it, which is a fact about the compose file rather than about a container.
    (ov.stacks || []).forEach(function (stack) {
      var used = {};
      (stack.services || []).forEach(function (svc) {
        (svc.mounts || []).forEach(function (m) { used[m.source || ''] = true; });
      });
      (stack.declaredVolumes || []).forEach(function (vol, i) {
        if (used[vol.name]) return;
        var r = newRow(M.rowStorage, stack.id + '#volume/' + pad(i), vol.name);
        r.stack = stack.id;
        r.bases = [[PRE.stack, stack], [PRE.mount, { type: M.mountVolume, source: vol.name }]];
        r.raw = vol;
        r.lead = 2;
        r.sort = [(vol.name || '').toLowerCase(), '', pad(i)];
        tag(r, M.dimState, M.mountVolume, M.storageUnused);
        if (vol.external) tag(r, M.dimState, M.storageExternal);
        say(r, vol.name, vol.driver, stack.name);
        r.numbers.shared = 0;
        r.cells.service = { absent: true };
        r.cells.external = { text: [vol.external ? 'yes' : 'no'] };
        out.push(r);
      });
    });
    return out;
  }

  function externalSource(stack, m) {
    var name = m.source || '';
    return (stack.declaredVolumes || []).some(function (v) { return v.name === name && v.external; });
  }

  function configRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      (svc.env || []).forEach(function (e, i) {
        var r = serviceRowBase(M.rowConfig, stack, svc, key);
        r.id = key + '#env/' + pad(i);
        r.label = e.key;
        r.bases = serviceBases(stack, svc).concat([[PRE.env, e]]);
        r.raw = e;
        r.tags = {};
        applyRules(M.shapeEnv, r, e);
        r.lead = 1;
        r.sort = [(svc.name || '').toLowerCase(), (e.key || '').toLowerCase(), pad(i)];
        // The key and the source, never the value (I6). A masked value is absent, not starred.
        say(r, e.key, svc.name);
        r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
        r.cells.prefix = { text: [prefixOf(e.key)] };
        r.cells.value = e.masked
          ? { absent: true, note: 'masked: a mask that carried the length would carry the secret (I6)' }
          : { text: [asString(e.value)] };
        r.cells.conclusion = { absent: true };
        r.open = { kind: M.rowService, svc: key, title: svc.name, subject: svc, bases: serviceBases(stack, svc) };
        out.push(r);
      });
      var labels = svc.labels || {};
      Object.keys(labels).sort().forEach(function (label) {
        var r = serviceRowBase(M.rowConfig, stack, svc, key);
        r.id = key + '#label/' + label;
        r.label = label;
        r.bases = serviceBases(stack, svc).concat([[PRE.env, null]]);
        r.raw = { key: label, value: labels[label] };
        r.tags = {};
        tag(r, M.dimState, M.configLabel);
        var cited = citedBy(svc, label);
        r.lead = leadIf(cited.length > 0);
        r.sort = [(svc.name || '').toLowerCase(), label.toLowerCase(), ''];
        say(r, label, svc.name, asString(labels[label]));
        r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
        r.cells.prefix = { text: [prefixOf(label)] };
        r.cells.key = { text: [label] };
        r.cells.value = { text: [asString(labels[label])] };
        r.cells.conclusion = cited.length ? { text: cited, evidence: true } : { absent: true };
        r.cells.source = { absent: true };
        r.open = { kind: M.rowService, svc: key, title: svc.name, subject: svc, bases: serviceBases(stack, svc) };
        out.push(r);
      });
    });
    return out;
  }

  // prefixOf groups labels so that one proxy's labels read as one block.
  function prefixOf(key) {
    var i = key.indexOf('.');
    return i > 0 ? key.slice(0, i) : key;
  }

  // citedBy is the evidence that quotes this label, so a label can be read next to the conclusion it
  // produced. It searches the service's stored evidence rather than re-deriving anything.
  function citedBy(svc, label) {
    var out = [];
    var seen = ['auth.evidence', 'notes'];
    seen.forEach(function (p) {
      stringsAt(svc, p).forEach(function (e) {
        if (e.indexOf(label) >= 0) once(out, e);
      });
    });
    (svc.traefik || []).forEach(function (r) {
      stringsAt(r, 'evidence').forEach(function (e) {
        if (e.indexOf(label) >= 0) once(out, e);
      });
    });
    return out;
  }

  function applicationRows(ov) {
    var out = [], seen = {};
    eachService(ov, function (stack, svc, key) {
      var ak = svc.authentik;
      if (!ak) return;
      (ak.applications || []).forEach(function (app, i) {
        var id = M.prefixApp + (app.slug || pad(i));
        if (seen[id]) return;
        seen[id] = true;
        var r = serviceRowBase(M.rowApplication, stack, svc, key);
        r.kind = M.rowApplication;
        r.id = id;
        r.label = app.name || app.slug || id;
        r.bases = serviceBases(stack, svc).concat([[PRE.ak, ak], [PRE.app, app]]);
        r.raw = app;
        r.lead = 1;
        r.sort = [(app.name || app.slug || '').toLowerCase(), id];
        say(r, app.name, app.slug, app.group, app.launchUrl, svc.name);
        r.open = { kind: M.rowApplication, title: r.label, subject: app, bases: r.bases };
        out.push(r);
      });
    });
    (pathOf(ov, 'meta.authentik.unmatchedApplications') || []).forEach function_placeholder(0);
    return out;
  }

  function pathOf(obj, path) {
    var vals = nodesAt(obj, path);
    return vals.length ? vals[0] : null;
  }

  // ---------------------------------------------------------------------------
  // Filtering and ordering (§22.6)
  // ---------------------------------------------------------------------------

  function keep(s, r, consumed) {
    var ok = true;
    Object.keys(s.tags).forEach(function (dim) {
      if (!filterMatches(s.tags[dim], r.tags[dim])) ok = false;
    });
    if (!ok) return false;
    if (s.stack && r.stack !== s.stack) return false;
    if (s.net && r.networks.indexOf(s.net) < 0) return false;
    if (s.exposed && !consumed.exposed && !r.exposed) return false;
    if (s.accepted && !consumed.accepted && !r.accepted) return false;
    if (s.drift && !consumed.drift && !r.drift) return false;
    if (s.q && !matchesText(r.text, s.q)) return false;
    return true;
  }

  function matchesText(hay, q) {
    var needle = q.toLowerCase();
    return hay.some(function (h) { return h.toLowerCase().indexOf(needle) >= 0; });
  }

  function sortRows(rows) {
    return rows.map(function (r, i) { return { r: r, i: i }; })
      .sort(function (a, b) {
        if (a.r.lead !== b.r.lead) return a.r.lead - b.r.lead;
        var n = Math.min(a.r.sort.length, b.r.sort.length);
        for (var k = 0; k < n; k++) {
          if (a.r.sort[k] !== b.r.sort[k]) return a.r.sort[k] < b.r.sort[k] ? -1 : 1;
        }
        if (a.r.sort.length !== b.r.sort.length) return a.r.sort.length - b.r.sort.length;
        if (a.r.id !== b.r.id) return a.r.id < b.r.id ? -1 : 1;
        return a.i - b.i;
      })
      .map(function (e) { return e.r; });
  }
})();
