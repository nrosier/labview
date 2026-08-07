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
    var out = [];
    C.diagrams.forEach(function (d, i) {
      var r = newRow(M.rowDiagram, d.id, d.title);
      // The unfocused drawing, so the node count is the diagram's own size rather than one reader's
      // neighbourhood. `total` is the count before focus for exactly this reason.
      var dr = draw(d, newState(), ov);
      r.sort = [pad(i)];
      r.numbers.nodes = dr.total;
      r.numbers.edges = dr.edges.length;
      say(r, d.title, d.shows, d.note);
      r.cells.diagram = { text: [d.title], note: d.note, link: diagramState(newState(), d.id) };
      r.cells.shows = { text: [d.shows] };
      r.cells.export = { text: ['Mermaid'], export: mermaid(dr) };
      r.open = null;
      r.diagram = d;
      out.push(r);
    });
    return out;
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
        var k = stack.id + '\x00' + (m.source || '');
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
        var shared = (mounted[stack.id + '\x00' + (m.source || '')] || 1) - 1;
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
    // An application that matched nothing is a row, not an omission: a record that protects nothing
    // this scan found is the finding (§11). Mirrors applicationRows' second half in rows.go.
    (pathOf(ov, 'meta.authentik.unmatchedApplications') || []).forEach(function (un, i) {
      var app = un.application || {};
      var r = newRow(M.rowApplication, 'unmatched-app/' + pad(i), app.name || app.slug || '');
      r.lead = 0;
      r.bases = [[PRE.unApp, un], [PRE.app, app]];
      r.raw = un;
      r.sort = [asString(app.slug).toLowerCase(), r.id];
      say(r, app.name, app.slug, app.group, app.launchUrl);
      (app.providers || []).forEach(function (p) { say(r, p.name, p.internalHost, p.externalHost); });
      applyRules(M.shapeUnmatched, r, un);
      // Rebuilt from a provider rather than read from the applications list — the reason the record
      // exists at all, and the payload already says so.
      if (app.discoveredVia === M.discoveredViaProvider) tag(r, M.dimMatch, M.matchRebuilt);
      r.open = { kind: M.rowApplication, title: r.label, subject: un, bases: r.bases };
      out.push(r);
    });
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

  // rowHas is Go's Row.Has: whether a row already carries a reading. The orderings below read the tags
  // the rule tables granted rather than re-deriving them, so an ordering and a filter cannot disagree
  // about the same row.
  function rowHas(row, dim, member) {
    return (row.tags[dim] || []).indexOf(member) >= 0;
  }

  // ---------------------------------------------------------------------------
  // Cards (§22.3)
  //
  // Go: Cards and Card.Count in internal/webui/cards.go. Every `stats` counter has a card, every card is
  // a link, and a card with no `path` takes its count from its destination's own rows — so the number and
  // the destination cannot disagree. An absent optional count is *not reported*, never 0.
  // ---------------------------------------------------------------------------

  // The field-path separator. Not a new fact about the payload: it is the character `resolve` above
  // splits a path on, and the character the contract spells its own field paths with.
  var PATH_SEP = '.';

  // The lists this file reads straight off the payload rather than through a row's bases, addressed by
  // cutting the trailing separator off the prefix that already names them. `warnings` is the one path
  // with no prefix of its own: it is a list of strings and no column resolves against it.
  var PATHS = {
    warnings: 'meta.warnings',
    connections: PRE.conn.slice(0, -PATH_SEP.length),
    unApps: PRE.unApp.slice(0, -PATH_SEP.length),
    unRouters: PRE.unRouter.slice(0, -PATH_SEP.length)
  };

  // The one tone this file assigns instead of reading off a term, and Go assigns it in the same place for
  // the same reason (cards.go): the no-mechanism segment *warns* rather than alerts, because no detected
  // mechanism is not the same statement as reachable without authentication, and alert is reserved for
  // that one. Every other tone below comes from a term or from a diagram's own tag table.
  var TONE_WARN = 'warn';

  function cardsOf(ov) {
    var out = [];
    C.cards.forEach(function (card) {
      if (!card.segments) { out.push(card); return; }
      segmentMembers(card, ov).forEach(function (m) { out.push(segmentOf(card, m)); });
    });
    return out;
  }

  // segmentMembers is a distribution's members: the vocabulary in its own order, then anything else the
  // payload counted, sorted. A member this build does not know still gets a segment — a distribution that
  // dropped one would report a total that does not add up (§16).
  function segmentMembers(card, ov) {
    var known = setMembers(card.set);
    var extra = [];
    var counted = pathOf(ov, card.path);
    if (counted && typeof counted === 'object' && !Array.isArray(counted)) {
      Object.keys(counted).forEach(function (m) { if (known.indexOf(m) < 0) once(extra, m); });
    }
    extra.sort();
    return known.concat(extra);
  }

  function segmentOf(card, member) {
    var term = termOf(card.set, member);
    return {
      id: card.id + M.keySeparator + member,
      label: term.label,
      unit: card.unit,
      note: term.note,
      path: card.path + PATH_SEP + member,
      dest: queryOf(including(card.dest, M.dimAuth, member)),
      view: card.view,
      exact: card.exact,
      tone: member === M.authNone ? TONE_WARN : '',
      set: card.set,
      member: member
    };
  }

  // including is Go's State.Including: a destination with one more member on a dimension. Written back
  // out as the filter's own string and re-parsed, so the result is canonical by construction — the same
  // link Go would write for the same segment (§22.7).
  function including(dest, dim, member) {
    var s = parseState(dest);
    var cur = s.tags[dim] ? filterString(s.tags[dim]) : '';
    return withFilter(s, dim, parseFilter(DIMS[dim], cur ? cur + ',' + member : member));
  }

  function countOf(card, ov) {
    if (!card.path) return { n: rowsOf(parseState(card.dest), ov).length, ok: true };
    var vals = valuesAt(ov, card.path), n;
    for (var i = 0; i < vals.length; i++) {
      n = asInt(vals[i]);
      if (n !== null) return { n: n, ok: true };
    }
    return { n: 0, ok: false };
  }

  // ---------------------------------------------------------------------------
  // Diagrams (§22.5)
  //
  // Go: internal/webui/diagram.go. A diagram is *a selection of `graph` by edge kind* and that is the
  // whole of it — the scan already decided every relation drawn here. Focus, depth and the per-hub cap
  // are the only things that remove anything, and each one says so in words.
  // ---------------------------------------------------------------------------

  function diagramOf(id) {
    return DIAGS[id] || C.diagrams[0];
  }

  function diagramState(s, id) {
    return withField(s, 'diagram', id);
  }

  // diagramTerm reads a reading's label, tone and note off the diagram's own tag table, falling back to
  // the contract's unknown template. No tone or member is spelled here.
  function diagramTerm(d, member) {
    var found = null;
    (d.tags || []).forEach(function (t) { if (!found && t.member === member) found = t; });
    if (found) return found;
    var t = {};
    Object.keys(C.unknown).forEach(function (k) { t[k] = C.unknown[k]; });
    t.member = member;
    t.label = member;
    return t;
  }

  function drawsKind(d, kind) {
    return (d.kinds || []).indexOf(kind) >= 0;
  }

  function graphNodes(ov) {
    return ov.graph && ov.graph.nodes ? ov.graph.nodes : [];
  }

  function graphEdges(ov) {
    return ov.graph && ov.graph.edges ? ov.graph.edges : [];
  }

  // edgesOf is the diagram's edges with the readings it gives them, in the graph's own order — which the
  // scan built by walking the fleet and which is therefore stable for a payload (I7). The picture, the
  // edge list and the text export all read this, so the three cannot disagree.
  function edgesOf(d, ov) {
    var declared = declaredPairs(ov);
    var ungated = ungatedHosts(ov);
    var unattached = unattachedNodes(ov);
    var out = [];
    graphEdges(ov).forEach(function (e) {
      if (!drawsKind(d, e.kind)) return;
      var edge = { id: e.id, from: e.source, to: e.target, label: asString(e.label),
        kind: e.kind, via: (e.via || []).slice(), tags: [], tone: '', raw: e };
      if (e.kind === M.edgeDependsOn) {
        // Declared and observed are both readings an edge can carry, and a pair that is both carries
        // both: merging them would lose the distinction §14 rule 1 exists to keep.
        if (e.declaredBy || declared[e.source + '\x00' + e.target]) once(edge.tags, M.edgeDeclared);
        if (!e.declaredBy) once(edge.tags, M.edgeObserved);
        if (!edge.via.length) {
          // §22.5: drawn direct and marked. The only service → service line allowed, and it is allowed
          // because there is no network to route it through (§8).
          once(edge.tags, M.edgeDirect);
          edge.tone = diagramTerm(d, M.edgeDirect).tone;
        }
      } else if (e.kind === M.edgeNetworkKind) {
        [asString(e.flow), asString(e.flowSource)].forEach(function (v) { if (v) once(edge.tags, v); });
      } else if (e.kind === M.edgeIngressKind) {
        if (ungated[e.source] || ungated[e.target]) {
          once(edge.tags, M.edgeUngated);
          edge.tone = diagramTerm(d, M.edgeUngated).tone;
        }
      } else if (e.kind === M.edgeAuthKind) {
        if (edge.label) once(edge.tags, edge.label);
      }
      if (unattached[e.source] || unattached[e.target]) once(edge.tags, M.edgeUnattached);
      out.push(edge);
    });
    return out;
  }

  // declaredPairs is every source → target pair a declaration named, in graph node spelling.
  //
  // The graph marks `declaredBy` only where a declaration is an edge's *only* account — dashing a pair
  // compose already resolved would claim it was never measured — so a pair that is both observed and
  // declared has to be recognised from the declaration itself (§14).
  function declaredPairs(ov) {
    var names = {};
    eachService(ov, function (stack, svc, key) {
      if (!names[svc.name]) names[svc.name] = [];
      once(names[svc.name], key);
    });
    var out = {};
    eachService(ov, function (stack, svc, key) {
      if (!svc.declared) return;
      var from = M.prefixService + key;
      (svc.declared.dependsOn || []).forEach(function (ref) {
        refTargets(names, stack.id, asString(ref.ref)).forEach(function (target) {
          out[from + '\x00' + M.prefixService + target] = true;
        });
      });
    });
    return out;
  }

  // refTargets is the keys a declared reference accounts for, in §14's forms: a qualified reference names
  // one service, and a bare one prefers the declaring stack's own — the order resolution already used.
  function refTargets(names, stackID, ref) {
    var cut = ref.indexOf(M.keySeparator);
    if (cut >= 0) return [keyOf(ref.slice(0, cut), ref.slice(cut + M.keySeparator.length))];
    var local = keyOf(stackID, ref);
    var found = names[ref] || [];
    return found.indexOf(local) >= 0 ? [local] : found.slice();
  }

  // ungatedHosts is every node whose path into the fleet had no gate this scan could find. Read off the
  // stored finding, so the reserved colour on a path and the exposure count on the overview are the same
  // statement (§4.2, §22.3).
  function ungatedHosts(ov) {
    var out = {};
    eachService(ov, function (stack, svc, key) {
      if (!(svc.auth && svc.auth.exposedWithoutAuth)) return;
      out[M.prefixService + key] = true;
      (svc.cloudflare || []).forEach(function (route) {
        if (route.hostname && !route.access) out[M.prefixHostname + route.hostname] = true;
      });
      (svc.traefik || []).forEach(function (route) {
        (route.hosts || []).forEach(function (h) { out[M.prefixHostname + h] = true; });
      });
    });
    return out;
  }

  // unattachedNodes is the node ids naming a record that matched nothing in this fleet. §22.5 requires
  // them drawn rather than hidden, and the payload already says which they are: the two unmatched lists.
  function unattachedNodes(ov) {
    var out = {};
    (pathOf(ov, PATHS.unApps) || []).forEach(function (un) {
      var app = un.application || {};
      out[M.prefixApp + asString(app.slug)] = true;
    });
    (pathOf(ov, PATHS.unRouters) || []).forEach(function (un) {
      var live = un.router || {};
      out[M.prefixRouter + asString(live.router) + '@' + asString(live.provider)] = true;
    });
    return out;
  }

  // nodesOf is every node a drawn edge touches, in the graph's order, plus the unmatched records the
  // identity diagram must draw unattached. Derived from the edges rather than filtered by node kind,
  // because a node's kind does not say which diagram it belongs to — a service is in all four.
  function nodesOf(d, ov, edges) {
    var want = {};
    edges.forEach(function (e) { want[e.from] = true; want[e.to] = true; });
    if (drawsKind(d, M.edgeAuthKind)) {
      var unattached = unattachedNodes(ov);
      graphNodes(ov).forEach(function (n) { if (unattached[n.id]) want[n.id] = true; });
    }
    return graphNodes(ov).filter(function (n) { return want[n.id]; });
  }

  // defaultFocus is the node a forced-focus diagram opens on: the finding first, then the busiest hub.
  function defaultFocus(ov, nodes, edges) {
    var ungated = ungatedHosts(ov);
    for (var i = 0; i < nodes.length; i++) {
      if (ungated[nodes[i].id]) return nodes[i].id;
    }
    var degree = {};
    edges.forEach(function (e) {
      degree[e.from] = (degree[e.from] || 0) + 1;
      degree[e.to] = (degree[e.to] || 0) + 1;
    });
    var best = '', bestDegree = -1;
    nodes.forEach(function (n) {
      // Strictly greater, walking the graph's own node order: a tie resolves to the first node the scan
      // emitted, so the picture is the same picture on every reload (I7).
      if ((degree[n.id] || 0) > bestDegree) { best = n.id; bestDegree = degree[n.id] || 0; }
    });
    return best;
  }

  // neighbourhood is the focus and everything within depth hops of it, breadth-first over the drawn
  // edges regardless of direction — *what this depends on* and *what depends on it* are both the
  // neighbourhood a reader focusing on a service means.
  function neighbourhood(focus, depth, nodes, edges) {
    var reach = {};
    reach[focus] = 0;
    var frontier = [focus];
    for (var hop = 1; hop <= depth && frontier.length; hop++) {
      var next = [];
      var here = frontier;
      edges.forEach(function (e) {
        [[e.from, e.to], [e.to, e.from]].forEach(function (pair) {
          if (here.indexOf(pair[0]) < 0) return;
          if (Object.prototype.hasOwnProperty.call(reach, pair[1])) return;
          reach[pair[1]] = hop;
          next.push(pair[1]);
        });
      });
      frontier = next;
    }
    function reached(id) { return Object.prototype.hasOwnProperty.call(reach, id); }
    return {
      nodes: nodes.filter(function (n) { return reached(n.id); }),
      edges: edges.filter(function (e) { return reached(e.from) && reached(e.to); })
    };
  }

  // applyCap drops spokes past the cap and says what it dropped. Per hub and counted over the hub's whole
  // degree, so *showing 12 of 31* is the truth about that node rather than about the diagram. Edges are
  // kept in the graph's own order, so which twelve are shown is deterministic — and the edge list at
  // `panel=edges` is uncapped, which is the way to see the rest §22.5 requires.
  function applyCap(d, nodes, edges) {
    if (!d.cap || d.cap <= 0) return { edges: edges, caps: [] };
    var total = {}, shown = {}, dropped = {}, out = [];
    edges.forEach(function (e) {
      total[e.from] = (total[e.from] || 0) + 1;
      total[e.to] = (total[e.to] || 0) + 1;
    });
    edges.forEach(function (e) {
      if ((shown[e.from] || 0) >= d.cap) { dropped[e.from] = (dropped[e.from] || 0) + 1; return; }
      if ((shown[e.to] || 0) >= d.cap) { dropped[e.to] = (dropped[e.to] || 0) + 1; return; }
      shown[e.from] = (shown[e.from] || 0) + 1;
      shown[e.to] = (shown[e.to] || 0) + 1;
      out.push(e);
    });
    var caps = [];
    nodes.forEach(function (n) {
      if (dropped[n.id] > 0) caps.push({ node: n.id, shown: shown[n.id] || 0, total: total[n.id] || 0 });
    });
    return { edges: out, caps: caps };
  }

  // untouchedNodes is the nodes no edge in the given set touches.
  function untouchedNodes(nodes, edges) {
    var touched = {}, out = {};
    edges.forEach(function (e) { touched[e.from] = true; touched[e.to] = true; });
    nodes.forEach(function (n) { if (!touched[n.id]) out[n.id] = true; });
    return out;
  }

  // keepConnected drops the nodes no surviving edge touches, keeping the focus itself and anything that
  // was unattached before the cap ran. A node stranded by a *cap* is not a node with nothing to say, and
  // leaving it floating would read as *nothing connects here* — while an unmatched record must stay
  // visible, because a record protecting nothing this scan found is the finding (§11, §12).
  function keepConnected(nodes, edges, focus, unattached) {
    var touched = {};
    edges.forEach(function (e) { touched[e.from] = true; touched[e.to] = true; });
    return nodes.filter(function (n) { return touched[n.id] || n.id === focus || unattached[n.id]; });
  }

  function draw(d, s, ov) {
    var edges = edgesOf(d, ov);
    var nodes = nodesOf(d, ov, edges);
    var dr = { diagram: d, focus: s.focus || '', depth: s.depth > 0 ? s.depth : G.defaultDepth,
      forced: false, caps: [], total: nodes.length, nodes: [], edges: [] };

    // §22.5: above the threshold the diagram MUST open focused rather than draw a fleet nobody can read.
    // With no focus in the URL there is still a choice about *what* to focus on, and the honest one is
    // the finding — else the busiest hub, never an arbitrary node.
    if (!dr.focus && nodes.length > d.nodeThreshold) {
      dr.focus = defaultFocus(ov, nodes, edges);
      dr.forced = true;
    }
    if (dr.focus) {
      var near = neighbourhood(dr.focus, dr.depth, nodes, edges);
      nodes = near.nodes;
      edges = near.edges;
    }
    // Which nodes no edge touched *before* the cap ran: afterwards a node the cap stranded looks exactly
    // like one that never had an edge.
    var unattached = untouchedNodes(nodes, edges);
    var capped = applyCap(d, nodes, edges);
    dr.caps = capped.caps;
    dr.edges = capped.edges;
    dr.nodes = keepConnected(nodes, capped.edges, dr.focus, unattached);
    return dr;
  }

  // capSentence is the cap in words, in the diagram's own terms.
  function capSentence(c, noun) {
    return 'showing ' + c.shown + ' of ' + c.total + ' ' + noun + ' of ' + c.node;
  }

  // mermaid is the drawing's own source: copyable, and deterministic for a payload (§22.5). Deterministic
  // means every choice here is made from the payload's own order and nothing else — node ids are numbered
  // in the order the graph emitted them, subgraphs are the stacks in scan order, caps are stated in node
  // order, and no map iteration reaches the output.
  function mermaid(dr) {
    var d = dr.diagram;
    var out = '%% LabView ' + d.title + '\n';
    if (dr.focus) {
      var reason = 'focused';
      if (dr.forced) {
        // The reader is told the picture is partial *because* the fleet is over the threshold, and the
        // export carries it too: a copied diagram outlives its page (§22.8).
        reason = 'opened focused: ' + dr.total + ' nodes is over the threshold of ' + d.nodeThreshold;
      }
      out += '%% ' + reason + ' on ' + dr.focus + ' at depth ' + dr.depth + '\n';
    }
    dr.caps.forEach(function (c) {
      out += '%% ' + capSentence(c, 'edges') + '; the edge list shows all of them\n';
    });
    out += 'graph LR\n';

    var ids = {};
    dr.nodes.forEach(function (n, i) { ids[n.id] = 'n' + i; });

    if (d.groupByStack) {
      stacksOf(dr.nodes).forEach(function (stack) {
        out += '  subgraph ' + mmQuote(stack) + '\n';
        dr.nodes.forEach(function (n) {
          if (n.stack === stack) out += '    ' + ids[n.id] + nodeShape(n) + '\n';
        });
        out += '  end\n';
      });
      dr.nodes.forEach(function (n) {
        if (!n.stack) out += '  ' + ids[n.id] + nodeShape(n) + '\n';
      });
    } else {
      dr.nodes.forEach(function (n) { out += '  ' + ids[n.id] + nodeShape(n) + '\n'; });
    }

    dr.edges.forEach(function (e) {
      var from = ids[e.from], to = ids[e.to];
      // An edge whose endpoint the drawing dropped is not drawn. It is still in the edge list.
      if (!from || !to) return;
      out += '  ' + from + arrow(e) + to + '\n';
    });
    return out;
  }

  function nodeLabel(n) {
    var label = asString(n.label);
    // The count is on the node because §22.5 asks for it there: a network that connects nothing looks the
    // same as one connecting eight until it says so.
    if (n.memberCount !== null && n.memberCount !== undefined) label += ' (' + n.memberCount + ')';
    return label;
  }

  // nodeShape is the node's label and shape: a network is a rounded box, an external record a stadium,
  // a service a plain box.
  function nodeShape(n) {
    var label = nodeLabel(n);
    if (n.kind === M.nodeNetwork) return '(' + mmQuote(label) + ')';
    if (n.kind === M.nodeExternal) return '([' + mmQuote(label) + '])';
    return '[' + mmQuote(label) + ']';
  }

  function edgeDashed(e) {
    return e.tags.indexOf(M.flowSourceDeclared) >= 0 ||
      (e.tags.indexOf(M.edgeDeclared) >= 0 && e.tags.indexOf(M.edgeObserved) < 0);
  }

  // edgeFlowless is membership with no flow: the service is on the network and nothing crosses it. Drawn
  // without an arrowhead, because an arrow would claim a direction the payload does not carry.
  function edgeFlowless(e) {
    return e.kind === M.edgeNetworkKind && e.tags.indexOf(M.flowBoth) < 0 &&
      e.tags.indexOf(M.flowToNetwork) < 0 && e.tags.indexOf(M.flowToService) < 0;
  }

  // edgeLabel is what the edge is labelled with. §22.5: an empty `via` is drawn direct **and marked** —
  // in the picture the mark is the warn tone, and an export has no colour, so there it is the word.
  // Without it a copied diagram shows a service → service line with nothing saying why it may exist.
  function edgeLabel(e) {
    if (!e.label && e.tags.indexOf(M.edgeDirect) >= 0) return M.edgeDirect;
    return e.label;
  }

  function arrow(e) {
    var dashed = edgeDashed(e);
    var line = dashed ? '-.->' : (edgeFlowless(e) ? '---' : '-->');
    var label = edgeLabel(e);
    if (!label) return ' ' + line + ' ';
    if (dashed) return ' -.' + mmQuote(label) + '.-> ';
    if (line === '---') return ' --- ' + mmQuote(label) + ' --- ';
    return ' --' + mmQuote(label) + '--> ';
  }

  // stacksOf is the stacks the drawn nodes belong to, in the order the nodes appeared.
  function stacksOf(nodes) {
    var out = [];
    nodes.forEach(function (n) { if (n.stack) once(out, n.stack); });
    return out;
  }

  // mmQuote makes a label safe for the export: Mermaid's own delimiters are the only thing removed, and
  // removed rather than escaped. Everything else survives exactly as it survives the URL (§22.7).
  function mmQuote(s) {
    return '"' + String(s).replace(/"/g, "'").replace(/[\n\r]/g, ' ')
      .replace(/\[/g, '(').replace(/\]/g, ')') + '"';
  }

  // ---------------------------------------------------------------------------
  // The remaining projections
  //
  // Go: the same functions in internal/webui/rows.go. Each one reads fields the scan already decided and
  // orders by the tags the rule tables already granted (§22.2).
  // ---------------------------------------------------------------------------

  // edgeRows is a diagram's tabular equivalent: the edge list §22.5 requires, as rows, uncapped.
  function edgeRows(s, ov) {
    var d = diagramOf(s.diagram);
    var out = [];
    edgesOf(d, ov).forEach(function (e, i) {
      var r = newRow(M.rowEdge, d.id + '#' + pad(i), e.from + ' → ' + e.to);
      r.sort = [pad(i)];
      r.networks = e.via.slice();
      r.bases = [[PRE.edge, e.raw]];
      r.raw = e.raw;
      say(r, e.from, e.to, e.label);
      e.tags.forEach(function (t) { tag(r, M.dimState, t); });
      r.cells.diagram = { text: [r.label], note: e.via.length ? 'crosses ' + e.via.join(', ') : '' };
      r.cells.shows = { terms: e.tags.map(function (t) { return diagramTerm(d, t); }) };
      r.cells.nodes = { text: [e.from, e.to] };
      r.cells.edges = { text: [e.id] };
      r.open = null;
      out.push(r);
    });
    return out;
  }

  function routerRows(ov) {
    var out = [], seen = {};
    eachService(ov, function (stack, svc, key) {
      (svc.traefikLive || []).forEach(function (live, i) {
        var id = live.router ? 'router/' + live.router : key + '#router/' + pad(i);
        if (seen[id]) return;
        seen[id] = true;
        var r = newRow(M.rowRouter, id, asString(live.router));
        r.stack = stack.id;
        r.service = key;
        r.networks = (svc.networks || []).slice();
        r.bases = serviceBases(stack, svc).concat([[PRE.live, live]]);
        r.raw = live;
        say(r, live.router, live.provider, live.service, svc.name);
        (live.hosts || []).forEach(function (h) { say(r, h); });
        applyRules(M.shapeLiveRouter, r, live);
        tag(r, M.dimIngress, M.ingressTraefik);
        r.lead = leadIf(rowHas(r, M.dimState, M.routerErrored));
        r.sort = [asString(live.router).toLowerCase(), id];
        r.cells.match = { text: [svc.name], link: withField(newState(), 'svc', key) };
        r.open = { kind: M.rowRouter, title: r.label || id, subject: live, bases: r.bases };
        out.push(r);
      });
    });
    // A router that matched no service is a row, not an omission (§12).
    (pathOf(ov, PATHS.unRouters) || []).forEach(function (un, i) {
      var live = un.router || {};
      var r = newRow(M.rowRouter, 'unmatched-router/' + pad(i), asString(live.router));
      r.lead = 0;
      r.bases = [[PRE.unRouter, un], [PRE.live, live]];
      r.raw = un;
      say(r, live.router, live.provider, live.service);
      (live.hosts || []).forEach(function (h) { say(r, h); });
      applyRules(M.shapeUnmatched, r, un);
      tag(r, M.dimIngress, M.ingressTraefik);
      r.sort = [asString(live.router).toLowerCase(), r.id];
      r.open = { kind: M.rowRouter, title: r.label || r.id, subject: un, bases: r.bases };
      out.push(r);
    });
    return out;
  }

  // probeRows is one row per probed service, in §22.2's stated finding order: answered with no login
  // page, then answered with one, then did not answer.
  function probeRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      if (!svc.probe) return;
      var p = svc.probe;
      var r = serviceRowBase(M.rowProbe, stack, svc, key);
      r.bases = serviceBases(stack, svc).concat([[PRE.probe, p]]);
      r.raw = p;
      say(r, p.endpoint);
      tag(r, M.dimState, asString(p.phase));
      // The order §22.2 states, read off the tags the rule table already granted rather than re-derived
      // from the probe record: the ordering and the filter cannot disagree about which probes answered
      // without a gate.
      r.lead = rowHas(r, M.dimProbe, M.outcomeOpen) ? 0 : (rowHas(r, M.dimProbe, M.outcomeGated) ? 1 : 2);
      r.sort = [asString(svc.name).toLowerCase(), key];
      r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
      r.open = { kind: M.rowProbe, title: svc.name, subject: p, bases: r.bases };
      out.push(r);
    });
    return out;
  }

  // declarationRows is one row per declaring service: drift first, then not confirmed, then accepted
  // exposures, then the rest (§22.2).
  function declarationRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      var d = svc.declared;
      if (!d) return;
      var drift = (d.drift || []).length, unconfirmed = (d.unconfirmed || []).length;
      var r = serviceRowBase(M.rowDeclaration, stack, svc, key);
      r.bases = serviceBases(stack, svc).concat([[PRE.decl, d]]);
      r.raw = d;
      say(r, d.owner, d.description, d.file);
      r.numbers.drift = drift;
      r.numbers.unconfirmed = unconfirmed;
      r.lead = drift ? 0 : (unconfirmed ? 1 : (d.unauthenticatedAccepted ? 2 : 3));
      r.sort = [asString(svc.name).toLowerCase(), key];
      r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
      out.push(r);
    });
    return out;
  }

  // entryRows is one row per drift or not-confirmed **entry**, which is what `stats.declarationDrift`
  // counts: a service with two drift entries contributes two (§22.3).
  function entryRows(ov, kind) {
    var out = [];
    var unconfirmed = kind === M.rowUnconfirmed;
    var member = unconfirmed ? M.declNotConfirmed : M.declDrift;
    var column = unconfirmed ? 'unconfirmed' : 'drift';
    eachService(ov, function (stack, svc, key) {
      var d = svc.declared;
      if (!d) return;
      ((unconfirmed ? d.unconfirmed : d.drift) || []).forEach(function (entry, i) {
        var text = asString(entry);
        var r = newRow(kind, key + '#' + kind + M.keySeparator + pad(i), text);
        r.stack = stack.id;
        r.service = key;
        r.networks = (svc.networks || []).slice();
        r.exposed = !!(svc.auth && svc.auth.exposedWithoutAuth);
        r.drift = !unconfirmed;
        r.bases = serviceBases(stack, svc).concat([[PRE.decl, d]]);
        r.raw = entry;
        say(r, svc.name, text, d.file);
        tag(r, M.dimDecl, member);
        r.sort = [asString(svc.name).toLowerCase(), pad(i)];
        r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
        // The entry itself is the row, so it goes in the column the narrowing was on.
        r.cells[column] = { text: [text] };
        r.open = { kind: M.rowDeclaration, title: svc.name, subject: d, bases: r.bases };
        out.push(r);
      });
    });
    return out;
  }

  // acceptedRows is §22.3's accepted list: one row per service whose exposure the operator accepted,
  // **labelled as still exposed** — an acceptance records a decision and changes nothing about
  // reachability (§14 rule 3).
  function acceptedRows(ov) {
    var out = [];
    eachService(ov, function (stack, svc, key) {
      var d = svc.declared;
      if (!d || !d.unauthenticatedAccepted) return;
      var r = serviceRowBase(M.rowAccepted, stack, svc, key);
      r.bases = serviceBases(stack, svc).concat([[PRE.decl, d]]);
      r.raw = d;
      r.accepted = true;
      r.lead = leadIf(r.exposed);
      say(r, asString(d.unauthenticatedAccepted.reason));
      r.sort = [asString(svc.name).toLowerCase(), key];
      r.cells.service = { text: [svc.name], link: withField(newState(), 'svc', key) };
      out.push(r);
    });
    return out;
  }

  // reportRows is one row per connection report: failures and `partial` first (§22.2).
  function reportRows(ov) {
    var out = [];
    (pathOf(ov, PATHS.connections) || []).forEach(function (rep, i) {
      var r = newRow(M.rowReport, 'report/' + pad(i), asString(rep.target));
      r.bases = [[PRE.conn, rep]];
      r.raw = rep;
      say(r, rep.target, rep.endpoint, rep.detail, asString(rep.code), rep.hint);
      applyRules(M.shapeReport, r, rep);
      r.lead = leadIf(rowHas(r, M.dimState, M.reportFailing));
      r.sort = [asString(rep.target).toLowerCase(), r.id];
      r.open = { kind: M.rowReport, title: r.label, subject: rep, bases: r.bases };
      out.push(r);
    });
    return out;
  }

  // warningRows is one row per scan warning: §22.3's bounded list, as its own panel.
  function warningRows(ov) {
    var out = [];
    stringsAt(ov, PATHS.warnings).forEach(function (w, i) {
      var r = newRow(M.rowWarning, 'warning/' + pad(i), w);
      r.sort = [pad(i)];
      say(r, w);
      r.raw = w;
      r.cells.target = { text: [w] };
      out.push(r);
    });
    return out;
  }

  // ---------------------------------------------------------------------------
  // Projection (§22.2)
  //
  // Go: project and Rows in internal/webui/rows.go. The view's kind chooses the builder, and two of
  // §22.7's boolean narrowings switch it — because §22.3's counts are of different things:
  // `declarationDrift` counts drift *entries* and `exposureAccepted` counts services. A narrowing that
  // chose the row set must not then be applied again as a filter, which is what `consumed` records.
  // ---------------------------------------------------------------------------

  var BUILDERS = {};
  BUILDERS[M.rowStat] = function (s, ov) { return statRows(ov); };
  BUILDERS[M.rowStack] = function (s, ov) { return stackRows(ov); };
  BUILDERS[M.rowService] = function (s, ov) { return serviceRows(ov); };
  BUILDERS[M.rowRoute] = function (s, ov) { return routeRows(ov); };
  BUILDERS[M.rowNetwork] = function (s, ov) { return networkRows(ov); };
  BUILDERS[M.rowDiagram] = function (s, ov) { return diagramRows(ov); };
  BUILDERS[M.rowEdge] = function (s, ov) { return edgeRows(s, ov); };
  BUILDERS[M.rowContainer] = function (s, ov) { return containerRows(ov); };
  BUILDERS[M.rowStorage] = function (s, ov) { return storageRows(ov); };
  BUILDERS[M.rowConfig] = function (s, ov) { return configRows(ov); };
  BUILDERS[M.rowApplication] = function (s, ov) { return applicationRows(ov); };
  BUILDERS[M.rowRouter] = function (s, ov) { return routerRows(ov); };
  BUILDERS[M.rowProbe] = function (s, ov) { return probeRows(ov); };
  BUILDERS[M.rowDeclaration] = function (s, ov) { return declarationRows(ov); };
  BUILDERS[M.rowDrift] = function (s, ov) { return entryRows(ov, M.rowDrift); };
  BUILDERS[M.rowUnconfirmed] = function (s, ov) { return entryRows(ov, M.rowUnconfirmed); };
  BUILDERS[M.rowAccepted] = function (s, ov) { return acceptedRows(ov); };
  BUILDERS[M.rowReport] = function (s, ov) { return reportRows(ov); };
  BUILDERS[M.rowWarning] = function (s, ov) { return warningRows(ov); };

  function project(s, ov) {
    var kind = viewOf(s).kind;
    var consumed = { exposed: false, accepted: false, drift: false };
    if (kind === M.rowDeclaration) {
      if (s.drift) { kind = M.rowDrift; consumed.drift = true; }
      else if (s.accepted) { kind = M.rowAccepted; consumed.accepted = true; }
    } else if (kind === M.rowDiagram) {
      // §22.5 requires a tabular equivalent for every diagram, reachable from it — which means
      // addressable (§22.7). The edge list is that table.
      if (s.panel === M.panelEdges) kind = M.rowEdge;
    } else if (kind === M.rowReport) {
      if (s.panel === M.panelWarnings) kind = M.rowWarning;
    }
    var build = BUILDERS[kind];
    return { kind: kind, rows: build ? build(s, ov) : [], consumed: consumed };
  }

  function rowsOf(s, ov) {
    var p = project(s, ov);
    return sortRows(p.rows.filter(function (r) { return keep(s, r, p.consumed); }));
  }

  // ---------------------------------------------------------------------------
  // The document (§22.1)
  //
  // Everything below writes into the elements index.html declares, using the classes labview.css styles.
  // No colour is decided here: a tone class is `tone-` followed by a *term's own* tone, so a member added
  // in Go arrives with a colour instead of rendering as an invisible chip.
  // ---------------------------------------------------------------------------

  // What the interface says about a value the payload did not carry. §15 and §22.3 fix the reading — not
  // `0`, not `none`, not an empty cell that could be mistaken for either — so it is written once here and
  // every absent cell, count and card uses it.
  var NOT_REPORTED = 'not reported';

  // How many values one cell shows before it says how many more there are. A cap that stayed silent would
  // read as *that is all of them*, so the overflow is stated and the drawer has the rest (§22.5's rule
  // about caps, applied to a table cell).
  var CELL_VALUES = 6;

  var EL = {};
  function el(id) {
    if (!Object.prototype.hasOwnProperty.call(EL, id)) EL[id] = document.getElementById(id);
    return EL[id];
  }

  function mk(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt !== undefined && txt !== null && txt !== '') n.textContent = String(txt);
    return n;
  }

  function clear(n) {
    while (n.firstChild) n.removeChild(n.firstChild);
    return n;
  }

  function add(parent, child) {
    parent.appendChild(child);
    return child;
  }

  function absentNode() {
    return mk('span', 'absent', NOT_REPORTED);
  }

  // toneClass is the whole of this file's colour logic: a prefix plus a tone a term already carries.
  function toneClass(base, tone) {
    return tone ? base + ' tone-' + tone : base;
  }

  var SVG_NS = 'http://www.w3.org/2000/svg';
  function mkSVG(tag, attrs) {
    var n = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, String(attrs[k])); });
    return n;
  }

  // ---------------------------------------------------------------------------
  // What is on screen
  // ---------------------------------------------------------------------------

  var S = newState();     // the state the URL names (§22.7)
  var OV = null;          // the payload being read; null until the first one arrives
  var SESSION = null;     // GET api/session — the posture, for the sign-in form
  var COUNTS = null;      // the previous payload's card counts, for the change note
  var BUSY = false;       // a request is in flight
  var CONTROLS_FOR = null; // which view the filter controls were built for
  var OPEN = null;        // the drawer's subject

  // ---------------------------------------------------------------------------
  // Cells (§22.2, §22.4)
  //
  // One resolver for every column of every view. A column names *payload field paths*; a row carries
  // `bases`, which are `[prefix, object]` pairs; the longest matching prefix is stripped and the rest is
  // resolved against that object. That is what lets one renderer read fifteen different records — and a
  // field no base accounts for reads *not reported* rather than throwing (I4).
  // ---------------------------------------------------------------------------

  function baseFor(row, path) {
    var best = null, bestLen = -1;
    (row.bases || []).forEach(function (b) {
      if (path.indexOf(b[0]) === 0 && b[0].length > bestLen) { best = b; bestLen = b[0].length; }
    });
    return best;
  }

  // fieldValues is a column's values for one row, in the order the column declared its fields.
  //
  // A base whose object is null resolves to nothing *deliberately*: a Cloudflare route row carries a null
  // base for the Traefik prefix, so the Traefik columns read as not reported rather than borrowing the
  // service's other routes (routeRows).
  function fieldValues(row, col) {
    var out = [];
    (col.fields || []).forEach(function (path) {
      var base = baseFor(row, path);
      if (!base || !base[1]) return;
      valuesAt(base[1], path.slice(base[0].length)).forEach(function (v) {
        var s = asString(v);
        if (s) once(out, s);
      });
    });
    return out;
  }

  function fieldNumber(row, col) {
    var found = null;
    (col.fields || []).forEach(function (path) {
      if (found !== null) return;
      var base = baseFor(row, path);
      if (!base || !base[1]) return;
      valuesAt(base[1], path.slice(base[0].length)).forEach(function (v) {
        if (found !== null) return;
        var n = asInt(v);
        if (n !== null) found = n;
      });
    });
    return found;
  }

  // cellOf resolves one column of one row, in a fixed order of authority:
  //
  //   1. a cell the projection wrote — a roll-up, a link, an export: something no single field holds;
  //   2. a numeric column's recorded count, then a number resolved from its fields;
  //   3. the dimension's own tags, so the column and the filter beside it read the same members;
  //   4. the column's field paths, as members when it names a set and as text otherwise;
  //   5. nothing, which is *not reported*.
  function cellOf(row, col) {
    if (row.cells && Object.prototype.hasOwnProperty.call(row.cells, col.key)) return row.cells[col.key];
    if (col.numeric) {
      if (Object.prototype.hasOwnProperty.call(row.numbers, col.key)) {
        return { number: row.numbers[col.key] };
      }
      var n = fieldNumber(row, col);
      if (n !== null) return { number: n };
      return { absent: true };
    }
    if (col.dim && (row.tags[col.dim] || []).length) {
      var dim = DIMS[col.dim];
      return { members: row.tags[col.dim], set: dim ? dim.set : '' };
    }
    var vals = fieldValues(row, col);
    if (!vals.length) return { absent: true };
    if (col.set) return { members: vals, set: col.set };
    return { text: vals, evidence: col.evidence };
  }

  // tagNode is one member, rendered through its term: the term's label, the term's tone, and the term's
  // mark — which is what carries the reading for a reader who cannot see the colour (§22.1).
  function tagNode(term, dim) {
    var node = mk('span', toneClass('tag', term.tone));
    if (term.mark) add(node, mk('span', 'mark', term.mark));
    add(node, document.createTextNode(term.label || term.member));
    if (term.note) node.title = term.note;
    // A tag is clickable: it narrows to itself (§22.6). Only where there is a dimension to narrow *on* —
    // a diagram reading has no filter, so it is a label and says nothing by being unclickable.
    if (dim) {
      node.setAttribute('data-dim', dim);
      node.setAttribute('data-member', term.member);
      node.setAttribute('role', 'button');
      node.setAttribute('tabindex', '0');
    }
    return node;
  }

  function fillCell(td, cell, col, row) {
    if (!cell || cell.absent) { add(td, absentNode()); return; }

    if (cell.number !== undefined && cell.number !== null) {
      td.classList.add('num');
      var num = mk('span', cell.tone ? 'tone-' + cell.tone : '', String(cell.number));
      add(td, num);
      return;
    }

    if (cell.members) {
      var dim = col && col.dim && row && (row.tags[col.dim] || []).length ? col.dim : '';
      cell.members.forEach(function (m) { add(td, tagNode(termOf(cell.set, m), dim)); });
      return;
    }

    if (cell.terms) {
      cell.terms.forEach(function (t) { add(td, tagNode(t, '')); });
      if (!cell.terms.length) add(td, absentNode());
      return;
    }

    var lines = (cell.text || []).filter(function (v) { return v !== ''; });
    if (!lines.length && !cell.export) { add(td, absentNode()); return; }

    var href = cell.href || (cell.link ? linkOf(cell.link) : '');
    lines.slice(0, CELL_VALUES).forEach(function (v) {
      var line;
      if (href) {
        line = mk('a', '', v);
        line.setAttribute('href', href);
      } else {
        line = mk('span', '', v);
      }
      add(td, line);
      add(td, document.createElement('br'));
    });
    if (lines.length > CELL_VALUES) {
      add(td, mk('span', 'muted', '+ ' + (lines.length - CELL_VALUES) + ' more; the drawer has all of them'));
    }
    if (cell.note) add(td, mk('span', 'hint', cell.note));
    if (cell.export) add(td, exportNode(cell.export));
  }

  // exportNode is the copyable text export beside a diagram row (§22.5, §22.8).
  function exportNode(source) {
    var box = mk('button', '', 'Copy');
    box.type = 'button';
    box.setAttribute('data-export', source);
    return box;
  }

  // ---------------------------------------------------------------------------
  // The chrome (§22.1)
  // ---------------------------------------------------------------------------

  function renderChrome() {
    var scanned = pathOf(OV, 'meta.scannedAt');
    var ms = asInt(pathOf(OV, 'meta.durationMs'));
    var when = scanned ? 'scanned ' + asString(scanned) : 'scan time ' + NOT_REPORTED;
    el('scanned').textContent = ms === null ? when : when + ' in ' + ms + 'ms';

    // §3.4: an unknown revision is a supported state and says so, rather than showing a blank.
    var version = asString(pathOf(OV, 'meta.build.version'));
    var commit = asString(pathOf(OV, 'meta.build.commit'));
    var source = asString(pathOf(OV, 'meta.build.source'));
    var stamp = version || NOT_REPORTED;
    if (commit) stamp += ' ' + commit;
    if (source) stamp += ' (' + source + ')';
    el('build').textContent = stamp;

    // §22.1: the switch is re-synced from `meta.probe.enabled` on every payload, so it reports what the
    // answering scan did rather than what was last asked for.
    el('probe-switch').checked = pathOf(OV, 'meta.probe.enabled') === true;
    el('probe-switch').title = 'probe ' + (el('probe-switch').checked ? 'on' : 'off') +
      ' (' + (asString(pathOf(OV, 'meta.probe.source')) || NOT_REPORTED) + ')';
  }

  function syncBusy() {
    el('rescan').disabled = BUSY;
    el('rescan').textContent = BUSY ? 'Scanning…' : 'Rescan';
  }

  // renderBanners states, above every view, what this scan could not read (§15, §22.1).
  //
  // Never `alert`: that colour is reserved for reachable-with-no-gate and nothing else (§22.1). A
  // connection that failed is a `warn`, and its tone comes from the report's own rule table.
  function renderBanners() {
    var host = clear(el('banners'));

    (pathOf(OV, PATHS.connections) || []).forEach(function (rep, i) {
      var probe = { kind: '', id: '', label: '', stack: '', service: '', networks: [], exposed: false,
        accepted: false, drift: false, lead: 3, sort: [], tags: {}, text: [], bases: [], cells: {},
        numbers: {}, raw: null, open: null };
      applyRules(M.shapeReport, probe, rep);
      if (!rowHas(probe, M.dimState, M.reportFailing)) return;
      var term = termOf('connectionPhase', asString(rep.phase));
      var b = mk('div', toneClass('banner', term.tone || TONE_WARN));
      add(b, mk('strong', '', asString(rep.target) || 'connection'));
      add(b, document.createTextNode(' — ' + (asString(rep.detail) || term.label || asString(rep.phase))));
      if (rep.hint) add(b, mk('span', 'hint', asString(rep.hint)));
      // The banner is a link to the row it summarises, which is what makes it answerable (§22.4).
      var a = mk('a', '', 'Diagnostics');
      a.setAttribute('href', linkOf(withField(newState(), 'view', 'diagnostics')));
      add(b, a);
      add(host, b);
      return i;
    });

    // §22.8: the Engine not being read is *not read*, never *stopped*. Said once, here, rather than
    // implied by every empty runtime column.
    if (pathOf(OV, 'meta.dockerAvailable') === false) {
      var d = mk('div', toneClass('banner', TONE_WARN));
      add(d, mk('strong', '', 'Container engine'));
      add(d, document.createTextNode(' — not read: ' +
        (asString(pathOf(OV, 'meta.dockerError')) || NOT_REPORTED) +
        '. Runtime columns read as not read, not as stopped.'));
      add(host, d);
    }

    var warnings = stringsAt(OV, PATHS.warnings);
    if (warnings.length) {
      var w = mk('div', toneClass('banner', TONE_WARN));
      add(w, mk('strong', '', warnings.length + (warnings.length === 1 ? ' scan warning' : ' scan warnings')));
      var link = mk('a', '', 'Read them');
      link.setAttribute('href', '?' + queryOf(warningsState()));
      add(w, link);
      add(host, w);
    }
  }

  function warningsState() {
    var s = withField(newState(), 'view', 'diagnostics');
    return withField(s, 'panel', M.panelWarnings);
  }

  // renderChange is the change note beside Rescan: what this payload says that the last one did not.
  //
  // It is the diff of the overview's *own* counters rather than a second summary of the fleet, so the
  // note and the cards can never disagree — and a scan that changed nothing says so, because silence
  // there would read as *the rescan did not run*.
  function renderChange(before, after) {
    var node = el('change');
    if (!before) { node.hidden = true; clear(node); return; }
    var moved = [];
    Object.keys(after).forEach(function (id) {
      if (!Object.prototype.hasOwnProperty.call(before, id)) return;
      if (before[id].n === after[id].n && before[id].ok === after[id].ok) return;
      moved.push({ id: id, label: after[id].label, from: before[id], to: after[id] });
    });
    clear(node);
    node.hidden = false;
    if (!moved.length) {
      add(node, document.createTextNode('This scan reports the same counts as the last one.'));
      return;
    }
    add(node, mk('strong', '', 'Since the last scan: '));
    moved.slice(0, 8).forEach(function (m, i) {
      if (i) add(node, document.createTextNode('; '));
      var from = m.from.ok ? String(m.from.n) : NOT_REPORTED;
      var to = m.to.ok ? String(m.to.n) : NOT_REPORTED;
      add(node, document.createTextNode(m.label + ' ' + from + ' → ' + to));
    });
    if (moved.length > 8) {
      add(node, document.createTextNode('; and ' + (moved.length - 8) + ' more counts moved'));
    }
  }

  // countsOf snapshots every card's count, which is what the change note diffs.
  function countsOf(ov) {
    var out = {};
    cardsOf(ov).forEach(function (card) {
      var c = countOf(card, ov);
      out[card.id] = { n: c.n, ok: c.ok, label: card.label };
    });
    return out;
  }

  // ---------------------------------------------------------------------------
  // Navigation (§22.1)
  // ---------------------------------------------------------------------------

  function renderNav() {
    var host = clear(el('nav'));
    var current = viewOf(S).slug;
    C.groups.forEach(function (group) {
      var views = VIEW_ORDER.map(function (slug) { return VIEWS[slug]; })
        .filter(function (v) { return v.group === group; });
      if (!views.length) return;
      add(host, mk('h2', '', group));
      var list = add(host, mk('ol', ''));
      views.forEach(function (v) {
        var li = add(list, mk('li', ''));
        var a = mk('a', '', v.title);
        // A view link keeps nothing of the old view: the filters of one view are not the filters of
        // another, and a stale `net=` would silently narrow a table that never mentions networks.
        a.setAttribute('href', linkOf(withField(newState(), 'view', v.slug === G.defaultView ? '' : v.slug)));
        a.title = v.question;
        if (v.slug === current) a.setAttribute('aria-current', 'page');
        add(li, a);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Filters (§22.6)
  // ---------------------------------------------------------------------------

  // dimMembers is what a dimension's control offers.
  //
  // A dimension with a set has a closed vocabulary and offers all of it, including members no row on
  // screen carries — that a state is *available and empty* is itself an answer. A dimension with no set
  // has an open one: container state is the Engine's own status strings, which §16 says this build cannot
  // know ahead of time, so the control offers what this payload actually carried. Plus whatever the URL
  // already asks for, because a filter that matched nothing must still be switchable off from the control
  // that set it.
  function dimMembers(param, rows) {
    var dim = DIMS[param];
    if (!dim) return [];
    if (dim.set) return setMembers(dim.set);
    var out = [];
    rows.forEach(function (r) { (r.tags[param] || []).forEach(function (m) { once(out, m); }); });
    var f = S.tags[param];
    if (f) f.include.concat(f.exclude).forEach(function (m) { once(out, m); });
    return canonical(dim, out);
  }

  function renderFilters(rows) {
    var view = viewOf(S);
    if (el('q').value !== S.q && document.activeElement !== el('q')) el('q').value = S.q;

    // An open vocabulary changes with the payload, so the cache key is the offered members and not just
    // the view — otherwise a container that appeared in a rescan would have no control.
    var key = (view.dims || []).map(function (param) {
      return param + '=' + dimMembers(param, rows).join(',');
    }).join(';');
    if (CONTROLS_FOR === view.slug + '\x00' + key) { syncControls(); return; }
    CONTROLS_FOR = view.slug + '\x00' + key;

    var host = clear(el('controls'));
    (view.dims || []).forEach(function (param) {
      var dim = DIMS[param];
      if (!dim) return;
      var box = add(host, mk('div', 'dim'));
      var head = add(box, mk('div', 'dim-head'));
      add(head, mk('span', 'dim-label', dim.label));
      // §22.6: a multi-valued dimension can ask for *all of these* or *any of these*, and which one is
      // in force has to be visible — an `all:` filter reading as `any:` is a different question.
      if (dim.multi) {
        var mode = mk('button', 'mode');
        mode.type = 'button';
        mode.setAttribute('data-mode-dim', param);
        add(head, mode);
      }
      if (dim.note) add(head, mk('span', 'hint', dim.note));
      var values = add(box, mk('div', 'dim-values'));
      var members = dimMembers(param, rows);
      if (!members.length) {
        // §22.6 with nothing to offer: a control with no buttons would read as *this cannot be filtered*,
        // which is a different fact from *this payload carried no such reading*.
        add(values, mk('span', 'absent', 'nothing to filter on — ' + NOT_REPORTED + ' in this scan'));
        return;
      }
      members.forEach(function (member) {
        var term = termOf(dim.set, member);
        var b = mk('button', 'tri');
        b.type = 'button';
        b.setAttribute('data-tri-dim', param);
        b.setAttribute('data-tri-member', member);
        if (term.note) b.title = term.note;
        add(b, mk('span', 'mark', term.mark || ''));
        add(b, document.createTextNode(term.label || member));
        add(values, b);
      });
    });
    syncControls();
  }

  // syncControls writes the URL's filter back onto the buttons, so the controls are a view of the state
  // rather than a second copy of it.
  function syncControls() {
    var host = el('controls');
    Array.prototype.forEach.call(host.querySelectorAll('[data-tri-dim]'), function (b) {
      var f = S.tags[b.getAttribute('data-tri-dim')];
      var member = b.getAttribute('data-tri-member');
      var state = 'off';
      if (f && f.exclude.indexOf(member) >= 0) state = 'exclude';
      else if (f && f.include.indexOf(member) >= 0) state = 'include';
      b.setAttribute('data-state', state);
      b.setAttribute('aria-pressed', state === 'off' ? 'false' : 'true');
    });
    Array.prototype.forEach.call(host.querySelectorAll('[data-mode-dim]'), function (b) {
      var f = S.tags[b.getAttribute('data-mode-dim')];
      var all = !!(f && f.all);
      b.textContent = all ? 'all of these' : 'any of these';
      b.setAttribute('aria-pressed', all ? 'true' : 'false');
      b.disabled = !f || f.include.length < 2;
    });
  }

  // cycle is §22.6's tri-state: off → include → exclude → off.
  function cycle(param, member) {
    var dim = DIMS[param];
    var f = S.tags[param] || { all: false, include: [], exclude: [] };
    var include = f.include.filter(function (m) { return m !== member; });
    var exclude = f.exclude.filter(function (m) { return m !== member; });
    if (f.exclude.indexOf(member) >= 0) {
      // was excluded → off
    } else if (f.include.indexOf(member) >= 0) {
      exclude.push(member);
    } else {
      include.push(member);
    }
    // Re-parsed from its own string rather than assembled: the single-valued rule, the vocabulary check
    // and the canonical order all live in parseFilter, and applying them twice in two places is how the
    // two would drift apart.
    var parts = include.slice();
    exclude.forEach(function (m) { parts.push(G.excludePrefix + m); });
    var raw = parts.join(',');
    if (f.all && raw) raw = G.allPrefix + raw;
    return withFilter(S, param, parseFilter(dim, raw));
  }

  function toggleMode(param) {
    var f = S.tags[param];
    if (!f) return S;
    var parts = f.include.slice();
    f.exclude.forEach(function (m) { parts.push(G.excludePrefix + m); });
    var raw = parts.join(',');
    if (!f.all && raw) raw = G.allPrefix + raw;
    return withFilter(S, param, parseFilter(DIMS[param], raw));
  }

  // ---------------------------------------------------------------------------
  // Chips and the count (§22.6)
  // ---------------------------------------------------------------------------

  // renderChips shows every narrowing in force, each removable. §22.6: a filtered table must say it is
  // filtered — an empty table with a hidden filter reads as *there is nothing here*.
  function renderChips() {
    var host = clear(el('chips'));
    var made = 0;

    function chip(label, tone, next) {
      var c = add(host, mk('span', toneClass('chip', tone)));
      add(c, document.createTextNode(label));
      var b = mk('button', '', '×');
      b.type = 'button';
      b.setAttribute('aria-label', 'Remove filter: ' + label);
      b.setAttribute('data-chip', linkOf(next));
      add(c, b);
      made++;
    }

    if (S.q) chip('text: ' + S.q, '', withField(S, 'q', ''));
    if (S.stack) chip('stack: ' + S.stack, '', withField(S, 'stack', ''));
    if (S.net) chip('network: ' + S.net, '', withField(S, 'net', ''));
    if (S.svc) chip('service: ' + S.svc, '', withField(S, 'svc', ''));
    if (S.exposed) chip('exposed without authentication', 'alert', withField(S, 'exposed', false));
    if (S.accepted) chip('accepted exposure', '', withField(S, 'accepted', false));
    if (S.drift) chip('declaration drift', '', withField(S, 'drift', false));
    if (S.focus) chip('focus: ' + S.focus, '', withField(S, 'focus', ''));
    if (S.panel) chip('panel: ' + S.panel, '', withField(S, 'panel', ''));

    Object.keys(S.tags).forEach(function (param) {
      var dim = DIMS[param];
      var f = S.tags[param];
      var label = dim ? dim.label : param;
      var join = f.all ? ' and ' : ' or ';
      f.include.forEach(function (m) {
        chip(label + ': ' + (termOf(dim ? dim.set : '', m).label || m),
          termOf(dim ? dim.set : '', m).tone, withFilter(S, param, dropMember(dim, f, m)));
      });
      f.exclude.forEach(function (m) {
        chip(label + ': not ' + (termOf(dim ? dim.set : '', m).label || m), '',
          withFilter(S, param, dropMember(dim, f, m)));
      });
      // Which of `all` and `any` is in force, once per dimension and only where it can matter.
      if (f.include.length > 1) add(host, mk('span', 'muted', '(' + join.trim() + ')'));
    });

    if (!made) host.hidden = true;
    else host.hidden = false;
  }

  function dropMember(dim, f, member) {
    var parts = f.include.filter(function (m) { return m !== member; });
    f.exclude.forEach(function (m) { if (m !== member) parts.push(G.excludePrefix + m); });
    var raw = parts.join(',');
    if (f.all && raw) raw = G.allPrefix + raw;
    return parseFilter(dim, raw);
  }

  // renderCount states how many rows are shown out of how many the view has — §22.6's *say it is
  // filtered*, as a number rather than as a colour.
  function renderCount(shown, total, view) {
    var noun = view.rowNoun + (shown === 1 ? '' : 's');
    var node = el('count');
    if (shown === total) {
      node.textContent = shown + ' ' + noun;
      return;
    }
    node.textContent = shown + ' of ' + total + ' ' + view.rowNoun +
      (total === 1 ? '' : 's') + ' — the rest are filtered out';
  }

  // ---------------------------------------------------------------------------
  // The table (§22.2)
  // ---------------------------------------------------------------------------

  function renderTable(host, view, rows) {
    if (!rows.length) {
      add(host, mk('p', 'empty', view.empty));
      return;
    }
    var scroll = add(host, mk('div', 'scroll'));
    var table = add(scroll, mk('table', ''));
    var head = add(add(table, mk('thead', '')), mk('tr', ''));
    var body = add(table, mk('tbody', ''));

    // Which columns actually hold numbers in *this* payload, so a column of drift sentences is not
    // right-aligned as though the sentences were counts. Decided before the header is written and from
    // the rows themselves, so the header and the cells always agree.
    var numeric = {};
    var cells = rows.map(function (row) {
      return view.columns.map(function (col) {
        var cell = cellOf(row, col);
        if (cell && cell.number !== undefined && cell.number !== null) numeric[col.key] = true;
        return cell;
      });
    });

    view.columns.forEach(function (col) {
      var th = add(head, mk('th', numeric[col.key] ? 'num' : ''));
      add(th, document.createTextNode(col.header));
      // The column note is in the header rather than in a tooltip: §22.8's readings ("not read, never
      // stopped", "confidence is how, not how strong") are the kind of thing a reader needs without
      // hovering.
      if (col.note) add(th, mk('span', 'hint', col.note));
    });

    rows.forEach(function (row, i) {
      var tr = add(body, mk('tr', ''));
      if (row.open) {
        tr.setAttribute('data-open', row.id);
        tr.setAttribute('tabindex', '0');
      }
      if (row.lead === 0) tr.classList.add('lead');
      view.columns.forEach(function (col, j) {
        var td = add(tr, mk('td', ''));
        fillCell(td, cells[i][j], col, row);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // The overview's cards (§22.3)
  //
  // The cards are the *stat rows* rendered as cards: they are filtered, ordered and searched by the same
  // code as every other view, which is why the exposure card leads and why the search box works here.
  // ---------------------------------------------------------------------------

  function renderCards(host, view, rows) {
    if (!rows.length) {
      add(host, mk('p', 'empty', view.empty));
      return;
    }
    var group = null, grid = null;
    rows.forEach(function (row) {
      var card = row.card;
      var dest = VIEWS[card.view];
      // The lead card is above every heading: §22.3 puts the exposure finding first and above the fold,
      // and a section label in front of it would push it down.
      var label = row.lead === 0 ? '' : (dest ? dest.group : 'Other');
      if (label !== group || !grid) {
        group = label;
        if (label) add(host, mk('h2', 'section-label', label));
        grid = add(host, mk('div', 'cards'));
      }
      var a = add(grid, mk('a', toneClass('card', card.tone)));
      a.setAttribute('href', '?' + card.dest);
      if (row.lead === 0) a.classList.add('lead');
      if (card.note) a.title = card.note;

      var count = cellOf(row, { key: 'count', numeric: true });
      if (count.absent) add(a, mk('span', 'n absent', NOT_REPORTED));
      else add(a, mk('span', 'n', String(count.number)));

      add(a, mk('span', 'l', card.label));
      // What the destination shows, and whether it is *exactly* these rows or the records the view can
      // show — §22.3 requires the difference to be visible, because a card that overstated it would be a
      // number pointing at a different set.
      add(a, mk('span', 'hint', destinationOf(card)));
    });
  }

  // ---------------------------------------------------------------------------
  // The drawing (§22.5)
  //
  // A deterministic hand-laid SVG: nodes in columns by distance from the focus, in the graph's own order
  // within a column. No layout engine and no randomness, so the same payload draws the same picture (I7)
  // — the same property the text export has, and for the same reason.
  // ---------------------------------------------------------------------------

  var NODE_H = 26, COL_W = 210, ROW_H = 44, PAD = 16, CHAR_W = 6.2, LABEL_MAX = 30;

  function renderDiagram(host, d) {
    var dr = draw(d, S, OV);

    var bar = add(host, mk('div', 'diagram-bar'));
    C.diagrams.forEach(function (other) {
      var a = mk('a', '', other.title);
      a.setAttribute('href', linkOf(diagramState(S, other.id)));
      if (other.id === d.id) a.setAttribute('aria-current', 'page');
      add(bar, a);
    });
    // The tabular equivalent §22.5 requires, addressable rather than a toggle (§22.7).
    var edges = mk('a', '', 'Edge list (uncapped)');
    edges.setAttribute('href', linkOf(withField(S, 'panel', M.panelEdges)));
    add(bar, edges);
    var copy = mk('button', '', 'Copy Mermaid');
    copy.type = 'button';
    copy.setAttribute('data-export', mermaid(dr));
    add(bar, copy);
    if (S.focus) {
      var wider = mk('a', '', 'Depth ' + (dr.depth + 1));
      wider.setAttribute('href', linkOf(withField(S, 'depth', dr.depth + 1)));
      add(bar, wider);
      var whole = mk('a', '', 'Whole diagram');
      whole.setAttribute('href', linkOf(withField(S, 'focus', '')));
      add(bar, whole);
    }

    add(host, mk('p', 'diagram-note', d.note));

    // Every reason the picture is partial, in words. §22.5: forced focus and each capped hub must say so
    // — and the sentence names where the rest is.
    if (dr.forced) {
      add(host, mk('p', 'caps', 'Opened focused on ' + dr.focus + ' at depth ' + dr.depth + ': ' +
        dr.total + ' nodes is over this diagram\'s threshold of ' + d.nodeThreshold +
        '. The whole drawing is one click away.'));
    } else if (dr.focus) {
      add(host, mk('p', 'diagram-note', 'Focused on ' + dr.focus + ' at depth ' + dr.depth + '.'));
    }
    dr.caps.forEach(function (c) {
      add(host, mk('p', 'caps', capSentence(c, 'edges') + ' — the edge list shows all of them.'));
    });

    add(host, figureOf(dr));

    // The legend is the diagram's own tag table, so a reading in the picture and the same reading in the
    // edge list are the same term with the same mark.
    var legend = add(host, mk('div', 'legend'));
    (d.tags || []).forEach(function (t) { add(legend, tagNode(t, '')); });

    if (!dr.nodes.length) {
      add(host, mk('p', 'empty', VIEWS['diagrams'].empty));
    }
  }

  // columnsOf assigns each node a column: breadth-first from the focus, then from the first node not yet
  // placed, walking the graph's own order. Deterministic, and it puts what a reader focused on at the
  // left with its neighbourhood fanning out to the right (`graph LR`, the same as the export).
  function columnsOf(dr) {
    var col = {}, order = dr.nodes.map(function (n) { return n.id; });
    var adjacency = {};
    dr.edges.forEach(function (e) {
      (adjacency[e.from] = adjacency[e.from] || []).push(e.to);
      (adjacency[e.to] = adjacency[e.to] || []).push(e.from);
    });
    var start = dr.focus && order.indexOf(dr.focus) >= 0 ? dr.focus : null;
    var queue = [];
    function seed(id) { col[id] = 0; queue.push(id); }
    if (start) seed(start);
    for (var guard = 0; guard <= order.length; guard++) {
      while (queue.length) {
        var id = queue.shift();
        (adjacency[id] || []).forEach(function (next) {
          if (Object.prototype.hasOwnProperty.call(col, next)) return;
          col[next] = col[id] + 1;
          queue.push(next);
        });
      }
      var pending = null;
      for (var i = 0; i < order.length; i++) {
        if (!Object.prototype.hasOwnProperty.call(col, order[i])) { pending = order[i]; break; }
      }
      if (pending === null) break;
      seed(pending);
    }
    return col;
  }

  function figureOf(dr) {
    var figure = mk('div', 'figure');
    if (!dr.nodes.length) return figure;

    var col = columnsOf(dr);
    var lanes = {}, at = {};
    dr.nodes.forEach(function (n) {
      var c = col[n.id] || 0;
      lanes[c] = lanes[c] || [];
      at[n.id] = { col: c, row: lanes[c].length };
      lanes[c].push(n.id);
    });

    var widest = 0, tallest = 0;
    Object.keys(lanes).forEach(function (c) {
      widest = Math.max(widest, Number(c) + 1);
      tallest = Math.max(tallest, lanes[c].length);
    });

    var boxes = {};
    dr.nodes.forEach(function (n) {
      var label = nodeLabel(n);
      if (label.length > LABEL_MAX) label = label.slice(0, LABEL_MAX - 1) + '…';
      var w = Math.max(70, Math.round(label.length * CHAR_W) + 18);
      var spot = at[n.id];
      boxes[n.id] = {
        node: n, label: label, w: w, h: NODE_H,
        x: PAD + spot.col * COL_W, y: PAD + spot.row * ROW_H
      };
    });

    var width = PAD * 2 + (widest - 1) * COL_W + 200;
    var height = PAD * 2 + Math.max(1, tallest) * ROW_H;
    var root = mkSVG('svg', {
      width: width, height: height, viewBox: '0 0 ' + width + ' ' + height,
      role: 'img', 'aria-label': dr.diagram.title + ': ' + dr.nodes.length + ' nodes, ' + dr.edges.length + ' edges'
    });

    // Edges first, so a line never covers the label of the node it ends at.
    dr.edges.forEach(function (e) {
      var from = boxes[e.from], to = boxes[e.to];
      if (!from || !to) return;
      add(root, edgeNode(e, from, to));
    });
    dr.nodes.forEach(function (n) { add(root, nodeGroup(boxes[n.id])); });

    add(figure, root);
    return figure;
  }

  function nodeGroup(box) {
    var n = box.node;
    var g = mkSVG('g', { class: 'node' });
    g.setAttribute('data-kind', asString(n.kind));
    // The one node colour, and it is the reserved one: a node with no gate on its path (§22.1). Read off
    // the same stored finding the exposure card counts, never recomputed here.
    if (ungatedNow[n.id]) g.setAttribute('data-tone', 'alert');
    g.setAttribute('data-node', n.id);
    g.setAttribute('tabindex', '0');
    // Rounded for a network, stadium for a record from outside this fleet, square for a service — the
    // same three shapes the text export uses, so the picture and the export read alike.
    var rx = n.kind === M.nodeNetwork ? 12 : (n.kind === M.nodeExternal ? box.h / 2 : 3);
    add(g, mkSVG('rect', { x: box.x, y: box.y, width: box.w, height: box.h, rx: rx, ry: rx }));
    var t = mkSVG('text', { x: box.x + box.w / 2, y: box.y + box.h / 2 + 4, 'text-anchor': 'middle' });
    t.textContent = box.label;
    add(g, t);
    var title = mkSVG('title', {});
    title.textContent = n.id + (n.stack ? ' — stack ' + n.stack : '');
    add(g, title);
    return g;
  }

  function edgeNode(e, from, to) {
    var g = mkSVG('g', { class: 'edge' });
    if (e.tone) g.setAttribute('data-tone', e.tone);
    if (edgeDashed(e)) g.setAttribute('data-dashed', G.flag);

    var x1 = from.x + from.w, y1 = from.y + from.h / 2;
    var x2 = to.x, y2 = to.y + to.h / 2;
    // Right-to-left and same-column edges leave from the bottom instead, so a back edge is not drawn
    // through the box it starts at.
    if (x2 < x1) { x1 = from.x; y1 = from.y + from.h / 2; x2 = to.x + to.w; }
    var mx = (x1 + x2) / 2;
    add(g, mkSVG('path', { d: 'M ' + x1 + ' ' + y1 + ' C ' + mx + ' ' + y1 + ', ' + mx + ' ' + y2 + ', ' + x2 + ' ' + y2 }));

    // An arrowhead only where there is a direction to claim: network membership with no flow is drawn
    // without one, exactly as the export draws it with `---` (§8).
    if (!edgeFlowless(e)) {
      var back = x2 < x1 ? -1 : 1;
      add(g, mkSVG('path', {
        d: 'M ' + (x2 - 7 * back) + ' ' + (y2 - 4) + ' L ' + x2 + ' ' + y2 +
           ' L ' + (x2 - 7 * back) + ' ' + (y2 + 4)
      }));
    }

    var label = edgeLabel(e);
    if (label) {
      var t = mkSVG('text', { x: mx, y: (y1 + y2) / 2 - 4, 'text-anchor': 'middle' });
      t.textContent = label.length > 22 ? label.slice(0, 21) + '…' : label;
      add(g, t);
    }
    var title = mkSVG('title', {});
    title.textContent = e.from + ' → ' + e.to + (e.via.length ? ' via ' + e.via.join(', ') : '') +
      (e.tags.length ? ' (' + e.tags.join(', ') + ')' : '');
    add(g, title);
    return g;
  }

  // The ungated set for the payload on screen, recomputed once per render rather than per node.
  var ungatedNow = {};

  // ---------------------------------------------------------------------------
  // The drawer (§22.4)
  //
  // One drawer per row kind, built from the contract's section tables. Every section is a list of payload
  // field paths resolved against the row's own bases — which is what makes §22.4's coverage rule a
  // property of the tables rather than of this code.
  // ---------------------------------------------------------------------------

  function drawerOf(kind) {
    var found = null;
    C.drawers.forEach(function (d) { if (!found && d.kind === kind) found = d; });
    return found;
  }

  // PANEL maps each addressable panel string to the drawer and section it names.
  //
  // Built by matching the contract's own `panels` list against the drawer tables rather than by joining a
  // kind and a section id with a separator this file spells: the separator is Go's, `M.keySeparator` is a
  // *different* character, and a link this page wrote with the wrong one would look right and resolve to
  // nothing. `edges` and `list:warnings` are deliberately absent — they name row sets, not drawers, and
  // project() has already switched to them.
  var PANEL = {};
  C.drawers.forEach(function (d) {
    d.sections.forEach(function (section) {
      C.panels.forEach(function (p) {
        if (p.length !== d.kind.length + 1 + section.id.length) return;
        if (p.indexOf(d.kind) !== 0 || p.slice(p.length - section.id.length) !== section.id) return;
        PANEL[p] = { kind: d.kind, section: section.id };
      });
    });
  });

  function panelOf(kind, sectionID) {
    var found = '';
    Object.keys(PANEL).forEach(function (p) {
      if (PANEL[p].kind === kind && PANEL[p].section === sectionID) found = p;
    });
    return found;
  }

  function openDrawer(open, at) {
    OPEN = open;
    var spec = open ? drawerOf(open.kind) : null;
    var host = el('drawer');
    if (!spec) { closeDrawer(); return; }

    el('drawer-title').textContent = open.title ? open.title + ' — ' + spec.title : spec.title;
    var body = clear(el('drawer-body'));
    add(body, mk('p', 'note', spec.opens));

    spec.sections.forEach(function (section) {
      var box = add(body, mk('section', ''));
      var panel = panelOf(open.kind, section.id);
      if (panel) box.setAttribute('data-panel', panel);
      var h = add(box, mk('h3', '', section.title));
      // Every section is addressable, because §22.7 says a reader must be able to link to what they are
      // looking at rather than describe how to get there.
      var link = mk('a', '', '#');
      link.setAttribute('href', linkOf(withField(S, 'panel', panel)));
      link.title = 'link to this panel';
      add(h, link);
      if (section.note) add(box, mk('p', 'note', section.note));

      if (section.raw) {
        var pre = add(box, mk('pre', 'raw'));
        pre.textContent = open.subject === null || open.subject === undefined
          ? NOT_REPORTED : JSON.stringify(open.subject, null, 2);
        return;
      }

      var kv = add(box, mk('dl', 'kv'));
      var wrote = 0;
      (section.fields || []).forEach(function (path) {
        var base = baseFor(open, path);
        var rest = base ? path.slice(base[0].length) : path;
        var vals = base && base[1] ? valuesAt(base[1], rest) : [];
        add(kv, mk('dt', 'mono', rest || path));
        var dd = add(kv, mk('dd', ''));
        var shown = vals.map(asString).filter(function (v) { return v !== ''; });
        if (!shown.length) add(dd, absentNode());
        else shown.forEach(function (v, i) {
          if (i) add(dd, document.createElement('br'));
          add(dd, document.createTextNode(v));
        });
        wrote++;
      });
      if (!wrote) {
        // A section with no field table of its own reads the subject it was opened on. Better than an
        // empty panel, and it is the same subject the raw section shows.
        add(kv, mk('dt', 'mono', 'subject'));
        var dd2 = add(kv, mk('dd', ''));
        dd2.appendChild(mk('pre', 'raw', open.subject === null || open.subject === undefined
          ? NOT_REPORTED : JSON.stringify(open.subject, null, 2)));
      }
    });

    host.hidden = false;
    host.focus();

    // A link into one panel opens the drawer *at* that panel rather than at the top of it — otherwise the
    // addressability §22.7 asks for stops at the drawer and the reader still has to hunt.
    if (at) {
      var target = host.querySelector('[data-panel="' + panelOf(open.kind, at) + '"]');
      if (target) {
        target.setAttribute('aria-current', 'true');
        if (target.scrollIntoView) target.scrollIntoView();
      }
    }
  }

  function closeDrawer() {
    OPEN = null;
    el('drawer').hidden = true;
    clear(el('drawer-body'));
    el('drawer-title').textContent = '';
  }

  // ---------------------------------------------------------------------------
  // One render
  // ---------------------------------------------------------------------------

  function render() {
    if (!OV) return;
    ungatedNow = ungatedHosts(OV);
    var view = viewOf(S);

    document.title = 'LabView — ' + view.title;
    el('title').textContent = view.title;
    el('question').textContent = view.question;

    renderChrome();
    renderBanners();
    renderNav();

    // Projected before the filters are drawn: an open-vocabulary control offers the members this payload
    // carried, so it needs the view's rows *before* the filters narrow them.
    var p = project(S, OV);
    renderFilters(p.rows);
    renderChips();

    var rows = sortRows(p.rows.filter(function (r) { return keep(S, r, p.consumed); }));
    renderCount(rows.length, p.rows.length, view);

    var host = clear(el('content'));
    if (view.kind === M.rowStat) {
      renderCards(host, view, rows);
    } else if (view.kind === M.rowDiagram && S.diagram && p.kind !== M.rowEdge) {
      renderDiagram(host, diagramOf(S.diagram));
    } else {
      renderTable(host, view, rows);
    }

    // §22.7: `panel` and `svc` are state, so a reload lands on the same open drawer rather than on the
    // table behind it.
    syncDrawer(rows);
  }

  function syncDrawer(rows) {
    var spot = S.panel ? PANEL[S.panel] : null;
    if (spot) {
      // `svc` picks *which* subject when the view has more than one row of that kind; without it the
      // first is as good an answer as any, and better than refusing to open.
      var want = null;
      rows.forEach(function (r) {
        if (want || !r.open || r.open.kind !== spot.kind) return;
        if (S.svc && r.open.svc && r.open.svc !== S.svc) return;
        want = r.open;
      });
      // A panel whose subject is not a row of the view that links to it — the build stamp is the
      // overview's, and the overview has cards rather than rows with drawers — reads the payload itself.
      // Generic, so a later drawer of that shape needs no case here.
      if (!want) want = { kind: spot.kind, title: '', subject: OV, bases: [['', OV]] };
      openDrawer(want, spot.section);
      return;
    }
    if (S.svc) {
      var found = null;
      rows.forEach(function (r) {
        if (!found && r.open && (r.open.svc === S.svc || r.service === S.svc)) found = r.open;
      });
      if (found) { openDrawer(found, ''); return; }
    }
    if (OPEN) closeDrawer();
  }

  // ---------------------------------------------------------------------------
  // Navigation and events (§22.7)
  // ---------------------------------------------------------------------------

  function go(next, replace) {
    // History gets an entry only when navigation-scale state changed. Typing in the search box moves
    // through a dozen states nobody wants Back to walk, and §22.7 names which parameters count.
    var push = !replace && !sameNav(S, next);
    S = next;
    var url = linkOf(S);
    if (push) window.history.pushState(null, '', url);
    else window.history.replaceState(null, '', url);
    render();
  }

  function closest(node, test) {
    while (node && node !== document) {
      if (test(node)) return node;
      node = node.parentNode;
    }
    return null;
  }

  function attr(node, name) {
    return node && node.getAttribute ? node.getAttribute(name) : null;
  }

  function internal(href) {
    return href === '.' || href.charAt(0) === '?';
  }

  function onActivate(ev) {
    var target = ev.target;

    var copy = closest(target, function (n) { return attr(n, 'data-export') !== null; });
    if (copy) {
      ev.preventDefault();
      var source = attr(copy, 'data-export');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(source).then(function () {
          copy.textContent = 'Copied';
        }, function () {
          copy.textContent = 'Could not copy — the text is in the drawer';
        });
      } else {
        copy.textContent = 'Could not copy — this browser did not offer a clipboard';
      }
      return;
    }

    var chip = closest(target, function (n) { return attr(n, 'data-chip') !== null; });
    if (chip) {
      ev.preventDefault();
      go(parseState(attr(chip, 'data-chip')), false);
      return;
    }

    var tri = closest(target, function (n) { return attr(n, 'data-tri-dim') !== null; });
    if (tri) {
      ev.preventDefault();
      go(cycle(attr(tri, 'data-tri-dim'), attr(tri, 'data-tri-member')), true);
      return;
    }

    var mode = closest(target, function (n) { return attr(n, 'data-mode-dim') !== null; });
    if (mode) {
      ev.preventDefault();
      go(toggleMode(attr(mode, 'data-mode-dim')), true);
      return;
    }

    var tag = closest(target, function (n) { return attr(n, 'data-dim') !== null; });
    if (tag) {
      ev.preventDefault();
      go(cycle(attr(tag, 'data-dim'), attr(tag, 'data-member')), true);
      return;
    }

    var link = closest(target, function (n) { return n.tagName === 'A' && attr(n, 'href') !== null; });
    if (link && internal(attr(link, 'href'))) {
      ev.preventDefault();
      var href = attr(link, 'href');
      go(parseState(href === '.' ? '' : href), false);
      return;
    }
    if (link) return;

    // A node in a drawing opens the service drawer, which is the same drawer its row opens (§22.5).
    var node = closest(target, function (n) { return attr(n, 'data-node') !== null; });
    if (node) {
      ev.preventDefault();
      openNode(attr(node, 'data-node'));
      return;
    }

    var tr = closest(target, function (n) { return n.tagName === 'TR' && attr(n, 'data-open') !== null; });
    if (tr) {
      var id = attr(tr, 'data-open');
      var rows = rowsOf(S, OV);
      var found = null;
      rows.forEach(function (r) { if (!found && r.id === id) found = r.open; });
      if (found) openDrawer(found);
    }
  }

  // openNode maps a graph node back to something with a drawer. A service node has a service row; a
  // network node has a network row; anything else keeps the node itself as the subject, so a hostname or
  // an unmatched record still opens rather than silently doing nothing (I4).
  function openNode(id) {
    var node = null;
    graphNodes(OV).forEach(function (n) { if (n.id === id) node = n; });
    if (!node) return;
    var candidates = [M.rowService, M.rowNetwork, M.rowRoute, M.rowApplication, M.rowRouter];
    for (var i = 0; i < candidates.length; i++) {
      var build = BUILDERS[candidates[i]];
      if (!build) continue;
      var hit = null;
      build(S, OV).forEach(function (r) {
        if (hit || !r.open) return;
        if (r.id === id || M.prefixService + r.service === id || r.label === node.label) hit = r.open;
      });
      if (hit) { openDrawer(withNode(hit, node), ''); return; }
    }
    openDrawer({ kind: M.rowService, title: asString(node.label) || id, subject: node,
      bases: [[PRE.node, node]] }, '');
  }

  // withNode carries the clicked node into the drawer alongside the row it matched.
  //
  // A drawer opened from the drawing has two subjects, and its field table says so: the route drawer's path
  // section reads `graph.nodes.*`, which no route *row* carries — a route row's bases are the service and
  // the Cloudflare or Traefik record. Added rather than substituted, so the row's own record is still there
  // and the same drawer opened from the table is unchanged.
  function withNode(open, node) {
    var out = {};
    Object.keys(open).forEach(function (k) { out[k] = open[k]; });
    out.bases = (open.bases || []).concat([[PRE.node, node]]);
    return out;
  }

  function wire() {
    document.addEventListener('click', onActivate);
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && !el('drawer').hidden) { closeDrawer(); return; }
      if (ev.key !== 'Enter' && ev.key !== ' ') return;
      var t = ev.target;
      if (t && (attr(t, 'data-node') !== null || attr(t, 'data-dim') !== null ||
                (t.tagName === 'TR' && attr(t, 'data-open') !== null))) {
        onActivate(ev);
      }
    });

    el('drawer-close').addEventListener('click', function () {
      closeDrawer();
      // Closing clears the parameters that named the panel, so the URL keeps describing the screen.
      if (S.panel || S.svc) go(withField(withField(S, 'panel', ''), 'svc', ''), false);
    });

    var debounce = null;
    el('q').addEventListener('input', function () {
      if (debounce) window.clearTimeout(debounce);
      debounce = window.setTimeout(function () {
        // Sanitised through the grammar's own reader, so what the box accepts and what a pasted link
        // accepts are the same thing (§22.7).
        go(withField(S, 'q', text(el('q').value)), true);
      }, 120);
    });

    el('rescan').addEventListener('click', function () {
      load(true, el('probe-switch').checked);
    });

    // The switch alone changes nothing: §13.7's setting is request-scoped, so it takes effect on the
    // next scan and the box says which scan it described until then.
    el('probe-switch').addEventListener('change', function () {
      el('probe-switch').title = 'takes effect on the next Rescan';
    });

    window.addEventListener('popstate', function () {
      S = parseState(window.location.search);
      CONTROLS_FOR = null;
      render();
    });
  }

  // ---------------------------------------------------------------------------
  // Boot (§18, §19)
  // ---------------------------------------------------------------------------

  function load(force, probe) {
    if (BUSY) return;
    BUSY = true;
    syncBusy();

    var opts = { method: 'GET', headers: { Accept: 'application/json' } };
    if (force) {
      opts = {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        // §13.7: one known key of one known type. `null` is *use configuration*, which is what an
        // absent opinion means, so the switch is sent as a boolean or not at all.
        body: JSON.stringify({ probe: typeof probe === 'boolean' ? probe : null })
      };
    }

    // Relative, never rooted: §2.2 requires a path-prefixed mount to work.
    window.fetch(force ? 'api/rescan' : 'api/overview', opts)
      .then(function (res) {
        if (res.status === 401 || res.status === 403) return signIn();
        if (!res.ok) {
          return fail('the payload request answered ' + res.status +
            (res.statusText ? ' ' + res.statusText : ''));
        }
        return res.json().then(arrived, function () {
          return fail('the payload arrived but is not JSON. api/overview is the whole of what this ' +
            'page shows, so there is nothing to fall back to.');
        });
      })
      .catch(function (err) {
        fail('the payload request did not complete: ' + ((err && err.message) || String(err)));
      })
      .then(function () { BUSY = false; syncBusy(); });
  }

  function arrived(ov) {
    var before = COUNTS;
    OV = ov;
    COUNTS = countsOf(ov);
    el('app').hidden = false;
    el('boot').hidden = true;
    render();
    renderChange(before, COUNTS);
  }

  // fail keeps whatever is already on screen. A payload that could not be refreshed is a reason to say
  // so, not a reason to replace a good reading with an empty one (I4).
  function fail(message) {
    if (!OV) {
      el('boot').hidden = false;
      el('boot').textContent = 'LabView could not read the payload: ' + message;
      return;
    }
    var b = mk('div', toneClass('banner', TONE_WARN));
    add(b, mk('strong', '', 'Not refreshed'));
    add(b, document.createTextNode(' — ' + message + '. What is shown is the last payload that arrived, ' +
      'scanned ' + (asString(pathOf(OV, 'meta.scannedAt')) || NOT_REPORTED) + '.'));
    el('banners').insertBefore(b, el('banners').firstChild);
  }

  // signIn draws the form §19's passwd method needs, and only the methods the posture actually offers.
  //
  // The posture comes from the public `api/session` route: a login form that was only visible to people
  // who were already past it would be no use to the one reader who needs it.
  function signIn() {
    return window.fetch('api/session', { headers: { Accept: 'application/json' } })
      .then(function (res) { return res.ok ? res.json() : null; })
      .catch(function () { return null; })
      .then(function (info) {
        SESSION = info;
        drawSignIn(info, '');
      });
  }

  function drawSignIn(info, error) {
    var methods = (info && info.methods) || [];
    el('app').hidden = true;
    var boot = clear(el('boot'));
    boot.hidden = false;

    add(boot, mk('h1', '', 'LabView'));
    add(boot, mk('p', '', 'This LabView requires a sign-in before it will answer with a payload.'));
    if (error) add(boot, mk('p', toneClass('banner', TONE_WARN), error));
    ((info && info.notes) || []).forEach(function (note) {
      add(boot, mk('p', 'muted', asString(note)));
    });

    if (methods.indexOf(M.methodOIDC) >= 0) {
      var a = add(boot, mk('a', '', 'Sign in with ' + ((info && info.oidcLabel) || 'your provider')));
      // A full page navigation, not a fetch: the handshake is a redirect to the provider (§18).
      a.setAttribute('href', 'auth/oidc/start');
    }

    if (methods.indexOf(M.methodPasswd) < 0) {
      if (!methods.length) {
        add(boot, mk('p', 'absent', 'The posture reports no usable sign-in method. ' +
          'That is a configuration to fix rather than something this page can work around (§19).'));
      }
      return;
    }

    var form = add(boot, mk('form', 'filters'));
    var user = mk('input', '');
    user.type = 'text';
    user.name = 'username';
    user.autocomplete = 'username';
    user.placeholder = 'Username';
    user.setAttribute('aria-label', 'Username');
    var pass = mk('input', '');
    pass.type = 'password';
    pass.name = 'password';
    pass.autocomplete = 'current-password';
    pass.placeholder = 'Password';
    pass.setAttribute('aria-label', 'Password');
    var submit = mk('button', '', 'Sign in');
    submit.type = 'submit';
    add(form, user);
    add(form, pass);
    add(form, submit);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      submit.disabled = true;
      submit.textContent = 'Signing in…';
      window.fetch('api/login', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user.value, password: pass.value })
      })
        .then(function (res) {
          return res.json().then(function (body) { return { res: res, body: body }; },
            function () { return { res: res, body: {} }; });
        })
        .then(function (out) {
          if (out.res.ok && out.body.ok) {
            // The cookie is set; start over from the boot path so the payload arrives the normal way.
            el('boot').textContent = 'Reading the payload…';
            load(false, null);
            return;
          }
          // §4.7 fixes the codes and the server sends the sentence. It is shown as sent rather than
          // rewritten: *locked out* and *wrong password* are different facts and this page must not
          // flatten them into one.
          var retry = out.res.headers.get('Retry-After');
          var said = asString(out.body.error) ||
            'the attempt was refused and the reason was not reported';
          drawSignIn(SESSION, retry ? said + ' Try again in ' + retry + 's.' : said);
        })
        .catch(function (err) {
          drawSignIn(SESSION, 'the sign-in request did not complete: ' + ((err && err.message) || String(err)));
        });
    });
  }

  function boot() {
    S = parseState(window.location.search);
    wire();
    load(false, null);
  }

  boot();
})();
