// Does the browser bundle actually render?
//
// `go test ./...` cannot answer that. §2.2 keeps the bundle hand-authored and committed under
// internal/webui/dist, §2.1 caps the dependency surface at a YAML parser, bcrypt and JWT verification, and
// the only Go code that mentions internal/webui/dist/assets/app.js is an auth-gate test asserting the
// *path* is gated. So nothing in the repository ever parsed the bundle, let alone ran it — which is how a
// build whose app.js contained a syntax error and no DOM code at all went green through every check and
// shipped a page that said "Reading the payload…" forever.
//
// This is that missing check. It builds a DOM small enough to own (there is no jsdom here and adding one
// would break §2.1), serves a real payload from the edge fixture root, and drives the bundle through the
// entry point a browser uses. Any throw, any view that renders nothing, any card or drawer or diagram that
// breaks, fails the run.
//
//   node .github/scripts/render-smoke.mjs <payload.json>
//
// where payload.json is the output of `LABVIEW_APPS_ROOT=fixtures/edge go run ./cmd/labview scan`.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// LABVIEW_DIST is for checking this check: point it at a copy with a fix backed out and the run must go
// red. A gate nobody has ever seen fail is not known to be a gate.
const ROOT = process.env.LABVIEW_DIST ||
  join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'labview', 'internal', 'webui', 'dist');
const HTML = readFileSync(join(ROOT, 'index.html'), 'utf8');
const CONTRACT_JS = readFileSync(join(ROOT, 'assets', 'contract.js'), 'utf8');
const APP_JS = readFileSync(join(ROOT, 'assets', 'app.js'), 'utf8');

const payloadPath = process.argv[2];
if (!payloadPath) {
  console.error('usage: node render-smoke.mjs <payload.json>');
  process.exit(2);
}
const PAYLOAD = JSON.parse(readFileSync(payloadPath, 'utf8'));

// ---------------------------------------------------------------------------
// A DOM, in as few lines as the bundle can be driven with
//
// Deliberately not a browser: it implements exactly what app.js touches, so a call the real page would make
// and this shim has not got fails loudly here rather than silently passing.
// ---------------------------------------------------------------------------

class Node2 {
  constructor(tag, ns) {
    this.tagName = tag.toUpperCase();
    this.localName = tag;
    this.namespaceURI = ns || null;
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.listeners = new Map();
    this.hidden = false;
    this._text = '';
  }

  get firstChild() { return this.childNodes[0] || null; }
  get children() { return this.childNodes.filter((n) => n instanceof Node2); }

  appendChild(child) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  insertBefore(child, before) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    const at = before ? this.childNodes.indexOf(before) : -1;
    if (at < 0) this.childNodes.push(child);
    else this.childNodes.splice(at, 0, child);
    return child;
  }

  removeChild(child) {
    const at = this.childNodes.indexOf(child);
    if (at >= 0) this.childNodes.splice(at, 1);
    child.parentNode = null;
    return child;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === 'class') this._class = String(value);
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  hasAttribute(name) { return this.attributes.has(name); }

  get className() { return this._class || ''; }
  set className(v) { this._class = String(v); this.attributes.set('class', String(v)); }

  get classList() {
    const self = this;
    return {
      add(...names) {
        const have = self.className.split(/\s+/).filter(Boolean);
        names.forEach((n) => { if (!have.includes(n)) have.push(n); });
        self.className = have.join(' ');
      },
      remove(...names) {
        self.className = self.className.split(/\s+/).filter((n) => n && !names.includes(n)).join(' ');
      },
      contains(name) { return self.className.split(/\s+/).includes(name); },
    };
  }

  get textContent() {
    if (this.tagName === '#TEXT') return this._text;
    return this.childNodes.map((n) => n.textContent).join('');
  }

  set textContent(v) {
    this.childNodes.forEach((n) => { n.parentNode = null; });
    this.childNodes = [];
    if (v !== '' && v !== null && v !== undefined) {
      const t = new Node2('#text');
      t._text = String(v);
      this.appendChild(t);
    }
  }

  addEventListener(kind, fn) {
    if (!this.listeners.has(kind)) this.listeners.set(kind, []);
    this.listeners.get(kind).push(fn);
  }

  dispatch(kind, ev) {
    (this.listeners.get(kind) || []).forEach((fn) => fn(ev));
  }

  focus() { DOC.activeElement = this; }
  scrollIntoView() {}
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }

  // Only the two selector shapes app.js uses: `[attr]` and `[attr="value"]`.
  querySelectorAll(sel) {
    const m = /^\[([-a-z]+)(?:="([^"]*)")?\]$/.exec(sel.trim());
    if (!m) throw new Error('render-smoke: unsupported selector ' + sel);
    const [, name, value] = m;
    const out = [];
    const walk = (n) => {
      if (!(n instanceof Node2)) return;
      if (n.attributes.has(name) && (value === undefined || n.attributes.get(name) === value)) out.push(n);
      n.childNodes.forEach(walk);
    };
    this.childNodes.forEach(walk);
    return out;
  }

  // Everything under this node, for assertions.
  all() {
    const out = [];
    const walk = (n) => { out.push(n); n.childNodes.forEach(walk); };
    this.childNodes.forEach(walk);
    return out;
  }
}

// index.html is the DOM contract, and the *shape* of it matters as much as the ids: the drawer looks for
// its own sections with a selector, so #drawer-body has to actually be inside #drawer. So this parses the
// document into a tree rather than into a bag of ids. It is a tag-stack parser, not an HTML parser — good
// for the hand-written, well-formed document §22.1 describes, and loud if that stops being true.
const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr']);

function parseHTML(html) {
  const body = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<!doctype[^>]*>/i, '');
  const root = new Node2('#document');
  const byID = new Map();
  const stack = [root];
  const re = /<(\/?)([a-zA-Z][-a-zA-Z0-9]*)((?:"[^"]*"|'[^']*'|[^>"'])*?)(\/?)>/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    const [, closing, rawTag, attrs, selfClosed] = m;
    const tag = rawTag.toLowerCase();
    if (closing) {
      // An unbalanced document would silently nest the rest of the page inside the wrong element, so it
      // is an error here rather than a mystery in a later check.
      const top = stack[stack.length - 1];
      if (top.localName !== tag) {
        throw new Error('render-smoke: index.html closes </' + tag + '> inside <' + top.localName + '>');
      }
      stack.pop();
      continue;
    }
    const node = new Node2(tag);
    let a;
    const attrRE = /([-a-zA-Z0-9]+)(?:="([^"]*)")?/g;
    while ((a = attrRE.exec(attrs)) !== null) {
      const [, name, value] = a;
      node.setAttribute(name, value === undefined ? '' : value);
      if (name === 'id') { node.id = value; byID.set(value, node); }
      if (name === 'class') node.className = value;
      if (name === 'hidden') node.hidden = true;
      if (name === 'type') node.type = value;
      if (name === 'value') node.value = value;
      if (name === 'checked') node.checked = true;
    }
    if (node.value === undefined) node.value = '';
    if (tag === 'input' && node.checked === undefined) node.checked = false;
    stack[stack.length - 1].appendChild(node);
    if (!VOID_TAGS.has(tag) && !selfClosed) stack.push(node);
  }
  if (stack.length !== 1) {
    throw new Error('render-smoke: index.html leaves <' + stack[stack.length - 1].localName + '> unclosed');
  }
  return { root, byID };
}

const DOC = {
  activeElement: null,
  title: '',
  root: null,
  byID: new Map(),
  listeners: new Map(),
  getElementById(id) { return DOC.byID.get(id) || null; },
  createElement(tag) { return new Node2(tag); },
  createElementNS(ns, tag) { return new Node2(tag, ns); },
  createTextNode(txt) { const n = new Node2('#text'); n._text = String(txt); return n; },
  addEventListener(kind, fn) {
    if (!DOC.listeners.has(kind)) DOC.listeners.set(kind, []);
    DOC.listeners.get(kind).push(fn);
  },
  dispatch(kind, ev) { (DOC.listeners.get(kind) || []).forEach((fn) => fn(ev)); },
};

// ---------------------------------------------------------------------------
// One run of the bundle
// ---------------------------------------------------------------------------

const flush = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

// run loads the bundle at a URL, exactly the way index.html does, and hands back what it drew.
//
// A fresh document each time and a fresh evaluation of app.js: the module is an IIFE with no exports, so
// the entry point is the only way in — which is the entry point that was broken.
async function run(search, { status = 200, body = PAYLOAD, session = null } = {}) {
  const parsed = parseHTML(HTML);
  DOC.root = parsed.root;
  DOC.byID = parsed.byID;
  DOC.activeElement = null;
  DOC.listeners = new Map();

  const thrown = [];
  const requests = [];
  const history = [];

  const win = {
    location: { search, pathname: '/', href: 'http://labview.test/' + search },
    history: {
      pushState(_a, _b, url) { history.push(['push', url]); },
      replaceState(_a, _b, url) { history.push(['replace', url]); },
    },
    addEventListener(kind, fn) { win.listeners.set(kind, (win.listeners.get(kind) || []).concat(fn)); },
    listeners: new Map(),
    setTimeout, clearTimeout,
    fetch(url, opts) {
      requests.push([url, opts && opts.method ? opts.method : 'GET']);
      if (url === 'api/session') {
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(session || {}) });
      }
      return Promise.resolve({
        ok: status >= 200 && status < 300,
        status,
        statusText: '',
        headers: { get: () => null },
        json: () => Promise.resolve(body),
      });
    },
  };

  const sandbox = {
    window: win,
    document: DOC,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    URLSearchParams,
    JSON, Math, Object, Array, String, Number, Boolean, RegExp, Error, isNaN, parseInt, parseFloat,
    console,
  };

  // The contract is data and app.js reads it off `window`, so both are evaluated in the same sandbox with
  // the same globals a browser would give them.
  const args = Object.keys(sandbox);
  const values = args.map((k) => sandbox[k]);
  try {
    new Function(...args, CONTRACT_JS)(...values);
    new Function(...args, APP_JS)(...values);
  } catch (err) {
    thrown.push(err);
  }
  await flush();

  const id = (name) => DOC.getElementById(name);
  return { thrown, requests, history, id, win, text: (name) => (id(name) ? id(name).textContent : null) };
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

let failures = 0;
let checks = 0;

function check(what, ok, detail) {
  checks++;
  if (ok) return true;
  failures++;
  console.error('FAIL  ' + what + (detail ? '\n      ' + detail : ''));
  return false;
}

function noThrow(what, out) {
  return check(what, out.thrown.length === 0,
    out.thrown.length ? (out.thrown[0].stack || String(out.thrown[0])) : '');
}

const bodyRows = (out) => out.id('content').all()
  .filter((n) => n.tagName === 'TR' && n.parentNode && n.parentNode.tagName === 'TBODY');

// The number the view states it is showing, which is a different fact from the number of rows it drew —
// the two disagreeing is exactly what a reader cannot see for themselves.
const statedCount = (out) => {
  const m = /^(\d+)/.exec(out.text('count') || '');
  return m ? Number(m[1]) : null;
};

const isInteger = (s) => /^-?\d+$/.test(s.trim());

// The node ids §4.2 says have no gate on their path, read straight out of the payload. Deliberately a
// second, independent reading of the same stored finding: the page must not be the only thing that knows.
function ungatedFromPayload() {
  const out = [];
  (PAYLOAD.stacks || []).forEach((stack) => {
    (stack.services || []).forEach((svc) => {
      if (!(svc.auth && svc.auth.exposedWithoutAuth)) return;
      out.push('svc:' + stack.id + '/' + svc.name);
      (svc.cloudflare || []).forEach((r) => { if (r.hostname && !r.access) out.push('host:' + r.hostname); });
      (svc.traefik || []).forEach((r) => (r.hosts || []).forEach((h) => out.push('host:' + h)));
    });
  });
  return Array.from(new Set(out));
}

const cellsOf = (tr) => tr.children;

// The contract, read the same way app.js reads it, so the checks below cover every view, card, panel and
// diagram this build declares rather than a list kept in step by hand.
const C = (() => {
  const w = {};
  new Function('window', CONTRACT_JS)(w);
  return w.LABVIEW_CONTRACT;
})();

console.log('render-smoke: ' + C.views.length + ' views, ' + C.cards.length + ' cards, ' +
  C.diagrams.length + ' diagrams, ' + C.panels.length + ' panels');

// --- 1. The bug that shipped: the page must leave its boot message ---------

{
  const out = await run('');
  noThrow('the bundle runs at the default view', out);
  check('#app is shown once the payload arrives', out.id('app').hidden === false);
  check('#boot is hidden once the payload arrives', out.id('boot').hidden === true,
    'boot still reads: ' + JSON.stringify(out.text('boot')));
  check('api/overview is what it asks for',
    out.requests.length === 1 && out.requests[0][0] === 'api/overview' && out.requests[0][1] === 'GET',
    JSON.stringify(out.requests));
  const cards = out.id('content').all().filter((n) => n.classList.contains('card'));
  check('the overview drew cards', cards.length > 0);
  check('a lead card is present and first', cards.length > 0 && cards[0].classList.contains('lead'),
    cards.length ? 'first card classes: ' + cards[0].className : 'no cards at all');
  check('the navigation lists every view',
    out.id('nav').all().filter((n) => n.tagName === 'A').length === C.views.length);
  check('the build stamp is filled in', (out.text('build') || '').length > 0);
  check('the scan time is stated', (out.text('scanned') || '').includes('scanned'));
  check('the row count is stated', /^\d+/.test(out.text('count') || ''));
  check('the title is the view title', out.text('title') === C.views.find((v) => v.slug === 'overview').title);
}

// --- 2. Every view renders something ---------------------------------------

for (const view of C.views) {
  const out = await run(view.slug === C.grammar.defaultView ? '' : '?view=' + view.slug);
  if (!noThrow('view ' + view.slug + ' renders', out)) continue;
  const content = out.id('content');
  check('view ' + view.slug + ' drew content', content.childNodes.length > 0);
  check('view ' + view.slug + ' states a count', /^\d+/.test(out.text('count') || ''));
  check('view ' + view.slug + ' names its question', (out.text('question') || '').length > 0);

  const empty = content.all().some((n) => n.classList.contains('empty'));
  if (!empty && view.kind !== 'stat' && view.slug !== 'diagrams') {
    // Every column of the view, in the header, once — a table missing a column would otherwise pass by
    // rendering the ones it has.
    const headers = content.all().filter((n) => n.tagName === 'TH').map((n) => n.textContent);
    view.columns.forEach((col) => {
      check('view ' + view.slug + ' has column ' + col.key,
        headers.some((h) => h.startsWith(col.header)), 'headers: ' + JSON.stringify(headers));
    });
    const rows = bodyRows(out);
    check('view ' + view.slug + ' gave every row every cell',
      rows.every((tr) => cellsOf(tr).length === view.columns.length),
      'expected ' + view.columns.length + ' cells per row');
    check('view ' + view.slug + ' row count matches the stated count',
      rows.length === statedCount(out),
      rows.length + ' rows vs count "' + out.text('count') + '"');

    // A number must be rendered as a number. §22.2's numeric columns are right-aligned and that alignment
    // is what makes a column of counts scannable, so a count that resolved as text — which is what happens
    // when the numeric path is bypassed and the field paths answer instead — is a real regression and looks
    // almost right.
    view.columns.forEach((col, j) => {
      const cells = rows.map((tr) => cellsOf(tr)[j]).filter(Boolean);
      if (!col.numeric) return;
      const numbers = cells.filter((td) => isInteger(td.textContent));
      check('view ' + view.slug + ' column ' + col.key + ' renders its numbers as numbers',
        numbers.every((td) => td.classList.contains('num')),
        numbers.length + ' integer cells, ' + numbers.filter((td) => !td.classList.contains('num')).length +
        ' of them not marked numeric');
      if (numbers.length) {
        const th = content.all().filter((n) => n.tagName === 'TH')[j];
        check('view ' + view.slug + ' column ' + col.key + ' has a numeric header',
          th && th.classList.contains('num'));
      }
      // A count the projection records itself — no `fields` to resolve — is always available. Every one of
      // them reading *not reported* means the recorded number never reached the cell.
      if (!col.fields) {
        check('view ' + view.slug + ' column ' + col.key + ' reports its recorded count',
          cells.some((td) => !td.textContent.includes('not reported')),
          'every one of ' + cells.length + ' cells reads as absent');
      }
    });
  }
}

// --- 3. Every card's destination shows what the card counts ----------------
//
// §22.3: a card is a link and its number must be the number of rows at the far end. A card pointing at a
// view that renders nothing is the failure this catches.

// The count each card actually shows, read off the rendered overview and keyed by where it points — so
// this is the number a reader sees, not one recomputed here from the same code under test.
const shownCounts = new Map();
{
  const overview = await run('');
  overview.id('content').all().filter((n) => n.classList.contains('card')).forEach((a) => {
    const n = a.all().find((c) => c.classList.contains('n'));
    shownCounts.set(a.getAttribute('href'), n ? n.textContent : null);
  });
  check('every card is a link with a count', shownCounts.size === C.cards.length,
    shownCounts.size + ' cards rendered, ' + C.cards.length + ' declared');
}

for (const card of C.cards) {
  const out = await run('?' + card.dest);
  if (!noThrow('card ' + card.id + ' destination renders', out)) continue;
  check('card ' + card.id + ' lands on a view that drew something',
    out.id('content').childNodes.length > 0, 'dest: ?' + card.dest);
  check('card ' + card.id + ' lands with its filters shown',
    out.id('chips').hidden === false || card.dest.indexOf('&') < 0,
    'dest ?' + card.dest + ' set filters but showed no chips');

  // §22.3, and the check the whole overview rests on: the number on the card is the number of rows at the
  // far end of the link. A card claiming 35 services over a table showing none is the failure mode this
  // catches — and a row builder that stopped being reached shows up here first, because the count comes
  // from the payload's own statistics and the rows come from the projection.
  const shown = shownCounts.get('?' + card.dest);
  const rows = bodyRows(out).length;
  if (shown === null || shown === undefined) {
    check('card ' + card.id + ' rendered a count', false, 'no count node');
  } else if (shown.includes('not reported')) {
    // An optional counter the payload did not carry. §22.3 requires *not reported* rather than 0, and the
    // destination is then unconstrained.
    check('card ' + card.id + ' is declared optional if it reports nothing', card.optional === true,
      card.id + ' reads as absent but is not marked optional');
  } else if (card.exact) {
    check('card ' + card.id + ' counts exactly what its destination shows',
      Number(shown) === rows, 'card says ' + shown + ', destination drew ' + rows + ' rows (?' + card.dest + ')');
  } else {
    check('card ' + card.id + ' counts no more than its destination shows',
      Number(shown) <= rows, 'card says ' + shown + ', destination drew only ' + rows + ' rows');
  }
}

// --- 4. Diagrams: drawn, capped in words, and deterministic ----------------

for (const d of C.diagrams) {
  const out = await run('?view=diagrams&diagram=' + d.id);
  if (!noThrow('diagram ' + d.id + ' draws', out)) continue;
  const svg = out.id('content').all().find((n) => n.localName === 'svg');
  check('diagram ' + d.id + ' drew an svg', !!svg);
  if (svg) {
    const nodes = svg.all().filter((n) => n.classList.contains('node'));
    const edges = svg.all().filter((n) => n.classList.contains('edge'));
    check('diagram ' + d.id + ' drew nodes', nodes.length > 0);
    check('diagram ' + d.id + ' every node has a kind and a label',
      nodes.every((n) => n.getAttribute('data-kind') !== null &&
        n.all().some((c) => c.localName === 'text' && c.textContent.length > 0)));
    check('diagram ' + d.id + ' every edge is a stroked path',
      edges.every((e) => e.all().some((c) => c.localName === 'path' && c.getAttribute('d'))));

    // The one colour that is reserved: a node with no gate on its path (§22.1). Computed here from the
    // payload's own stored finding rather than by asking the code under test, so the picture agreeing with
    // the exposure count is something this run establishes instead of assumes.
    const drawn = new Set(nodes.map((n) => n.getAttribute('data-node')));
    const expected = ungatedFromPayload().filter((id) => drawn.has(id));
    if (expected.length) {
      const toned = nodes.filter((n) => n.getAttribute('data-tone') === 'alert')
        .map((n) => n.getAttribute('data-node'));
      check('diagram ' + d.id + ' marks every ungated node with the reserved tone',
        expected.every((id) => toned.includes(id)),
        'expected ' + JSON.stringify(expected) + ', marked ' + JSON.stringify(toned));
      check('diagram ' + d.id + ' marks nothing else with it',
        toned.every((id) => expected.includes(id)), JSON.stringify(toned));
    }

    // §22.8: a copied diagram outlives the page it came from, so the export has to carry what the page says
    // in colour — the readings, and every reason the picture is partial.
    const copy = out.id('content').querySelectorAll('[data-export]')[0];
    check('diagram ' + d.id + ' offers a text export', !!copy);
    if (copy) {
      const source = copy.getAttribute('data-export');
      check('diagram ' + d.id + ' export is a Mermaid graph', source.includes('graph LR'));
      check('diagram ' + d.id + ' export names the diagram', source.includes(d.title));
      check('diagram ' + d.id + ' export has a line per drawn edge',
        (source.match(/\n {2}n\d+ [-.]/g) || []).length === edges.length,
        (source.match(/\n {2}n\d+ [-.]/g) || []).length + ' export edges vs ' + edges.length + ' drawn');
    }
    // I7: the same payload draws the same picture. Two runs, byte-identical geometry.
    const again = await run('?view=diagrams&diagram=' + d.id);
    const geom = (o) => o.id('content').all().filter((n) => n.localName === 'path' || n.localName === 'rect')
      .map((n) => n.getAttribute('d') || [n.getAttribute('x'), n.getAttribute('y')].join(',')).join('|');
    check('diagram ' + d.id + ' is deterministic for a payload', geom(out) === geom(again));
  }
  // §22.5: the tabular equivalent, and it is uncapped — which makes it the yardstick for the picture. It
  // is built from the diagram's edges directly rather than from the drawn set, so the two are independent
  // and comparing them is worth something.
  const list = await run('?view=diagrams&diagram=' + d.id + '&panel=edges');
  if (!noThrow('diagram ' + d.id + ' edge list renders', list)) continue;
  const total = bodyRows(list).length;
  check('diagram ' + d.id + ' edge list drew rows or said it was empty',
    total > 0 || list.id('content').all().some((n) => n.classList.contains('empty')));
  if (!svg || !total) continue;

  const drawn = svg.all().filter((n) => n.classList.contains('edge')).length;
  // A diagram whose edge list has entries must draw lines. Nodes with no lines between them is a picture
  // that says the fleet is unconnected, which is a claim, not a rendering detail.
  check('diagram ' + d.id + ' draws lines when it has edges to draw', drawn > 0,
    'edge list has ' + total + ' edges, the drawing has none');
  check('diagram ' + d.id + ' draws no more edges than exist', drawn <= total,
    drawn + ' drawn vs ' + total + ' in the list');

  // §22.5's rule against silent caps: fewer lines than edges is allowed, and saying nothing about it is
  // not. The reason is either a cap or a focus, and both are sentences on the page.
  if (drawn < total) {
    const said = out.id('content').all()
      .some((n) => n.classList.contains('caps') || n.classList.contains('diagram-note'));
    check('diagram ' + d.id + ' states why it is showing ' + drawn + ' of ' + total + ' edges', said);
    const sentences = out.id('content').all()
      .filter((n) => n.classList.contains('caps')).map((n) => n.textContent);
    sentences.forEach((s) => {
      check('diagram ' + d.id + ' cap sentence names both numbers and the node',
        /showing \d+ of \d+ edges of \S/.test(s), JSON.stringify(s));
    });
  }
}

// --- 4b. Forced focus and the per-hub cap (§22.5) -------------------------
//
// The fixture roots are a few dozen services, so no diagram they produce comes near a node threshold or a
// hub cap — which leaves the most spec-heavy half of §22.5 (open focused above the threshold, cap each hub
// and *say so*) never once executed. This is a graph built to cross both lines. Synthetic on purpose: it is
// a graph, not a fleet, and nothing here is a claim about any lab.

{
  const HUB = 'svc:hub/core';
  const LEAVES = 90;                       // over the dependencies cap of 24
  const nodes = [{ id: HUB, label: 'core', kind: 'service', stack: 'hub' }];
  const edges = [];
  for (let i = 0; i < LEAVES; i++) {
    const id = 'svc:leaf/n' + i;
    nodes.push({ id, label: 'n' + i, kind: 'service', stack: 'leaf' });
    edges.push({ id: 'depends_on|' + id + '|' + HUB, source: id, target: HUB,
      kind: 'depends_on', label: 'leafnet', via: ['leafnet'] });
  }
  const big = { meta: { scannedAt: '2026-01-01T00:00:00Z' }, graph: { nodes, edges } };
  const d = C.diagrams.find((x) => x.id === 'dependencies');
  check('the synthetic graph is over the dependencies threshold', nodes.length > d.nodeThreshold);
  check('the synthetic graph is over the dependencies cap', LEAVES > d.cap);

  const out = await run('?view=diagrams&diagram=dependencies', { body: big });
  if (noThrow('a graph over the threshold draws', out)) {
    const said = out.id('content').all().filter((n) => n.classList.contains('caps')).map((n) => n.textContent);
    check('over the threshold it opens focused and says why',
      said.some((s) => s.includes('Opened focused') && s.includes(String(d.nodeThreshold))),
      JSON.stringify(said));
    check('it focuses the busiest hub', said.some((s) => s.includes(HUB)), JSON.stringify(said));
    // The cap sentence, with both numbers and the node it applies to. A cap stated without the total is
    // indistinguishable from *that is all of them*, which is the reading §22.5 forbids.
    const cap = said.find((s) => /showing \d+ of \d+ edges of /.test(s));
    check('the per-hub cap is stated with both numbers and the node', !!cap, JSON.stringify(said));
    if (cap) {
      check('the cap sentence names the cap and the true total',
        cap.includes('showing ' + d.cap + ' of ' + LEAVES + ' edges of ' + HUB), JSON.stringify(cap));
      check('the cap sentence says where the rest is', cap.includes('edge list'), JSON.stringify(cap));
    }
    const svg = out.id('content').all().find((n) => n.localName === 'svg');
    check('the drawing honours the cap',
      svg && svg.all().filter((n) => n.classList.contains('edge')).length <= d.cap,
      svg ? svg.all().filter((n) => n.classList.contains('edge')).length + ' edges drawn' : 'no svg');
  }

  // The escape hatch the sentences promise: the uncapped list really is uncapped.
  const list = await run('?view=diagrams&diagram=dependencies&panel=edges', { body: big });
  if (noThrow('the uncapped edge list renders for a capped diagram', list)) {
    check('the edge list is uncapped', bodyRows(list).length === LEAVES,
      bodyRows(list).length + ' rows for ' + LEAVES + ' edges');
  }

  // Focus is state, so a link to a narrower reading is a link (§22.7).
  const focused = await run('?view=diagrams&diagram=dependencies&focus=' + encodeURIComponent('svc:leaf/n0'),
    { body: big });
  if (noThrow('a focused diagram draws', focused)) {
    const svg = focused.id('content').all().find((n) => n.localName === 'svg');
    check('focusing on a leaf draws its neighbourhood and not the fleet',
      svg && svg.all().filter((n) => n.classList.contains('node')).length < nodes.length,
      svg ? svg.all().filter((n) => n.classList.contains('node')).length + ' of ' + nodes.length : 'no svg');
    check('a focused diagram says what it is focused on and at what depth',
      focused.id('content').all().some((n) => n.textContent.includes('svc:leaf/n0') &&
        n.textContent.includes('depth')));
  }
}

// --- 5. Every drawer panel opens ------------------------------------------

const resolvedBy = new Map();   // drawer kind -> did any panel of it resolve a real value?

for (const panel of C.panels) {
  const kind = C.drawers.find((d) => panel.startsWith(d.kind + ':'));
  if (!kind) continue; // `edges` and `list:warnings` name row sets, not drawers
  const view = C.views.find((v) => v.kind === kind.kind) || C.views.find((v) => v.slug === 'overview');
  const out = await run('?view=' + view.slug + '&panel=' + encodeURIComponent(panel));
  if (!noThrow('panel ' + panel + ' opens', out)) continue;
  check('panel ' + panel + ' opened the drawer', out.id('drawer').hidden === false);
  check('panel ' + panel + ' filled the drawer', out.id('drawer-body').childNodes.length > 0);
  check('panel ' + panel + ' named its subject', (out.text('drawer-title') || '').length > 0);
  check('panel ' + panel + ' is the section scrolled to',
    out.id('drawer').querySelectorAll('[data-panel="' + panel + '"]').length === 1);

  // Every field the section declares gets a row, present or not — §22.4's coverage rule is that the drawer
  // accounts for the payload rather than showing only what happens to be filled in.
  const section = kind.sections.find((s) => panel.endsWith(':' + s.id));
  const box = out.id('drawer').querySelectorAll('[data-panel="' + panel + '"]')[0];
  if (box && section && section.fields) {
    const terms = box.all().filter((n) => n.tagName === 'DT').length;
    check('panel ' + panel + ' accounts for each of its ' + section.fields.length + ' fields',
      terms === section.fields.length, terms + ' rows for ' + section.fields.length + ' fields');
    const values = box.all().filter((n) => n.tagName === 'DD');
    if (values.some((dd) => !dd.textContent.includes('not reported'))) resolvedBy.set(kind.kind, true);
  }
  if (box && section && section.raw) {
    check('panel ' + panel + ' shows the raw record it opened on',
      box.all().some((n) => n.classList.contains('raw') && n.textContent.trim().startsWith('{')),
      'raw section shows: ' + JSON.stringify(box.textContent.slice(0, 80)));
    resolvedBy.set(kind.kind, resolvedBy.get(kind.kind) || false);
  }
}

// A drawer's other documented entry point: clicking a node in a drawing (§22.5). It is not a shortcut to
// the table's drawer — the route drawer's path section reads `graph.nodes.*`, which only this entry point
// can supply — so it is checked on its own.
{
  const out = await run('?view=diagrams&diagram=ingress');
  const nodes = out.id('content').querySelectorAll('[data-node]');
  check('the ingress drawing has nodes to click', nodes.length > 0);
  const host = nodes.find((n) => (n.getAttribute('data-node') || '').startsWith('host:')) || nodes[0];
  if (host) {
    DOC.dispatch('click', { target: host, preventDefault() {} });
    await flush();
    check('clicking a node opens a drawer', out.id('drawer').hidden === false);
    const body = out.id('drawer-body');
    check('a drawer opened from a node names its subject', (out.text('drawer-title') || '').length > 0);
    const resolved = body.all().filter((n) => n.tagName === 'DD')
      .filter((dd) => !dd.textContent.includes('not reported')).length;
    check('a drawer opened from a node resolves the node\'s own fields', resolved > 0,
      'every field read as absent for ' + host.getAttribute('data-node'));
    if (resolved > 0) resolvedBy.set('route', true);
  }
}

// A whole drawer that resolves nothing is the failure a per-panel check cannot see: every panel is present,
// every field is accounted for, and every value reads as absent.
C.drawers.forEach((d) => {
  if (!d.sections.some((s) => s.fields && s.fields.length)) return;
  check('the ' + d.kind + ' drawer resolves values from the payload', resolvedBy.get(d.kind) === true,
    'every field of every section read as absent');
});

// --- 6. Filters and the free-text box -------------------------------------

// How many rows each view has with nothing narrowing it, so the checks below can tell a filter that hid
// something from one that hid nothing.
const unfiltered = new Map();
for (const view of C.views) {
  const out = await run(view.slug === C.grammar.defaultView ? '' : '?view=' + view.slug);
  unfiltered.set(view.slug, bodyRows(out).length);
}

for (const view of C.views.filter((v) => v.dims && v.dims.length)) {
  for (const param of view.dims) {
    const dim = C.dimensions.find((d) => d.param === param);
    check('dimension ' + param + ' is declared', !!dim);
    const set = dim.set ? C.sets.find((s) => s.name === dim.set) : null;
    check('dimension ' + param + ' names a set that exists', !dim.set || !!set);
    // A set-less dimension is an open vocabulary on purpose (container state is the Engine's own status
    // strings, §16), so there is no closed list to draw a member from. `running` is the one member the
    // contract does name for it, and it is the one this build assigns itself.
    const member = set ? set.terms[0].member : 'running';
    const out = await run('?view=' + view.slug + '&' + param + '=' + encodeURIComponent(member));
    if (!noThrow('view ' + view.slug + ' filtered by ' + param + '=' + member, out)) continue;
    check(view.slug + ' shows a chip for ' + param, out.id('chips').hidden === false);

    // §22.6: a table that is hiding rows must say so. Measured against the same view unfiltered, so the
    // check knows whether anything was actually hidden rather than accepting either sentence.
    const whole = unfiltered.get(view.slug);
    const here = bodyRows(out).length;
    if (here < whole) {
      check(view.slug + ' says it is filtered when ' + param + '=' + member + ' hides rows',
        (out.text('count') || '').includes(' of ' + whole + ' '),
        here + ' of ' + whole + ' shown, count reads: ' + JSON.stringify(out.text('count')));
    } else {
      check(view.slug + ' does not claim to be filtered when nothing is hidden',
        !(out.text('count') || '').includes(' of '), JSON.stringify(out.text('count')));
    }
    // The exclusion always wins, and it must not throw on a set whose only member is excluded.
    const away = await run('?view=' + view.slug + '&' + param + '=-' + encodeURIComponent(member));
    noThrow('view ' + view.slug + ' excluding ' + member, away);
  }
}

{
  const out = await run('?q=' + encodeURIComponent('nginx'));
  noThrow('free-text search runs', out);
  check('free-text search shows its chip', out.id('chips').hidden === false);
  const junk = await run('?view=services&q=' + encodeURIComponent('zzz-no-such-service'));
  noThrow('a search matching nothing runs', junk);
  check('a search matching nothing says so, rather than showing an empty table',
    junk.id('content').all().some((n) => n.classList.contains('empty')) ||
    (junk.text('count') || '').startsWith('0 '));
}

// --- 7. Unknown state is a supported state (§16, I4) ----------------------

{
  const out = await run('?view=no-such-view&nonsense=1&depth=abc&panel=no:such');
  noThrow('an unreadable URL still renders', out);
  check('an unreadable URL falls back to a view', out.id('content').childNodes.length > 0);
  check('an unreadable URL leaves the boot message behind', out.id('boot').hidden === true);
}

// --- 8. A degraded payload is degraded, not broken (I4) -------------------

{
  const out = await run('', { body: { meta: {} } });
  noThrow('a payload with nothing but meta renders', out);
  check('an all-but-empty payload still shows the page', out.id('app').hidden === false);
  check('an all-but-empty payload reports absent values rather than zeros',
    out.id('content').all().some((n) => n.textContent.includes('not reported')));
}

{
  const out = await run('', { status: 500 });
  noThrow('a failed payload request is handled', out);
  check('a failed request says so in the boot message', (out.text('boot') || '').includes('500'),
    JSON.stringify(out.text('boot')));
  check('a failed request does not show an empty page', out.id('app').hidden === true);
}

// --- 9. The sign-in form (§19) -------------------------------------------

{
  const out = await run('', {
    status: 401,
    session: { enforced: true, methods: ['passwd', 'oidc'], oidcLabel: 'Authentik', notes: [] },
  });
  noThrow('a 401 draws the sign-in form', out);
  check('401 asks the public session route for the posture',
    out.requests.some((r) => r[0] === 'api/session'), JSON.stringify(out.requests));
  const boot = out.id('boot');
  check('401 offers a password field', boot.all().some((n) => n.tagName === 'INPUT' && n.type === 'password'));
  check('401 offers a username field', boot.all().some((n) => n.tagName === 'INPUT' && n.type === 'text'));
  check('401 offers the provider link',
    boot.all().some((n) => n.tagName === 'A' && n.getAttribute('href') === 'auth/oidc/start'));
  check('401 hides the payload view', out.id('app').hidden === true);

  const only = await run('', { status: 401, session: { enforced: true, methods: ['oidc'], notes: [] } });
  check('a provider-only posture offers no password field',
    !only.id('boot').all().some((n) => n.tagName === 'INPUT' && n.type === 'password'));
  const none = await run('', { status: 401, session: { enforced: true, methods: [], notes: [] } });
  check('a posture with no usable method says that, rather than showing a dead form',
    none.id('boot').textContent.includes('no usable sign-in method'));
}

// --- 10. Rescan (§13.7) --------------------------------------------------

{
  const out = await run('');
  out.id('rescan').dispatch('click', {});
  await flush();
  check('Rescan posts to api/rescan',
    out.requests.some((r) => r[0] === 'api/rescan' && r[1] === 'POST'), JSON.stringify(out.requests));
  check('Rescan is the only thing that scans again', out.requests.length === 2);
}

// ---------------------------------------------------------------------------

console.log((checks - failures) + '/' + checks + ' checks passed');
if (failures) {
  console.error('\nrender-smoke failed: ' + failures + ' of ' + checks + ' checks.');
  process.exit(1);
}
console.log('render-smoke: the bundle renders.');
