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
async function run(search, { status = 200, body = PAYLOAD, session = null, remembered = null } = {}) {
  const parsed = parseHTML(HTML);
  DOC.root = parsed.root;
  DOC.byID = parsed.byID;
  DOC.activeElement = null;
  DOC.listeners = new Map();

  // `documentElement`, because the theme is written on the root element as well as on #app: the colour
  // tokens are bound there, so the boot card and the strip an over-scroll uncovers are the same palette
  // as the shell. Absent here, the guard in app.js would skip that write and nothing would say so.
  DOC.documentElement = parsed.root.childNodes.find((n) => n.localName === 'html') || parsed.root;

  const thrown = [];
  const requests = [];
  const history = [];
  // Seeded, so a run can start from a reader who already chose — which is the only way to check that a
  // remembered preference is applied before the payload arrives rather than after it.
  const store = new Map(Object.keys(remembered || {}).map((k) => [k, String(remembered[k])]));

  const win = {
    location: { search, pathname: '/', href: 'http://labview.test/' + search },
    history: {
      pushState(_a, _b, url) { history.push(['push', url]); },
      replaceState(_a, _b, url) { history.push(['replace', url]); },
    },
    addEventListener(kind, fn) { win.listeners.set(kind, (win.listeners.get(kind) || []).concat(fn)); },
    listeners: new Map(),
    setTimeout, clearTimeout,
    // A store that works, so what runs is the remembering path rather than the catch block beside it.
    // The bundle guards every access because storage can be absent or throwing; a shim with no storage
    // at all would exercise only the guard and would let a broken write ship.
    localStorage: {
      getItem(key) { return store.has(key) ? store.get(key) : null; },
      setItem(key, value) { store.set(key, String(value)); },
      removeItem(key) { store.delete(key); },
    },
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
  return { thrown, requests, history, id, win, store, doc: DOC,
    text: (name) => (id(name) ? id(name).textContent : null) };
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
    const terms = box.all().filter((n) => n.tagName === 'DT');
    check('panel ' + panel + ' accounts for each of its ' + section.fields.length + ' fields',
      terms.length === section.fields.length, terms.length + ' rows for ' + section.fields.length + ' fields');
    const values = box.all().filter((n) => n.tagName === 'DD');
    if (values.some((dd) => !dd.textContent.includes('not reported'))) resolvedBy.set(kind.kind, true);

    // §22.4's readability rule, checked here rather than in section 16 because a panel is already open:
    // it holds for every panel this build declares rather than for a sampled one.
    //
    // A term reads as words, and the path is still on it. `docker.publishedPorts.raw` as a label is the
    // drawer describing the payload to itself, and a label with no path behind it is a rename that loses
    // the one spelling the API answers to — so both halves are one check, since either alone is a
    // regression that reads as a fix. Sentence case is the assertion for the first half: the transform
    // capitalises the leading word or upper-cases it whole, and nothing else in it can produce a dot.
    const raw = terms.filter((dt) => dt.textContent.includes('.') || !/^[A-Z]/.test(dt.textContent));
    check('panel ' + panel + ' names its fields in words rather than in payload paths',
      raw.length === 0, JSON.stringify(raw.map((dt) => dt.textContent).slice(0, 4)));
    const paths = terms.map((dt) => dt.getAttribute('title'));
    check('panel ' + panel + ' keeps the exact path of every field it renames',
      paths.every((p) => section.fields.indexOf(p) >= 0) &&
      new Set(paths).size === section.fields.length,
      JSON.stringify(paths.filter((p) => section.fields.indexOf(p) < 0).slice(0, 4)) +
      ' of ' + JSON.stringify(paths));

    // The other half of the same rule: a run of *not reported* fields MAY be folded away, and the check
    // above is what keeps it in the document. This says the fold holds the absent ones *and only* those —
    // a fold that swallowed a reported value would hide a finding behind a control announcing it hides
    // nothing worth reading. Only asserted where the section has some of each, which is the only case
    // where the two can be told apart.
    const buried = (n) => {
      for (let p = n; p && p !== box; p = p.parentNode) {
        if (p.getAttribute && p.getAttribute('data-foldable') !== null) return true;
      }
      return false;
    };
    const said = values.filter((dd) => !dd.textContent.includes('not reported'));
    const silent = values.filter((dd) => dd.textContent.includes('not reported'));
    if (said.length && silent.length) {
      check('panel ' + panel + ' reads out what it has and folds away only what it does not',
        said.every((dd) => !buried(dd)) && silent.every((dd) => buried(dd)),
        said.filter(buried).length + ' of ' + said.length + ' reported values are behind the fold, ' +
        silent.filter((dd) => !buried(dd)).length + ' of ' + silent.length + ' absent ones in front of it');
    }
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

// --- 9b. An unauthenticated reader gets the sign-in and nothing else (§19) ----
//
// The bug this section exists for: §19 gates the data and not the bundle, so the shell reaches anyone who
// can reach the mount, and `#app` carried `hidden` from the first line of index.html to say so. It did
// nothing. `[hidden] { display: none }` is a *user-agent* rule and `#app { display: grid }` is an author
// one, and origin beats specificity — so an unauthenticated reader got the brand, the search box and a
// Rescan button painted under the sign-in card, offering controls that cannot work.
//
// Nothing in the DOM was wrong, which is why every check above passed over it for as long as it shipped.
// So the rule is asserted as stylesheet *text* (this file executes the bundle with no CSS at all), and it
// is asserted for **both** ids: `#boot` is a centred grid too, so the same trap in the other direction
// would leave the sign-in stage over the payload once one arrived. The swap needs both halves able to hide.

{
  const css = readFileSync(join(ROOT, 'assets', 'labview.css'), 'utf8');
  // Comments stripped first, because the two selectors are discussed in prose a few lines above the rule
  // and a check that a *comment* mentions them would be no check at all.
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const hides = (id) => {
    const at = bare.indexOf(id + '[hidden]');
    if (at < 0) return '';
    const open = bare.indexOf('{', at);
    return open < 0 ? '' : bare.slice(open, bare.indexOf('}', open));
  };
  check('the shell can actually hide, so `hidden` on it means hidden',
    /display:\s*none/.test(hides('#app')), JSON.stringify(hides('#app')));
  check('and so can the sign-in stage, or it would sit over the payload once one arrived',
    /display:\s*none/.test(hides('#boot')), JSON.stringify(hides('#boot')));
}

{
  const out = await run('', {
    status: 401,
    session: { enforced: true, methods: ['oidc'], oidcLabel: 'Authentik', notes: [] },
  });
  noThrow('a provider-only 401 draws the login page', out);
  const boot = out.id('boot');
  const card = boot.all().find((n) => n.classList.contains('boot-card'));

  check('the shell is hidden rather than drawn behind the card', out.id('app').hidden === true);
  check('the sign-in stage is showing', boot.hidden === false);
  check('and says it is a sign-in, so the stylesheet check above has a state to key off',
    boot.getAttribute('data-signin') === 'true');
  check('there is a card', !!card);

  // *Welcome, then the button* — the order asked for. Both are asserted, because a heading with no action
  // is a dead end and an action with no welcome is a naked button on an empty page.
  const heading = (card ? card.all() : []).find((n) => n.tagName === 'H1');
  check('the card opens with a welcome', !!heading && (heading.textContent || '').trim().length > 0,
    JSON.stringify(heading && heading.textContent));
  const sso = (card ? card.all() : []).find((n) => n.getAttribute('href') === 'auth/oidc/start');
  check('the provider button is in the card', !!sso);
  check('and it is the primary action, not one link among several',
    !!sso && sso.classList.contains('primary'), sso ? sso.className : '');
  check('the welcome comes before the button',
    !!heading && !!sso && card.all().indexOf(heading) < card.all().indexOf(sso));

  check('the button names the provider the posture named',
    !!sso && (sso.textContent || '').includes('Authentik'), sso ? sso.textContent : '');

  // Where the reader's hands land. With one way in there is no reason to make them find it. Read here
  // rather than saved for later: the document and its id map are shared between runs and replaced by the
  // next one, so anything asked about a page after another has rendered is asked of the wrong page.
  check('the provider button has focus, since it is the only way in',
    out.doc.activeElement === sso,
    out.doc.activeElement ? out.doc.activeElement.tagName : 'none');
}

// The provider's *name* comes from the posture. A build that hardcoded "Authentik" would read correctly on
// this lab and lie on the next one, and no DOM shape would catch it — so it is checked against a posture
// that names something else, and against one that names nothing.
{
  const other = await run('', {
    status: 401,
    session: { enforced: true, methods: ['oidc'], oidcLabel: 'Keycloak at ops', notes: [] },
  });
  check('a different provider gets its own name rather than this one',
    (other.id('boot').textContent || '').includes('Keycloak at ops'),
    JSON.stringify(other.id('boot').textContent));
}

{
  const unnamed = await run('', { status: 401, session: { enforced: true, methods: ['oidc'], notes: [] } });
  check('a posture that names no provider still offers the button',
    unnamed.id('boot').all().some((n) => n.getAttribute('href') === 'auth/oidc/start'));
}

{
  const both = await run('', {
    status: 401,
    session: { enforced: true, methods: ['passwd', 'oidc'], oidcLabel: 'Authentik', notes: [] },
  });
  const bootBoth = both.id('boot');
  check('with two ways in, focus is still on the primary one',
    !!both.doc.activeElement && both.doc.activeElement.getAttribute('href') === 'auth/oidc/start');
  check('and the second way in is separated from the first rather than stacked on it',
    bootBoth.all().some((n) => n.classList.contains('boot-or')));

  // The card holds a heading and a form. #boot was a <p>, which may contain neither — it only ever worked
  // because DOM insertion has no parser to object, and it would have broken the moment anything rendered
  // this markup rather than building it.
  const inP = (n) => { for (let p = n.parentNode; p; p = p.parentNode) if (p.tagName === 'P') return true; return false; };
  check('no part of the card is nested inside a paragraph',
    !bootBoth.all().some((n) => (n.tagName === 'FORM' || n.tagName === 'H1') && inP(n)));
}

{
  const pw = await run('', { status: 401, session: { enforced: true, methods: ['passwd'], notes: [] } });
  check('focus is on the username field when the form is the only way in',
    !!pw.doc.activeElement && pw.doc.activeElement.tagName === 'INPUT' && pw.doc.activeElement.type === 'text',
    pw.doc.activeElement ? pw.doc.activeElement.tagName + '/' + pw.doc.activeElement.type : 'none');
  check('a form-only posture draws no provider button',
    !pw.id('boot').all().some((n) => n.getAttribute('href') === 'auth/oidc/start'));
}

// The posture's warnings are still on the page, and under the actions rather than between the welcome
// and the button (§22.8: a reported fact is not dropped for being inconvenient).
{
  const noted = await run('', {
    status: 401,
    session: {
      enforced: true, methods: ['oidc'], oidcLabel: 'Authentik',
      notes: ['Password sign-in is enabled but its file could not be read, so it is not available.'],
    },
  });
  const nBoot = noted.id('boot');
  check('a posture warning is shown rather than swallowed',
    (nBoot.textContent || '').includes('could not be read'));
  const nAll = nBoot.all();
  const nSSO = nAll.find((n) => n.getAttribute('href') === 'auth/oidc/start');
  const nNote = nAll.find((n) => (n.textContent || '').includes('could not be read') && n.tagName === 'P');
  check('and after the action, not between the welcome and it',
    !!nSSO && !!nNote && nAll.indexOf(nSSO) < nAll.indexOf(nNote));
}

// A failed handshake reports itself as a 302 to `/?login_error=<code>` and in no other way (access/oidc.go),
// so a browser that does not read that parameter says nothing at all about it — the reader is returned to a
// login page that looks exactly like the one they just came from. The sentence is the contract's: §4.7 fixes
// eight codes and the vocabulary carries a label for each, and §4.7 also says a code outside the set is
// rejected rather than displayed.
{
  const set = C.sets.find((s) => s.name === 'loginFailureReason');
  check('the contract carries a sentence per login failure code', !!set && set.terms.length > 0);
  const param = (C.names.find((n) => n.name === 'paramLoginError') || {}).value;
  check('and the parameter that carries the code', !!param, JSON.stringify(param));

  for (const term of (set ? set.terms : [])) {
    const out = await run('?' + param + '=' + encodeURIComponent(term.member), {
      status: 401,
      session: { enforced: true, methods: ['oidc'], oidcLabel: 'Authentik', notes: [] },
    });
    noThrow('a redirect carrying ' + term.member + ' draws the login page', out);
    check('a failed handshake says why: ' + term.member,
      (out.id('boot').textContent || '').includes(term.label),
      JSON.stringify(out.id('boot').textContent));
  }

  // Rejected rather than displayed. The code lands in the URL, so it is reader-supplied text — a build that
  // printed it back would be putting an attacker's string in its own banner.
  const bogus = await run('?' + param + '=<script>alert(1)</script>', {
    status: 401,
    session: { enforced: true, methods: ['oidc'], oidcLabel: 'Authentik', notes: [] },
  });
  noThrow('a code outside the closed set does not break the page', bogus);
  check('a code outside the closed set is rejected rather than displayed (§4.7)',
    !(bogus.id('boot').textContent || '').includes('alert(1)'),
    JSON.stringify(bogus.id('boot').textContent));
  check('and the page still offers the way in',
    bogus.id('boot').all().some((n) => n.getAttribute('href') === 'auth/oidc/start'));

  const stale = await run('?' + param + '=oidc-state', {
    status: 401,
    session: { enforced: true, methods: ['passwd'], notes: [] },
  });
  const staleBoot = stale.id('boot');
  const first = (set.terms.find((t) => t.member === 'oidc-state') || {}).label || '';
  check('the handshake error is shown on arrival', (staleBoot.textContent || '').includes(first));
  const form = staleBoot.all().find((n) => n.tagName === 'FORM');
  check('a login page reached with a stale error still has a working form', !!form);
  if (form) {
    form.dispatch('submit', { target: form, preventDefault() {} });
    await flush();
    const said = staleBoot.textContent || '';
    check('a refused attempt replaces the handshake error rather than stacking under it',
      !said.includes(first), JSON.stringify(said));
    check('and the refusal is what is shown instead', said.includes('refused'), JSON.stringify(said));
  }
}

// --- 9c. A session that ends while the page is open (§19) ----------------
//
// The two rules below are only reachable on a page that already has a payload, which is why neither was
// covered by anything above: `#app` carries `hidden` from index.html, so on a first-load 401 it is hidden
// whether or not the sign-in path says so, and the handshake code in the URL is only read once, so no
// first load can show it twice. Both are about the *second* refusal — a session that expired an hour into
// a reading — and both fail silently, in the way the original bug did: the page keeps drawing.
//
// The transport is swapped rather than parameterised, because what is being modelled is a server whose
// answer changed between two requests, and that is not a property of the run.
const expire = (session) => (url) => {
  if (url === 'api/session') {
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(session) });
  }
  return Promise.resolve({
    ok: false, status: 401, statusText: '', headers: { get: () => null },
    json: () => Promise.resolve({}),
  });
};

{
  const out = await run('');
  noThrow('a payload arrives before the session ends', out);
  check('the shell is showing to begin with', out.id('app').hidden === false);

  out.win.fetch = expire({ enforced: true, methods: ['oidc'], oidcLabel: 'Authentik', notes: [] });
  out.id('rescan').dispatch('click', {});
  await flush();

  const boot = out.id('boot');
  check('a refused rescan draws the sign-in', boot.hidden === false &&
    boot.all().some((n) => n.getAttribute('href') === 'auth/oidc/start'));
  // The rule this traps: the sign-in *takes the shell away*. Without it the reader is left looking at the
  // fleet they can no longer read, with a login card over the top of it.
  check('and takes the shell away rather than sitting over it', out.id('app').hidden === true);
}

{
  // A stale code in the URL, and a load that succeeded. Whatever the code described, the reader got past
  // it — so when the session later ends, the page must report the expiry and not revive that.
  const key = (C.names.find((n) => n.name === 'paramLoginError') || {}).value;
  const codes = C.sets.find((s) => s.name === 'loginFailureReason');
  const said = ((codes ? codes.terms : []).find((t) => t.member === 'oidc-state') || {}).label || '';
  const out = await run('?' + key + '=oidc-state');
  noThrow('a stale handshake code does not disturb a payload that arrived', out);
  check('a stale code is not shown over a payload that arrived',
    !(out.id('content').textContent || '').includes(said));

  out.win.fetch = expire({ enforced: true, methods: ['oidc'], oidcLabel: 'Authentik', notes: [] });
  out.id('rescan').dispatch('click', {});
  await flush();

  const boot = out.id('boot');
  check('the expiry draws the sign-in', boot.hidden === false);
  check('and reports the expiry rather than reviving a handshake the reader recovered from',
    !(boot.textContent || '').includes(said), JSON.stringify(boot.textContent));
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

// --- 11. Collecting a report view ----------------------------------------
//
// A report view offers one control that turns the view into something a reader can take elsewhere. The
// interesting failure is not that the button is missing — it is that the button is there and the text it
// produces is thinner than the table, which nobody notices until they need it. So the checks below measure
// the text against the view's own declaration: every column header, every declared context path, every row
// shown, and the received object per row.

const NAME = (n) => {
  const found = C.names.find((x) => x.name === n);
  if (!found) throw new Error('the contract has no name ' + n);
  return found.value;
};

const REPORT_VIEWS = C.views.filter((v) => v.kind === NAME('rowReport'));
check('the contract declares at least one report view', REPORT_VIEWS.length > 0);

// One function, run below over the scanned payload and then over a synthetic one, because every expectation
// here is read out of the payload under test rather than written down: what a report view owes its reader is
// *its own* rows in full. Two payloads because the scanned one cannot be relied on to contain the deepest
// case — see 11b.
async function checkCollect(view, PAY, tag) {
  const at = ' (' + tag + ')';

  // Where this view's rows come from, taken from its own columns rather than named here. A report view
  // declares the payload path of every cell it draws, so the row source is one segment above the first of
  // them, and the nested paths below fall out of the same declaration.
  const rowPath = ((view.columns[0].fields || [])[0] || '').split('.').slice(0, -1).join('.');
  const source = rowPath ? rowPath.split('.').reduce((o, k) => (o == null ? o : o[k]), PAY) : null;
  if (!check('the ' + view.slug + ' rows come from ' + rowPath + ', which is a list' + at,
    Array.isArray(source))) return;

  const out = await run('?view=' + view.slug, { body: PAY });
  noThrow('the ' + view.slug + ' view runs' + at, out);

  const button = out.id('content').querySelectorAll('[data-collect]')[0];
  if (!check('the ' + view.slug + ' view offers a collect control' + at, !!button)) return;

  // A disclosure, not a wall: the block must not already be on the page.
  check('the collected text is not drawn until it is asked for' + at,
    out.id('content').querySelectorAll('[data-collected]').length === 0);

  // It must sit above the table, or on a view whose table is a bounded scroll region the reader clicks and
  // sees nothing happen.
  const contentKids = out.id('content').children;
  const barAt = contentKids.findIndex((n) => n.all().includes(button));
  const tableAt = contentKids.findIndex((n) => n.all().some((x) => x.tagName === 'TABLE'));
  check('the collect control is above the table' + at, barAt >= 0 && tableAt >= 0 && barAt < tableAt,
    'bar at ' + barAt + ', table at ' + tableAt);

  // Through the document, because app.js delegates: one listener, and the handler reads the target's
  // attributes. Dispatching on the node itself would find no listener and silently prove nothing.
  DOC.dispatch('click', { target: button, preventDefault() {} });
  await flush();

  const box = out.id('content').querySelectorAll('[data-collected]')[0];
  if (!check('clicking collect discloses the text' + at, !!box)) return;
  const text = box.textContent;
  check('the collected text is not empty' + at, text.length > 0);

  // Clicking again is a thing readers do when a click produced a lot of text and they are not sure it
  // registered. It must not stack a second copy underneath the first.
  DOC.dispatch('click', { target: button, preventDefault() {} });
  await flush();
  check('collecting twice leaves one block, not two' + at,
    out.id('content').querySelectorAll('[data-collected]').length === 1);

  // Against the view's declaration, not against a list kept here by hand.
  view.columns.forEach((col) => {
    check('the collected text names the ' + view.slug + ' column ' + JSON.stringify(col.header) + at,
      text.includes(col.header));
  });
  (view.fields || []).forEach((path) => {
    check('the collected text accounts for the declared context ' + path + at, text.includes(path));
  });

  // Every row on screen, and the object each one came from. The received object is the half the cells
  // cannot give: a cell shows what this build knew how to read.
  const rows = bodyRows(out);
  check('the ' + view.slug + ' view drew rows to collect' + at, rows.length > 0);
  check('the collected text says how many ' + view.rowNoun + 's it holds' + at,
    new RegExp('\\b' + rows.length + ' ' + view.rowNoun).test(text), text.slice(0, 200));
  rows.forEach((tr) => {
    const label = (cellsOf(tr)[0] || { textContent: '' }).textContent.trim();
    if (!label) return;
    check('the collected text includes the row ' + JSON.stringify(label) + at, text.includes(label));
  });
  // Not just that the marker is there — that what follows it parses back into the object it came from.
  // Counting markers passes a build that truncates each block the way a table cell is truncated, and the
  // whole point of the received half is that it is the one thing here that is never abridged.
  // `bare` is the same text with the received blocks lifted out, so a claim can be made about the readable
  // half on its own. Without it, every value in the payload is trivially "present" in the text — the JSON
  // dump contains all of them — and a check reading the whole text cannot tell a cell that shows its value
  // from a cell that dropped it.
  const received = [];
  const bare = [];
  {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim() !== 'as received:') { bare.push(lines[i]); continue; }
      const buf = [];
      let j = i + 1;
      for (; j < lines.length && lines[j].startsWith('    '); j++) buf.push(lines[j].slice(4));
      received.push(buf.join('\n'));
      i = j - 1;
    }
  }
  const bareText = bare.join('\n');
  // The marks, read off the table and looked for in the file. §22.1 makes the mark and not the colour carry
  // the distinction, and a collected file has no colour at all — so the mark is the *only* thing separating
  // a failed phase from a setting once the text leaves the page. Read from the rendered tags rather than
  // from the tone table, because what has to agree is the screen and the file.
  {
    const want = new Set();
    rows.forEach((tr) => tr.all()
      .filter((n) => (n.className || '').split(/\s+/).includes('tag'))
      .forEach((tag) => {
        const mark = tag.children.find((c) => (c.className || '') === 'mark');
        if (!mark || !mark.textContent) return;
        want.add(mark.textContent + ' ' + tag.textContent.slice(mark.textContent.length));
      }));
    const missing = Array.from(want).filter((w) => !bareText.includes(w));
    check('the marked terms reach the file with their marks, which is all a file has' + at,
      want.size > 0 && missing.length === 0,
      want.size ? 'missing: ' + missing.join(' | ') : 'the table drew no marked term to check');
  }

  check('the collected text carries each row as it was received' + at, received.length === rows.length,
    'found ' + received.length + ' received blocks for ' + rows.length + ' rows');
  const parsedRaw = received.map((t) => {
    try { return JSON.stringify(JSON.parse(t)); } catch (e) { return null; }
  });
  check('each received block is still valid JSON' + at, parsedRaw.every(Boolean),
    'a block did not parse — truncated?');
  const wantRaw = source.map((c) => JSON.stringify(c));
  check('each received block is the whole object that arrived, not a summary of it' + at,
    parsedRaw.filter(Boolean).every((r) => wantRaw.includes(r)),
    'a received block did not match any ' + view.rowNoun + ' in the payload');

  // The deepest evidence in the payload, which is the whole reason to collect rather than read: a rejected
  // candidate is nested a level below anything a cell shows in full. The nested paths come from the columns'
  // own declaration, so a column that grows a field grows this check with it — and the check runs against
  // every value at those paths, not only the endpoint, because "the candidate and why" is the whole point.
  //
  // Read against `bare`, so what is being claimed is that the *readable* half carries them. The received
  // JSON below each row holds every value by construction, so asserting against the whole text would pass a
  // build whose cells silently show one candidate of five and leave the rest to a reader willing to parse.
  const nestedPaths = view.columns.flatMap((col) => col.fields || [])
    .filter((f) => f.startsWith(rowPath + '.'))
    .map((f) => f.slice(rowPath.length + 1).split('.'))
    .filter((parts) => parts.length > 1);
  const nested = source.flatMap((row) => nestedPaths.flatMap((parts) => {
    const list = row[parts[0]];
    return Array.isArray(list) ? list.map((x) => (x || {})[parts[1]]) : [];
  })).filter((v) => typeof v === 'string' && v !== '');
  // Guarded, not asserted: the scanned payload records rejected candidates only when something was actually
  // rejected, which depends on the runner's network. 11b is the payload that makes this run every time.
  if (nested.length) {
    check('the collected report shows every rejected candidate, not only the JSON does' + at,
      nested.every((e) => bareText.includes(e)),
      'missing: ' + nested.filter((e) => !bareText.includes(e)).join(' | '));
  }

  // Both ways out of the page, because clipboard is a secure-context API and this listener is often plain
  // HTTP — the deployment most likely to have a connection worth collecting is the one where Copy fails.
  const copy = out.id('content').querySelectorAll('[data-export]')
    .find((n) => n.getAttribute('data-export') === text);
  check('the collected text is offered to the clipboard verbatim' + at, !!copy);
  const down = out.id('content').all()
    .find((n) => n.tagName === 'A' && n.getAttribute('download'));
  if (check('the collected text is offered as a download' + at, !!down)) {
    check('the download names a plain-text file' + at,
      /^labview-.*\.txt$/.test(down.getAttribute('download')), down.getAttribute('download'));
    check('the download carries the text itself' + at,
      decodeURIComponent((down.getAttribute('href') || '').replace(/^data:[^,]*,/, '')) === text);
    // I7: one payload, one filename. A clock reading here would make two collections of one scan
    // disagree, and the file is named after the scan precisely so it can be filed against it.
    check('the download is named after the scan rather than the clock' + at,
      down.getAttribute('download').includes(
        String(PAY.meta.scannedAt || '').replace(/[^0-9A-Za-z]/g, '-')),
      down.getAttribute('download'));
  }

  // Deterministic for a payload (I7), the same property the diagram export has and for the same reason.
  const again = await run('?view=' + view.slug, { body: PAY });
  const b2 = again.id('content').querySelectorAll('[data-collect]')[0];
  DOC.dispatch('click', { target: b2, preventDefault() {} });
  await flush();
  check('collecting twice from one payload produces one text' + at,
    again.id('content').querySelectorAll('[data-collected]')[0].textContent === text);

  // Filters narrow the collection, because the count above the table says what was left out and a reader
  // collecting one failing target is a normal thing to want. Measured against the rows the filtered view
  // actually drew — a length comparison would also pass a build that collected a different wrong set, and
  // an `if the control is there` guard would pass a build where collecting threw.
  const firstLabel = (cellsOf(rows[0])[0] || { textContent: '' }).textContent.trim();
  const narrowed = await run('?view=' + view.slug + '&q=' + encodeURIComponent(firstLabel), { body: PAY });
  const narrowedRows = bodyRows(narrowed);
  const b3 = narrowed.id('content').querySelectorAll('[data-collect]')[0];
  check('a filtered report still offers the control' + at, !!b3);
  if (b3) {
    DOC.dispatch('click', { target: b3, preventDefault() {} });
    await flush();
    const t3 = narrowed.id('content').querySelectorAll('[data-collected]')[0];
    if (check('a filtered report collects without throwing' + at, !!t3)) {
      check('a filtered report collects only the rows on screen' + at,
        new RegExp('\\b' + narrowedRows.length + ' ' + view.rowNoun).test(t3.textContent),
        'drew ' + narrowedRows.length + ' rows; the text says: ' +
          (/^.*$/m.exec(t3.textContent.split('\n')[3] || '') || [''])[0]);
      check('narrowing the view narrowed the collection' + at,
        narrowedRows.length < rows.length && narrowedRows.length > 0,
        'filtering on ' + JSON.stringify(firstLabel) + ' left ' + narrowedRows.length + ' of ' + rows.length);
    }
  }
}

for (const view of REPORT_VIEWS) await checkCollect(view, PAYLOAD, 'scanned');

// --- 11b. A report with rejected candidates in it -------------------------
//
// The scanned payload above cannot be relied on for the case that matters most. CI runs the scan with every
// outbound transport switched off (see .github/workflows/docker-image.yml), which is what makes it hermetic —
// and a transport that was never attempted rejects no candidates, so `attempts` is empty on all four reports
// and the deepest check in the function above is *skipped* in exactly the run that gates the image. Locally,
// with the transports on, it runs; the gate is the one place it must.
//
// So: a payload built to contain the shape. Synthetic on purpose, and in the same sense as the graph in 4b —
// these are reports, not a lab, the hosts are `.invalid` per RFC 6761, and nothing here describes any
// deployment. What it does describe is the failure worth collecting: one target that answered with something
// that was not the API, one that resolved nothing across several candidates, one partial read, one setting.
//
// It is also the case a reader hits the button for. A rejected candidate carries the address, what made it a
// candidate, how far it got and why it stopped — four facts a level below anything a table cell shows in
// full, which is why the collected text and not the view is where they have to survive.

{
  const DEEP = 'the response body was HTML beginning "<!doctype html>", ' +
    'which is a web page and not the API this asks for — 512 bytes read, no JSON token in any of them';

  const SYNTH = {
    meta: {
      scannedAt: '2026-01-01T00:00:00Z',
      appsRoot: '/synthetic',
      durationMs: 1,
      warnings: ['one synthetic warning, so the declared context has something to carry'],
      build: { version: '0.0.0-synthetic', commit: '0000000', source: 'synthetic' },
      dockerAvailable: false,
      dockerError: 'the container list did not parse (not-json)',
      connections: [
        {
          target: 'docker',
          ok: false,
          phase: 'decode',
          endpoint: 'tcp://synthetic-proxy.invalid:2375',
          source: 'config',
          detail: 'the container list did not parse (not-json)',
          code: '200',
          hint: 'something answered on that path that is not the Engine — check LABVIEW_DOCKER_HOST',
          attempts: [
            {
              endpoint: 'tcp://synthetic-proxy.invalid:2375',
              why: 'LABVIEW_DOCKER_HOST names it',
              phase: 'decode',
              code: '200',
              detail: DEEP,
            },
          ],
        },
        {
          target: 'authentik',
          ok: false,
          phase: 'resolve',
          source: 'discovered',
          detail: '2 discovered addresses answered, and none of them is the API',
          hint: 'the name did not resolve — see the detail beside this line',
          attempts: [
            {
              endpoint: 'http://identity-server.invalid:9000',
              why: 'a scanned service publishes that port',
              phase: 'resolve',
              detail: 'the name did not resolve',
            },
            {
              endpoint: 'https://sso.synthetic.invalid',
              why: 'a scanned route claims that hostname',
              phase: 'tls',
              code: '526',
              detail: 'the certificate did not verify against the system roots',
            },
          ],
        },
        {
          target: 'traefik',
          ok: true,
          phase: 'partial',
          endpoint: 'http://router-api.invalid:8080',
          source: 'discovered',
          detail: 'the entrypoint list was refused',
          code: '403',
          hint: 'the API is answering unauthenticated for some paths and not others',
          read: 'routers and services; not entrypoints',
          attempts: [],
        },
        {
          target: 'probe',
          ok: false,
          phase: 'disabled',
          hint: 'set LABVIEW_PROBE_ENABLED=true if you want this read',
          attempts: [],
        },
      ],
    },
    stacks: [],
    services: [],
    graph: { nodes: [], edges: [] },
  };

  // Preconditions, asserted here rather than assumed: this payload is only worth running if it actually
  // contains the shape the checks above go looking for. Every leaf the column declares must be populated on
  // some attempt, so a column that grows a field fails here until this payload grows with it.
  const DIAG = REPORT_VIEWS.find((v) => (v.columns[0].fields || [])[0] === 'meta.connections.target');
  if (check('the contract still has a connection report view to feed', !!DIAG)) {
    const attempts = SYNTH.meta.connections.flatMap((c) => c.attempts || []);
    check('the synthetic payload records rejected candidates', attempts.length > 1);
    const leaves = DIAG.columns.flatMap((col) => col.fields || [])
      .filter((f) => f.startsWith('meta.connections.attempts.'))
      .map((f) => f.slice('meta.connections.attempts.'.length));
    check('the column declares nested fields to exercise', leaves.length > 0);
    leaves.forEach((leaf) => {
      check('the synthetic payload populates attempts.' + leaf,
        attempts.some((a) => typeof a[leaf] === 'string' && a[leaf] !== ''));
    });
    // The one fact a truncating build gets wrong and a counting check cannot see.
    check('one rejected candidate carries more detail than a cell would show', DEEP.length > 120);

    await checkCollect(DIAG, SYNTH, 'synthetic');
  }
}

// --- 12. The shell: the rail, the scope card and the two preferences ------
//
// The shell is markup this file's other sections do not look at, and all of it is load-bearing in a way
// the eye catches late: a navigation entry that lost its label reads as a mystery glyph, a rail that
// remembers nothing reads as a switch that does not work, and a theme written on `#app` alone leaves the
// boot card in the other palette. None of that throws, so none of it would fail anything without this.

{
  const out = await run('');
  noThrow('the shell renders', out);

  const links = out.id('nav').all().filter((n) => n.tagName === 'A');
  check('every navigation entry draws a glyph',
    links.length > 0 && links.every((a) => a.all().some((n) => n.localName === 'svg' && n.childNodes.length > 0)),
    links.filter((a) => !a.all().some((n) => n.localName === 'svg')).length + ' entries drew none');
  // The glyph table is keyed by the icon token the *contract* carries, and a token the table does not
  // know draws a dot instead of nothing — so a misspelt token still yields fourteen entries with
  // fourteen glyphs and the check above stays green. The fallback is the only visible symptom, which
  // makes looking for the fallback the check.
  const DOT_D = 'M12 9a3 3 0 1 0 0 6 3 3 0 1 0 0-6z';
  const fellBack = links.filter((a) =>
    a.all().some((n) => n.localName === 'path' && n.getAttribute('d') === DOT_D));
  check('every icon token the contract carries has a glyph of its own', fellBack.length === 0,
    fellBack.length + ' of ' + links.length + ' entries fell back to the dot');

  // The glyph is a picture and the title is the name. A rail that collapses to icons is only usable
  // because the name is still in the document, so the label is checked as text rather than as a class.
  const labels = links.map((a) => {
    const span = a.all().find((n) => n.classList.contains('navlabel'));
    return span ? span.textContent : '';
  });
  check('every navigation entry keeps the view title as text',
    labels.length === C.views.length && labels.every((t) => C.views.some((v) => v.title === t)),
    JSON.stringify(labels.filter((t) => !C.views.some((v) => v.title === t))));

  const defaultView = C.views.find((v) => v.slug === C.grammar.defaultView);
  check('the hero names the group the view belongs to', out.text('eyebrow') === defaultView.group,
    JSON.stringify(out.text('eyebrow')) + ' vs ' + JSON.stringify(defaultView.group));

  // §22.1's coverage map claims `meta.appsRoot`, and before the rail had a scope card nothing drew it.
  const root = (PAYLOAD.meta || {}).appsRoot;
  check('the rail names the tree that was scanned',
    out.text('scope-detail') === (root || 'not reported'),
    JSON.stringify(out.text('scope-detail')) + ' vs ' + JSON.stringify(root));

  // A statistic is read out in the order it is written, which is why the label is the first child: a
  // reader who hears the number first has to hold a bare integer until the next word arrives.
  const card = out.id('content').all().find((n) => n.classList.contains('card'));
  const order = (card ? card.children : []).map((n) => (n.className || '').split(/\s+/)[0]);
  check('a statistic reads its label before its number', order[0] === 'l' && order[1] === 'n',
    order.join(' → '));

  const app = out.id('app');
  check('the theme follows the system preference until the reader says otherwise',
    app.getAttribute('data-theme') === 'system');

  out.id('theme-toggle').dispatch('click', {});
  check('the theme switch moves off the system preference', app.getAttribute('data-theme') === 'light',
    JSON.stringify(app.getAttribute('data-theme')));
  check('the theme is written on the root element too, where the colour tokens are bound',
    out.doc.documentElement.getAttribute('data-theme') === 'light',
    JSON.stringify(out.doc.documentElement.getAttribute('data-theme')));
  check('the theme switch says which of the three states it is in',
    (out.text('theme-label') || '').toLowerCase().includes('light'),
    JSON.stringify(out.text('theme-label')));
  check('the chosen theme is remembered', out.store.get('labview.theme') === 'light',
    JSON.stringify(out.store.get('labview.theme')));

  out.id('theme-toggle').dispatch('click', {});
  check('the switch cycles through the pinned dark state', app.getAttribute('data-theme') === 'dark');
  out.id('theme-toggle').dispatch('click', {});
  check('the switch cycles back to following the system', app.getAttribute('data-theme') === 'system');

  out.id('side-toggle').dispatch('click', {});
  check('the rail collapses', app.getAttribute('data-side') === 'collapsed');
  check('the rail toggle reports whether it is expanded',
    out.id('side-toggle').getAttribute('aria-expanded') === 'false');
  check('a collapsed rail keeps every label in the document, for anyone not reading the glyphs',
    links.every((a) => (a.textContent || '').length > 0));
  check('the collapsed rail is remembered', out.store.get('labview.side') === 'collapsed');
}

// The drawer takes focus when it opens, which is only operable if closing gives it back. Nothing about a
// lost focus throws or draws differently — the reader is simply returned to the top of the document and
// has to walk the rail and the topbar again to get back to the row they were reading.
{
  const out = await run('view=services');
  noThrow('a table view renders', out);

  const row = out.id('content').all().find((n) => n.tagName === 'TR' && n.getAttribute('data-open') !== null);
  check('a row offers itself to the keyboard', row && row.getAttribute('tabindex') === '0',
    row ? JSON.stringify(row.getAttribute('tabindex')) : 'no row carried data-open');
  row.focus();
  out.doc.dispatch('click', { target: row });
  check('a row opens the drawer', out.id('drawer').hidden === false);
  check('the drawer takes focus so the keyboard lands in it', out.doc.activeElement === out.id('drawer'));

  out.doc.dispatch('keydown', { key: 'Escape' });
  check('Escape closes the drawer', out.id('drawer').hidden === true);
  check('closing gives focus back to the row it was opened from', out.doc.activeElement === row,
    out.doc.activeElement === null ? 'focus was dropped on the document'
      : out.doc.activeElement.tagName + ' ' + (out.doc.activeElement.id || ''));
}

// A reader who already chose, arriving fresh: the preference has to be applied before the payload does,
// or the page is drawn once in the wrong palette and corrected afterwards.
{
  const out = await run('', { remembered: { 'labview.theme': 'dark', 'labview.side': 'collapsed' } });
  noThrow('a remembered preference is applied at boot', out);
  check('a remembered theme is in force before the payload arrives',
    out.id('app').getAttribute('data-theme') === 'dark',
    JSON.stringify(out.id('app').getAttribute('data-theme')));
  check('a remembered rail state is in force before the payload arrives',
    out.id('app').getAttribute('data-side') === 'collapsed');
  check('the remembered theme reaches the root element, so the boot card matches the shell',
    out.doc.documentElement.getAttribute('data-theme') === 'dark');
}

// --- 13. The structure the stylesheet needs ------------------------------
//
// There is no layout engine here, so none of these checks can see a column that is too narrow. What they
// can see is the structure the stylesheet's readings depend on, and the readings themselves — both of the
// scroll rules below were wrong in a way that is invisible until someone opens the widest view:
//
//   * `overflow-x: auto` with `overflow-y: visible` computes to `auto` on both axes (CSS Overflow 3), so
//     .scroll is a scrollport whether or not that was intended, and `position: sticky` in the header
//     resolves against it rather than the viewport. Unbounded, it never scrolls and the header never sticks.
//   * an auto-layout table at `width: 100%` with no per-cell floor shrinks to its container however many
//     columns it has, so the scroll container can never produce a horizontal scrollbar.
//
// Asserted as text because that is where the bug was. A visual check is still the reader's to make.

{
  // A table view, not the default one: the overview's content is the card grid and has no table in it.
  const tableView = C.views.find((v) => v.kind !== NAME('rowStat') && v.kind !== NAME('rowDiagram'));
  const out = await run('?view=' + tableView.slug);
  const scroll = out.id('content').all().find((n) => (n.className || '').split(/\s+/).includes('scroll'));
  check('the table is wrapped in the scroll region the stylesheet styles', !!scroll);
  check('the scroll region holds the table directly',
    !!scroll && scroll.children.some((n) => n.tagName === 'TABLE'));

  const css = readFileSync(join(ROOT, 'assets', 'labview.css'), 'utf8');
  const block = (sel) => {
    const at = css.indexOf(sel + ' {');
    if (at < 0) return '';
    return css.slice(at, css.indexOf('}', at));
  };
  const scrollCSS = block('.scroll');
  // Both bounds, in that order: `dvh` alone drops the whole declaration on a browser that does not know the
  // unit, and a dropped bound means an unbounded scrollport, which means the sticky header silently stops
  // working again on exactly the browsers least able to say so.
  check('.scroll bounds its height, so the sticky header has a scrollport that scrolls',
    /max-height:[^;]*100vh/.test(scrollCSS), scrollCSS);
  check('.scroll keeps a static-viewport fallback under the dynamic one',
    /max-height:[^;]*100vh[^]*max-height:[^;]*100dvh/.test(scrollCSS), scrollCSS);
  check('.scroll scrolls both axes, which is the only thing that combination can mean',
    /overflow:\s*auto/.test(scrollCSS), scrollCSS);
  check('the sticky header is offset from its own scrollport, not the viewport',
    /top:\s*0;/.test(block('thead th')), block('thead th'));
  check('cells carry a width floor, so a wide table overflows instead of shrinking to fit',
    /min-width:/.test(block('tbody td, thead th')), block('tbody td, thead th'));
  check('cells break long values instead of letting one set the column width',
    /overflow-wrap:\s*anywhere/.test(block('tbody td')), block('tbody td'));
}

// --- 14. A table compares, and the row is the way to the rest of it --------
//
// §22.2: a view's reading may be split between the table and the row's drawer, which is only honest if the
// row actually opens. Section 5 above opens every panel by URL — the way a shared link arrives — and that
// path cannot see a table whose rows stopped being clickable, because syncDrawer falls back to the payload
// when no row matches. This is the reader's entry point: the click.
//
// The trap this exists for is subtle and was live in three views: onActivate resolves an `<a href>` before it
// resolves `TR[data-open]`, so whatever the cell that *names* the row links to is what a reader gets when
// they click the most obvious thing in it. A name whose link lands somewhere that does not show that subject
// is therefore a row that cannot be opened by clicking it — and nothing throws, the drawer simply never
// appears and the page goes somewhere plausible instead. So the name may be a link, but only to a reading of
// the same subject; the second loop below is what checks where it landed.
//
// The drawer title is how the subject is identified, rather than a row's first cell: the naming cell is not
// always the first one (a service row leads with its stack) and this way the check reads the same fact the
// reader does.

const namedLinks = [];   // { rowNoun, subject, href } — verified after this loop, see below

for (const view of C.views) {
  const drawer = C.drawers.find((d) => d.kind === view.kind);
  if (!drawer) continue;                       // stat and diagram views: rows that navigate, not rows that open
  const out = await run('?view=' + view.slug);
  if (!noThrow('view ' + view.slug + ' renders for the row-click check', out)) continue;
  const rows = bodyRows(out);
  if (!rows.length) continue;                  // an empty fixture view says nothing either way

  const openable = rows.filter((tr) => tr.getAttribute('data-open') !== null);
  check('every row of ' + view.slug + ' opens its ' + drawer.kind + ' drawer',
    openable.length === rows.length,
    openable.length + ' of ' + rows.length + ' rows carry data-open');
  const row = openable[0];
  if (!row) continue;
  check('a row of ' + view.slug + ' offers itself to the keyboard', row.getAttribute('tabindex') === '0',
    JSON.stringify(row.getAttribute('tabindex')));

  out.doc.dispatch('click', { target: row, preventDefault() {} });
  await flush();
  check('clicking a ' + view.rowNoun + ' opens a drawer', out.id('drawer').hidden === false);
  const title = out.text('drawer-title') || '';
  check('the drawer names the ' + view.rowNoun + ' it opened on', title.length > 0);
  const panels = out.id('drawer').querySelectorAll('[data-panel]')
    .map((n) => n.getAttribute('data-panel'));
  check('clicking a ' + view.rowNoun + ' opens the ' + drawer.kind + ' drawer, not another one',
    panels.length > 0 && panels.every((p) => p.startsWith(drawer.kind + ':')),
    'panels: ' + JSON.stringify(panels));
  check('the ' + drawer.kind + ' drawer opened with all ' + drawer.sections.length + ' of its sections',
    panels.length === drawer.sections.length, panels.length + ' sections drawn');

  // Which cell names the row: the one reading exactly what the drawer title says the subject is.
  const subject = title.split(' — ')[0].trim();
  if (!subject) continue;
  cellsOf(row).filter((td) => td.textContent.trim() === subject).forEach((td) => {
    td.all().filter((n) => n.tagName === 'A').forEach((a) => {
      namedLinks.push({ rowNoun: view.rowNoun, subject, href: a.getAttribute('href') || '' });
    });
  });
}

// Where a naming cell's link landed. Run after the loop above rather than inside it, because a run replaces
// the document those rows belong to.
for (const l of namedLinks) {
  const what = 'the name of a ' + l.rowNoun + ' links to a reading of that same ' + l.rowNoun;
  const dest = await run(l.href === '.' ? '' : l.href);
  if (!noThrow(what + ' — its destination renders', dest)) continue;
  const title = dest.text('drawer-title') || '';
  check(what, dest.id('drawer').hidden === false && title.split(' — ')[0].trim() === l.subject,
    JSON.stringify(l.subject) + ' → ' + l.href + (dest.id('drawer').hidden
      ? ' opened no drawer at all' : ' opened ' + JSON.stringify(title)));
}

// A count worth attention is marked (§22.2). The marking is a glyph rather than one of the two reserved
// emphasis colours, so what is checked is that the glyph is there — on every nonzero count and on no zero,
// since a mark on every row marks none. Driven by the column's `icon`, so a column that gains or loses the
// marking is covered without a list here.
{
  let markedCells = 0;
  const markedColumns = [];
  for (const view of C.views) {
    const cols = view.columns.filter((c) => c.icon);
    if (!cols.length) continue;
    const out = await run('?view=' + view.slug);
    if (!noThrow('view ' + view.slug + ' renders for the marked-count check', out)) continue;
    const rows = bodyRows(out);
    if (!rows.length) continue;
    cols.forEach((col) => {
      markedColumns.push(view.slug + '.' + col.key);
      const j = view.columns.indexOf(col);
      const cells = rows.map((tr) => cellsOf(tr)[j]).filter(Boolean);
      const glyphs = (td) => td.all().filter((n) => n.classList.contains('numicon')).length;

      // The glyph must contribute no text of its own: section 2 reads these cells as integers to check the
      // numeric alignment, and a marker that wrote a character would take the whole column out of that
      // check rather than fail it.
      check('view ' + view.slug + ' column ' + col.key + ' still reads as a number beside its mark',
        cells.every((td) => isInteger(td.textContent) || td.textContent.includes('not reported')),
        'cells read: ' + JSON.stringify(cells.map((td) => td.textContent.trim()).slice(0, 6)));

      const numbers = cells.filter((td) => isInteger(td.textContent));
      const wrong = numbers.filter((td) => (Number(td.textContent) !== 0) !== (glyphs(td) > 0));
      check('view ' + view.slug + ' column ' + col.key + ' marks every count that is not zero, and no zero',
        wrong.length === 0,
        wrong.length + ' of ' + numbers.length + ' wrong, at values ' +
        JSON.stringify(wrong.map((td) => td.textContent.trim()).slice(0, 6)));
      markedCells += numbers.filter((td) => Number(td.textContent) !== 0).length;
    });
  }
  check('a marked column is declared somewhere', markedColumns.length > 0);
  // Every assertion above passes vacuously on a fleet with nothing to report, which is exactly the fleet the
  // marking does not matter on. The edge fixture has both a stack the scan could not fully read and a
  // service whose declaration this scan contradicts, so at least one mark must have been drawn.
  check('the mark was actually drawn for something', markedCells > 0,
    'no nonzero count in ' + JSON.stringify(markedColumns));
}

// A count can be the link to the rows it counts — the service count on a stack, the member count on a
// network. §22.3 asks that of a card and the reason is the same here: a number whose destination shows
// nothing is a number a reader cannot check.
// A link out of a row must name the view it lands on. This is the shape of the bug the two checks above only
// catch where a fixture happens to have rows: a state parameter scopes a view to one record, so a link that
// carries `svc=…`, `stack=…`, `net=…` or `diagram=…` and no `view=…` resolves to the *default* view — whose
// rows are statistics, which no scope matches. The reader clicks a service and gets the overview with every
// card filtered out. Nothing throws; §22.7 is satisfied, because the URL is honest about a state nobody
// wants. Checked on the URL rather than by opening it, so it holds for a view a fixture leaves empty.
for (const view of C.views) {
  if (view.slug === C.grammar.defaultView) continue;   // a scoped link that stays here needs no `view`
  const out = await run('?view=' + view.slug);
  if (out.thrown.length) continue;
  const hrefs = [...new Set(out.id('content').all()
    .filter((n) => n.tagName === 'A')
    .map((n) => n.getAttribute('href') || '')
    .filter((h) => h.charAt(0) === '?'))];
  const dead = hrefs.filter((h) => {
    const params = new URLSearchParams(h.slice(1));
    return [...params.keys()].length > 0 && !params.get('view');
  });
  check('every link out of a ' + view.rowNoun + ' names the view it lands on', dead.length === 0,
    'these fall back to the default view: ' + JSON.stringify(dead));
}

// Every linked count is read off the tables first and the destinations are opened afterwards, because a run
// replaces the document these nodes belong to: reading a row after opening its own link would read the
// destination's table instead, and agree with itself.
{
  const linked = [];
  for (const view of C.views) {
    const out = await run('?view=' + view.slug);
    if (out.thrown.length) continue;
    const rows = bodyRows(out);
    view.columns.forEach((col, j) => {
      if (!col.numeric) return;
      rows.forEach((tr) => {
        const td = cellsOf(tr)[j];
        if (!td || !isInteger(td.textContent)) return;
        const a = td.all().find((n) => n.tagName === 'A');
        if (!a) return;
        linked.push({ slug: view.slug, key: col.key, count: Number(td.textContent),
          href: a.getAttribute('href') || '' });
      });
    });
  }
  const seen = new Set();
  for (const l of linked) {
    if (seen.has(l.href)) continue;
    seen.add(l.href);
    const what = 'the ' + l.key + ' count in ' + l.slug + ' leads to the rows it counts';
    const dest = await run(l.href === '.' ? '' : l.href);
    if (!noThrow(what + ' — its destination renders', dest)) continue;
    const rows = bodyRows(dest).length;
    check(what, rows >= l.count,
      'count ' + l.count + ' → ' + l.href + ' drew ' + rows + ' rows');
  }
}

// --- 15. The reserved colour marks the reserved reading, and nothing else --
//
// §22.1 reserves one emphasis colour for reachable-from-outside-with-no-gate. There are two ways to lose it
// and both were live: spend it somewhere else, or fail to spend it on the reading. `tbody tr.lead td` washed
// every first-ranked row in `--alert-bg`, and eleven views rank by eleven different questions — unhealthy,
// read-write, more than one stack — so the colour meant "sorted first" rather than what it is reserved for.
// Meanwhile the count that *is* that finding, a stack's exposed services, rendered as an unremarkable digit.
//
// The stylesheet half is checked as text because that is where the bug lives; the reading half is checked in
// the DOM. Neither one names the tone: both read it out of the finding set, so renaming it in tone.go moves
// the check rather than breaking it.
{
  const css = readFileSync(join(ROOT, 'assets', 'labview.css'), 'utf8');
  const leadAt = css.indexOf('tbody tr.lead td {');
  const leadCSS = leadAt < 0 ? '' : css.slice(leadAt, css.indexOf('}', leadAt));
  check('the stylesheet still emphasises the first-ranked rows', leadCSS !== '');
  check('a first-ranked row is not painted in the reserved colour', !/--alert/.test(leadCSS), leadCSS);

  const finding = C.sets.find((s) => s.name === 'finding');
  const reserved = finding && finding.terms.find((t) => t.member === NAME('findingExposed'));
  check('the finding set reserves a tone for the exposure', !!(reserved && reserved.tone));
  // `tone-<name>` is the bundle's one convention for putting a term's tone on a node, shared by the
  // stylesheet and every renderer in app.js. The name itself comes from the contract above.
  const cls = 'tone-' + (reserved ? reserved.tone : '');

  let toldInColour = 0;
  for (const view of C.views) {
    // A count of the finding, which is a different cell from the finding itself: the set says which
    // vocabulary the number counts, `numeric` says it is a count and not the terms.
    const cols = view.columns.filter((c) => c.numeric && finding && c.set === finding.name);
    if (!cols.length) continue;
    const out = await run('?view=' + view.slug);
    if (!noThrow('view ' + view.slug + ' renders for the reserved-tone check', out)) continue;
    const rows = bodyRows(out);
    cols.forEach((col) => {
      const j = view.columns.indexOf(col);
      const found = rows.map((tr) => ({ tr: tr, td: cellsOf(tr)[j] }))
        .filter((p) => p.td && isInteger(p.td.textContent))
        .map((p) => ({ tr: p.tr, td: p.td, n: Number(p.td.textContent) }));

      const toned = (td) => td.all().some((n) => n.classList.contains(cls));
      const wrong = found.filter((p) => (p.n !== 0) !== toned(p.td));
      check('the ' + col.key + ' count in ' + view.slug +
        ' wears the reserved tone when it is not zero, and never when it is',
        wrong.length === 0,
        wrong.length + ' of ' + found.length + ' wrong, at values ' +
        JSON.stringify(wrong.map((p) => p.td.textContent.trim()).slice(0, 6)));

      // And the rows this view ranks first are those rows. A view that counts the finding and then sorts
      // by something else is the other half of the same bug: the emphasis lands on rows the reader was not
      // pointed at, and the ones they were pointed at are somewhere further down the table.
      const misranked = found.filter((p) => (p.n !== 0) !== p.tr.classList.contains('lead'));
      check('the rows ' + view.slug + ' ranks first are the ones with an exposure', misranked.length === 0,
        misranked.length + ' of ' + found.length + ' misranked, at values ' +
        JSON.stringify(misranked.map((p) => p.td.textContent.trim()).slice(0, 6)));

      toldInColour += found.filter((p) => p.n !== 0).length;
    });
  }
  // As with the marks above: every assertion passes vacuously on a fleet with nothing exposed. The edge
  // fixture has services reachable with no gate, so the reserved colour must have been spent on one.
  check('the reserved colour was actually spent on an exposure', toldInColour > 0);
}

// --- 16. What the page opens on, and what it keeps behind a control --------
//
// The main column used to stack thirty-nine counters across eight bands, and eight bordered filter panels
// between the heading and the first row. What replaced it is one CSS rule and a `data-open` attribute —
// which makes it the one kind of change this file is structurally blind to: nothing throws, every node is
// still in the document, and every existing count still matches. So the hiding is asserted against the
// stylesheet's text, the way sections 13 and 15 do, and the shape is asserted in the DOM.
//
// §22.4's two rules about the drawer's own folded tail are in section 5 instead, where a panel is already
// open.

{
  const css = readFileSync(join(ROOT, 'assets', 'labview.css'), 'utf8');
  const at = css.indexOf('[data-foldable][data-open="false"] {');
  const rule = at < 0 ? '' : css.slice(at, css.indexOf('}', at));
  // Without this one declaration every fold below is decoration: the controls flip an attribute, all of
  // the checks pass, and the page hides nothing at all.
  check('a shut fold is hidden, which is the whole of what folding is here',
    /display:\s*none/.test(rule), JSON.stringify(rule));
}

// The overview: §22.3 keeps a card for every counter in `stats`, and the ask was that a reader arriving at
// it sees the interesting ones rather than all of them. Both at once means the cards a fold is hiding are
// still cards on the page, so *how many are drawn* cannot tell the two apart — `data-card` says which.
{
  const out = await run('');
  noThrow('the overview renders for the fold checks', out);
  const content = out.id('content');
  // Against the cards actually drawn rather than against the contract's count, because one declaration can
  // expand into several: a distribution card becomes a card per member (`segmentOf`), and those are drawn
  // without a headline, so they fold with their group. Section 3 above is what ties the drawn set back to
  // the contract; this only asks that none of them is anonymous.
  const drawn = content.all().filter((n) => n.classList.contains('card'));
  const cards = content.querySelectorAll('[data-card]');
  check('every card on the overview says which card it is',
    cards.length === drawn.length, cards.length + ' named of ' + drawn.length + ' drawn');

  // A fold nests: a card sits in `.cards` inside the box the control opens. Read as *is anything above
  // this shut*, so a band inside a band would still count as hidden.
  const hidden = (n) => {
    for (let p = n; p; p = p.parentNode) {
      if (p.getAttribute && p.getAttribute('data-open') === 'false') return true;
    }
    return false;
  };
  const shown = cards.filter((a) => !hidden(a)).map((a) => a.getAttribute('data-card'));
  const headline = C.cards.filter((c) => c.headline).map((c) => c.id);
  check('the overview opens on the cards the contract calls headline, and on no others',
    JSON.stringify(shown.slice().sort()) === JSON.stringify(headline.slice().sort()),
    'shown ' + JSON.stringify(shown) + ' vs headline ' + JSON.stringify(headline));

  // Attention before size, which is a claim about order and not only about membership: the reserved
  // finding of §22.1 is the first thing on the page or the ranking has quietly become alphabetical.
  const lead = C.cards.find((c) => c.lead);
  check('the overview leads with the finding the contract ranks first',
    !!lead && shown[0] === lead.id, JSON.stringify(shown[0]) + ' vs ' + (lead ? lead.id : 'no lead card'));

  // One control per folded band, and it says how much it is holding: a control reading only its group name
  // cannot be told apart from one with nothing behind it, which is the mistake §22.6 already names for a
  // dimension with no members.
  const bandOf = (c) => { const v = C.views.find((x) => x.slug === c.view); return v ? v.group : 'Other'; };
  const folded = new Set(C.cards.filter((c) => !c.headline).map(bandOf));
  const controls = content.querySelectorAll('[data-fold]');
  check('the overview folds one band per group and leaves the headline bands open',
    controls.length === folded.size,
    controls.length + ' controls for ' + folded.size + ' folded bands: ' + JSON.stringify([...folded]));
  check('every band the reader has not opened yet is shut',
    controls.every((b) => b.getAttribute('aria-expanded') === 'false'),
    controls.filter((b) => b.getAttribute('aria-expanded') !== 'false').length + ' arrived open');
  const mute = controls.filter((b) => {
    const box = content.querySelectorAll('[data-foldable="' + b.getAttribute('data-fold') + '"]')[0];
    const held = box ? box.querySelectorAll('[data-card]').length : 0;
    return !held || !b.textContent.includes('(' + held + ')');
  });
  check('every fold control says how many cards it is holding', mute.length === 0,
    JSON.stringify(mute.map((b) => b.textContent)));
}

// The filters: the panels behind one control, the chips in front of it. §22.6 obliges a narrowed table to
// say it is narrowed, and a chip is the only thing on the page that both states a filter and undoes it —
// so it is the one part of the control strip that cannot be what the fold hides.
const filterable = C.views.find((v) => (v.dims || []).length);
{
  const out = await run('?view=' + filterable.slug);
  noThrow('a filterable view renders for the fold checks', out);
  const host = out.id('controls');
  const box = host.querySelectorAll('[data-foldable="filters"]')[0];
  check('the dimension panels are behind one control', !!box);
  const inside = (n, ancestor) => {
    if (!ancestor) return false;
    for (let p = n; p; p = p.parentNode) if (p === ancestor) return true;
    return false;
  };
  const dims = host.all().filter((n) => n.classList.contains('dim'));
  check(filterable.slug + ' still draws a panel per dimension it declares',
    dims.length === filterable.dims.length, dims.length + ' panels for ' + filterable.dims.length + ' dimensions');
  check('every dimension panel is behind that control',
    !!box && dims.every((n) => inside(n, box)),
    dims.filter((n) => !inside(n, box)).length + ' of ' + dims.length + ' panels are outside it');
  check('the control arrives shut, so the view opens on its first row',
    !!box && box.getAttribute('data-open') === 'false',
    box ? JSON.stringify(box.getAttribute('data-open')) : 'no fold at all');
  check('the chips are in front of the control, never behind it', !inside(out.id('chips'), box));
}

// A reader who followed a filtered link has to be able to see and unset what is narrowing the table, so
// the panels open themselves when the URL carries a filter — whatever the remembered preference says.
{
  const param = filterable.dims[0];
  const dim = C.dimensions.find((d) => d.param === param);
  const set = dim && dim.set ? C.sets.find((s) => s.name === dim.set) : null;
  const member = set ? set.terms[0].member : 'running';
  const out = await run('?view=' + filterable.slug + '&' + param + '=' + encodeURIComponent(member));
  noThrow('a narrowed table renders', out);
  const box = out.id('controls').querySelectorAll('[data-foldable="filters"]')[0];
  check('a link that narrows the table opens the panels that narrowed it',
    !!box && box.getAttribute('data-open') === 'true',
    box ? JSON.stringify(box.getAttribute('data-open')) : 'no fold at all');
  check('and the control counts what is in force, rather than reading as an empty one',
    (out.id('controls').textContent || '').includes('(1)'),
    JSON.stringify(out.id('controls').textContent));
}

// The section-12 pattern, applied to the one fold a reader sets deliberately: written when they set it, in
// force before the payload arrives. A preference that is not remembered is a control that undoes itself on
// every navigation (§22.7).
{
  const out = await run('?view=' + filterable.slug);
  const button = out.id('controls').querySelectorAll('[data-fold="filters"]')[0];
  check('the control is a button, so the keyboard reaches it and Enter works on it',
    !!button && button.tagName === 'BUTTON', button ? button.tagName : 'no control');
  if (button) {
    out.doc.dispatch('click', { target: button, preventDefault() {} });
    await flush();
    check('opening the panels writes it down',
      out.store.get('labview.fold.filters') === 'open',
      JSON.stringify(out.store.get('labview.fold.filters')));
    check('and the control reports that it is open',
      button.getAttribute('aria-expanded') === 'true',
      JSON.stringify(button.getAttribute('aria-expanded')));
  }
  const back = await run('?view=' + filterable.slug, { remembered: { 'labview.fold.filters': 'open' } });
  noThrow('a remembered fold is applied at boot', back);
  const box = back.id('controls').querySelectorAll('[data-foldable="filters"]')[0];
  check('a reader who opened the panels finds them open on the next view they visit',
    !!box && box.getAttribute('data-open') === 'true',
    box ? JSON.stringify(box.getAttribute('data-open')) : 'no fold at all');
}

// ---------------------------------------------------------------------------

console.log((checks - failures) + '/' + checks + ' checks passed');
if (failures) {
  console.error('\nrender-smoke failed: ' + failures + ' of ' + checks + ' checks.');
  process.exit(1);
}
console.log('render-smoke: the bundle renders.');
