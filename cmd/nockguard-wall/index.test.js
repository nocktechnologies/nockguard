const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function wall(contextPayload, mediaQuery, globals = {}) {
  const elements = new Map();
  function element() {
    const classes = new Set();
    return {
      className: '', dataset: {}, textContent: '', innerHTML: '', value: '', hidden: false,
      children: [], options: [], offsetWidth: 0,
      classList: {
        contains(name) { return classes.has(name) || this.owner.className.split(' ').includes(name); },
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
      },
      addEventListener(type, listener) { (this.listeners ??= {})[type] = listener; },
      click() { this.listeners?.click(); },
      add(option) { this.options.push(option); },
      remove(index) { this.options.splice(index, 1); },
      prepend(child) { this.children.unshift(child); child.parent = this; },
      get childElementCount() { return this.children.length; },
      get lastElementChild() { return this.children.at(-1); },
      removeSelf() { this.parent.children.splice(this.parent.children.indexOf(this), 1); },
    };
  }
  const document = {
    body: { dataset: {} }, visibilityState: globals.visibilityState,
    getElementById(id) {
      if (!elements.has(id)) {
        const el = element();
        el.classList.owner = el;
        elements.set(id, el);
      }
      return elements.get(id);
    },
    createElement() {
      const el = element();
      Object.defineProperty(el, 'innerHTML', {
        get() { return this.html ?? this.textContent; },
        set(value) { this.html = value; },
      });
      el.classList.owner = el;
      el.remove = el.removeSelf;
      return el;
    },
  };
  const page = fs.readFileSync(new URL('./index.html', `file://${__filename}`), 'utf8');
  const feed = document.getElementById('feed');
  const empty = document.getElementById('empty');
  empty.parent = feed;
  empty.remove = empty.removeSelf;
  feed.children.push(empty);
  const decisions = document.getElementById('f-decision');
  decisions.options = [...page.match(/<select id="f-decision"[\s\S]*?<\/select>/)[0].matchAll(/<option value="([^"]*)"/g)]
    .map(m => ({ value: m[1] }));
  Object.defineProperty(decisions, 'value', {
    get() { return this.selectedValue ?? ''; },
    set(value) {
      this.selectedIndex = this.options.findIndex(o => o.value === value);
      this.selectedValue = this.selectedIndex < 0 ? null : value;
    },
  });
  const context = vm.createContext({
    document, window: mediaQuery ? { matchMedia: () => mediaQuery } : {}, Date, URLSearchParams,
    Option: function(label, value) { this.label = label; this.value = value; },
    EventSource: class {}, fetch: () => contextPayload === undefined
      ? new Promise(() => {})
      : Promise.resolve({ json: () => Promise.resolve(contextPayload) }), setInterval() {},
    ...globals,
  });
  vm.runInContext(page.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { context, elements, decisions };
}

test('evidence details follow narrow and wide resizes with current and legacy listeners', () => {
  for (const legacy of [false, true]) {
    let onChange;
    const mediaQuery = { matches: false };
    if (legacy) mediaQuery.addListener = listener => { onChange = listener; };
    else mediaQuery.addEventListener = (type, listener) => {
      assert.equal(type, 'change');
      onChange = listener;
    };
    const w = wall(undefined, mediaQuery);
    const details = w.elements.get('evidence-details');
    assert.equal(details.open, false);
    assert.equal(typeof onChange, 'function');
    onChange({ matches: true });
    assert.equal(details.open, true);
    onChange({ matches: false });
    assert.equal(details.open, false);
    assert.ok(w.elements.has('f-text')); // initialization continued past media query setup
  }
});

test('context window stays a bounded positive integer', async () => {
  for (const [window, expected] of [
    [undefined, 500], [0, 500], [-1, 500], [1.5, 500], ['2', 500],
    [Infinity, 500], [1000000, 500], [12, 12],
  ]) {
    const w = wall({ window });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(vm.runInContext('MAX_ROWS', w.context), expected);
    assert.equal(w.elements.get('window-size').textContent, expected);
  }
});

test('one unreadable row leaves the readable block count visible', () => {
  const w = wall();
  vm.runInContext("render({decision:'block', bucket:'blocked', severity:'high', agent:'a'})", w.context);
  assert.equal(w.elements.get('p-blocked').textContent, 1); // clean control
  vm.runInContext("render({decision:'unparseable', bucket:'unreadable', agent:'a'})", w.context);
  assert.equal(w.elements.get('p-blocked').textContent, 1);
  assert.equal(w.elements.get('c-block').textContent, 1);
  assert.equal(w.elements.get('p-unreadable').textContent, 1);
  assert.equal(w.elements.get('c-unreadable').textContent, 1);
  assert.equal(w.elements.get('c-caught').textContent, '—');
});

test('routine decisions count as approved and unfamiliar decisions stay other', () => {
  const w = wall();
  vm.runInContext("render({decision:'allow', bucket:'approved'}); render({decision:'deny', bucket:'blocked'})", w.context);
  assert.equal(w.elements.get('c-caught').textContent, '50%');
  vm.runInContext("render({decision:'would-deny', bucket:'approved'}); render({decision:'future-review', bucket:'other', severity:'high'})", w.context);
  assert.equal(w.elements.get('p-blocked').textContent, 1);
  assert.equal(w.elements.get('p-approved').textContent, 2);
  assert.equal(w.elements.get('p-other').textContent, 1);
  assert.equal(w.elements.get('c-other').textContent, 1);
  assert.equal(w.elements.get('c-rate').textContent, 0);
  assert.equal(w.elements.get('c-caught').textContent, '33%');
  assert.equal(w.elements.get('feed').children[0].dataset.decision, 'future-review');
  assert.equal(w.elements.get('feed').children[0].className, 'row unknown');
  assert.match(w.elements.get('feed').children[0].innerHTML, /future-review/);
});

test('pulse uses the server bucket for routine decisions', () => {
  const w = wall();
  vm.runInContext("render({decision:'dispatch', bucket:'approved', severity:'none'}); render({decision:'state-write', bucket:'approved', severity:'none'}); render({decision:'approval-granted', bucket:'approved', severity:'none'})", w.context);
  assert.equal(w.elements.get('p-approved').textContent, 3);
  assert.equal(w.elements.get('p-other').textContent, 0);
  assert.equal(w.elements.get('p-threats').textContent, 0);
  // Negative control: the browser must trust the bucket, not its own decision list.
  vm.runInContext("render({decision:'allow', bucket:'other', severity:'high'})", w.context);
  assert.equal(w.elements.get('p-approved').textContent, 3);
  assert.equal(w.elements.get('p-other').textContent, 1);
});

test('tools/list hides are counted apart from rejected calls and threats', () => {
  const w = wall();
  vm.runInContext("render({decision:'deny', bucket:'blocked', severity:'low', agent:'a'})", w.context);
  assert.equal(w.elements.get('c-caught').textContent, '100%');
  for (let i = 0; i < 12; i++) vm.runInContext("render({decision:'hide', bucket:'hidden', severity:'none', agent:'a'})", w.context);
  // Negative control: twelve hides must not move the rejected, threat or rate figures.
  assert.equal(w.elements.get('p-hidden').textContent, 12);
  assert.equal(w.elements.get('c-hidden').textContent, 12);
  assert.equal(w.elements.get('p-blocked').textContent, 1);
  assert.equal(w.elements.get('p-threats').textContent, 1);
  assert.equal(w.elements.get('p-other').textContent, 0);
  assert.equal(w.elements.get('c-caught').textContent, '100%');
  assert.equal(w.elements.get('c-total').textContent, 13);
});

test('approval-denied uses rejection styling and a fixed decision filter option', () => {
  const w = wall();
  vm.runInContext("render({decision:'approval-denied', bucket:'blocked', severity:'high'})", w.context);
  assert.equal(w.elements.get('feed').children[0].className, 'row approval-denied');
  assert.equal(w.elements.get('p-blocked').textContent, 1);
  assert.equal(w.decisions.options.filter(o => o.value === 'approval-denied').length, 1);
  const page = fs.readFileSync(new URL('./index.html', `file://${__filename}`), 'utf8');
  assert.match(page, /<option value="approval-denied">approval-denied<\/option>/);
  assert.match(page, /\.approval-denied\s*\{[^}]*border-left-color:var\(--deny\)/);
  assert.match(page, /\.approval-denied \.badge\s*\{[^}]*color:var\(--deny\)/);
});

// Every decision value the Go source emits (internal/forward's
// TestWallDecisionFilterMatchesEmittedDecisions keeps this list honest).
const EMITTED = ['allow', 'method-allow', 'method-deny', 'deny', 'block', 'ratelimit', 'hide', 'approval-denied', 'approval-granted',
  'would-deny', 'dispatch', 'observe', 'state-write', 'inject', 'budget-ask', 'downgrade'];
const FIXED = ['', ...EMITTED];

test('filter lists every emitted decision and filters to exactly its rows', () => {
  const w = wall();
  assert.deepEqual(w.decisions.options.map(o => o.value).sort(), [...FIXED].sort());
  for (const d of EMITTED) vm.runInContext(`render({decision:'${d}', bucket:'approved', agent:'a'})`, w.context);
  const feed = w.elements.get('feed');
  for (const d of EMITTED) {
    w.decisions.value = d;
    vm.runInContext('applyFilters()', w.context);
    const shown = feed.children.filter(r => r.classList.contains('row') && !r.classList.contains('fout'));
    assert.deepEqual(shown.map(r => r.dataset.decision), [d]);
    assert.equal(feed.children.find(r => r.dataset.decision === d).className.split(' ')[1], d); // known: not 'unknown'
  }
});

test('approval-granted, dispatch and would-deny get their own tiles', () => {
  const w = wall();
  vm.runInContext(`render({decision:'approval-granted', bucket:'approved'});
    render({decision:'dispatch', bucket:'approved'}); render({decision:'dispatch', bucket:'approved'});
    render({decision:'would-deny', bucket:'approved'}); render({decision:'deny', bucket:'blocked', severity:'low'})`, w.context);
  assert.equal(w.elements.get('p-granted').textContent, 1);
  assert.equal(w.elements.get('p-dispatched').textContent, 2);
  assert.equal(w.elements.get('p-would-deny').textContent, 1);
  assert.equal(w.elements.get('p-blocked').textContent, 1); // would-deny is not a rejection
  assert.equal(w.elements.get('p-approved').textContent, 4);
});

test('an unknown decision lands in other, gets its own filter option and stays visible', () => {
  const w = wall();
  vm.runInContext("render({decision:'brand-new', bucket:'other', severity:'high'})", w.context);
  assert.equal(w.elements.get('p-other').textContent, 1);
  assert.equal(w.elements.get('feed').children[0].className, 'row unknown');
  assert.ok(w.decisions.options.some(o => o.value === 'brand-new'));
  w.decisions.value = 'brand-new';
  vm.runInContext('applyFilters()', w.context);
  assert.equal(w.elements.get('p-other').textContent, 1);
});

test('unknown decision options stay within the retained window', () => {
  const w = wall();
  vm.runInContext('MAX_ROWS = 2', w.context);
  vm.runInContext("render({decision:'first'}); render({decision:'second'})", w.context);
  w.decisions.value = 'second';
  vm.runInContext('applyFilters()', w.context);
  vm.runInContext("render({decision:'third'})", w.context);
  assert.equal(w.decisions.value, 'second');
  assert.deepEqual(w.decisions.options.map(o => o.value),
    [...FIXED, 'third', 'second']);
  vm.runInContext("render({decision:'fourth'})", w.context);
  assert.equal(w.decisions.value, '');
  assert.equal(w.decisions.selectedIndex, 0);
  assert.equal(w.elements.get('f-count').textContent, '');
  assert.deepEqual(w.decisions.options.map(o => o.value),
    [...FIXED, 'fourth', 'third']);
});

test('method rows retain labels without inflating tool allow counts', () => {
 const w = wall();
 vm.runInContext("render({decision:'allow', bucket:'approved', severity:'none'}); render({decision:'method-allow', bucket:'other', severity:'none'}); render({decision:'method-deny', bucket:'other', severity:'high'})", w.context);
 assert.equal(w.elements.get('c-allow').textContent, 1);
});

// A fake browser for the notify toggle: permission prompt, storage, a manual
// clock for setTimeout, an EventSource whose reconnect the test drives, and a
// record of every Notification shown.
function notifyEnv({ permission = 'granted', stored = null, visibilityState = 'hidden', storageThrows = false } = {}) {
  const shown = [], timers = [], sources = [], store = new Map(stored === null ? [] : [['nockguard.notify', stored]]);
  let requests = 0, now = 0;
  function Notification(title, opts) { shown.push({ title, body: opts.body }); }
  Notification.permission = stored === null ? 'default' : permission;
  Notification.requestPermission = () => { requests++; Notification.permission = permission; return Promise.resolve(permission); };
  const localStorage = {
    getItem(k) { if (storageThrows) throw new Error('blocked'); return store.get(k) ?? null; },
    setItem(k, v) { if (storageThrows) throw new Error('blocked'); store.set(k, v); },
  };
  const setTimeout = (fn, ms) => timers.push({ at: now + ms, fn });
  function advance(ms) {
    now += ms;
    for (let t; (t = timers.find(t => t.at <= now));) { timers.splice(timers.indexOf(t), 1); t.fn(); }
  }
  const EventSource = class { constructor() { sources.push(this); } };
  return { globals: { Notification, localStorage, setTimeout, visibilityState, EventSource },
    shown, store, advance, requests: () => requests, reconnect: () => sources.at(-1).onopen() };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const fresh = (extra) => `render({decision:'block', bucket:'blocked', severity:'high', agent:'coder', tool:'write_file',
  ts:new Date(Date.now() + 1000).toISOString(), ${extra || ''}})`;

test('notify toggle asks permission once clicked and remembers the choice', async () => {
  const page = fs.readFileSync(new URL('./index.html', `file://${__filename}`), 'utf8');
  assert.match(page, /<button class="toggle snd" id="t-notify"[^>]*>/);
  const env = notifyEnv();
  const w = wall(undefined, undefined, env.globals);
  const button = w.elements.get('t-notify');
  assert.equal(button.hidden, false);
  assert.equal(env.requests(), 0); // no prompt before the click
  vm.runInContext(fresh(), w.context);
  assert.equal(env.shown.length, 0); // negative control: off by default
  button.click();
  await tick();
  assert.equal(env.requests(), 1);
  assert.equal(env.store.get('nockguard.notify'), '1');
  assert.ok(button.classList.contains('on'));
  button.click();
  assert.equal(env.store.get('nockguard.notify'), '0');
  assert.ok(!button.classList.contains('on'));
  // A remembered choice survives a reload, unless the permission was revoked.
  const again = notifyEnv({ stored: '1' });
  assert.ok(wall(undefined, undefined, again.globals).elements.get('t-notify').classList.contains('on'));
  const revoked = notifyEnv({ stored: '1', permission: 'denied' });
  assert.ok(!wall(undefined, undefined, revoked.globals).elements.get('t-notify').classList.contains('on'));
});

test('notify turns itself off when permission is refused and survives blocked storage', async () => {
  const env = notifyEnv({ permission: 'denied' });
  const w = wall(undefined, undefined, env.globals);
  w.elements.get('t-notify').click();
  await tick();
  assert.equal(env.store.get('nockguard.notify'), '0');
  assert.ok(!w.elements.get('t-notify').classList.contains('on'));
  const locked = notifyEnv({ storageThrows: true });
  const w2 = wall(undefined, undefined, locked.globals);
  w2.elements.get('t-notify').click();
  await tick();
  vm.runInContext(fresh(), w2.context);
  assert.equal(locked.shown.length, 1);
  // Without the Notification API the toggle is hidden and the page still runs.
  const w3 = wall();
  assert.equal(w3.elements.get('t-notify').hidden, true);
  vm.runInContext(fresh(), w3.context);
});

test('blocks notify only while hidden, at most once per 10 s, the rest as +N more', () => {
  const env = notifyEnv({ stored: '1' });
  const w = wall(undefined, undefined, env.globals);
  vm.runInContext(`render({decision:'block', bucket:'blocked', severity:'high', agent:'coder', tool:'old', ts:'2020-01-01T00:00:00Z'})`, w.context);
  vm.runInContext(fresh("decision:'deny', severity:'low', tool:'routine'"), w.context);
  assert.equal(env.shown.length, 0); // replayed history and routine denies stay quiet
  vm.runInContext(fresh("args:'SECRET'"), w.context);
  assert.deepEqual(env.shown, [{ title: 'NockGuard blocked write_file', body: 'coder · write_file · block' }]);
  assert.doesNotMatch(JSON.stringify(env.shown), /SECRET/);
  vm.runInContext(fresh("tool:'a'"), w.context);
  vm.runInContext(fresh("tool:'a'"), w.context); // same second, same key: still counted
  vm.runInContext(fresh("decision:'deny', severity:'critical', tool:'c'"), w.context);
  assert.equal(env.shown.length, 1);
  env.advance(9999);
  assert.equal(env.shown.length, 1);
  env.advance(1);
  assert.equal(env.shown.length, 2);
  assert.equal(env.shown[1].title, 'NockGuard blocked +3 more');
  env.advance(10000); // nothing pending: the window closes quietly
  assert.equal(env.shown.length, 2);
  vm.runInContext(fresh("tool:'d'"), w.context);
  assert.equal(env.shown[2].title, 'NockGuard blocked d');
  vm.runInContext(fresh("tool:'e'"), w.context);
  w.context.document.visibilityState = 'visible';
  env.advance(10000); // the tab came back: the pending +1 is dropped
  assert.equal(env.shown.length, 3);
});

test('history replayed on reconnect does not notify again, even rows first seen while visible', () => {
  const env = notifyEnv({ stored: '1', visibilityState: 'visible' });
  const w = wall(undefined, undefined, env.globals);
  const row = fresh("ts:'2099-01-01T00:00:00Z'");
  env.reconnect();
  vm.runInContext(row, w.context);
  vm.runInContext(row, w.context);
  assert.equal(env.shown.length, 0); // a visible tab does not notify
  w.context.document.visibilityState = 'hidden';
  env.reconnect();
  vm.runInContext(row, w.context);
  vm.runInContext(row, w.context);
  assert.equal(env.shown.length, 0);
  vm.runInContext(row, w.context); // a third occurrence on this connection is new
  assert.equal(env.shown.length, 1);
});

test('demo rows never raise desktop notifications', async () => {
  const env = notifyEnv({ stored: '1' });
  const w = wall({ demo: true }, undefined, env.globals);
  await tick();
  vm.runInContext(fresh(), w.context);
  assert.equal(env.shown.length, 0);
});

test('a broken audit chain notifies once per break while hidden', async () => {
  let report = { chain_intact: true, status: 'verified', entries_verified: 3 };
  const env = notifyEnv({ stored: '1' });
  const w = wall(undefined, undefined, env.globals);
  w.context.fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve(report) });
  await vm.runInContext('checkChain()', w.context);
  assert.equal(env.shown.length, 0); // intact chain stays quiet
  report = { chain_intact: false, status: 'tampered', break_at: 4 };
  await vm.runInContext('checkChain()', w.context);
  await vm.runInContext('checkChain()', w.context);
  assert.deepEqual(env.shown, [{ title: 'NockGuard audit trail broken',
    body: 'Audit trail broken at entry 4: the record may have been altered.' }]);
  report = { chain_intact: false, status: 'tampered', break_at: null }; // rollback: no single entry
  await vm.runInContext('checkChain()', w.context);
  assert.equal(env.shown[1].body, 'Audit trail broken: the record may have been altered.');
  // A break first seen with the banner on screen does not notify later.
  w.context.document.visibilityState = 'visible';
  report = { chain_intact: false, status: 'tampered', break_at: 2 };
  await vm.runInContext('checkChain()', w.context);
  w.context.document.visibilityState = 'hidden';
  await vm.runInContext('checkChain()', w.context);
  assert.equal(env.shown.length, 2);
});
