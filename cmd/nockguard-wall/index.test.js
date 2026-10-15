const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function wall(contextPayload, mediaQuery) {
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
      addEventListener() {},
      add(option) { this.options.push(option); },
      remove(index) { this.options.splice(index, 1); },
      prepend(child) { this.children.unshift(child); child.parent = this; },
      get childElementCount() { return this.children.length; },
      get lastElementChild() { return this.children.at(-1); },
      removeSelf() { this.parent.children.splice(this.parent.children.indexOf(this), 1); },
    };
  }
  const document = {
    body: { dataset: {} },
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
const EMITTED = ['allow', 'deny', 'block', 'ratelimit', 'hide', 'approval-denied', 'approval-granted',
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
