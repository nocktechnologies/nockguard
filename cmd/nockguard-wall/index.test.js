const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function wall(contextPayload) {
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
  const feed = document.getElementById('feed');
  const empty = document.getElementById('empty');
  empty.parent = feed;
  empty.remove = empty.removeSelf;
  feed.children.push(empty);
  const decisions = document.getElementById('f-decision');
  decisions.options = ['', 'allow', 'deny', 'block', 'ratelimit', 'hide', 'approval-denied'].map(value => ({ value }));
  Object.defineProperty(decisions, 'value', {
    get() { return this.selectedValue ?? ''; },
    set(value) {
      this.selectedIndex = this.options.findIndex(o => o.value === value);
      this.selectedValue = this.selectedIndex < 0 ? null : value;
    },
  });
  const context = vm.createContext({
    document, window: {}, Date, URLSearchParams,
    Option: function(label, value) { this.label = label; this.value = value; },
    EventSource: class {}, fetch: () => contextPayload === undefined
      ? new Promise(() => {})
      : Promise.resolve({ json: () => Promise.resolve(contextPayload) }), setInterval() {},
  });
  const page = fs.readFileSync(new URL('./index.html', `file://${__filename}`), 'utf8');
  vm.runInContext(page.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { context, elements, decisions };
}

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

test('unknown decision options stay within the retained window', () => {
  const w = wall();
  vm.runInContext('MAX_ROWS = 2', w.context);
  vm.runInContext("render({decision:'first'}); render({decision:'second'})", w.context);
  w.decisions.value = 'second';
  vm.runInContext('applyFilters()', w.context);
  vm.runInContext("render({decision:'third'})", w.context);
  assert.equal(w.decisions.value, 'second');
  assert.deepEqual(w.decisions.options.map(o => o.value),
    ['', 'allow', 'deny', 'block', 'ratelimit', 'hide', 'approval-denied', 'third', 'second']);
  vm.runInContext("render({decision:'fourth'})", w.context);
  assert.equal(w.decisions.value, '');
  assert.equal(w.decisions.selectedIndex, 0);
  assert.equal(w.elements.get('f-count').textContent, '');
  assert.deepEqual(w.decisions.options.map(o => o.value),
    ['', 'allow', 'deny', 'block', 'ratelimit', 'hide', 'approval-denied', 'fourth', 'third']);
});
