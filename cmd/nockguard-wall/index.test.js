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
  decisions.options = ['', 'allow', 'deny', 'block', 'ratelimit', 'hide'].map(value => ({ value }));
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
  vm.runInContext("render({decision:'block', severity:'high', agent:'a'})", w.context);
  assert.equal(w.elements.get('p-blocked').textContent, 1); // clean control
  vm.runInContext("render({decision:'unparseable', agent:'a'})", w.context);
  assert.equal(w.elements.get('p-blocked').textContent, 1);
  assert.equal(w.elements.get('c-block').textContent, 1);
  assert.equal(w.elements.get('p-unreadable').textContent, 1);
  assert.equal(w.elements.get('c-unreadable').textContent, 1);
  assert.equal(w.elements.get('c-caught').textContent, '—');
});

test('audit and unfamiliar decisions do not become rejections or change the catch rate', () => {
  const w = wall();
  vm.runInContext("render({decision:'allow'}); render({decision:'deny'})", w.context);
  assert.equal(w.elements.get('c-caught').textContent, '50%');
  vm.runInContext("render({decision:'would-deny'}); render({decision:'future-review'})", w.context);
  assert.equal(w.elements.get('p-blocked').textContent, 1);
  assert.equal(w.elements.get('p-approved').textContent, 1);
  assert.equal(w.elements.get('p-other').textContent, 2);
  assert.equal(w.elements.get('c-other').textContent, 2);
  assert.equal(w.elements.get('c-rate').textContent, 0);
  assert.equal(w.elements.get('c-caught').textContent, '50%');
  assert.equal(w.elements.get('feed').children[0].dataset.decision, 'future-review');
  assert.match(w.elements.get('feed').children[0].innerHTML, /future-review/);
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
    ['', 'allow', 'deny', 'block', 'ratelimit', 'hide', 'third', 'second']);
  vm.runInContext("render({decision:'fourth'})", w.context);
  assert.equal(w.decisions.value, '');
  assert.equal(w.decisions.selectedIndex, 0);
  assert.equal(w.elements.get('f-count').textContent, '');
  assert.deepEqual(w.decisions.options.map(o => o.value),
    ['', 'allow', 'deny', 'block', 'ratelimit', 'hide', 'fourth', 'third']);
});
