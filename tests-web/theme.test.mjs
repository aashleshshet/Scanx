import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const source = readFileSync('src/api_sentry/web/static/theme.js', 'utf8');
function boot({ stored = null, light = false, denied = false } = {}) {
  const handlers = {}, media = { matches: light, addEventListener: (_, fn) => { handlers.system = fn; } };
  const button = { attributes: {}, setAttribute(k, v) { this.attributes[k] = v; }, addEventListener(_, fn) { handlers.click = fn; } };
  const document = { documentElement: { dataset: {} }, querySelectorAll: () => [button], addEventListener: (_, fn) => { handlers.ready = fn; } };
  const writes = [];
  vm.runInNewContext(source, { document, window: { matchMedia: () => media }, localStorage: { getItem() { if (denied) throw Error('denied'); return stored; }, setItem(k, v) { if (denied) throw Error('denied'); writes.push([k, v]); } } });
  handlers.ready();
  return { document, handlers, media, button, writes };
}
test('system appearance updates until the user chooses an explicit preference', () => {
  const x = boot();
  assert.equal(x.document.documentElement.dataset.theme, 'dark');
  x.media.matches = true; x.handlers.system();
  assert.equal(x.document.documentElement.dataset.theme, 'light');
  x.handlers.click(); x.handlers.system();
  assert.equal(x.document.documentElement.dataset.theme, 'dark');
  assert.equal(x.button.attributes['aria-label'], 'Switch to light appearance');
  assert.deepEqual(x.writes, [['onescanx-appearance', 'dark']]);
});
test('stored preference wins; blocked storage still allows toggling', () => {
  assert.equal(boot({ stored: 'dark', light: true }).document.documentElement.dataset.theme, 'dark');
  const x = boot({ denied: true, light: true });
  x.handlers.click();
  assert.equal(x.document.documentElement.dataset.theme, 'dark');
});
