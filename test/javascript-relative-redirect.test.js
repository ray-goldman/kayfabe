'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function redirects(t, source, filename = 'routes.js') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-js-redirect-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-js-redirect-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, filename), source);
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'JS-REDIRECT-001');
}

test('fixed relative redirect with encoded request component stays local', async t => {
  const source = 'function redirect(response, path) { response.redirect(303, path); }\nfunction route(request, response) {\n  redirect(response, `/admin/agents?agent=${encodeURIComponent(request.params.id)}`);\n}';
  assert.equal((await redirects(t, source)).length, 0);
  assert.equal((await redirects(t, source, 'routes.ts')).length, 0);
});

test('arbitrary destination and protocol-relative template still warn', async t => {
  const arbitrary = 'function route(request, response) { redirect(response, request.query.next); }';
  const protocolRelative = 'function route(request, response) { redirect(response, `//${encodeURIComponent(request.query.host)}`); }';
  assert.ok((await redirects(t, arbitrary)).length > 0);
  assert.ok((await redirects(t, protocolRelative)).length > 0);
});

test('unsafe wrapper or shadowed encoder retains a warning', async t => {
  const route = 'function route(request, response) {\n  redirect(response, `/admin/agents?agent=${encodeURIComponent(request.params.id)}`);\n}';
  const unsafeWrapper = `function redirect(response, path) { response.redirect(303, 'https://other.example/' + path); }\n${route}`;
  const shadowed = `const encodeURIComponent = value => value;\nfunction redirect(response, path) { response.redirect(303, path); }\n${route}`;
  assert.ok((await redirects(t, unsafeWrapper)).length > 0);
  assert.ok((await redirects(t, shadowed)).length > 0);
});
