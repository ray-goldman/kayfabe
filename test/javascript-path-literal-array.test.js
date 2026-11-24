'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function pathFindings(t, source, filename = 'routes.js') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-js-literal-path-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-js-literal-path-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, filename), source);
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'JS-PATH-001');
}

const source = `const { readFileSync } = require('node:fs');
function createRouter(router) {
  const fontNames = ['regular.woff2', 'bold.woff2'];
  const fonts = new Map(fontNames.map((font) => [font, readFileSync(new URL(\`../static/fonts/\${font}\`, import.meta.url))]));
  router.get('/font/:font', (request, response) => {
    const font = request.params.font;
    response.send(fonts.get(font));
  });
  return router;
}`;

test('closed literal basename array keeps a map callback path untainted', async t => {
  assert.equal((await pathFindings(t, source)).length, 0);
  assert.equal((await pathFindings(t, source, 'routes.ts')).length, 0);
});

test('request-controlled filename retains a path warning', async t => {
  const unsafe = source.replace("['regular.woff2', 'bold.woff2']", 'request.query.fontNames');
  assert.ok((await pathFindings(t, unsafe)).length > 0);
});

test('traversal literals and mutable arrays do not borrow the closed-array proof', async t => {
  const traversal = source.replace('regular.woff2', '../outside');
  const mutable = source.replace('const fonts =', "fontNames.push(request.query.font);\n  const fonts =");
  assert.ok((await pathFindings(t, traversal)).length > 0);
  assert.ok((await pathFindings(t, mutable)).length > 0);
});
