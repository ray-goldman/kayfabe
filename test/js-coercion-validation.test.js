'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

const pair = path.join(__dirname, '../corpus/a05-js-coercion-validation');
const read = (side, file) => fs.readFileSync(path.join(pair, side, file), 'utf8');
const original = Object.fromEntries(['routes.ts', 'service.ts', 'storage.ts'].map(file => [file, read('vuln', file)]));
async function findings(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-coercion-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-coercion-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  for (const [name, source] of Object.entries(files)) fs.writeFileSync(path.join(root, name), source);
  return (await scan(root, { includeTests: true })).findings.filter(x => x.ruleId === 'JS-COERCE-001' && x.status === 'open');
}

test('bounded coercion proof flags the vulnerable path and its wrong-guard twin', async t => {
  assert.deepEqual((await findings(t, original)).map(x => [x.file, x.line]), [['service.ts', 3]]);
  const wrongGuard = original['service.ts'].replace('return issue(db, String(label));',
    "if (typeof other !== 'string') throw new Error('bad');\n  return issue(db, String(label));");
  assert.equal((await findings(t, { ...original, 'service.ts': wrongGuard })).length, 1);
});

test('raw type guard, direct pass-through and explicit default stay quiet', async t => {
  assert.equal((await findings(t, {
    ...original, 'service.ts': original['service.ts'].replace('return issue(db, String(label));',
      "if (typeof label !== 'string') throw new Error('bad');\n  return issue(db, String(label));"),
  })).length, 0);
  assert.equal((await findings(t, { ...original, 'service.ts': read('fixed', 'service.ts') })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'service.ts': original['service.ts'].replace('String(label)', "label === undefined ? 'unnamed' : String(label)"),
  })).length, 0);
});

test('a rejecting allowlist, absent route, or absent insert supplies no finding', async t => {
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('[A-Za-z0-9_.-]', '[0-9]'),
  })).length, 0);
  assert.equal((await findings(t, { ...original, 'routes.ts': 'export function endpoint(req, db) { return createChain(db, "fixed"); }' })).length, 0);
  assert.equal((await findings(t, { ...original, 'routes.ts': 'export function endpoint(req, db) { return createChain(db, "fixed", req.body.label); }' })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace("db.prepare('INSERT INTO chains(label) VALUES (?)').run(clean)", 'db.read(clean)'),
  })).length, 0);
});

test('duplicate downstream function names and a shadowed String remain unsupported', async t => {
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'] + '\nfunction issue(db, label) { return label; }',
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'service.ts': 'const String = value => value;\n' + original['service.ts'],
  })).length, 0);
});

test('route guard, explicit rejection, and unrelated write do not certify a vulnerable chain', async t => {
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'].replace('return createChain',
      "if (typeof req.body.label !== 'string') throw new Error('bad');\n  return createChain"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('return label;',
      "if (label === 'undefined') throw new Error('bad');\n  return label;"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('.run(clean)', '.run(other)'),
  })).length, 0);
});

test('coerced value must occupy the downstream argument position', async t => {
  assert.equal((await findings(t, {
    ...original, 'service.ts': original['service.ts'].replace('issue(db, String(label))', 'issue(db, fixedLabel, String(label))'),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'service.ts': original['service.ts'].replace('return issue(db, String(label));',
      'return issue(db, label) + String(label);'),
  })).length, 0);
  const renamed = {
    ...original,
    'service.ts': original['service.ts'].replace('function issue(db, label: string)', 'function issue(db, value: string)').replace('createRecord(db, label)', 'createRecord(db, value)'),
  };
  assert.equal((await findings(t, renamed)).length, 1);
});

test('validator must reject failed allowlist and the validated value must reach INSERT', async t => {
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('|| !/^[A-Za-z0-9_.-]{1,80}$/.test(label)',
      '|| /^[A-Za-z0-9_.-]{1,80}$/.test(label)'),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace("db.prepare('INSERT INTO chains(label) VALUES (?)').run(clean)",
      "(db.prepare('INSERT INTO audit(label) VALUES (?)').run('fixed'), db.prepare('SELECT label').run(clean))"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('return label;',
      "if (label.length < 10) throw new Error('bad');\n  return label;"),
  })).length, 0);
});

test('qualified calls abstain and a nonterminating route check does not hide the bug', async t => {
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'].replace('return createChain', 'return other.createChain'),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'service.ts': original['service.ts'].replace('createRecord(db, label)', 'other.createRecord(db, label)'),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'].replace('return createChain',
      "if (typeof req.body.label === 'string') console.log('ok');\n  return createChain"),
  })).length, 1);
});

test('route and write guards must be resolved on the same path', async t => {
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'].replace('return createChain',
      "if (req.body.label == null) throw new Error('required');\n  return createChain"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'].replace('return createChain',
      "if (!req.body.label) throw new Error('required');\n  return createChain"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('return db.prepare',
      "if (clean === 'undefined') throw new Error('bad');\n  return db.prepare"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'storage.ts': original['storage.ts'].replace('const clean = validate(label);',
      "let clean = validate(label);\n  clean = 'fixed';"),
  })).length, 0);
  assert.equal((await findings(t, {
    ...original, 'routes.ts': original['routes.ts'].replace("from './service'", "from './safe'"),
  })).length, 0);
  const twoRoutes = original['routes.ts'].replace('export function endpoint',
    "export function guarded(req, db) { if (typeof req.body.label !== 'string') throw new Error('bad'); }\nexport function endpoint");
  assert.equal((await findings(t, { ...original, 'routes.ts': twoRoutes })).length, 1);
});
