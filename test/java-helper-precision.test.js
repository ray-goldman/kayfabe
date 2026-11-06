'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function findings(t, source, extra = {}, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-java-helpers-'));
  t.after(() => {
    const resolved = fs.realpathSync(root);
    assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('appsec-java-helpers-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  for (const [file, text] of Object.entries({ 'Example.java': source, ...extra })) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  }
  return (await scan(root, { includeTests: true, ...options })).findings.filter(f => f.cwe.includes(89) || f.cwe.includes(78));
}
const query = value => `statement.executeQuery("SELECT name FROM users WHERE name='" + ${value} + "'");`;

const literalCharAtBody = (literal = '"ABC"', index = '1', selected = '66') =>
  `String guess = ${literal}; char chosen = guess.charAt(${index}); String answer;
   switch (chosen) { case ${selected}: answer = "fixed"; break; default: answer = input; } return answer;`;
function literalCharAtProof(body = literalCharAtBody(), options = {}, extra = {}) {
  const { buildJavaProjectIndex } = require('../src/java-project');
  const { stripComments } = require('../src/languages');
  const source = independentSource(body, options);
  const project = buildJavaProjectIndex(Object.entries({ 'Example.java': source, ...extra })
    .map(([file, raw]) => ({ file, raw, code: stripComments(raw, 'java') })));
  const filter = project.byFile.get('Example.java').filter, position = source.indexOf('String selected');
  return { source, project, filter, position,
    ordinary: context => filter.valueAt('choose(request, response, input)', position, context),
    bulk: () => filter.independentOutputValuesAt([{ expression: 'selected', position: source.indexOf('statement.executeQuery') }]) };
}

test('literal charAt proves both opaque routes and exact SQL sinks while selected taint still warns', async t => {
  for (const options of [{}, { helper: 'private static String choose(Request request, Response response, String input)' }]) {
    const unsafe = literalCharAtProof(literalCharAtBody('"ABC"', '1', '65'), options);
    assert.equal(unsafe.ordinary(), false, 'selected tainted arm');
    assert.equal(unsafe.bulk(), false, 'selected tainted bulk arm');
    assert.deepEqual((await findings(t, unsafe.source)).map(({ ruleId, line }) => ({ ruleId, line })),
      [{ ruleId: 'JAVA-SQLI-001', line: 7 }]);
    const proof = literalCharAtProof(undefined, options);
    assert.equal(proof.ordinary(), true, 'ordinary opaque producer');
    assert.equal(proof.bulk(), true, 'restricted independent output producer');
    assert.deepEqual(await findings(t, proof.source), []);
    for (const owner of options.helper ? ['Example.'] : ['this.']) {
      assert.deepEqual(await findings(t, proof.source.replace('= choose(', `= ${owner}choose(`)), [], owner);
    }
  }
  const assembly = literalCharAtProof(undefined, { sink: 'String sql = "SELECT name FROM users WHERE name=" + selected;\n    statement.executeQuery(sql);' });
  assert.deepEqual(await findings(t, assembly.source), [], 'independent SQL assembly');
  assert.deepEqual((await findings(t, assembly.source.replace('case 66:', 'case 65:')))
    .map(({ ruleId, line }) => ({ ruleId, line })),
  [{ ruleId: 'JAVA-SQLI-002', line: 7 }, { ruleId: 'JAVA-SQLI-001', line: 8 }], 'tainted assembly twin');
  for (const sink of [
    'jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected, input);',
    'jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected, new Object[] {input});',
    'wrapper(jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected), input);',
    'String result = jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected) + input;',
  ]) assert.ok((await findings(t, literalCharAtProof(undefined, { sink }).source)).length, sink);
  assert.deepEqual(await findings(t, literalCharAtProof(undefined, {
    sink: 'String result = jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected, new Object[] {});',
  }).source), [], 'existing harmless empty SQL metadata');
});

test('literal charAt uses exact source slices and UTF16 code units', () => {
  const supported = [
    ['"ABC"', '0', '65'], ['"ABC"', '2', '67'], ['"😀Z"', '0', '55357'],
    ['"😀Z"', '1', '56832'], ['"😀Z"', '2', '90'],
    [String.raw`"\b\t\n\f\r\"\'\\"`, '7', '92'],
  ];
  for (const args of supported) {
    const proof = literalCharAtProof(literalCharAtBody(...args));
    assert.equal(proof.ordinary(), true, JSON.stringify(args));
    assert.equal(proof.bulk(), true, JSON.stringify(args));
  }
  for (const body of [
    literalCharAtBody().replace('String guess', '/* String guess = "BAD"; guess.charAt(0); */ final String guess')
      .replace('guess.charAt(1)', '(guess /* gap */ . /* member */ charAt /* open */ ( /* index */ 1 /* close */ ))'),
    'String fake = "guess.charAt(0); String guess = BAD; 😀"; ' + literalCharAtBody(),
    '{ String guess = "BAD"; } ' + literalCharAtBody(),
    'String guess = "ABC"; if (true) { char ignored = guess.charAt(0); } return "fixed";',
  ]) assert.equal(literalCharAtProof(body).ordinary(), true, body);
});

test('literal charAt rejects unsupported values receiver shapes and index syntax in both routes', () => {
  for (const [literal, index] of [
    ['""', '0'], ['"ABC"', '3'], ['"ABC"', '2147483648'], ['"ABC"', '-1'],
    ['"ABC"', '+1'], ['"ABC"', '1L'], ['"ABC"', '0x1'], ['"ABC"', '01'],
    ['"ABC"', '1.0'], ['"ABC"', '1_0'], ['"ABC"', "'a'"], ['"ABC"', 'chosen'],
    ['"ABC"', 'input'], ['"ABC"', '(1)'], ['"ABC"', '0 + 1'], ['"ABC"', 'callback()'],
    [String.raw`"\q"`, '0'], [String.raw`"\101"`, '0'], [String.raw`"\u0041"`, '0'], ['"""ABC"""', '0'],
  ]) {
    const proof = literalCharAtProof(literalCharAtBody(literal, index));
    assert.equal(proof.ordinary(), false, `${literal} ${index}`);
    assert.equal(proof.bulk(), false, `${literal} ${index}`);
  }
  for (const call of ['input.charAt(1)', 'field.charAt(1)', '(guess).charAt(1)', '"ABC".charAt(1)',
    '((String) guess).charAt(1)', 'this.guess.charAt(1)', 'guess[0].charAt(1)',
    'guess.substring(1)', 'guess.charAt()', 'guess.charAt(1, 2)', 'guess.charAt(1).toString()',
    'guess.charAt(1)()', 'guess.charAt(1)[0]', 'guess.char/* split */At(1)']) {
    const proof = literalCharAtProof(literalCharAtBody().replace('guess.charAt(1)', call));
    assert.equal(proof.ordinary(), false, call);
    assert.equal(proof.bulk(), false, call);
  }
});

test('literal charAt binds only initialized root locals and defers all syntactic writes', () => {
  const use = 'char ignored = guess.charAt(1);';
  const rejected = [
    `String guess; guess = "ABC"; ${use} return "fixed";`,
    `String original = "ABC"; String guess = original; ${use} return "fixed";`,
    ...['null', '("ABC")', '"A" + "BC"', 'true ? "ABC" : "BAD"'].map(init => `String guess = ${init}; ${use} return "fixed";`),
    `{ String guess = "ABC"; ${use} } return "fixed";`,
    `{ String guess = "ABC"; } ${use} String guess = "ABC"; return "fixed";`,
    `if (true) { String guess = "ABC"; ${use} } return "fixed";`,
    `switch (1) { case 0: String guess = "ABC"; case 1: ${use} break; default: break; } return "fixed";`,
    `${use} String guess = "ABC"; return "fixed";`,
    'String guess = guess.charAt(1); return "fixed";',
    'if (true) String guess = "ABC"; return "fixed";',
    `String guess = "ABC"; guess = "ABC"; ${use} return "fixed";`,
    `String guess = "ABC"; ${use} guess = "ABC"; return "fixed";`,
    `String guess = "ABC"; ${use} if (false) guess = "ABC"; return "fixed";`,
    `String guess = "ABC"; ${use} if (true) { } else { guess = "ABC"; } return "fixed";`,
    `String guess = "ABC"; ${use} switch (0) { case 0: break; default: guess = "ABC"; } return "fixed";`,
    `String guess = "ABC"; ${use} return "fixed"; guess = "ABC";`,
    `String guess = "ABC"; ${use} guess++; return "fixed";`,
    `String guess = "ABC"; ${use} (guess) = "ABC"; return "fixed";`,
  ];
  for (const body of rejected) {
    const proof = literalCharAtProof(body);
    assert.equal(proof.ordinary(), false, body);
    assert.equal(proof.bulk(), false, body);
  }
  const proof = literalCharAtProof(`String guess = "ABC"; String alias = guess; boolean same = alias == guess; ${use} return "fixed";`);
  assert.equal(proof.ordinary(), true, 'harmless copies do not invalidate the immutable literal receiver');
});

test('literal charAt requires canonical callee scope and preserves older helper eligibility', () => {
  for (const [options, extra] of [
    [{ header: 'import missing.String; class Example' }, {}],
    [{ header: 'import missing.*; class Example' }, {}],
    [{ header: 'import static missing.Names.*; class Example' }, {}],
    [{ header: 'import java.lang.String; import java.lang.String; class Example' }, {}],
    [{ header: 'import java.lang.String junk; class Example' }, {}],
    [{ header: 'import missing.java; class Example' }, {}],
    [{ header: 'class Example<String>' }, {}],
    [{ helper: 'private <String> String choose(Request request, Response response, String input)' }, {}],
    [{ header: 'class Example extends Unknown' }, {}],
    [{ header: 'class Example implements Marker' }, {}],
    [{}, { 'String.java': 'class String {}' }],
    [{ header: 'package sample; class Example' }, { 'sample/String.java': 'package sample; class String {}' }],
    [{}, { 'Object.java': 'package java.lang; public class Object {}' }],
    [{}, { 'CanonicalString.java': 'package java.lang; public class String {}' }],
    [{}, { 'java.java': 'class java {}' }],
    [{ header: 'class Example extends javax.servlet.http.HttpServlet' }, { 'HttpServlet.java': 'package javax.servlet.http; public class HttpServlet {}' }],
  ]) {
    const proof = literalCharAtProof(undefined, options, extra);
    assert.equal(proof.ordinary(), false, JSON.stringify(options));
    assert.equal(proof.bulk(), false, JSON.stringify(options));
  }
  for (const header of ['import java.lang.String; class Example', 'import java /* gap */ . lang . String; class Example',
    'class Example extends java.lang.Object', 'class Example extends javax.servlet.http.HttpServlet',
    'import jakarta.servlet.http.HttpServlet; class Example extends HttpServlet']) {
    assert.equal(literalCharAtProof(undefined, { header }).ordinary(), true, header);
  }
  const incomplete = literalCharAtProof();
  incomplete.project.complete = false;
  assert.equal(incomplete.ordinary(), false, 'incomplete source inventory');
  assert.equal(incomplete.bulk(), false);
  const { constantSinkFilter } = require('../src/java-constants');
  assert.equal(constantSinkFilter(incomplete.source, () => []).valueAt('choose(request, response, input)', incomplete.position), false, 'absent project');
  const old = literalCharAtProof('return "fixed";', { header: 'class Example extends Unknown' });
  assert.equal(old.ordinary(), true, 'old opaque bodies retain existing scope eligibility');
  assert.equal(old.bulk(), true);
});

test('literal charAt cannot hide syntactic effects unsafe returns or caller facts', () => {
  const prefix = 'String guess = "ABC"; char ignored = guess.charAt(1); ';
  for (const tail of ['if (false) callback(); return "fixed";',
    'String answer = true ? "fixed" : callback(); return answer;',
    'switch (0) { case 0: break; default: request.toString(); } return "fixed";',
    'return "fixed"; field = input;', 'return "fixed"; callback();',
    'Object danger = new Object(); return "fixed";',
    'return "fixed"; boolean danger = ("prefix" + input) == "";',
    'if (false) return input; return "fixed";', 'return input;']) {
    const proof = literalCharAtProof(prefix + tail);
    const method = proof.filter.index.methods.find(m => m.name === 'choose');
    assert.equal(proof.ordinary({ parameterMethod: method.start,
      parameters: new Map([['input', { known: true, dependencies: [], encodings: [] }]]) }), false, tail);
    assert.equal(proof.bulk(), false, tail);
  }
});

test('literal charAt keeps one cumulative intrinsic allowance and shared proof limits', () => {
  const simple = literalCharAtProof();
  assert.equal(simple.ordinary(), true);
  for (const context of [{ budget: { left: 0, methods: new Set() } },
    { budget: { left: 100, methods: new Set() } }, { stack: ['a', 'b', 'c', 'd'] },
    { budget: { left: 10000, methods: new Set(Array.from({ length: 32 }, (_, i) => 'other-' + i)) } }]) {
    assert.equal(simple.ordinary(context), false);
  }
  const budget = { left: 10000, methods: new Set() };
  assert.equal(simple.ordinary({ budget }), true);
  const afterFirst = budget.left;
  assert.equal(simple.ordinary({ budget }), true);
  assert.ok(budget.left < afterFirst, 'no cross-invocation certificate cache');
  const uses = count => `String guess = "ABC"; char chosen; ${'chosen = guess.charAt(1);'.repeat(count)} return "fixed";`;
  assert.equal(literalCharAtProof(uses(2)).ordinary(), true);
  const cumulativeBudget = { left: 10000, methods: new Set() };
  assert.equal(literalCharAtProof(uses(120)).ordinary({ budget: cumulativeBudget }), false, 'many small calls do not each receive 512');
  assert.ok(cumulativeBudget.left > 5000, 'intrinsic allowance exhausts while shared work remains');
  assert.equal(literalCharAtProof(uses(120)).bulk(), false);
  const literals = 'char chosen; ' + Array.from({ length: 20 }, (_, i) =>
    `String guess${i} = "ABC"; ${`chosen = guess${i}.charAt(1);`.repeat(5)}`).join('') + ' return "fixed";';
  assert.equal(literalCharAtProof(literals).ordinary(), false, 'decoding new literals also shares the one allowance');
  const failed = literalCharAtProof(literalCharAtBody('"ABC"', '99'));
  const failedBudget = { left: 10000, methods: new Set() };
  assert.equal(failed.ordinary({ budget: failedBudget }), false);
  assert.ok(failedBudget.left < 10000, 'failed evaluation still spends shared work');
  for (const body of [' '.repeat(50001) + 'return "fixed";',
    'String guess = "ABC"; ' + Array.from({ length: 65 }, (_, i) => `char x${i};`).join('') + 'return "fixed";',
    '{'.repeat(65) + literalCharAtBody() + '}'.repeat(65),
    'String guess = "ABC"; ' + ';'.repeat(4096) + 'return "fixed";']) {
    assert.equal(literalCharAtProof(body).ordinary(), false, 'existing body bounds');
  }
  assert.equal(literalCharAtProof(undefined, { header: '@M("' + 'x'.repeat(4000) + '") class Example' }).ordinary(), false, 'bounded canonical headers');
});

test('independent owner fix1 rejects imported package prefixes in both opaque proof modes', async t => {
  const { buildJavaProjectIndex } = require('../src/java-project');
  const { stripComments } = require('../src/languages');
  const fixtures = [
    ['wildcard', 'import evil.*;', 'org.foo.Example.choose'],
    ['explicit', 'import evil.org;', 'org.foo.Example.choose'],
    ['spaced explicit', 'import evil /* gap */ . org;', 'org.foo.Example.choose'],
    ['absent wildcard', 'import missing.*;', 'org.foo.Example.choose'],
    ['genuine qualified coverage cost', '', 'org.foo.Example.choose'],
    ['static field', 'import static evil.Names.Example;', 'Example.choose'],
    ['static wildcard', 'import static evil.Names.*;', 'Example.choose'],
    ['spaced static field', 'import /* gap */ static evil . Names . Example;', 'Example.choose'],
  ];
  for (const [name, imports, owner] of fixtures) await t.test(name, async t => {
    const source = `package org.foo; import javax.servlet.http.HttpServletRequest; ${imports}
class Example {
  private static String choose(HttpServletRequest request, String input) { return "fixed"; }
  void run(HttpServletRequest request) {
    String input = request.getParameter("x");
    String selected = ${owner}(request, input);
    ${query('selected')}
  }
}`;
    const extra = {
      'evil/org.java': `package evil; public class org {
        public static Namespace foo = new Namespace();
        public static class Namespace { public Chooser Example = new Chooser(); }
        public static class Chooser { public String choose(javax.servlet.http.HttpServletRequest request, String input) { return input; } }
      }`,
      'evil/Names.java': `package evil; public class Names {
        public static Chooser Example = new Chooser();
        public static class Chooser { public String choose(javax.servlet.http.HttpServletRequest request, String input) { return input; } }
      }`,
    };
    if (name === 'absent wildcard') delete extra['evil/org.java'];
    const files = { 'Example.java': source, ...extra };
    const project = buildJavaProjectIndex(Object.entries(files).map(([file, raw]) => ({ file, raw, code: stripComments(raw, 'java') })));
    const position = source.indexOf('statement.executeQuery');
    const filter = project.byFile.get('Example.java').filter;
    const observed = { ordinary: filter.valueAt('selected', position),
      bulk: filter.independentOutputValuesAt([{ expression: 'selected', position }]) };
    const control = await findings(t, source.replace('return "fixed";', 'return input;'), extra);
    assert.ok(control.some(hit => hit.file === 'Example.java' && hit.ruleId === 'JAVA-SQLI-001' && hit.line === 7), 'tainted-return candidate twin');
    const hits = await findings(t, source, extra);
    assert.deepEqual(observed, { ordinary: false, bulk: false }, 'both opaque proof modes');
    assert.ok(hits.some(hit => hit.file === 'Example.java' && hit.ruleId === 'JAVA-SQLI-001' && hit.line === 7), 'exact current SQL call');
  });
});

test('independent owner fix1 preserves local owner shapes and old supported-only summaries', async t => {
  const { constantSinkFilter } = require('../src/java-constants');
  for (const [helper, owner] of [
    ['private String choose(Request request, String input)', 'choose'],
    ['private String choose(Request request, String input)', 'this.choose'],
    ['private static String choose(Request request, String input)', 'Example.choose'],
  ]) {
    for (const imports of ['', 'import missing.*;', ...(owner === 'Example.choose' ? [] : ['import static missing.Names.*;'])]) {
      const source = `package org.foo; ${imports} class Example {
      ${helper} { return "fixed"; }
      void run(Request request) {
        String input = request.getParameter("x");
        String selected = ${owner}(request, input);
        ${query('selected')}
      }
    }`;
      const position = source.indexOf('statement.executeQuery');
      const filter = constantSinkFilter(source, () => []);
      assert.equal(filter.valueAt('selected', position), true, owner + imports);
      assert.equal(filter.independentOutputValuesAt([{ expression: 'selected', position }]), true, owner + imports);
      assert.deepEqual(await findings(t, source), [], owner + imports);
    }
  }
  const source = `package org.foo; import static evil.Names.*; class Example {
    private static String old(String input) { return "fixed"; }
    void run(Request request) {
      String input = request.getParameter("x");
      String selected = org.foo.Example.old(input);
      ${query('selected')}
    }
  }`;
  const position = source.indexOf('statement.executeQuery');
  const filter = constantSinkFilter(source, () => []);
  assert.equal(filter.valueAt('selected', position), true, 'old supported-only behavior remains');
  assert.equal(filter.independentOutputValuesAt([{ expression: 'selected', position }]), false);
  assert.deepEqual(await findings(t, source), []);
});

// These fixtures catch an over-broad independent-return route: a safe return
// must be proved with opaque parameters, exact bindings, and its original sink
// envelope. Every rejection has a supported complete-call twin below.
const independentSource = (body = 'String answer = "fixed"; return answer;', {
  helper = 'private String choose(Request request, Response response, String input)',
  caller = 'void run(Request request, Response response)',
  argument = 'request, response, input', header = 'class Example',
  setup = 'String input = request.getParameter("x");', sink = query('selected'),
} = {}) => `${header} {
  ${helper} { ${body} }
  ${caller} {
    ${setup}
    String selected = choose(${argument});
    ${sink}
  }
}`;

test('class annotation literals permit independent complete SQL calls and retain tainted returns', async t => {
  for (const annotation of [
    '@Arbitrary("label")', '@arbitrary.metadata.Label(value = "label")',
    '@Label(first = "one", second = "two")', '@One("x") @Two(value = "y") @Marker',
    '@Marker', '@Marker()', '@Label( /* metadata */ value /* name */ = "/* literal */ // text")',
    '@Label("{ } < > ( ) @Other(value = \\\"quoted\\\") ; class Fake")',
    String.raw`@Label("quote: \" slash: \\ tab: \t newline: \n return: \r back: \b form: \f apostrophe: \'")`,
  ]) {
    const options = { header: `${annotation}\npublic final class Example`,
      caller: '@Override protected void run(Request request, Response response)' };
    assert.deepEqual(await findings(t, independentSource(undefined, options)), [], annotation);
    assert.ok((await findings(t, independentSource('return input;', options))).length, `tainted twin: ${annotation}`);
  }
});

test('class annotation literal parser rejects unsupported argument grammar rather than erasing annotations', () => {
  const { constantSinkFilter } = require('../src/java-constants');
  const rejected = [
    '@Label(CONSTANT)', '@Label(value = CONSTANT)', '@Label(null)', '@Label(true)', '@Label(123)', "@Label('x')",
    '@Label(call())', '@Label(value = call())', '@Label(@Nested("x"))',
    '@Label({"x"})', '@Label(value = {"x", "y"})', '@Label(String.class)', '@Label(Type<String>.class)',
    '@Label(value = "x", value = "y")', '@Label("x", name = "y")', '@Label(name = "x", "y")',
    '@Label("x", "y")', '@Label("x",)', '@Label(value = "x",)', '@Label(,)',
    '@Label(value = "x" junk)', '@Label("x") junk', '@Label("x" + "y")', '@Label("x" "y")',
    '@Label("unterminated)', '@Label("line\nbreak")', '@Label("line\rbreak")',
    String.raw`@Label("bad\q")`, String.raw`@Label("truncated\")`,
    String.raw`@Label("\u0061")`, String.raw`@Label("\141")`, String.raw`@Label("\s")`,
    '@Label("""text block""")',
  ];
  for (const annotation of rejected) {
    const source = independentSource(undefined, { header: `${annotation} class Example` });
    const filter = constantSinkFilter(source, () => []);
    assert.equal(filter.valueAt('choose(request, response, input)', source.indexOf('String selected')), false, annotation);
  }
  // The same parser entry proves a real supported candidate when syntax is ordinary.
  const source = independentSource(undefined, { header: '@Label("ordinary") class Example' });
  assert.equal(constantSinkFilter(source, () => []).valueAt('choose(request, response, input)', source.indexOf('String selected')), true);
});

test('class annotation literal metadata leaves caller placement and generic overload gates closed', async t => {
  const header = '@Label("metadata") class Example';
  assert.deepEqual(await findings(t, independentSource(undefined, { header })), []);
  for (const options of [
    { header: `${header}<T>` }, { header: `${header} extends Base<String>` },
    { header: `${header} implements Marker<String>` }, { header: `${header} extends Base extra` },
    { header: 'public @Label("metadata") class Example' },
    { header: '@Label("metadata") public @TypeUse class Example' },
    { caller: '<T> void run(Request request, Response response)' },
    { caller: '@Label("metadata") void run(Request request, Response response)' },
    { caller: '@Marker() void run(Request request, Response response)' },
    { caller: 'public @Label("metadata") void run(Request request, Response response)' },
    { caller: 'void run(@Label("metadata") Request request, Response response)' },
  ]) assert.ok((await findings(t, independentSource(undefined, { header, ...options }))).length, JSON.stringify(options));
  const extra = { 'Base.java': 'class Base { String choose(CharSequence input) { return System.getenv("VALUE"); } }' };
  const trap = `@Label("metadata") class Example extends Base {
    private String choose(Runnable input) { return "fixed"; }
    <Runnable extends CharSequence> void run(Runnable input) { String selected = choose(input); ${query('selected')} }
  }`;
  assert.ok((await findings(t, trap, extra)).length, 'generic inherited overload trap');
  assert.deepEqual(await findings(t, trap.replace('<Runnable extends CharSequence> ', ''), extra), [], 'nongeneric private twin');
});

test('class annotation literal metadata preserves effects, opaque dependencies and complete call envelopes', async t => {
  const options = { header: '@Label("metadata") class Example' };
  assert.deepEqual(await findings(t, independentSource(undefined, options)), []);
  for (const body of [
    'return input;', 'input = "fixed"; return input;', 'return request.getParameter("x");',
    'callback(request); return "fixed";', 'field = input; return "fixed";',
    'request.startAsync().getResponse().getWriter().write("<script>"); return "fixed";',
    'boolean ignored = ("prefix" + input) == ""; return null;',
    'String alias = input; alias = null; boolean ignored = ("prefix" + alias) == ""; return null;',
  ]) assert.ok((await findings(t, independentSource(body, options))).length, body);
  const complete = independentSource(undefined, { ...options,
    sink: 'String result = jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected);' });
  assert.deepEqual(await findings(t, complete), [], 'original complete sink');
  for (const expression of [
    'jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected) + input',
    'wrapper(jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected), input)',
  ]) assert.ok((await findings(t, complete.replace('jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected)', expression))).length, expression);
  for (const values of ['"name"', "'x'", 'input']) assert.ok((await findings(t, complete.replace(' + selected)', ` + selected, new Object[] {${values}})`))).length, values);
  assert.deepEqual(await findings(t, complete.replace(' + selected)', ' + selected, new Object[] {})')), []);
});

test('class annotation literals preserve shared budgets localOnly and fact isolation', () => {
  const { constantSinkFilter } = require('../src/java-constants');
  const options = { header: '@Label(value = "metadata") class Example' };
  const source = independentSource(undefined, options), filter = constantSinkFilter(source, () => []);
  const position = source.indexOf('String selected'), expression = 'choose(request, response, input)';
  const method = filter.index.methods.find(m => m.name === 'choose');
  assert.equal(filter.valueAt(expression, position), true);
  for (const context of [
    { budget: { left: 0, methods: new Set() } }, { budget: { left: 20, methods: new Set() } },
    { budget: { left: 10000, methods: new Set(Array.from({ length: 32 }, (_, i) => `other:${i}`)) } },
    { stack: [method.id] }, { stack: ['a', 'b', 'c', 'd'] }, { localOnly: true }, { mode: 'html' },
  ]) assert.equal(filter.valueAt(expression, position, context), false, JSON.stringify(context));
  const budget = { left: 10000, methods: new Set() };
  assert.equal(filter.valueAt(expression, position, { budget }), true);
  assert.ok(budget.left < 10000 && budget.methods.has(method.id));
  for (const body of ['return input;', 'String alias = input; return alias;']) {
    const tainted = independentSource(body, options), proof = constantSinkFilter(tainted, () => []);
    const callee = proof.index.methods.find(m => m.name === 'choose');
    assert.equal(proof.valueAt(expression, tainted.indexOf('String selected'), {
      parameters: new Map([['input', { known: true, dependencies: [], encodings: [], evidence: [] }]]),
      parameterMethod: callee.start, external: true,
    }), false, body);
  }
});

test('class annotation literal parser enforces header token character and annotation bounds', () => {
  const { constantSinkFilter } = require('../src/java-constants');
  const prove = header => {
    const source = independentSource(undefined, { header });
    return constantSinkFilter(source, () => []).valueAt('choose(request, response, input)', source.indexOf('String selected'));
  };
  assert.equal(prove(`${'@M("x") '.repeat(16)}class Example`), true, '16 annotation limit');
  assert.equal(prove(`${'@M("x") '.repeat(17)}class Example`), false, '17 annotations');
  const prefix = '@M("', suffix = '") class Example ';
  // independentSource adds one space between this header and the opening brace.
  assert.equal(prove(prefix + 'x'.repeat(3999 - prefix.length - suffix.length) + suffix), true, '4000 header characters');
  assert.equal(prove(prefix + 'x'.repeat(4000 - prefix.length - suffix.length) + suffix), false, '4001 header characters');
  const names = count => Array.from({ length: count }, (_, i) => `p${i}="x"`).join(',');
  assert.equal(prove(`@M(${names(62)}) class Example`), true, '253 tokens');
  assert.equal(prove(`@M(${names(63)}) class Example`), false, '257 tokens');
  assert.equal(prove(`@M("${'x'.repeat(100000)}") class Example`), false, 'huge literal');
});

test('independent returns accept exact opaque formals and unused tainted String bindings', async t => {
  for (const options of [
    {},
    { helper: 'private static String choose(Request request, Response response, String input)' },
    { caller: '@Override protected void run(Request request, Response response) throws java.io.IOException' },
    { caller: '@sample.Marker public final synchronized void run(final Request request, Response response)' },
    { header: 'class Example extends Base implements sample.Marker, Other' },
    { helper: 'private String choose(sample.Request request, sample.Response response, String input)',
      caller: 'void run(sample.Request request, sample.Response response)' },
    { setup: '', caller: 'void run(Request request, Response response, String input)' },
    { argument: 'request, response, "literal"', setup: '' },
  ]) assert.deepEqual(await findings(t, independentSource(undefined, options)), [], JSON.stringify(options));
});

test('independent return proof retains local arithmetic branches, ternaries and switches', async t => {
  for (const body of [
    'int flag = 3 * 2; String answer; if (flag == 6) answer = "fixed"; else answer = input; return answer;',
    'int flag = 6; String answer = flag == 6 ? "fixed" : input; return answer;',
    'int flag = 6; String answer; switch (flag) { case 6: answer = "fixed"; break; default: answer = input; } return answer;',
    'input = "fixed"; String answer = "independent"; return answer;',
  ]) assert.deepEqual(await findings(t, independentSource(body)), [], body);
});

test('independent returns keep parameter dependencies opaque after reassignment and in finally', async t => {
  for (const body of [
    'return input;', 'String answer = input; return answer;',
    'String answer = "prefix" + input; return answer;',
    'String[] names = input.split("-"); return names[0];',
    'input = "fixed"; return input;',
    'String answer; if (input == "fixed") answer = "fixed"; else answer = request.getParameter("x"); return answer;',
    'String answer = "fixed"; try { return answer; } finally { answer = request.getParameter("x"); }',
    'try { return "fixed"; } finally { return input; }',
    'return field;', 'return unknown();', 'return request.getParameter("x");',
    'String answer = "fixed"; if (unknown()) answer = input; return answer;',
    'if (false) return input; return "fixed";',
    'class Local { String value = input; } return "fixed";',
    'Object callback = new Object() { String value = input; }; return "fixed";',
    'callback(input); return field;',
  ]) assert.ok((await findings(t, independentSource(body))).length, body);
});

test('independent route rejects conversions, argument effects and nonformal opaque bindings', async t => {
  for (const options of [
    { argument: 'null, response, input' },
    { argument: '(Request) request, response, input' },
    { argument: 'holder.request, response, input' },
    { argument: 'requests[0], response, input' },
    { argument: 'getRequest(), response, input' },
    { argument: 'new Request(), response, input' },
    { argument: 'request = other, response, input' },
    { argument: 'request, response, (input = request.getParameter("later"))' },
    { setup: 'Request local = request; String input = "fixed";', argument: 'local, response, input' },
    { helper: 'private String choose(Other request, Response response, String input)' },
    { helper: 'private String choose(Request request, Response response, long input)', argument: 'request, response, 1' },
    { helper: 'private String choose(Request request, Response response, Integer input)', argument: 'request, response, 1' },
    { helper: 'private String choose(float request, Response response, String input)', caller: 'void run(float request, Response response)' },
    { helper: 'private String choose(Request[] request, Response response, String input)' },
    { helper: 'private String choose(Request... request)' },
    { helper: 'private String choose(Request..Bad request, Response response, String input)', caller: 'void run(Request..Bad request, Response response)' },
    { helper: 'private String choose(Request<String> request, Response response, String input)', caller: 'void run(Request<String> request, Response response)' },
    { setup: 'String input = "fixed"; String input = request.getParameter("x");' },
  ]) assert.ok((await findings(t, independentSource(undefined, options))).length, JSON.stringify(options));
  for (const [type, literal] of [['int', '3'], ['boolean', 'true'], ['char', "'x'"], ['String', '"fixed"']]) {
    assert.deepEqual(await findings(t, independentSource(undefined, {
      helper: `private String choose(Request request, Response response, ${type} input)`,
      argument: `request, response, ${literal}`, setup: '',
    })), [], type);
  }
});

test('independent route requires nongeneric recognized class and caller headers', async t => {
  for (const options of [
    { header: 'class Example<T>' }, { header: 'class Example extends Base<String>' },
    { header: 'class Example implements Marker<String>' },
    { header: 'class Example extends Base unknown' },
    { caller: '<T> void run(Request request, Response response)' },
    { caller: '@Marker("value") void run(Request request, Response response)' },
    { caller: '@Marker({"value"}) void run(Request request, Response response)' },
    { caller: 'void run(@Marker Request request, Response response)' },
    { caller: 'public @TypeUse String run(Request request, Response response)' },
    { caller: 'void run(Request request, Response request)' },
    { caller: 'unknown void run(Request request, Response response)' },
    { caller: 'Example(Request request, Response response)' },
    { caller: 'Result run(Request request, Response response)' },
  ]) assert.ok((await findings(t, independentSource(undefined, options))).length, JSON.stringify(options));
  const trap = `class Example extends Base {
    private String choose(Runnable input) { return "fixed"; }
    <Runnable extends CharSequence> void run(Runnable input) { String selected = choose(input); ${query('selected')} }
  }`;
  const extra = { 'Base.java': 'class Base { String choose(CharSequence input) { return System.getenv("VALUE"); } }' };
  assert.ok((await findings(t, trap, extra)).length, 'generic inherited overload trap');
  assert.deepEqual(await findings(t, trap.replace('<Runnable extends CharSequence> ', ''), extra), [], 'exact nongeneric private overload twin');
});

test('independent route keeps declaration, private owner and static restrictions', async t => {
  for (const options of [
    { helper: 'public String choose(Request request, Response response, String input)' },
    { helper: '@Override public String choose(Request request, Response response, String input)' },
    { helper: 'public static String choose(Request request, Response response, String input)' },
    { caller: 'static void run(Request request, Response response)' },
  ]) assert.ok((await findings(t, independentSource(undefined, options))).length, JSON.stringify(options));
  for (const declaration of [
    'private String choose(int other) { return "fixed"; }',
    'private double choose(int other) { return 0; }',
  ]) assert.ok((await findings(t, independentSource().replace('  void run', `  ${declaration}\n  void run`))).length, declaration);
  for (const owner of ['other', 'Missing', 'Example']) {
    assert.ok((await findings(t, independentSource().replace('= choose(', `= ${owner}.choose(`))).length, owner);
  }
  assert.deepEqual(await findings(t, independentSource().replace('= choose(', '= this.choose(')), []);
  assert.deepEqual(await findings(t, independentSource(undefined, {
    helper: 'private static String choose(Request request, Response response, String input)',
  }).replace('= choose(', '= Example.choose(')), []);
  assert.ok((await findings(t, `class Example { void run(Request request, Response response) {
    String input = request.getParameter("x"); String selected = Names.choose(request, response, input); ${query('selected')}
  } }`, { 'Names.java': 'class Names { private static String choose(Request request, Response response, String input) { return "fixed"; } }' })).length);
});

test('independent returned constants do not erase helper sinks, sibling values or effects', async t => {
  const effects = independentSource(`${query('input')} return "fixed";`);
  assert.deepEqual((await findings(t, effects)).map(h => ({ ruleId: h.ruleId, line: h.line })),
    [{ ruleId: 'JAVA-SQLI-001', line: 2 }, { ruleId: 'JAVA-SQLI-001', line: 6 }], 'effectful helper is not summarized');
  const source = independentSource('field = input; callback(request); return "fixed";', {
    sink: `${query('selected')}\n    ${query('input')}\n    ${query('field')}`,
  });
  assert.deepEqual((await findings(t, source)).map(h => ({ ruleId: h.ruleId, line: h.line })),
    [{ ruleId: 'JAVA-SQLI-001', line: 6 }, { ruleId: 'JAVA-SQLI-001', line: 7 }, { ruleId: 'JAVA-SQLI-001', line: 8 }]);
  const sibling = independentSource(undefined, { sink: 'jdbcTemplate.queryForObject("SELECT " + selected, input);' });
  assert.ok((await findings(t, sibling)).length, 'other SQL argument');
  const argumentEffect = independentSource(undefined, { setup: 'String input = "fixed";',
    argument: 'request, response, (input = request.getParameter("x"))', sink: query('input') });
  assert.ok((await findings(t, argumentEffect)).length, 'assignment in helper argument changes sibling SQL');
});

test('independent return facts preserve complete SQL envelopes through aliases, splits and arrays', async t => {
  for (const [setup, argument] of [
    ['String data = choose(request, response, input);', 'data'],
    ['String data = "fixed";', 'data + choose(request, response, input)'],
    ['String selected = choose(request, response, input); String data = selected;', 'data'],
    ['String selected = choose(request, response, input); String data = "prefix" + (selected);', 'data'],
    ['String selected = choose(request, response, input); String[] names = selected.split("-"); String data = names[0];', 'data'],
    ['String[] names = choose(request, response, input).split("-"); String data = names[0];', 'data'],
  ]) {
    const source = `class Example { String data = request.getParameter("outer");
      private String choose(Request request, Response response, String input) { return "fixed"; }
      String run(Request request, Response response) {
        String input = request.getParameter("x"); ${setup}
        return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + ${argument}) + input;
      }
    }`;
    assert.deepEqual(await findings(t, source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');')), [], setup);
    assert.deepEqual((await findings(t, source)).map(({ ruleId, line }) => ({ ruleId, line })),
      [{ ruleId: 'JAVA-SQLI-002', line: 5 }], setup);
    for (const expression of [
      `wrapper(jdbcTemplate.queryForObject("SELECT " + ${argument}), input)`,
      `combine(jdbcTemplate.queryForObject("SELECT " + ${argument}), input)`,
    ]) assert.deepEqual((await findings(t, source.replace(`jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + ${argument}) + input`, expression)))
      .map(({ ruleId, line }) => ({ ruleId, line })), [{ ruleId: 'JAVA-SQLI-002', line: 5 }], expression);
  }
});

test('independent return context cannot borrow nested specialized caller facts', async t => {
  for (const body of ['return input;', 'String alias = input; return alias;',
    'String alias = "prefix" + input; return alias;',
    'String[] names = input.split("-"); return names[0];']) {
    const source = `class Example {
      private String choose(Request request, String input) { ${body} }
      private String outer(String input) { Request request = unknown(); return choose(request, input); }
      void run() { String selected = outer("fixed"); ${query('selected')} }
    }`;
    assert.ok((await findings(t, source)).length, body);
    const { constantSinkFilter } = require('../src/java-constants');
    const direct = independentSource(body);
    const filter = constantSinkFilter(direct, () => []);
    const callee = filter.index.methods.find(m => m.name === 'choose');
    assert.equal(filter.valueAt('choose(request, response, input)', direct.indexOf('String selected'), {
      parameters: new Map([['input', { known: true, dependencies: [], encodings: [], evidence: [] }]]),
      parameterMethod: callee.start, external: true,
    }), false, `injected caller fact: ${body}`);
  }
});

test('independent route rejects fixed returns behind unknown calls and nonlocal effects', async t => {
  assert.deepEqual(await findings(t, independentSource()), []);
  for (const effect of [
    'callback(request);', 'field = input;', 'this.field = input;', 'request.value = input;',
    'request.startAsync().getResponse().getWriter().write("<script>");',
    'unknown();', 'throw new RuntimeException();', 'synchronized (request) {}',
    'while (true) {}', 'Object callback = new Object() { void call() {} };',
  ]) assert.ok((await findings(t, independentSource(`${effect} return "fixed";`))).length, effect);
});

test('independent purity proof resolves block locals without borrowing an expired binding for a field write', async t => {
  assert.deepEqual(await findings(t, independentSource('{ String local = "fixed"; local = "other"; } return "fixed";')), []);
  for (const body of [
    '{ String field = "fixed"; } field = input; return "fixed";',
    'if (true) { String field = "fixed"; } field = input; return "fixed";',
    'switch (1) { case 1: { String field = "fixed"; } break; default: break; } field = input; return "fixed";',
    'if (true) String field = "fixed"; field = input; return "fixed";',
  ]) assert.ok((await findings(t, independentSource(body))).length, body);
});

test('independent purity proof rejects implicit callbacks from opaque reference string conversion', async t => {
  assert.deepEqual(await findings(t, independentSource('String ignored = "prefix" + "literal"; return "fixed";')), []);
  assert.ok((await findings(t, independentSource('String ignored = "prefix" + request; return "fixed";'))).length,
    'opaque request.toString can mutate output even when the returned literal is fixed');
});

test('independent String reference effects propagate through parentheses aliases and conditional expressions', async t => {
  for (const body of [
    'boolean ignored = ("prefix" + input) == ""; return null;',
    'boolean ignored = ("prefix" + ((input))) == ""; return null;',
    'String alias = input; boolean ignored = ("prefix" + alias) == ""; return null;',
    'String alias = input; alias = null; boolean ignored = ("prefix" + alias) == ""; return null;',
    'boolean ignored = ("prefix" + (true ? input : null)) == ""; return null;',
    'boolean ignored = ("prefix" + (input == null ? null : input)) == ""; return null;',
    'if (false) { boolean ignored = ("prefix" + input) == ""; } return null;',
  ]) assert.ok((await findings(t, independentSource(body))).length, body);
  for (const body of [
    'String alias = input; boolean ignored = alias == input; return null;',
    'boolean ignored = ("prefix" + (input == null)) == ""; return null;',
    'String answer = "prefix" + "literal"; return answer;',
    'String answer = null; return answer;',
  ]) assert.deepEqual(await findings(t, independentSource(body)), [], body);
});

test('independent helper facts keep exact empty metadata and populated-array rejection', async t => {
  const safe = independentSource(undefined, {
    sink: 'jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + selected, new Object[] {});',
  });
  assert.deepEqual(await findings(t, safe), []);
  for (const values of ['"name"', "'x'", 'input']) assert.deepEqual((await findings(t, safe.replace('Object[] {}', `Object[] {${values}}`)))
    .map(({ ruleId, line }) => ({ ruleId, line })), [{ ruleId: 'JAVA-SQLI-001', line: 6 }], values);
});

test('independent route honors shared proof work, method, recursion and depth limits', () => {
  const { constantSinkFilter } = require('../src/java-constants');
  const source = independentSource();
  const filter = constantSinkFilter(source, () => []);
  const position = source.indexOf('String selected');
  const method = filter.index.methods.find(m => m.name === 'choose');
  const expression = 'choose(request, response, input)';
  assert.equal(filter.valueAt(expression, position), true);
  for (const context of [
    { budget: { left: 0, methods: new Set() } },
    { budget: { left: 10000, methods: new Set(Array.from({ length: 32 }, (_, i) => `other:${i}`)) } },
    { stack: [method.id] }, { stack: ['a', 'b', 'c', 'd'] }, { localOnly: true }, { mode: 'html' },
  ]) assert.equal(filter.valueAt(expression, position, context), false, JSON.stringify(context));
  const budget = { left: 10000, methods: new Set() };
  assert.equal(filter.valueAt(expression, position, { budget }), true);
  assert.ok(budget.left < 10000 && budget.methods.has(method.id), 'caller work and method set consumed in place');
});

test('private constant-return helper resolves at its caller', async t => {
  assert.equal((await findings(t, `class Example {
    private String value() { String answer = "fixed"; return answer; }
    void run() { String selected = value(); ${query('selected')} }
  }`)).length, 0);
});

test('private parameter-dependent helper specializes each call without sharing safe results', async t => {
  const hits = await findings(t, `class Example {
    private String decorate(String value) { return "prefix" + value; }
    void safe() { String selected = decorate("fixed"); ${query('selected')} }
    void unsafe() { String selected = decorate(request.getParameter("x")); ${query('selected')} }
  }`);
  assert.ok(hits.length);
  assert.ok(hits.every(h => h.line === 4));
});

test('private sink parameters require every caller to be safe', async t => {
  for (const unsafe of [false, true]) {
    const hits = await findings(t, `class Example {
      private void consume(String value) { ${query('value')} }
      void first() { consume("fixed"); }
      ${unsafe ? 'void second() { consume(request.getParameter("x")); }' : ''}
    }`);
    assert.equal(hits.length === 0, !unsafe);
  }
});

test('public sink helpers never infer complete callers from the scanned source', async t => {
  assert.ok((await findings(t, `class Example {
    public void consume(String value) { ${query('value')} }
    void run() { consume("fixed"); }
  }`)).length);
});

test('unknown return arm, recursion, overload ambiguity and virtual calls retain findings', async t => {
  for (const methods of [
    'private String value() { if (flag) return "fixed"; return request.getParameter("x"); }',
    'private String value() { return value(); }',
    'private String value() { return "fixed"; } private String value(int x) { return request.getParameter("x"); }',
    'public String value() { return "fixed"; }',
  ]) assert.ok((await findings(t, `class Example { ${methods}
    void run() { String selected = value(); ${query('selected')} }
  }`)).length, methods);
});

test('constant alternatives returned through a static source helper are independent of its guard', async t => {
  const source = `import sample.Commands; class Example {
    void run() { String prefix = Commands.prefix("echo"); Runtime.getRuntime().exec(prefix + "fixed"); }
  }`;
  const helper = `package sample; public class Commands {
    public static String prefix(String verb) {
      String result;
      if (System.getProperty("os.name").contains("Windows")) result = "cmd /c " + verb;
      else result = verb + " ";
      return result;
    }
  }`;
  assert.equal((await findings(t, source, { 'sample/Commands.java': helper })).length, 0);
  assert.ok((await findings(t, source.replace('"echo"', 'request.getParameter("x")'), { 'sample/Commands.java': helper })).length);
});

test('missing and duplicate static source definitions retain findings', async t => {
  const source = `class Example { void run() {
    String selected = sample.Names.value(); ${query('selected')}
  } }`;
  assert.ok((await findings(t, source)).length);
  const helper = 'package sample; public class Names { public static String value() { return "fixed"; } }';
  assert.ok((await findings(t, source, { 'a/Names.java': helper, 'b/Names.java': helper })).length);
});

test('parameter reassignment, method references and mutable returns retain findings', async t => {
  for (const methods of [
    'private String value(String x) { x = request.getParameter("x"); return x; }',
    'private String value(String x) { return field; }',
  ]) assert.ok((await findings(t, `class Example { ${methods}
    void run() { String selected = value("fixed"); ${query('selected')} }
  }`)).length);
  assert.ok((await findings(t, `class Example {
    private void consume(String value) { ${query('value')} }
    void run() { consume("fixed"); Object callback = this::consume; }
  }`)).length);
});

test('a value receiver shadowing an imported class must not select the static helper', async t => {
  assert.ok((await findings(t, `import sample.Names; class Example {
    void run(Other Names) { String selected = Names.value(); ${query('selected')} }
  }`, { 'sample/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
    'Other.java': 'class Other { public String value() { return request.getParameter("x"); } }' })).length, 'shadowed receiver retains SQL warning');
});

test('unsupported overload declarations and reflection prevent closed helper inference', async t => {
  assert.ok((await findings(t, `class Example {
    private String value() { return "fixed"; }
    private double value(int x) { return 0; }
    void run() { String selected = value(); ${query('selected')} }
  }`)).length, 'unsupported overload retains SQL warning');
  assert.ok((await findings(t, `class Example {
    private void consume(String value) { ${query('value')} }
    void run() { consume("fixed"); getClass().getDeclaredMethod("consume", String.class).invoke(this, request.getParameter("x")); }
  }`)).length, 'reflective callers retain SQL warning');
});

test('private parameter writes cannot create invariant guard facts', async t => {
  assert.ok((await findings(t, `class Example {
    private String value(int flag) {
      if (condition) flag = 1;
      String answer;
      if (flag == 1) answer = "fixed"; else answer = request.getParameter("x");
      return answer;
    }
    void run() { String selected = value(0); ${query('selected')} }
  }`)).length);
});

test('skipped Java definitions cannot establish a complete static source index', async t => {
  const source = `class Example { void run() { String selected = sample.Names.value(); ${query('selected')} } }`;
  assert.ok((await findings(t, source, {
    'a/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
    'b/Names.java': 'package sample; public class Names { public static String value() { return request.getParameter("x"); } }' + ' '.repeat(600),
  }, { maxFileSize: 512 })).length, 'incomplete Java source inventory');
});

test('helper expansion depth exhaustion retains findings', async t => {
  const methods = Array.from({ length: 7 }, (_, i) => `private String value${i}() { return ${i === 6 ? '"fixed"' : `value${i + 1}()`}; }`).join('\n');
  assert.ok((await findings(t, `class Example { ${methods}
    void run() { String selected = value0(); ${query('selected')} }
  }`)).length, 'depth bound');
});

test('reflective invocation prevents private caller closure even without a named reference', async t => {
  assert.ok((await findings(t, `class Example {
    private void consume(String value) { ${query('value')} }
    void safe() { consume("fixed"); }
    void unsafe() throws Exception {
      java.lang.reflect.Method m = getClass().getDeclaredMethods()[0];
      m.setAccessible(true);
      m.invoke(this, request.getParameter("x"));
    }
  }`)).length);
});

test('HTML encoding cannot sanitize SQL or shell arguments', async t => {
  for (const sink of [query('clean'), 'Runtime.getRuntime().exec(clean);']) {
    const hits = await findings(t, `class Example {
      void run() {
        String input = request.getParameter("value");
        String clean = org.owasp.encoder.Encode.forHtml(input);
        ${sink}
      }
    }`);
    assert.ok(hits.length, sink);
  }
});

test('an inherited value receiver cannot select an imported static helper', async t => {
  for (const inheritance of ['extends', 'implements']) {
    const hits = await findings(t, `import sample.Names; class Example ${inheritance} Base {
      void run() { String selected = Names.value(); ${query('selected')} }
    }`, {
      'Base.java': inheritance === 'extends' ? 'class Base { protected Other Names; }'
        : 'interface Base { Other Names = new Other(); }',
      'Other.java': 'class Other { public String value() { return request.getParameter("x"); } }',
      'sample/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
    });
    assert.ok(hits.length);
  }
});

test('inherited overloads cannot borrow a local summary for a different argument type', async t => {
  for (const crossFile of [false, true]) {
    const hits = await findings(t, crossFile
      ? `class Example { void run() { String selected = Names.value(1); ${query('selected')} } }`
      : `class Example extends Base { private String value(String x) { return "fixed"; }
        void run() { String selected = value(1); ${query('selected')} } }`, {
      'Names.java': 'class Names extends Base { static String value(String x) { return "fixed"; } }',
      'Base.java': 'class Base { static String value(int x) { return System.getenv("VALUE"); } }',
    });
    assert.ok(hits.length);
  }
});

test('comma-separated fields can shadow an imported class owner', async t => {
  const hits = await findings(t, `import sample.Names; class Example {
    Other first, Names;
    void run() { String selected = Names.value(); ${query('selected')} }
  }`, {
    'Other.java': 'class Other { public String value() { return System.getenv("VALUE"); } }',
    'sample/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
  });
  assert.ok(hits.length);
});

test('helper-derived SQL arguments keep the envelope across recursive local proof paths', async t => {
  for (const marker of ['', 'Object marker = Long.class;']) {
    for (const [setup, argument] of [
      ['String data = "fixed";', 'data + value()'],
      ['String data = "fixed";', 'data + (value())'],
      ['String data = value();', 'data'],
      ['String selected = value(); String data = selected;', 'data'],
      ['String selected = value(); String data = "prefix" + (selected);', 'data'],
      ['String selected = value(); String[] names = selected.split("-"); String data = names[0];', 'data'],
      ['String[] names = value().split("-"); String data = names[0];', 'data'],
    ]) {
      const source = `class Example { String data = request.getParameter("outer");
        private String value() { ${marker} String answer = "fixed"; return answer; }
        String run() {
          ${setup} String input = request.getParameter("x");
          return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + ${argument}) + input;
        }
      }`;
      const label = `${marker} / ${setup} / ${argument}`;
      // The complete-call twin proves the helper shape is actually supported;
      // the warning below must come from its enclosing expression, not an
      // already-unknown helper. The wrapper scan runs ordinary proof before
      // local-only proof, so that ordinary success must not leak into fallback.
      const complete = source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');');
      assert.deepEqual((await findings(t, source)).map(({ ruleId, line }) => ({ ruleId, line })),
        [{ ruleId: 'JAVA-SQLI-002', line: 5 }], label);
      assert.deepEqual(await findings(t, complete), [], label);
    }
  }
});

test('multi-hop newly class-enabled helper facts cannot bypass an old caller envelope', async t => {
  const source = `class Example { String data = request.getParameter("outer");
    private String leaf() { Object marker = Long.class; String answer = "fixed"; return answer; }
    private String value() { String answer = leaf(); return answer; }
    String run() {
      String data = value(); String input = request.getParameter("x");
      return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + data) + input;
    }
  }`;
  assert.deepEqual(await findings(t, source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');')), []);
  assert.deepEqual((await findings(t, source)).map(({ ruleId, line }) => ({ ruleId, line })),
    [{ ruleId: 'JAVA-SQLI-002', line: 6 }]);
});

test('project static helper facts newly enabled by class literals keep the old caller envelope', async t => {
  for (const setup of [
    'String data = "fixed";',
    'String selected = Names.value(); String data = selected;',
    'String[] names = Names.value().split("-"); String data = names[0];',
  ]) {
    const argument = setup === 'String data = "fixed";' ? 'data + Names.value()' : 'data';
    const source = `import sample.Names; class Example { String data = request.getParameter("outer");
      String run() {
        ${setup} String input = request.getParameter("x");
        return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + ${argument}) + input;
      }
    }`;
    const extra = { 'sample/Names.java': `package sample; public class Names {
      public static String value() { Object marker = Long.class; String answer = "fixed"; return answer; }
    }` };
    assert.deepEqual(await findings(t, source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');'), extra), [], setup);
    assert.deepEqual((await findings(t, source, extra)).map(({ ruleId, file, line }) => ({ ruleId, file, line })),
      [{ ruleId: 'JAVA-SQLI-002', file: 'Example.java', line: 4 }], setup);
  }
});

test('private caller-parameter SQL facts cannot enter the local wrapper exception', async t => {
  for (const caller of [
    'void run() { String selected = "fixed"; consume(selected); }',
    'void run() { Object marker = Long.class; String selected = "fixed"; consume(selected); }',
    'private String value() { Object marker = Long.class; String answer = "fixed"; return answer; } void run() { String selected = value(); consume(selected); }',
  ]) {
    const source = `class Example { String data = request.getParameter("outer");
      private String consume(String data) {
        String input = request.getParameter("x");
        return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + data) + input;
      }
      ${caller}
    }`;
    assert.deepEqual(await findings(t, source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');')), [], caller);
    assert.deepEqual((await findings(t, source)).map(({ ruleId, line }) => ({ ruleId, line })),
      [{ ruleId: 'JAVA-SQLI-002', line: 4 }], caller);
  }
});

test('every required argument must have independent local proof before bypassing a wrapper', async t => {
  const source = `class Example { String data = request.getParameter("outer");
    private String value() { Object marker = Long.class; String answer = "fixed"; return answer; }
    String run() {
      String data = "fixed"; String selected = value(); String input = request.getParameter("x");
      return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + data, selected) + input;
    }
  }`;
  assert.deepEqual(await findings(t, source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');')), []);
  assert.deepEqual((await findings(t, source)).map(({ ruleId, line }) => ({ ruleId, line })),
    [{ ruleId: 'JAVA-SQLI-002', line: 5 }]);
});

test('caller-parameter facts stay disabled through local aliases, split bases and arrays', async t => {
  for (const setup of [
    'String data = seed;',
    'String selected = seed; String data = "prefix" + (selected);',
    'String[] names = seed.split("-"); String data = names[0];',
  ]) {
    const source = `class Example { String data = request.getParameter("outer");
      private String consume(String seed) {
        ${setup} String input = request.getParameter("x");
        return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name=" + data) + input;
      }
      void run() { Object marker = Long.class; String selected = "fixed"; consume(selected); }
    }`;
    assert.deepEqual(await findings(t, source.replace('return jdbcTemplate', 'String result = jdbcTemplate').replace(') + input;', ');')), [], setup);
    assert.deepEqual((await findings(t, source)).map(({ ruleId, line }) => ({ ruleId, line })),
      [{ ruleId: 'JAVA-SQLI-002', line: 4 }], setup);
  }
});
