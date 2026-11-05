'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseCSharp } = require('../src/parsers/csharp/parser');
const { createCSharpConstantSinkProof } = require('../src/csharp-constant-sinks');
const { scan } = require('../src/engine');

function prove(source, rule = 'CS-SQLI-001', eol = '\n') {
  const code = source.replace(/\n/g, eol);
  return createCSharpConstantSinkProof(code)(code.split('\n').findIndex(line => line.includes('// sink')), rule);
}

// Counting the type header as an executable method must fail these assertions.
for (const kind of ['class', 'struct', 'record', 'record class', 'record struct']) {
  for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
    test(`primary ${kind} header is not a method (${ending})`, () => {
      const code = `public ${kind} Sample(string input) {\n public Sample() {}\n public void Run(string other) { return; }\n}`.replace(/\n/g, eol);
      const ast = parseCSharp(code);
      assert.equal(ast.complete, true, JSON.stringify(ast.errors));
      assert.deepEqual(ast.methods.map(method => method.name), ['Sample', 'Run']);
      assert.equal(ast.coverage.discoveredMethods, 2);
      assert.equal(ast.coverage.parsedMethods, 2);
      assert.equal(code.slice(ast.methods[1].bodyStart, ast.methods[1].bodyEnd), '{ return; }');
    });
  }
}

for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
  test(`primary constructor SQL methods prove locals and retain every input twin (${ending})`, () => {
    for (const sink of [
      'new SqlCommand("SELECT " + // sink\n VALUE, connection);',
      'command.CommandText = "SELECT " + // sink\n VALUE;',
      'db.FromSqlRaw("SELECT " + // sink\n VALUE);',
      'db.ExecuteSqlRaw("SELECT " + // sink\n VALUE);',
    ]) {
      const source = `public class Sample(string input) {\n public void Run() {\n const string value = "fixed";\n ${sink}\n }\n}`;
      assert.equal(prove(source.replace('VALUE', 'value'), undefined, eol), true, sink);
      assert.equal(prove(source.replace('VALUE', 'input'), undefined, eol), false, sink);
      const sibling = source.replace('const string value = "fixed";', '{ string input = "fixed"; }');
      assert.equal(prove(sibling.replace('VALUE', 'input'), undefined, eol), false, sink);
      assert.equal(prove(source.replace('const string value = "fixed";', 'string value = input;').replace('VALUE', 'value'), undefined, eol), false, sink);
    }
  });

  test(`primary constructor bindings remain unknown in scoped command proofs (${ending})`, () => {
    const source = `class Sample(string input) {\n void Run() {\n { string input = "fixed"; }\n string value = "status";\n Process.Start("cmd.exe", "/c " + VALUE); // sink\n }\n}`;
    assert.equal(prove(source.replace('VALUE', 'value'), 'CS-CMDI-001', eol), true);
    assert.equal(prove(source.replace('VALUE', 'input'), 'CS-CMDI-001', eol), false);
    assert.equal(prove(source.replace('VALUE', 'Value()').replace('class Sample(string input)', 'class Sample(Handler Value)').replace(/\n}$/, '\n private string Value() { return "fixed"; }\n}'), 'CS-CMDI-001', eol), false);
  });
}

test('a primary parameter in a separate type does not contaminate a local proof', () => {
  assert.equal(prove('class Other(string value) {}\nclass Sample {\n void Run() { string value = "fixed";\n command.CommandText = "SELECT " + // sink\n value;\n }\n}'), true);
});

test('unsupported constructor headers cannot disable an unrelated type local proof', () => {
  for (const other of [
    'class Other(string value = "fixed") {}',
    'class Other(string value = Defaults.Value) {}',
    'class Other(string value) : Base(value) {}',
    'class Other { public Other(string value) : base(value) {} }',
    'class Other<T>(string value) {}',
    'partial class Other(string value) {}',
    'class Other(External.Text value) {}',
  ]) {
    assert.equal(prove(`${other}\nclass Sample {\n void Run() { string value = "fixed";\n info.Arguments = "/c echo " + value; // sink\n }\n}`, 'CS-CMDI-001'), true, other);
  }
});

test('scoped header diagnostics do not discharge unrelated lexical or structural errors', () => {
  for (const other of ['class Other(string value = "fixed") {', 'class Other(string value = "fixed") { unsafe void Unknown() {} }']) {
    assert.equal(prove(`${other}\nclass Sample {\n void Run() { string value = "fixed";\n info.Arguments = "/c echo " + value; // sink\n }\n}`, 'CS-CMDI-001'), false);
  }
  assert.equal(prove('class Other(string value = "fixed") {}\nclass Sample {\n void Run(string input) {\n info.Arguments = "/c echo " + input; // sink\n }\n}', 'CS-CMDI-001'), false);
});

test('unknown primary owner shapes remain unresolved', () => {
  for (const header of ['partial class Sample(string input)', 'class Sample<T>(string input)', 'class Sample(string input) : Base(input)', 'class Sample(External.Text input)', 'class Sample([FromQuery] string input)', 'class Outer(string input) { class Sample']) {
    const source = `${header} {\n void Run() { string value = "fixed";\n command.CommandText = "SELECT " + // sink\n value;\n }\n}${header.includes('Outer') ? '}' : ''}`;
    assert.equal(prove(source), false, header);
  }
});

test('primary defaults and base initializers disclose unsupported executable headers', () => {
  for (const header of ['class Sample(string input = Defaults.Value)', 'class Sample(string input) : Base(input)', 'class Sample(string input = "fixed")']) {
    const ast = parseCSharp(`${header} { void Run() {} }`);
    assert.equal(ast.complete, false, header);
    assert.deepEqual(ast.methods.map(method => method.name), ['Run']);
    assert.ok(ast.errors.some(error => error.message.includes('primary constructor')), header);
    assert.equal(ast.coverage.parsedMethods, 0);
  }
});

test('explicit constructors and nested local functions keep their real bodies', () => {
  const code = 'class Sample { public Sample(string input) { Work(input); } void Run() { void Local() {} Local(); } }';
  assert.deepEqual(parseCSharp(code).methods.map(method => method.name), ['Sample', 'Run', 'Local']);
  assert.equal(prove('class Sample(string input) {\n void Run() { void Local() {\n command.CommandText = "SELECT " + "1"; // sink\n } }\n}'), false);
  assert.equal(prove('class Sample(string input) {\n SqlCommand field = new SqlCommand("SELECT " + input); void Run() { command.CommandText = "SELECT " + // sink\n "1"; }\n}'), false);
});

test('explicit constructor initializers are counted and disclose their unsupported header', () => {
  for (const initializer of ['base(input)', 'this(input, true)']) {
    const ast = parseCSharp(`class Sample { public Sample(string input) : ${initializer} { Work(input); } void Run() {} }`);
    assert.deepEqual(ast.methods.map(method => method.name), ['Sample', 'Run']);
    assert.equal(ast.complete, false);
    assert.ok(ast.errors.some(error => error.message.includes('constructor initializer')));
    assert.equal(ast.coverage.parsedMethods, 0);
  }
});

test('method default inputs cannot inherit a disjoint literal', () => {
  assert.equal(prove('class Sample(string input) {\n void Run(string value = Defaults.Value) {\n { string value = "fixed"; }\n command.CommandText = "SELECT " + // sink\n value;\n }\n}'), false);
  assert.equal(prove('class Sample(string input) {\n public Sample(string value = Defaults.Value) {\n { string value = "fixed"; }\n command.CommandText = "SELECT " + // sink\n value;\n }\n}'), false);
});

test('scanner retains primary inputs and suppresses independent literal locals', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-primary-constructors-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [file, value] of [['Safe.cs', 'value'], ['Unsafe.cs', 'input']]) {
    fs.writeFileSync(path.join(root, file), `class Sample(string input) {\n void Run() {\n { string input = "unrelated"; }\n string value = "fixed";\n command.CommandText = "SELECT " +\n ${value};\n Process.Start("cmd.exe", "/c " + ${value});\n }\n}`);
  }
  const result = await scan(root, { includeTests: true });
  assert.deepEqual(result.findings.filter(f => ['CS-SQLI-001', 'CS-CMDI-001'].includes(f.ruleId)).map(f => [f.file, f.ruleId]).sort(), [
    ['Unsafe.cs', 'CS-CMDI-001'], ['Unsafe.cs', 'CS-SQLI-001'],
  ]);
});
