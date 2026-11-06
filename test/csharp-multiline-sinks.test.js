'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createCSharpConstantSinkProof } = require('../src/csharp-constant-sinks');
const { scan } = require('../src/engine');

function proof(body, ruleId = 'CS-CMDI-001', eol = '\n', members = '') {
  const code = `class Sample {\n${members}\n void Run(string input) {\n${body}\n }\n}`.replace(/\n/g, eol);
  const line = code.split(eol).findIndex(text => text.includes('// sink'));
  return createCSharpConstantSinkProof(code)(line, ruleId);
}

// Removing complete-expression extraction must break these constant controls;
// truncating a continuation must break their dynamic twins.
for (const eol of ['\n', '\r\n']) {
  const label = eol === '\n' ? 'LF' : 'CRLF';
  test(`multiline process calls prove both executable and arguments (${label})`, () => {
    assert.equal(proof(' Process.Start("cmd.exe", "/c " + // sink\n "status");', undefined, eol), true);
    assert.equal(proof(' Process.Start("cmd.exe", // sink\n "/c " + input);', undefined, eol), false);
    assert.equal(proof(' Process.Start(input, // sink\n "/c " + "status");', undefined, eol), false);
    assert.equal(proof(' Process.Start("cmd.exe", "/c " + // sink\n Unknown());', undefined, eol), false);
  });
  for (const [lhs, rule] of [['info.Arguments', 'CS-CMDI-001'], ['command.CommandText', 'CS-SQLI-001']]) {
    test(`multiline ${lhs} assignment includes its whole RHS (${label})`, () => {
      assert.equal(proof(` string value = "fixed";\n ${lhs} = "prefix " + value + // sink\n "suffix";`, rule, eol), true);
      assert.equal(proof(` ${lhs} = "prefix " // sink\n + input;`, rule, eol), false);
      assert.equal(proof(` string value = "fixed";\n value = input;\n ${lhs} = "prefix " + // sink\n value;`, rule, eol), false);
      assert.equal(proof(` string value = "fixed";\n Mutate(ref value);\n ${lhs} = "prefix " + // sink\n value;`, rule, eol), false);
      assert.equal(proof(` ${lhs} = "prefix " + // sink\n "suffix"`, rule, eol), false);
    });
  }
  test(`multiline SQL call selects SQL text and keeps dynamic text unresolved (${label})`, () => {
    for (const call of ['new SqlCommand', 'db.FromSqlRaw', 'db.ExecuteSqlRaw', 'db.ExecuteSqlRawAsync', 'db.SqlQueryRaw']) {
      assert.equal(proof(` ${call}("select " + // sink\n "1", connection);`, 'CS-SQLI-001', eol), true, call);
      assert.equal(proof(` ${call}("select " // sink\n + input, connection);`, 'CS-SQLI-001', eol), false, call);
    }
  });
  test(`nested SQL constructors are selected at new on the candidate line (${label})`, () => {
    assert.equal(proof(' var value = "1";\n new SqlCommand("SELECT " + value, connection); // sink', 'CS-SQLI-001', eol), true);
    // Single-line var is historical compatibility, not a type-identity proof.
    // Complete multiline eligibility must not inherit that unsupported claim.
    assert.equal(proof(' var value = "1";\n new // sink\n SqlCommand("SELECT " + value, connection);', 'CS-SQLI-001', eol), false);
    assert.equal(proof(' string value = "1";\n new // sink\n SqlCommand("SELECT " + value, connection);', 'CS-SQLI-001', eol), true);
    assert.equal(proof(' db.ExecuteSqlRaw("SELECT " + "1", new // sink\n SqlCommand("SELECT " + input, connection).ExecuteReader());', 'CS-SQLI-001', eol), false);
    assert.equal(proof(' db.ExecuteSqlRaw("SELECT " + "1", new SqlCommand("SELECT " + input, connection).ExecuteReader()); // sink', 'CS-SQLI-001', eol), false);
    assert.equal(proof(' db.ExecuteSqlRaw("SELECT " + "1", new // sink\n SqlCommand("SELECT " + "2", connection).ExecuteReader());', 'CS-SQLI-001', eol), true);
    assert.equal(proof(' new // sink\n SqlCommand("SELECT " + "2", connection);', 'CS-SQLI-001', eol), true);
  });
  test(`same-line SQL candidates outside the method prevent partial proof (${label})`, () => {
    for (const fieldValue of ['GetInput()', '"2"']) {
      const code = `class Sample {\n SqlCommand field = new SqlCommand("SELECT " + ${fieldValue}); void Run() { command.CommandText = "SELECT " +\n "1"; }\n}`.replace(/\n/g, eol);
      assert.equal(createCSharpConstantSinkProof(code)(1, 'CS-SQLI-001'), false, fieldValue);
    }
    for (const name of ['field', 'ExecuteSqlRaw']) {
      const code = `class Sample {\n string ${name} = "fixed"; void Run() { command.CommandText = "SELECT " +\n "1"; }\n}`.replace(/\n/g, eol);
      assert.equal(createCSharpConstantSinkProof(code)(1, 'CS-SQLI-001'), true);
    }
  });
}

test('nested private constant helpers keep expression ownership', () => {
  assert.equal(proof(' Process.Start("cmd.exe", "/c " + // sink\n Value());', undefined, '\n',
    'private string Value() { return "status"; }'), true);
  assert.equal(proof(' Process.Start("cmd.exe", "/c " + // sink\n Unknown(Value()));', undefined, '\n',
    'private string Value() { return "status"; }'), false);
});

test('generic raw SQL calls preserve constant proof compatibility', () => {
  for (const type of ['Dto', 'Models.Dto', 'global::Models.Dto', 'Result<string, List<Dto>>', 'Dto[]']) {
    assert.equal(proof(` const string value = "1";\n db.SqlQueryRaw<${type}>("SELECT " + value); // sink`, 'CS-SQLI-001'), true, type);
    assert.equal(proof(` db.SqlQueryRaw<${type}>("SELECT " + // sink\n input);`, 'CS-SQLI-001'), false, type);
  }
  for (const prefix of ['<Dto> + Unknown', '<Dto,>', '<>', '<Dto)>', '<Dto> Other', '<Dto = input>']) {
    assert.equal(proof(` db.SqlQueryRaw${prefix}("SELECT " + "1"); // sink`, 'CS-SQLI-001'), false, prefix);
  }
});

test('adjacent sinks on separate lines stay distinct while every same-line sink is checked', () => {
  assert.equal(proof(' Process.Start("cmd.exe", "/c " + // sink\n "status");\n Process.Start("cmd.exe", "/c " + input);'), true);
  assert.equal(proof(' Process.Start("fixed"); Process.Start("cmd.exe", // sink\n "/c " + input);'), false);
  assert.equal(proof(' command.CommandText = "select " + "1"; command.CommandText = "select " + // sink\n input;', 'CS-SQLI-001'), false);
  assert.equal(proof(' new SqlCommand("select " + "1"); command.CommandText = "select " + // sink\n input;', 'CS-SQLI-001'), false);
});

test('malformed and cross-method continuations cannot establish a proof', () => {
  assert.equal(proof(' Process.Start("cmd.exe", // sink\n "/c " + "status";'), false);
  const code = 'class Sample {\n void Run() {\n Process.Start("cmd.exe", "/c " + // sink\n }\n void Other() { "status"; }\n}';
  assert.equal(createCSharpConstantSinkProof(code)(2, 'CS-CMDI-001'), false);
});

test('CRLF normalization cannot bypass the original file-size budget', () => {
  const code = '\r\n'.repeat(1024 * 1024) + 'class Sample {\r\n void Run() {\r\n Process.Start("fixed");\r\n }\r\n}';
  assert.equal(createCSharpConstantSinkProof(code)(1024 * 1024 + 2, 'CS-CMDI-001'), false);
});

test('the scoped value fallback preserves the method-size budget', () => {
  const code = `class Sample {\n void Run() {\n /*${' '.repeat(50000)}*/\n Process.Start("fixed");\n }\n}`;
  assert.equal(createCSharpConstantSinkProof(code)(3, 'CS-CMDI-001'), false);
});

test('scanner removes multiline constant findings and retains dynamic twins', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-multiline-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [file, value] of [['Literal.cs', '"status"'], ['Input.cs', 'input']]) {
    fs.writeFileSync(path.join(root, file), `class Sample {\n void Run(string input) {\n Process.Start("cmd.exe", "/c " +\n ${value});\n command.CommandText = "select " +\n ${value};\n }\n}`.replace(/\n/g, '\r\n'));
  }
  const result = await scan(root, { includeTests: true });
  assert.deepEqual(result.findings.filter(f => ['CS-CMDI-001', 'CS-SQLI-001'].includes(f.ruleId))
    .map(f => [f.file, f.ruleId]).sort(), [['Input.cs', 'CS-CMDI-001'], ['Input.cs', 'CS-SQLI-001']]);
});

test('scanner retains nested and out-of-method SQL candidates sharing a safe sink line', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-sql-line-ownership-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
    fs.writeFileSync(path.join(root, `Nested${ending}.cs`), 'class Sample {\n void Run(string input) {\n db.ExecuteSqlRaw("SELECT " + "1", new\n SqlCommand("SELECT " + input, connection).ExecuteReader());\n }\n}'.replace(/\n/g, eol));
    fs.writeFileSync(path.join(root, `Field${ending}.cs`), 'class Sample {\n SqlCommand field = new SqlCommand("SELECT " + GetInput()); void Run() { command.CommandText = "SELECT " +\n "1"; }\n}'.replace(/\n/g, eol));
  }
  const result = await scan(root, { includeTests: true });
  assert.deepEqual(result.findings.filter(f => f.ruleId === 'CS-SQLI-001').map(f => [f.file, f.line]).sort(), [
    ['FieldCRLF.cs', 2], ['FieldLF.cs', 2], ['NestedCRLF.cs', 3], ['NestedLF.cs', 3],
  ]);
});

const bindingBodies = {
  localFunction: sink => `void Local(string value) { ${sink} }\n Local(input);`,
  foreach: sink => `foreach (string value in new[] { input }) { ${sink} }`,
  catch: sink => `try { Work(); } catch (System.Exception value) { ${sink} }`,
  parenthesizedLambda: sink => `System.Action<string> act = (value) => { ${sink} };\n act(input);`,
  typedLambda: sink => `System.Action<string> act = (string value) => { ${sink} };\n act(input);`,
  simpleLambda: sink => `System.Action<string> act = value => { ${sink} };\n act(input);`,
  anonymousDelegate: sink => `System.Action<string> act = delegate (string value) { ${sink} };\n act(input);`,
  forInitializer: sink => `for (string value = input; value != null; value = null) { ${sink} }`,
  typedOut: sink => `{ TryGet(input, out string value); ${sink} }`,
  pattern: sink => `{ if (((object)input) is string value) { ${sink} } }`,
};

function bindingFixture(body, eol, ownLine = false) {
  const sink = `${ownLine ? '\n' : ''}command.CommandText = "select " + // sink\n value;`;
  return `class Sample {\n void Run(string input) {\n { string value = "fixed"; }\n ${body(sink)}\n }\n private static bool TryGet(string input, out string result) { result = input; return true; }\n}`.replace(/\n/g, eol);
}

for (const [form, body] of Object.entries(bindingBodies)) {
  for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
    test(`multiline ${form} cannot inherit a sibling block literal (${ending})`, () => {
      for (const ownLine of [false, true]) {
        const code = bindingFixture(body, eol, ownLine);
        const line = code.split('\n').findIndex(text => text.includes('// sink'));
        assert.equal(createCSharpConstantSinkProof(code)(line, 'CS-SQLI-001'), false, String(ownLine));
      }
    });
  }
}

test('unsupported multiline binding scopes do not block ordinary proven constant bindings', () => {
  assert.equal(proof(' { string other = "ignored"; }\n const string value = "1";\n command.CommandText = "SELECT " + // sink\n value;', 'CS-SQLI-001'), true);
  assert.equal(proof(' const string value = "status";\n var info = new ProcessStartInfo("cmd.exe") { UseShellExecute = false };\n info.Arguments = "/c echo " + // sink\n value;'), true);
  assert.equal(proof(' void Local() { command.CommandText = "SELECT " + // sink\n "1"; }', 'CS-SQLI-001'), false);
});

test('scanner retains all unsupported-binding twins in both line layouts and endings', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-binding-ownership-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const expected = [];
  for (const [form, body] of Object.entries(bindingBodies)) {
    for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
      for (const ownLine of [false, true]) {
        const file = `${form}${ending}${ownLine}.cs`;
        fs.writeFileSync(path.join(root, file), bindingFixture(body, eol, ownLine));
        expected.push(file);
      }
    }
  }
  const result = await scan(root, { includeTests: true });
  assert.deepEqual(result.findings.filter(f => f.ruleId === 'CS-SQLI-001').map(f => f.file).sort(), expected.sort());
});

// The complete-expression boundary must not expose weaker ordinary-method
// binding evidence. Disabling any strict guard restores an unsafe suppression.
const integrationVariants = {
  coalesce: { body: 'string value = null; value ??= input;' },
  wrappedCoalesce: { body: 'string value = null; ((value)) ??= input;' },
  wrappedPlus: { body: 'string value = "fixed"; (value) += input;' },
  wrappedRef: { body: 'string value = "fixed"; ref string alias = ref (value); alias = input;' },
  namedVar: { type: 'var', body: 'var value = "fixed";' },
  namedString: { type: 'String', body: 'String value = "fixed";' },
  siblingUnknown: { type: 'Text', body: '{ string value = "unrelated"; } { Text value = "fixed";', tail: '}' },
  importedString: { prefix: 'using External;\n', body: 'String value = "fixed";' },
  importedVar: { prefix: 'using External;\n', body: 'var value = "fixed";' },
  unknownVar: { body: 'var value = "fixed";' },
  from: { query: 'from value in inputs' },
  typedFrom: { query: 'from string value in inputs' },
  escapedFrom: { query: 'from @value in inputs' },
  join: { query: 'from item in inputs join value in inputs on item equals value' },
  into: { query: 'from item in inputs select item into value' },
  literal: { body: 'string value = "fixed";', safe: true },
  unrelatedMutation: { body: 'string value = "fixed"; string other = null; (other) ??= input;', safe: true },
  inertQueryText: { body: 'string value = "from item in inputs"; string @from = "ignored"; /* from value in inputs */', safe: true },
};
const integrationSinks = {
  sql: ['CS-SQLI-001', 'new SqlCommand("SELECT " +\n value, connection)'],
  arguments: ['CS-CMDI-001', 'info.Arguments = "/c " +\n value'],
  processTwo: ['CS-CMDI-001', 'Process.Start("cmd.exe", "/c " +\n value)'],
};
function integrationFixture(variant, call, eol) {
  const conversion = variant.type ? `class ${variant.type} { public static implicit operator ${variant.type}(string text) { return new ${variant.type}(); } public override string ToString() { return System.Environment.GetEnvironmentVariable("QUERY"); } }\n` : '';
  const body = variant.query ? `{ string value = "unrelated"; }\n var query = ${variant.query}\n select ${call};\n query.ToList();` : `${variant.body}\n ${call};\n ${variant.tail || ''}`;
  return (`using Microsoft.Data.SqlClient;\nusing System.Diagnostics;\nusing System.Linq;\n${variant.prefix || ''}${conversion}class Sample {\n void Run(string input, string[] inputs, SqlConnection connection) {\n ${body}\n }\n}`).replace(/\n/g, eol);
}
for (const [name, variant] of Object.entries(integrationVariants)) {
  for (const [sink, [rule, call]] of Object.entries(integrationSinks)) {
    // A query select must contain an expression; assignment is not a candidate
    // in this query shape, so query engine coverage uses SQL/Process calls.
    if (variant.query && sink === 'arguments') continue;
    for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
      test(`ordinary multiline integration ${name}/${sink}/${ending}`, () => {
        const code = integrationFixture(variant, call, eol);
        const line = code.split('\n').findIndex(text => text.includes(call.split('\n')[0]));
        assert.equal(createCSharpConstantSinkProof(code)(line, rule), !!variant.safe);
      });
    }
  }
}

test('engine retains unsafe ordinary multiline identities and literal controls', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-multiline-integration-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const expected = [];
  for (const [name, variant] of Object.entries(integrationVariants)) {
    for (const [sink, [rule, call]] of Object.entries(integrationSinks)) {
      if (variant.query && sink === 'arguments') continue;
      for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
        const file = `${name}-${sink}-${ending}.cs`, code = integrationFixture(variant, call, eol);
        fs.writeFileSync(path.join(root, file), code);
        if (!variant.safe) expected.push([file, rule, code.split('\n').findIndex(text => text.includes(call.split('\n')[0])) + 1]);
      }
    }
  }
  const result = await scan(root, { includeTests: true });
  assert.deepEqual(result.findings.filter(f => ['CS-CMDI-001', 'CS-SQLI-001'].includes(f.ruleId)).map(f => [f.file, f.ruleId, f.line]).sort(), expected.sort());
});

test('strict multiline fallback follows mutation and query guards into helpers', () => {
  for (const body of [
    'string value = null; (value) ??= System.Environment.GetEnvironmentVariable("QUERY"); return value;',
    'string value = "fixed"; var query = from item in new[] { "fixed" } select item; return value;',
  ]) {
    assert.equal(proof('Process.Start("cmd.exe", "/c " + // sink\n Value());', undefined, '\n', `private string Value() { ${body} }`), false);
  }
  assert.equal(proof('Process.Start("cmd.exe", "/c " + // sink\n value);', undefined, '\n',
    'private string value; public void Set(string input) { (value) ??= input; }'), false);
});

test('strict and legacy cached proof contexts are independent of query order', () => {
  const code = 'class Sample {\n void Run(string input) {\n string value = null; (value) ??= input;\n new SqlCommand("SELECT " + value, connection);\n new SqlCommand("SELECT " +\n value, connection);\n }\n}';
  for (const order of [[3, 4], [4, 3]]) {
    const prove = createCSharpConstantSinkProof(code);
    for (const line of order) assert.equal(prove(line, 'CS-SQLI-001'), line === 3);
  }
});
