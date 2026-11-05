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
