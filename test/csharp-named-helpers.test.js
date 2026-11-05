'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createCSharpConstantSinkProof } = require('../src/csharp-constant-sinks');
const { createCSharpValueProof } = require('../src/csharp-values');
const { parseCSharp } = require('../src/parsers/csharp/parser');
const { tokenizeCSharp } = require('../src/parsers/csharp/lexer');
const { scan } = require('../src/engine');

const helper = 'private static string Pick(string unused, string selected) { return selected; }';
const safe = 'Pick(unused: "ignored", selected: "fixed")';
const unsafe = 'Pick(unused: "ignored", selected: input)';
function fixture(body, member = helper, owner = 'class Sample') {
  return `${owner} {\n ${member}\n void Run(string input, bool flag) {\n ${body}\n }\n}`;
}
function prove(code, rule = 'CS-CMDI-001', marker = '// sink') {
  const line = code.split('\n').findIndex(text => text.includes(marker));
  assert.notEqual(line, -1);
  return createCSharpConstantSinkProof(code)(line, rule);
}

// Removing contextual argument binding, or reusing an answer across invocations,
// must break these literal expectations. The unsafe twin uses the same helper.
for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
  for (const [form, rule, sink] of [
    ['process', 'CS-CMDI-001', value => `Process.Start("cmd.exe", "/c " + ${value});`],
    ['arguments', 'CS-CMDI-001', value => `info.Arguments = "/c " + ${value};`],
    ['assignment', 'CS-SQLI-001', value => `command.CommandText = "SELECT " + ${value};`],
    ['constructor', 'CS-SQLI-001', value => `new SqlCommand("SELECT " + ${value}, connection);`],
  ]) {
    test(`named ${form} proves only its own invocation in both argument orders (${ending})`, () => {
      const code = fixture([
        sink(safe) + ' // safe1', sink(unsafe) + ' // unsafe1',
        sink('Pick(selected: "fixed", unused: "ignored")') + ' // safe2',
        sink('Pick(selected: input, unused: "ignored")') + ' // unsafe2',
      ].join('\n')).replace(/\n/g, eol);
      const proof = createCSharpConstantSinkProof(code);
      const lines = code.split('\n');
      for (const markers of [['safe1', 'unsafe1', 'safe2', 'unsafe2'], ['unsafe2', 'safe2', 'unsafe1', 'safe1']]) {
        for (const marker of markers) assert.equal(proof(lines.findIndex(line => line.includes('// ' + marker)), rule), marker.startsWith('safe'), marker);
      }
    });
  }

  test(`named proofs preserve same-line and multiline sink anchors (${ending})`, () => {
    for (const body of [
      `Process.Start("cmd /c " + ${safe}); Process.Start("cmd /c " + ${unsafe}); // sink`,
      `command.CommandText = "SELECT " + ${safe}; new SqlCommand("SELECT " + ${unsafe}); // sink`,
      `SqlCommand field = new SqlCommand("SELECT " + ${unsafe}); // sink`,
    ]) assert.equal(prove(fixture(body).replace(/\n/g, eol), body.includes('Process') ? 'CS-CMDI-001' : 'CS-SQLI-001'), false, body);
    assert.equal(prove(fixture(`new // sink\n SqlCommand("SELECT " + Pick(selected: "fixed",\n unused: "ignored"), connection);`).replace(/\n/g, eol), 'CS-SQLI-001'), true);
    const field = `class Sample {\n ${helper}\n SqlCommand field = new SqlCommand("SELECT " + ${unsafe}); void Run() { command.CommandText = "SELECT " + ${safe}; } // sink\n}`;
    assert.equal(prove(field.replace(/\n/g, eol), 'CS-SQLI-001'), false);
  });
}

test('returned formal identity is independent of named argument position', () => {
  const member = helper.replace('return selected', 'return unused');
  for (const call of ['Pick(selected: input, unused: "fixed")', 'Pick(unused: "fixed", selected: input)']) {
    // All actuals must be exact pure literals, even when an unused value is string-typed.
    assert.equal(prove(fixture(`Process.Start("cmd /c " + ${call}); // sink`, member)), false);
  }
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, member)), true);
  assert.equal(prove(fixture('Process.Start("cmd /c " + Pick(selected: "fixed", unused: input)); // sink', member)), false);
});

test('escaped formal and actual names use normalized binding identities', () => {
  const member = 'private static string Pick(string @unused, string @return) { return @return; }';
  assert.equal(prove(fixture('Process.Start("cmd /c " + Pick(@return: "fixed", unused: "ignored")); // sink', member)), true);
  assert.equal(prove(fixture('Process.Start("cmd /c " + Pick(@unused: "fixed", unused: "ignored")); // sink', member)), false);
});

test('malformed, mixed, unknown and duplicate argument bindings stay unknown', () => {
  for (const args of [
    '"ignored", selected: "fixed"', 'unused: "ignored", "fixed"',
    'unused: "ignored", unknown: "fixed"', 'unused: "ignored", Selected: "fixed"',
    'unused: "ignored", unused: "fixed"', 'unused: "ignored", @unused: "fixed"',
    'selected: "fixed"', 'unused: "ignored", selected: "fixed", extra: ""',
    'unused: , selected: "fixed"', ': "ignored", selected: "fixed"',
    'unused: "ignored", selected:', ',selected: "fixed"',
    'unused: "ignored", selected: "fixed",', 'unused:: "ignored", selected: "fixed"',
    ': "ignored", "fixed"', '123: "ignored", "fixed"',
    ', "fixed"', '"ignored",',
  ]) assert.equal(prove(fixture(`Process.Start("cmd /c " + Pick(${args})); // sink`)), false, args);
});

test('every named actual must be a pure built-in string literal, including unused values', () => {
  for (const actual of [
    'input', 'value', 'this.saved', 'external.Value', 'Read()', 'new Text()',
    '(value = input)', 'value++', 'flag ? "a" : "b"', '(Mutate() ? "a" : "b")',
    '"a" ?? "b"', '("fixed")', '"a" + "b"', '(string)value',
    'null', '42', "'x'", 'true', '"bytes"u8', '"""bytes"""u8',
    '$"{value = input}"', 'Pick(unused: "a", selected: "b")',
  ]) for (const args of [`unused: ${actual}, selected: "fixed"`, `selected: "fixed", unused: ${actual}`, `unused: "ignored", selected: ${actual}`]) {
    const code = fixture(`string value = "fixed";\n Process.Start("cmd /c " + Pick(${args})); // sink`);
    assert.equal(prove(code), false, args);
  }
  for (const literal of ['"fixed"', '@"fixed"', '"""fixed"""']) {
    assert.equal(prove(fixture(`Process.Start("cmd /c " + Pick(selected: ${literal}, unused: "")); // sink`)), true, literal);
  }
});

test('strict helper declarations reject conversions, overloads, modifiers and effects', () => {
  for (const member of [
    helper.replace('string selected', 'String selected'), helper.replace('string unused', 'Text unused'),
    helper.replace('static string Pick', 'static String Pick'), helper.replace('string selected', 'dynamic selected'),
    helper.replace('string selected', 'string selected = "default"'), helper.replace('string unused', 'params string[] unused'),
    ...['ref', 'out', 'in'].map(modifier => helper.replace('string unused', modifier + ' string unused')),
    helper.replace('Pick(', 'Pick<T>('), helper + ' private static string Pick(int n) { return "bad"; }',
    helper.replace('string unused', 'string selected'), helper.replace('return selected;', 'selected = Read(); return selected;'),
    helper.replace('return selected;', 'Mutate(); return selected;'), helper.replace('return selected;', 'return Pick(unused: "x", selected: selected);'),
    helper.replace('return selected;', 'if (flag) return selected; return unused;'),
    helper.replace('return selected;', 'string value = selected; return value;'),
    helper.replace('return selected;', 'return "fixed";'), helper.replace('private', 'public'),
    helper.replace('static ', ''), helper.replace('private static', 'private async static'),
    helper.replace('string selected', '[Custom] string selected'), helper.replace('string selected', 'string return').replace('return selected;', 'return return;'),
  ]) assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, member)), false, member);
  const alias = 'using String = string;\n' + fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper.replace('string selected', 'String selected'));
  assert.equal(prove(alias), false);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper, 'class Sample : ExternalBase<int>')), false);
});

test('exact string applicability resolves the declared private member independently of an external base spelling', () => {
  for (const base of ['ExternalBase', 'ControllerBase', 'Unknown.Parent']) {
    assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper, 'class Sample : ' + base)), true, base);
    // An inapplicable declaration cannot exclude inherited overload lookup.
    assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper.replace('string unused', 'int unused'), 'class Sample : ' + base)), false, base);
    assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper.replace('string unused', 'Convertible unused'), 'class Sample : ' + base)), false, base);
  }
  // A local base with a same-named overload exceeds single-owner proof scope.
  const code = 'class Parent { protected static string Pick(string unused, string selected) { return Read(); } }\n' + fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper, 'class Sample : Parent');
  assert.equal(prove(code), false);
});

test('receivers and caller binding shadows cannot borrow a private helper proof', () => {
  assert.equal(prove(fixture(`Process.Start("cmd /c " + Sample.${safe}); // sink`)), true);
  for (const call of ['this.' + safe, 'external.' + safe, 'base.' + safe, safe.replace('Pick(', 'Pick<string>(')]) {
    assert.equal(prove(fixture(`Process.Start("cmd /c " + ${call}); // sink`)), false, call);
  }
  for (const body of [
    `dynamic Pick = Read(); Process.Start("cmd /c " + ${safe}); // sink`,
    `dynamic Sample = Read(); Process.Start("cmd /c " + Sample.${safe}); // sink`,
    `try { Work(); } catch (ExternalException Pick) { Process.Start("cmd /c " + ${safe}); } // sink`,
    `var query = from Pick in delegates select Pick(unused: "a", selected: "b");\n Process.Start("cmd /c " + ${safe}); // sink`,
    `var (Pick, other) = Read();\n Process.Start("cmd /c " + ${safe}); // sink`,
    `(dynamic Pick, string other) = Read();\n Process.Start("cmd /c " + ${safe}); // sink`,
    `var (Sample, other) = Read();\n Process.Start("cmd /c " + Sample.${safe}); // sink`,
  ]) assert.equal(prove(fixture(body)), false, body);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`).replace('Run(string input, bool flag)', 'Run(dynamic Pick)')), false);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper, 'class Sample(Handler Pick)')), false);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + Sample.${safe}); // sink`, helper, 'class Sample(Handler Sample)')), false);
});

for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
  for (const [form, rule, sink] of [
    ['command', 'CS-CMDI-001', value => `Process.Start("cmd.exe", "/c " + ${value});`],
    ['SQL', 'CS-SQLI-001', value => `command.CommandText = "SELECT " + ${value};`],
  ]) {
    test(`named ${form} requires closed owner identity for a qualified receiver (${ending})`, () => {
      const body = sink('Sample.' + safe) + ' // sink';
      assert.equal(prove(fixture(body).replace(/\n/g, eol), rule), true);
      for (const base of ['ExternalBase', 'Unknown.Parent', 'global::ExternalBase', '@ExternalBase', 'Alias::ExternalBase']) {
        assert.equal(prove(fixture(body, helper, 'class Sample : ' + base).replace(/\n/g, eol), rule), false, base);
        assert.equal(prove(fixture(sink(safe) + ' // sink', helper, 'class Sample : ' + base).replace(/\n/g, eol), rule), true, base);
      }
    });

    test(`positional ${form} checks every top-level conditional colon before fallback (${ending})`, () => {
      for (const actual of [
        'flag ? "a" : "b": "ignored"',
        'flag ? flag ? "a" : "b" : "c": "ignored"',
        'flag ? "a" : flag ? "b" : "c": "ignored"',
        'flag ? (flag ? "a" : "b") : "c": "ignored"',
        'flag ? "a" : (flag ? "b" : "c"): "ignored"',
        'flag ? "a"', 'flag ? flag ? "a" : "b"',
      ]) {
        const body = sink(`Pick(${actual}, "fixed")`) + ' // sink';
        assert.equal(prove(fixture(body).replace(/\n/g, eol), rule), false, actual);
      }
      for (const actual of [
        'flag ? "a" : "b"',
        'flag ? flag ? "a" : "b" : "c"',
        'flag ? "a" : flag ? "b" : "c"',
        'flag ? (flag ? "a" : "b") : "c"',
        'flag ? "a" : (flag ? "b" : "c")',
      ]) {
        const body = sink(`Pick(${actual}, "fixed")`) + ' // sink';
        assert.equal(prove(fixture(body).replace(/\n/g, eol), rule), true, actual);
      }
    });

    test(`positional ${form} preserves conditional element access and composition (${ending})`, () => {
      for (const actual of [
        'values?[0]', '(values?[0])', 'values ? [0]',
        'values?[0] ?? "ignored"', '(values?[0] ?? "ignored")',
        'flag ? values?[0] : "ignored"', 'flag ? "ignored" : values?[0]',
        'flag ? values?[0] : values?[1]',
        'values?[0] ?? (flag ? "a" : "b")',
        'flag ? (values?[0] ?? "a") : "b"',
      ]) {
        const code = fixture(sink(`Pick(${actual}, "fixed")`) + ' // sink')
          .replace('Run(string input, bool flag)', 'Run(bool flag, string[] values)').replace(/\n/g, eol);
        assert.equal(prove(code, rule), true, actual);
      }
      for (const actual of ['values?[0] ? "a"', 'flag ? values?[0]', 'values?[0] ?? "a": "ignored": "extra"']) {
        const code = fixture(sink(`Pick(${actual}, "fixed")`) + ' // sink')
          .replace('Run(string input, bool flag)', 'Run(bool flag, string[] values)').replace(/\n/g, eol);
        assert.equal(prove(code, rule), false, actual);
      }
      const named = fixture(sink('Pick(unused: values?[0], selected: "fixed")') + ' // sink')
        .replace('Run(string input, bool flag)', 'Run(bool flag, string[] values)').replace(/\n/g, eol);
      assert.equal(prove(named, rule), false);
    });

    test(`positional ${form} preserves existing collection-expression conditional classification (${ending})`, () => {
      // The legacy path can ignore an unused external collection formal. A ? [
      // token sequence is also possible in a target-typed collection ternary;
      // do not turn this compatibility check into new type or purity inference.
      const member = helper.replace('string unused', 'ExternalCollection unused');
      for (const actual of [
        'flag ? ["a"] : ["b"]',
        'flag ? (flag ? ["a"] : ["b"]) : ["c"]',
        'flag ? ["a"] : flag ? ["b"] : ["c"]',
        'flag ? [..values] : []',
      ]) {
        const code = fixture(sink(`Pick(${actual}, "fixed")`) + ' // sink', member)
          .replace('Run(string input, bool flag)', 'Run(bool flag, string[] values)').replace(/\n/g, eol);
        assert.equal(prove(code, rule), true, actual);
      }
    });
  }

  test(`inherited field and property receivers retain scanner candidates (${ending})`, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-inherited-named-'));
    t.after(() => fs.rmSync(root, {recursive:true, force:true}));
    for (const member of [
      'protected dynamic Sample;', 'protected dynamic Sample { get; set; }',
      'protected Provider Sample;', 'protected Provider Sample { get; set; }',
      'private dynamic Sample;',
    ]) {
      // The two target files are static scanner input, never compiled/imported.
      // No inaccessible/private external-member closure is inferred either.
      fs.writeFileSync(path.join(root, 'Base.cs'), `class ExternalBase { ${member} }`.replace(/\n/g, eol));
      const body = [
        `info.Arguments = "/c " + Sample.${safe};`,
        `command.CommandText = "SELECT " + Sample.${safe};`,
        `info.Arguments = "/c " + ${safe};`,
        `command.CommandText = "SELECT " + ${safe};`,
      ].join('\n');
      fs.writeFileSync(path.join(root, 'Operations.cs'), fixture(body, helper, 'class Sample : ExternalBase').replace(/\n/g, eol));
      const result = await scan(root, {includeTests:true});
      assert.deepEqual(result.findings.filter(f => ['CS-CMDI-001', 'CS-SQLI-001'].includes(f.ruleId)).map(f => [f.ruleId, f.file, f.line]), [
        ['CS-CMDI-001', 'Operations.cs', 4], ['CS-SQLI-001', 'Operations.cs', 5],
      ], member);
    }
  });
}

test('primary-owner gates remain in force around newly supported literal calls', () => {
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper, 'class Sample(string input)')), true);
  for (const owner of ['class Sample<T>', 'partial class Sample', 'class Sample(string input = "default")', 'class Sample(string input) : Parent(input)']) {
    assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper, owner)), false, owner);
  }
  const code = fixture(`{ string input = "fixed"; }\n Process.Start("cmd /c " + ${unsafe}); // sink`, helper, 'class Sample(string input)').replace('Run(string input, bool flag)', 'Run()');
  assert.equal(prove(code), false);
});

test('helper-internal sinks keep all-callers conservatism and positional behavior', () => {
  for (const calls of ['Sink("fixed"); Sink(input);', 'Sink(value: "fixed"); Sink(value: input);']) {
    const code = `class Sample {\n void Run(string input) { ${calls} }\n private static void Sink(string value) {\n Process.Start("cmd /c " + value); // sink\n }\n}`;
    assert.equal(prove(code), false, calls);
  }
  assert.equal(prove(fixture('Process.Start("cmd /c " + Pick("ignored", "fixed")); // sink')), true);
  assert.equal(prove(fixture('Process.Start("cmd /c " + Pick(flag ? "a" : "b", "fixed")); // sink')), true);
  const code = fixture('Process.Start("cmd /c " + Pick("ignored", "fixed")); // sink\n Pick("ignored", input);');
  assert.equal(prove(code), false);
});

function branchFixture(levels, width = 3) {
  const members = ['private static string H0() { return "fixed"; }'];
  for (let n = 1; n <= levels; n++) members.push(`private static string H${n}() { return ${Array(width).fill(`H${n - 1}()`).join(' + ')}; }`);
  return fixture(`Process.Start("cmd /c " + H${levels}()); // expensive\n Process.Start("cmd /c " + ${safe}); // cheap`, helper + '\n' + members.join('\n'));
}

test('a shared query budget bounds branching expansion and resets between queries', () => {
  assert.equal(prove(branchFixture(3), 'CS-CMDI-001', '// expensive'), true);
  const code = branchFixture(10), proof = createCSharpConstantSinkProof(code), lines = code.split('\n');
  const expensive = lines.findIndex(line => line.includes('// expensive')), cheap = lines.findIndex(line => line.includes('// cheap'));
  assert.equal(proof(expensive, 'CS-CMDI-001'), false);
  assert.equal(proof(cheap, 'CS-CMDI-001'), true);
  assert.equal(proof(expensive, 'CS-CMDI-001'), false);
  assert.equal(proof(cheap, 'CS-CMDI-001'), true);
});

test('recursion and existing size, depth and lexer/parser limits retain unknown', () => {
  for (const member of [
    'private static string A() { return A(); }',
    'private static string A() { return B(); } private static string B() { return A(); }',
  ]) assert.equal(prove(fixture('Process.Start("cmd /c " + A()); // sink', member)), false);
  const controls = [
    fixture(`Process.Start("cmd /c " + ${safe}); // sink`, helper + '\n' + Array.from({length:255}, (_, n) => `private void M${n}() {}`).join('\n')),
    fixture(`/*${' '.repeat(50001)}*/ Process.Start("cmd /c " + ${safe}); // sink`),
    fixture(`Process.Start("cmd /c " + ${safe}); // sink\n` + 'value;'.repeat(10001)),
    fixture(`Process.Start("cmd /c " + ${Array(70).fill(safe).join(' + ')}); // sink`),
    fixture(`Process.Start("cmd /c " + ${safe}); // sink`).replace('selected; }', 'selected;'),
    fixture(`Process.Start("cmd /c " + ${safe}); // sink\n "unterminated`),
  ];
  for (const code of controls) assert.equal(prove(code), false, code.slice(0, 120));
  assert.equal(prove(branchFixture(25, 1), 'CS-CMDI-001', '// expensive'), false);
});

test('bounded named literal calls remain provable immediately below existing work and size gates', () => {
  const call = fixture(`Process.Start("cmd /c " + ${safe}); // sink`);
  const count = tokenizeCSharp(call).tokens.length;
  assert.equal(prove(';'.repeat(20000 - count) + call), true);
  assert.equal(prove(';'.repeat(20001 - count) + call), false);
  const atMethods = helper + '\n' + Array.from({length:254}, (_, n) => `private void M${n}() {}`).join('\n');
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, atMethods)), true);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${safe}); // sink`, atMethods + '\nprivate void Extra() {}')), false);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${Array(23).fill(safe).join(' + ')}); // sink`)), true);
  assert.equal(prove(fixture(`Process.Start("cmd /c " + ${Array(24).fill(safe).join(' + ')}); // sink`)), false);
  const withComment = fixture(`/**/ Process.Start("cmd /c " + ${safe}); // sink`);
  const method = parseCSharp(withComment).methods.find(m => m.name === 'Run');
  const padding = 50000 - (method.end - method.start);
  assert.equal(prove(withComment.replace('/**/', '/*' + ' '.repeat(padding) + '*/')), true);
  assert.equal(prove(withComment.replace('/**/', '/*' + ' '.repeat(padding + 1) + '*/')), false);
  assert.equal(prove(branchFixture(24, 1), 'CS-CMDI-001', '// expensive'), false);
  assert.equal(prove(branchFixture(22, 1), 'CS-CMDI-001', '// expensive'), true);
});

test('value proof invocation maps never leak across expressions or proof order', () => {
  const code = fixture(`string a = ${safe};\n string b = ${unsafe};`);
  const lex = tokenizeCSharp(code), ast = parseCSharp(code), proof = createCSharpValueProof(code, ast);
  const calls = lex.tokens.map((token, n) => [token, n]).filter(([token, n]) => token.text === 'Pick' && lex.tokens[n - 1]?.text === '=');
  const expressions = calls.map(([, n]) => lex.tokens.slice(n, lex.tokens.findIndex((token, i) => i > n && token.text === ';')));
  for (const n of [0, 1, 1, 0, 1, 0]) assert.equal(proof(expressions[n]), n === 0);
});

test('scanner keeps unsafe named twins and removes only literal invocation findings', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-named-helpers-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const body = [
    `info.Arguments = "/c " + ${safe};`,
    `info.Arguments = "/c " + ${unsafe};`,
    'command.CommandText = "SELECT " + Pick(selected: "fixed", unused: "ignored");',
    'command.CommandText = "SELECT " + Pick(selected: input, unused: "ignored");',
    `new SqlCommand("SELECT " + ${safe}, connection);`,
    `new SqlCommand("SELECT " + ${unsafe}, connection);`,
  ].join('\n');
  fs.writeFileSync(path.join(root, 'Operations.cs'), fixture(body));
  const result = await scan(root, {includeTests: true});
  assert.deepEqual(result.findings.filter(f => ['CS-CMDI-001', 'CS-SQLI-001'].includes(f.ruleId)).map(f => [f.ruleId, f.file, f.line]), [
    ['CS-CMDI-001', 'Operations.cs', 5], ['CS-SQLI-001', 'Operations.cs', 7], ['CS-SQLI-001', 'Operations.cs', 9],
  ]);
});
