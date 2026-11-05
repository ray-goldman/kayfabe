'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseCSharp } = require('../src/parsers/csharp/parser');
const { createCSharpConstantSinkProof } = require('../src/csharp-constant-sinks');
const { scan } = require('../src/engine');
const { tokenizeCSharp } = require('../src/parsers/csharp/lexer');
const { parenthesizedMutationTokens } = require('../src/csharp-mutations');

function prove(source, rule = 'CS-SQLI-001', eol = '\n') {
  const code = source.replace(/\n/g, eol);
  return createCSharpConstantSinkProof(code)(code.split('\n').findIndex(line => line.includes('// sink')), rule);
}

test('wrapped mutation recognition fails closed for malformed and over-budget operands', () => {
  for (const source of ['(value', 'value)', '('.repeat(1000) + 'value' + ') += input'.repeat(1000), ';'.repeat(20001)]) {
    assert.equal(parenthesizedMutationTokens(tokenizeCSharp(source).tokens), null);
  }
  const tokens = tokenizeCSharp('((value)) += input; ref (((other)));').tokens;
  assert.deepEqual(parenthesizedMutationTokens(tokens).map(token => token.text), ['value', 'other']);
});

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

const primaryShapes = ['class Sample(string input)', 'struct Sample(string input)', 'record Sample(string input)',
  'record class Sample(string input)', 'record struct Sample(string input)', 'class Sample()'];
const wrappedMutations = [
  ['string value = null; (value) ??= input;', false],
  ['string value = null; ((value)) ??= input;', false],
  ['string value = "fixed"; (value) += input;', false],
  ['string value = "fixed"; ((value)) += input;', false],
  ['string value = "fixed"; (value) = input;', false],
  ['string value = "fixed"; ref string alias = ref value; alias = input;', false],
  ['string value = "fixed"; ref string alias = ref (value); alias = input;', false],
  ['string value = "fixed"; ref string alias = ref (((value))); alias = input;', false],
  ['string value = "fixed"; string other = null; ((other)) ??= input;', true],
  ['string value = "fixed"; string other = ""; ((other)) += input;', true],
  ['string value = "fixed";', true],
];

for (const header of primaryShapes) for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
  for (const [rule, sink] of [
    ['CS-SQLI-001', 'command.CommandText = "SELECT " + VALUE;'],
    ['CS-CMDI-001', 'info.Arguments = "/c " + VALUE;'],
    ['CS-CMDI-001', 'Process.Start("cmd.exe", "/c " + VALUE);'],
  ]) {
    test(`${header} tracks wrapped mutation/ref operands for ${sink.split(' =')[0]} (${ending})`, () => {
      for (const [body, expected] of wrappedMutations) for (const multiline of [false, true]) {
        const code = `${header} {\n void Run(string input) {\n ${body}\n ${sink.replace('VALUE', multiline ? '// sink\n value' : 'value')} ${multiline ? '' : '// sink'}\n }\n}`;
        assert.equal(prove(code, rule, eol), expected, body);
      }
      const helper = `${header} {\n private string value;\n void Set(string input) { value = "fixed"; ((this.value)) += input; }\n private string Value() { return value; }\n void Run() {\n ${sink.replace('VALUE', 'Value()')} // sink\n }\n}`;
      assert.equal(prove(helper, rule, eol), false);
    });
  }
}
const queries = {
  from: 'from value in inputs',
  typedFrom: 'from string value in inputs',
  escapedFrom: 'from @value in inputs',
  join: 'from item in inputs join value in inputs on item equals value',
  into: 'from item in inputs select item into value',
  let: 'from item in inputs let value = item',
};

for (const header of primaryShapes) {
  for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
    test(`${header} rejects relevant null-coalescing writes but preserves unrelated writes (${ending})`, () => {
      for (const [rule, lhs] of [['CS-SQLI-001', 'command.CommandText'], ['CS-CMDI-001', 'info.Arguments']]) {
        for (const multiline of [false, true]) {
          const source = `${header} {\n void Run(string input) {\n BODY\n ${lhs} = "prefix " + ${multiline ? '// sink\n value;' : 'value; // sink'}\n }\n}`;
          assert.equal(prove(source.replace('BODY', 'string value = null; value ??= input;'), rule, eol), false);
          assert.equal(prove(source.replace('BODY', 'string value = null; value ??= Unknown();'), rule, eol), false);
          assert.equal(prove(source.replace('BODY', 'string value = "fixed"; string other = null; other ??= input;'), rule, eol), true);
          assert.equal(prove(source.replace('BODY', 'string value = "fixed";'), rule, eol), true);
          for (const operator of ['%=', '&=', '|=', '^=', '<<=', '>>=']) {
            const numeric = source.replace('Run(string input)', 'Run(int input)').replace('BODY', `int value = 1; value ${operator} input;`);
            assert.equal(prove(numeric, rule, eol), false, operator);
            const unrelated = source.replace('Run(string input)', 'Run(int input)').replace('BODY', `int value = 1; int other = 1; other ${operator} input;`);
            assert.equal(prove(unrelated, rule, eol), true, operator);
          }
        }
      }
    });
    test(`${header} does not borrow locals or fields for query range bindings (${ending})`, () => {
      for (const query of Object.values(queries)) for (const multiline of [false, true]) {
        for (const literalSource of [false, true]) {
          const source = `${header} {\n void Run(string[] inputs) {\n { string value = "fixed"; }\n { var query = ${literalSource ? query.replaceAll('inputs', 'new[] { "fixed" }') : query}\n select new SqlCommand("SELECT " + ${multiline ? '// sink\n value);' : 'value); // sink'}\n query.ToList(); }\n }\n}`;
          assert.equal(prove(source, 'CS-SQLI-001', eol), false, query);
        }
      }
      const field = `${header} {\n private string value;\n void Set() { value = "fixed"; }\n void Run(string[] inputs) { var query = from value in inputs\n select new SqlCommand("SELECT " + value); // sink\n }\n}`;
      assert.equal(prove(field, 'CS-SQLI-001', eol), false);
      const helper = `${header} {\n private string Value() { return "fixed"; }\n void Run(System.Func<string>[] inputs) { var query = from Value in inputs\n select new SqlCommand("SELECT " + Value()); // sink\n }\n}`;
      assert.equal(prove(helper, 'CS-SQLI-001', eol), false);
      for (const declaration of ['string from = "fixed";', 'string @from = "fixed";', 'string from = "from value in inputs"; /* from value in inputs */']) {
        assert.equal(prove(`${header} {\n void Run() { ${declaration}\n command.CommandText = "SELECT " + from; // sink\n }\n}`, 'CS-SQLI-001', eol), true, declaration);
      }
    });
  }
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

const primaryBindings = {
  localFunction: sink => `void Local(string value) { ${sink} } Local(input);`,
  foreach: sink => `foreach (string value in new[] { input }) { ${sink} }`,
  catch: sink => `try { Work(); } catch (System.Exception value) { ${sink} }`,
  parenthesizedLambda: sink => `System.Action<string> act = (value) => { ${sink} }; act(input);`,
  typedLambda: sink => `System.Action<string> act = (string value) => { ${sink} }; act(input);`,
  simpleLambda: sink => `System.Action<string> act = value => { ${sink} }; act(input);`,
  anonymousDelegate: sink => `System.Action<string> act = delegate (string value) { ${sink} }; act(input);`,
  forInitializer: sink => `for (string value = input; value != null; value = null) { ${sink} }`,
  typedOut: sink => `{ TryGet(input, out string value); ${sink} }`,
  pattern: sink => `{ if (((object)input) is string value) { ${sink} } }`,
};

test('unrelated unsupported declarations and named default parameters do not block keyword locals', () => {
  for (const [rule, lhs] of [['CS-SQLI-001', 'command.CommandText'], ['CS-CMDI-001', 'info.Arguments']]) {
    const source = `class Other {}\nclass Sample(string connectionString) {\n public void Run(CancellationToken cancellationToken = default) {\n using var connection = new SqlConnection(connectionString);\n const string value = "fixed";\n ${lhs} = "prefix " + // sink\n value;\n }\n}`;
    assert.equal(prove(source, rule), true);
  }
});

for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n']]) {
  for (const [form, body] of Object.entries(primaryBindings)) {
    for (const [rule, lhs] of [['CS-SQLI-001', 'command.CommandText'], ['CS-CMDI-001', 'info.Arguments']]) {
      test(`primary single-line ${form} keeps its own ${rule} binding (${ending})`, () => {
        const sink = `${lhs} = "prefix " + value; // sink\n`;
        const source = `class Sample(string input) {\n void Run() {\n { string value = "fixed"; }\n ${body(sink)}\n }\n private bool TryGet(string input, out string result) { result = input; return true; }\n}`;
        assert.equal(prove(source, rule, eol), false);
      });
    }
  }
  test(`primary local type identity is required for SQL and command proofs (${ending})`, () => {
    const conversion = name => `class ${name} { public static implicit operator ${name}(string value) => new ${name}(); public override string ToString() => System.Environment.GetEnvironmentVariable("QUERY"); }\n`;
    for (const [rule, lhs] of [['CS-SQLI-001', 'command.CommandText'], ['CS-CMDI-001', 'info.Arguments']]) {
      for (const [prefix, type] of [
        ['', 'string'], ['', 'var'], ['', 'String'],
        [conversion('var'), 'var'], [conversion('String'), 'String'],
        ['using Text = External.Text;\n', 'Text'],
        ['using var = External.Text;\n', 'var'],
        ['using String = External.Text;\n', 'String'],
        [`using External;\nnamespace External { ${conversion('String')} }\n`, 'String'],
        [`using External;\nnamespace External { ${conversion('var')} }\n`, 'var'],
      ]) {
        for (const primary of ['(string input)', '()']) {
          const source = `${prefix}class Sample${primary} {\n void Run() { ${type} value = "fixed";\n ${lhs} = "prefix " + value; // sink\n }\n}`;
          assert.equal(prove(source, rule, eol), type === 'string', `${type} ${prefix} ${primary}`);
        }
      }
      for (const declaration of ['Text value = "fixed";', 'Text first = "fixed", value = "fixed";', 'Text[] value = "fixed";']) {
        const source = `class Sample(string input) {\n void Run() {\n { string value = "unrelated"; }\n { ${declaration}\n ${lhs} = "prefix " + value; // sink\n } }\n}`;
        assert.equal(prove(source, rule, eol), false, declaration);
      }
    }
  });
}
