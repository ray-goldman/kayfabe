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
  assert.deepEqual(await findings(t, independentSource('String ignored = "prefix" + input; return "fixed";')), []);
  assert.ok((await findings(t, independentSource('String ignored = "prefix" + request; return "fixed";'))).length,
    'opaque request.toString can mutate output even when the returned literal is fixed');
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
