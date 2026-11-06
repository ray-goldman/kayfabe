'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
const escape = value => `org.springframework.web.util.HtmlUtils.htmlEscape(${value})`;
const print = value => `response.getWriter().print(${value});`;

const independentHelper = 'private String choose(HttpServletRequest request, String input) { return "fixed"; }';
const independentPrintf = (format = '"%s"', locale = '') => `response.getWriter().printf(${locale}${format}, parts);`;
const explicitServletImports = 'import javax.servlet.http.HttpServlet; import javax.servlet.http.HttpServletRequest; import javax.servlet.http.HttpServletResponse;';
const independentServletSource = (body, methods) => `${explicitServletImports}
  class Example extends HttpServlet {
    ${methods}
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
      String input = request.getParameter("value");
      ${body}
    }
  }`;

test('independent char copy print and println admit pure opaque helpers and keep tainted twins', async t => {
  for (const kind of ['print', 'println']) {
    await t.test(kind, async t => {
      const body = `String selected = choose(request, input);\nString alias = selected;\nresponse.getWriter().${kind}(alias.toCharArray());`;
      const source = independentServletSource(body, independentHelper);
      const tainted = await findings(t, '', '', { 'Example.java': source.replace('return "fixed";', 'return input;') });
      assert.ok(tainted.some(hit => hit.file === 'Example.java' && hit.ruleId === 'JAVA-XSS-001'), 'tainted twin already warns');
      assert.deepEqual(await findings(t, '', '', { 'Example.java': source }), [], 'independent copy');
    });
  }
});

function charCopyProof(statement = 'response.getWriter().print(selected.toCharArray());', options = {}) {
  const { buildJavaProjectIndex } = require('../src/java-project');
  const { stripComments } = require('../src/languages');
  const { argumentsOf } = require('../src/java-methods');
  const { independentCharCopy } = require('../src/java-independent-char-copy');
  let source = independentServletSource(`String selected = choose(request, input);\n${statement}`, options.helper || independentHelper);
  for (const [from, to] of options.replace || []) source = source.replace(from, to);
  const files = { ...options.extra, 'Example.java': source };
  const project = buildJavaProjectIndex(Object.entries(files).map(([file, raw]) => ({ file, raw, code: stripComments(raw, 'java') })));
  const filter = project.byFile.get('Example.java').filter, index = filter.index;
  const match = /response\.getWriter\(\)\.(print|println|write|append|printf)\(/.exec(index.code);
  const position = match.index, start = position + match[0].length;
  let depth = 1, end = start;
  for (; end < index.mask.length && depth; end++) {
    if (index.mask[end] === '(') depth++;
    if (index.mask[end] === ')') depth--;
  }
  const call = { position, end, kind: match[1], args: argumentsOf(index.code.slice(start, end - 1)) };
  const request = { index, filter, project, call, windowStart: position, windowEnd: end + 1, ...options.request };
  return { source, files, ...request, accepts: independentCharCopy(request) };
}

test('independent char copy closes over pure branch helpers and exact String bindings only', async t => {
  for (const helper of [independentHelper,
    'private String choose(HttpServletRequest request, String input) { String answer; if (true) answer = "fixed"; else answer = input; return answer; }',
    'private String choose(HttpServletRequest request, String input) { return true ? "fixed" : input; }']) {
    for (const kind of ['print', 'println']) {
      const proof = charCopyProof(`String alias = selected;\nresponse.getWriter().${kind}(alias . toCharArray ( ));`, { helper });
      assert.equal(proof.accepts, true, helper + kind);
      assert.deepEqual(await findings(t, '', '', proof.files), []);
    }
  }
  for (const helper of [
    independentHelper.replace('"fixed"', 'input'),
    'private String choose(HttpServletRequest request, String input) { request.toString(); return "fixed"; }',
    'private String choose(HttpServletRequest request, String input) { field = input; return "fixed"; }',
    'private String choose(HttpServletRequest request, String input) { return old(input); } private String old(String input) { sideEffect(input); return "fixed"; }',
    `private String choose(HttpServletRequest request, String input) { return ${escape('input')}; }`,
  ]) {
    const proof = charCopyProof(undefined, { helper });
    assert.equal(proof.accepts, false, helper);
    assert.ok((await findings(t, '', '', proof.files)).length, helper);
  }
  for (const expression of ['input', escape('input'), 'old(input)']) {
    const proof = charCopyProof(undefined, { replace: [['String selected = choose(request, input);', `String selected = ${expression};`]],
      helper: independentHelper + ' private String old(String input) { sideEffect(input); return "fixed"; }' });
    assert.equal(proof.accepts, false, expression);
    assert.ok((await findings(t, '', '', proof.files)).length, expression);
  }
});

test('independent char copy requires canonical String ownership with bounded class and caller headers', async t => {
  const { canonicalStringScope } = require('../src/java-independent-return');
  for (const imports of ['', 'import java.lang.String;', 'import java /* gap */ . lang . String;', 'import harmless /* gap */ . Name;']) {
    const proof = charCopyProof(undefined, { replace: [[explicitServletImports, explicitServletImports + imports]] });
    assert.equal(proof.accepts, true, imports);
    assert.deepEqual(await findings(t, '', '', proof.files), []);
  }
  const cases = [
    ['custom import', [['import javax.servlet.http.HttpServlet;', 'import javax.servlet.http.HttpServlet; import evil.String;']],
      { 'evil/String.java': 'package evil; public class String { public char[] toCharArray() { callback(); return null; } }' }],
    ['absent custom import', [[explicitServletImports, explicitServletImports + ' import absent.String;']]],
    ['spaced custom import', [[explicitServletImports, explicitServletImports + ' import evil . String;']]],
    ['comment custom import', [[explicitServletImports, explicitServletImports + ' import evil /* gap */ . String;']]],
    ['wildcard', [[explicitServletImports, explicitServletImports + ' import absent.*;']]],
    ['comment wildcard', [[explicitServletImports, explicitServletImports + ' import absent /* gap */ . *;']]],
    ['static import', [[explicitServletImports, explicitServletImports + ' import static evil.Types.String;']]],
    ['static wildcard', [[explicitServletImports, explicitServletImports + ' import static evil.Types.*;']]],
    ['malformed import', [[explicitServletImports, explicitServletImports + ' import evil..String;']]],
    ['duplicate import', [[explicitServletImports, explicitServletImports + ' import java.lang.String; import java.lang.String;']]],
    ['root String', [], { 'String.java': 'public class String { public char[] toCharArray() { callback(); return null; } }' }],
    ['source canonical String', [], { 'java/lang/String.java': 'package java.lang; public class String {}' }],
    ['implicit Object source shadow', [[' extends HttpServlet', '']], { 'java/lang/Object.java': 'package java.lang; public class Object extends Unknown {}' }],
    ['same package String', [['import javax.servlet.http.HttpServlet;', 'package sample; import javax.servlet.http.HttpServlet;']],
      { 'sample/String.java': 'package sample; public class String {}' }],
    ['java root shadow', [], { 'java.java': 'public class java {}' }],
    ['imported java shadow', [[explicitServletImports, explicitServletImports + ' import evil.java;']]],
    ['class generic', [['class Example extends', 'class Example<String> extends']]],
    ['caller generic', [['protected void doPost', 'protected <String> void doPost']]],
    ['helper generic', [['private String choose', 'private <String> String choose']]],
    ['unknown parent', [['extends HttpServlet', 'extends Unknown']]],
    ['known custom parent', [['extends HttpServlet', 'extends Parent']], { 'Parent.java': 'class Parent { static class String {} }' }],
    ['interface', [['extends HttpServlet', 'extends HttpServlet implements Unknown']]],
    ['shadowed servlet', [], { 'javax/servlet/http/HttpServlet.java': 'package javax.servlet.http; public class HttpServlet {}' }],
    ['Object import shadow', [['extends HttpServlet', 'extends Object'], [explicitServletImports, explicitServletImports + ' import evil.Object;']]],
  ];
  for (const [name, replace, extra] of cases) {
    const proof = charCopyProof(undefined, { replace, extra });
    assert.equal(proof.accepts, false, name);
    // Exercise the candidate-producing path as well as the strict proof.
    assert.ok((await findings(t, '', '', proof.files)).length, name);
  }
  for (const parent of ['', ' extends Object', ' extends java.lang.Object', ' extends javax.servlet.http.HttpServlet', ' extends jakarta.servlet.http.HttpServlet']) {
    const proof = charCopyProof(undefined, { replace: [[' extends HttpServlet', parent]] });
    assert.equal(proof.accepts, true, parent);
  }
  const proof = charCopyProof();
  assert.equal(canonicalStringScope({ ...proof, budget: { left: 0 } }), false);
  assert.equal(canonicalStringScope({ ...proof, position: proof.call.position, budget: { left: 1 } }), false);
  assert.equal(canonicalStringScope({ ...proof, position: proof.call.position, project: { ...proof.project, complete: false }, budget: { left: 10000 } }), false);
});

test('independent char copy never assumes a custom String conversion is effect free', async t => {
  const source = `${explicitServletImports} import custom.String;
class Example extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
    java.lang.String input = request.getParameter("value");
    String selected = new String(request, input);
    response.getWriter().print(selected.toCharArray());
  }
}`;
  const custom = `package custom;
public class String {
  private final javax.servlet.http.HttpServletRequest request;
  private final java.lang.String input;
  public String(javax.servlet.http.HttpServletRequest request, java.lang.String input) {
    this.request = request; this.input = input;
  }
  public char[] toCharArray() throws java.io.IOException {
    request.startAsync().getResponse().getWriter().write(input);
    return new char[] {'x'};
  }
}`;
  const hits = await findings(t, '', '', { 'Example.java': source, 'custom/String.java': custom });
  assert.ok(hits.some(hit => hit.file === 'Example.java' && hit.line === 6), 'the custom conversion call retains its current sink warning');
});

function nullCallbackCopy({ kind = 'print', namespace = 'javax', packageSpelling = '', rootShadow, callback = true,
  returnExpression = 'null', sourcePackageSpelling } = {}) {
  const replacements = [
    [explicitServletImports, (packageSpelling ? `package ${packageSpelling};\n` : '') + explicitServletImports.replaceAll('javax', namespace)],
    ['String input = request.getParameter("value");', 'int input = request.getParameter("value").length();'],
  ];
  const extra = {};
  if (rootShadow) {
    replacements.push(['extends HttpServlet', `extends ${namespace}.servlet.http.HttpServlet`]);
    const rootPackage = rootShadow === 'imported' ? 'evil' : packageSpelling.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\s/g, '');
    if (rootShadow === 'imported') replacements.push(['class Example extends', `import evil.${namespace};\nclass Example extends`]);
    if (callback) {
      extra[`${rootPackage.replaceAll('.', '/')}/${namespace}.java`] = `${rootPackage ? `package ${sourcePackageSpelling || rootPackage};` : ''}
public class ${namespace} { public static class servlet { public static class http {
  public static class HttpServlet extends p.Base {}
} } }`;
      extra['p/Base.java'] = `package p;
public class Base extends ${namespace}.servlet.http.HttpServlet {
  public static class String {
    public static ${namespace}.servlet.http.HttpServletRequest request;
    public static char[] toCharArray() throws java.io.IOException {
      request.startAsync().getResponse().getWriter().write(request.getParameter("value"));
      return new char[0];
    }
  }
}`;
    }
  } else if (callback) {
    extra['sample/app/String.java'] = `package ${sourcePackageSpelling || 'sample.app'};
public class String {
  public static ${namespace}.servlet.http.HttpServletRequest request;
  public static char[] toCharArray() throws java.io.IOException {
    request.startAsync().getResponse().getWriter().write(request.getParameter("value"));
    return new char[0];
  }
}`;
  }
  return charCopyProof(`${callback ? 'String.request = request;\n' : ''}response.getWriter().${kind}(selected.toCharArray());`, {
    helper: `private String choose(HttpServletRequest request, int input) { return ${returnExpression}; }`, extra,
    replace: [...replacements, ['protected void doPost(HttpServletRequest request, HttpServletResponse response)',
      'protected void doPost(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException']],
  });
}

test('independent char copy fix1 rejects normalized-package null-helper static callbacks', async t => {
  const { javaOutputFilter } = require('../src/java-sanitizers');
  for (const kind of ['print', 'println']) for (const packageSpelling of ['sample.app', 'sample . app', 'sample /* gap */ . app']) {
    await t.test(kind + ' ' + packageSpelling, async t => {
      const proof = nullCallbackCopy({ kind, packageSpelling });
      const position = proof.call.position, line = proof.source.slice(0, position).split('\n').length - 1;
      const window = proof.source.slice(position, proof.source.indexOf(';', position) + 1);
      const provenance = proof.filter.independentOutputValuesAt([{ expression: 'selected', position }]);
      const suppressed = javaOutputFilter({ code: proof.index.code, filter: proof.filter, project: proof.project })(line, window);
      const hits = await findings(t, '', '', proof.files);
      const warned = hits.some(hit => hit.file === 'Example.java' && hit.line === line + 1);
      t.diagnostic(JSON.stringify({ packageSpelling, indexedPackage: proof.index.package, provenance, strict: proof.accepts, suppressed, warned }));
      assert.equal(provenance, true, 'null helper is independently proved; nominal guard must block the callback');
      assert.equal(proof.accepts, false, 'custom same-package String cannot receive the new certificate');
      assert.equal(suppressed, false, 'current output window retains its warning');
      assert.equal(warned, true, 'scanner retains the initialized static callback sink');
    });
  }
});

test('independent char copy fix1 rejects source and imported servlet leading-type callbacks', async t => {
  const { javaOutputFilter } = require('../src/java-sanitizers');
  for (const kind of ['print', 'println']) for (const namespace of ['javax', 'jakarta']) {
    for (const [rootShadow, packageSpelling] of [['source', ''], ['source', 'sample.app'], ['source', 'sample . app'],
      ['source', 'sample /* gap */ . app'], ['imported', ''], ['imported', 'sample.app']]) {
      await t.test([kind, namespace, rootShadow, packageSpelling].join(' '), async t => {
        const proof = nullCallbackCopy({ kind, namespace, rootShadow, packageSpelling });
        const position = proof.call.position, line = proof.source.slice(0, position).split('\n').length - 1;
        const window = proof.source.slice(position, proof.source.indexOf(';', position) + 1);
        const provenance = proof.filter.independentOutputValuesAt([{ expression: 'selected', position }]);
        const suppressed = javaOutputFilter({ code: proof.index.code, filter: proof.filter, project: proof.project })(line, window);
        const hits = await findings(t, '', '', proof.files);
        const warned = hits.some(hit => hit.file === 'Example.java' && hit.line === line + 1);
        t.diagnostic(JSON.stringify({ namespace, rootShadow, packageSpelling, provenance, strict: proof.accepts, suppressed, warned }));
        assert.equal(provenance, true, 'independent null reference cannot prevent a static conversion callback');
        assert.equal(proof.accepts, false, 'qualified servlet spelling cannot conceal a source type root');
        assert.equal(suppressed, false, 'current output window retains its warning');
        assert.equal(warned, true, 'scanner retains the initialized inherited callback sink');
      });
    }
  }
});

test('independent char copy fix1 preserves canonical twins and rejects source inventory spelling uncertainty', async t => {
  for (const kind of ['print', 'println']) for (const namespace of ['javax', 'jakarta']) {
    for (const rootShadow of [undefined, 'source']) for (const packageSpelling of ['', 'sample.app']) {
      const options = { kind, namespace, packageSpelling, rootShadow, callback: false, returnExpression: '"fixed"' };
      const safe = nullCallbackCopy(options);
      assert.equal(safe.accepts, true, [kind, namespace, rootShadow, packageSpelling].join(' '));
      assert.deepEqual(await findings(t, '', '', safe.files), [], 'genuinely canonical helper twin');
      const tainted = nullCallbackCopy({ ...options, returnExpression: 'request.getParameter("value")' });
      assert.equal(tainted.accepts, false, 'tainted helper twin');
      const line = tainted.source.slice(0, tainted.call.position).split('\n').length;
      assert.ok((await findings(t, '', '', tainted.files)).some(hit => hit.file === 'Example.java' && hit.line === line));
    }
    for (const sourcePackageSpelling of ['sample . app', 'sample /* gap */ . app']) {
      for (const rootShadow of [undefined, 'source']) {
        const proof = nullCallbackCopy({ kind, namespace, rootShadow, packageSpelling: 'sample.app', sourcePackageSpelling });
        assert.equal(proof.accepts, false, 'uncertain source package keys must not hide nominal shadows');
        const line = proof.source.slice(0, proof.call.position).split('\n').length;
        assert.ok((await findings(t, '', '', proof.files)).some(hit => hit.file === 'Example.java' && hit.line === line));
      }
    }
    for (const packageSpelling of ['sample . app', 'sample /* gap */ . app']) {
      const proof = nullCallbackCopy({ kind, namespace, packageSpelling, callback: false, returnExpression: '"fixed"' });
      assert.equal(proof.accepts, false, 'new scope declines a caller package that disagrees with legacy inventory');
    }
  }
  for (const parent of ['', ' extends Object', ' extends java.lang.Object']) {
    const proof = charCopyProof(undefined, { replace: [[' extends HttpServlet', parent]] });
    assert.equal(proof.accepts, true, 'unambiguous canonical Object scope');
  }
});

test('independent char copy rejects wrappers arrays slices arguments chains and partial statements', () => {
  const { independentCharCopy } = require('../src/java-independent-char-copy');
  const copy = 'response.getWriter().print(selected.toCharArray())';
  for (const statement of [
    'if (condition) ' + copy + ';', '{ ' + copy + '; }',
    'outer(' + copy + ', input);', copy + '.append(input);', 'Object value = ' + copy + ';', 'return ' + copy + ';',
    'response.getWriter().print((selected).toCharArray());',
    'response.getWriter().print(((String) selected).toCharArray());',
    'response.getWriter().print(choose(request, input).toCharArray());',
    'response.getWriter().print(holder.selected.toCharArray());',
    'response.getWriter().print(selected.toCharArray(0));',
    'response.getWriter().print(selected.toCharArray(), 0, 1);',
    'response.getWriter().print(selected.toCharArray()[0]);',
    'response.getWriter().print(selected.toCharArray().clone());',
    'char[] chars = selected.toCharArray(); response.getWriter().print(chars);',
    'char[] chars = selected.toCharArray(); chars[0] = input.charAt(0); response.getWriter().print(chars);',
    'response.getWriter().write(selected.toCharArray());',
    'response.getWriter().append(selected.toCharArray());',
  ]) assert.equal(charCopyProof(statement).accepts, false, statement);
  const proof = charCopyProof();
  assert.equal(proof.accepts, true);
  assert.equal(independentCharCopy({ ...proof, windowStart: proof.call.position + 1 }), false);
  assert.equal(independentCharCopy({ ...proof, windowEnd: proof.call.end }), false);
  assert.equal(independentCharCopy({ ...proof, windowEnd: proof.call.end - 1 }), false);
  for (const type of ['Object', 'int', 'char', 'boolean', 'String[]']) {
    assert.equal(charCopyProof(undefined, { replace: [['String selected =', type + ' selected =']] }).accepts, false, type);
  }
  const exhausted = charCopyProof(undefined, { helper: `private String choose(HttpServletRequest request, String input) { int count = 0; ${'count = 1;'.repeat(1500)} return "fixed"; }` });
  assert.equal(exhausted.accepts, false, 'shared provenance work stays bounded');
  assert.equal(charCopyProof(undefined, { replace: [[explicitServletImports, ' '.repeat(4001) + explicitServletImports]] }).accepts, false, 'bounded header');
});

test('independent char copy keeps whole-window siblings and HTML stream replay conservative', async t => {
  for (const kind of ['print', 'println']) {
    const copy = `response.getWriter().${kind}(selected.toCharArray());`;
    const setup = 'String selected = choose(request, input);\n';
    for (const before of [
      'helper(response);', 'if (condition) ' + print('"<p>"'), '{ ' + print('"<p>"') + ' }',
      'for (;;) { }', print('"<script>"'), print('"<textarea>"'), print('"<a href=\\\""'), print('"<!--"'),
    ]) {
      const source = independentServletSource(`${before}\n${setup}${copy}`, independentHelper);
      assert.ok((await findings(t, '', '', { 'Example.java': source })).length, kind + before);
    }
    for (const sibling of [print('input'), 'other.getWriter().print(input);', 'out.print(input);']) {
      const source = independentServletSource(`${setup}${copy} ${sibling}`, independentHelper);
      assert.ok((await findings(t, '', '', { 'Example.java': source })).length, kind + sibling);
    }
    for (const separator of [' ', '\n']) {
      const source = independentServletSource(`${setup}${copy}${separator}${print(escape('input'))}`, independentHelper.replace('"fixed"', '"<script>"'));
      const hits = await findings(t, '', '', { 'Example.java': source });
      assert.ok(hits.length, kind + ' opaque markup must not become replay data');
    }
    const source = independentServletSource(`${print('"<p>"')}\n${setup}${copy}`, independentHelper);
    assert.deepEqual(await findings(t, '', '', { 'Example.java': source }), [], kind + ' known prior text');
  }
});

test('independent owner fix1 Locale requires a known leading owner without import uncertainty', async t => {
  const { buildJavaProjectIndex } = require('../src/java-project');
  const { independentFormat } = require('../src/java-independent-format');
  const { argumentsOf } = require('../src/java-methods');
  const { stripComments } = require('../src/languages');
  const source = imports => `${explicitServletImports}
${imports}
class Example extends HttpServlet {
  ${independentHelper}
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    String input = request.getParameter("x");
    String selected = choose(request, input);
    Object[] parts = {selected};
    response.getWriter().printf(java.util.Locale.US, "%s", parts);
  }
}`;
  assert.deepEqual(await findings(t, '', '', { 'Example.java': source('') }), [], 'known owner positive');
  assert.deepEqual(await findings(t, '', '', { 'Example.java': source('import harmless /* gap */ . Name;') }), [], 'ordinary normalized type import');
  const cases = [
    ['source wildcard', 'import evil.*;', { 'evil/java.java': `package evil; import java.util.Locale; public class java {
      public static javax.servlet.http.HttpServletRequest request;
      public static Namespace util = new Namespace();
      public static class Namespace { public Carrier Locale = new Carrier(); }
      public static class Carrier {
        public Locale US = initialize();
        private Locale initialize() {
          request.startAsync().getResponse().getWriter().write(request.getParameter("x"));
          return Locale.US;
        }
      }
    }` }],
    ['absent wildcard', 'import missing.*;', {}],
    ['static root field', 'import static evil.Names.java;', {}],
    ['static wildcard', 'import static missing.Names.*;', {}],
    ['explicit root type', 'import evil.java;', {}],
    ['spaced explicit root', 'import evil . java;', {}],
    ['comment explicit root', 'import evil /* gap */ . /* gap */ java;', {}],
    ['spaced wildcard', 'import missing /* gap */ . *;', {}],
    ['unsupported import grammar', 'import evil..java;', {}],
    ['same package source', '', { 'java.java': 'public class java { static Object util = callback(); }' }],
  ];
  for (const [name, imports, extra] of cases) await t.test(name, async t => {
    const raw = source(imports), files = { ...extra, 'Example.java': raw };
    const project = buildJavaProjectIndex(Object.entries(files).map(([file, raw]) => ({ file, raw, code: stripComments(raw, 'java') })));
    const filter = project.byFile.get('Example.java').filter, code = filter.index.code;
    const position = code.indexOf('response.getWriter()'), end = code.indexOf(';', position);
    const call = { kind: 'printf', position, end,
      args: argumentsOf(code.slice(code.indexOf('printf(', position) + 7, end - 1)) };
    const strict = independentFormat({ index: filter.index, filter, project, call, windowStart: position, windowEnd: end + 1 });
    const control = await findings(t, '', '', { ...extra, 'Example.java': raw.replace('return "fixed";', 'return input;') });
    assert.ok(control.some(hit => hit.file === 'Example.java' && hit.ruleId === 'JAVA-XSS-001' && hit.line === 9), 'tainted-return candidate twin');
    const hits = await findings(t, '', '', files);
    assert.equal(strict, false, 'strict checker: ' + name);
    assert.ok(hits.some(hit => hit.file === 'Example.java' && hit.ruleId === 'JAVA-XSS-001' && hit.line === 9), 'exact current printf: ' + name);
  });
});

function outputProof(body, helper = 'private String choose(Request request, String input) { return "fixed"; }') {
  const { constantSinkFilter } = require('../src/java-constants');
  const source = `class Example { ${helper} void run(Request request, String input) { ${body} consume(); } }`;
  return { source, position: source.indexOf('consume()'), filter: constantSinkFilter(source, () => []) };
}

test('independent printf bulk query closes over literal provenance and exact opaque helpers only', () => {
  const proof = outputProof(`String fixed = "[data]"; String alias = (fixed + "tail");
    String selected = choose(request, input); String copy = selected; String nil = null;
    String[] words = {"safe"}; String indexed = words[0]; int member = fixed.length();
    char character = fixed.charAt(0); String oldValue = old(input); String encoded = org.springframework.web.util.HtmlUtils.htmlEscape(input);
    String split = fixed.split("x")[0];`,
  'private String choose(Request request, String input) { return "fixed"; } private String old(String input) { sideEffect(input); return "fixed"; }');
  const query = expressions => proof.filter.independentOutputValuesAt(expressions.map(expression => ({ expression, position: proof.position })));
  for (const expression of ['"[literal]"', '42', "'x'", 'true', 'fixed', 'alias', 'selected', 'copy', 'nil']) {
    assert.equal(query([expression]), true, expression);
  }
  for (const expression of ['input', 'request', 'words[0]', 'indexed', 'member', 'character', 'oldValue', 'encoded', 'split',
    'fixed.length()', 'fixed.charAt(0)', 'fixed.split("x")', 'new String()', '(Object) fixed', 'unknown()',
    '"bad\\q"', '"line\nbreak"', "'many'", '"bad\\141"']) {
    assert.equal(query([expression]), false, expression);
    assert.equal(query(['selected', expression]), false, 'unselected element: ' + expression);
  }
  assert.equal(query([]), false);
  assert.equal(query(Array(33).fill('fixed')), false);
  assert.equal(query(['('.repeat(1900) + '"x"' + ')'.repeat(1900)]), false, 'deep wrappers remain bounded');
  assert.equal(proof.filter.independentOutputValuesAt([{ expression: 'fixed', position: -1 }]), false);
  assert.equal(proof.filter.independentOutputValuesAt([{ expression: 'fixed', position: proof.position + 0.5 }]), false);
  assert.equal(proof.filter.independentOutputValuesAt([{ expression: 'fixed', position: proof.source.length }]), false);
  // Ordinary helpers/encoders retain their old facts; the new bulk query does
  // not borrow them, regardless of proof order or injected optional arguments.
  assert.equal(proof.filter.valueAt('oldValue', proof.position), true);
  assert.equal(query(['oldValue']), false);
  assert.equal(proof.filter.independentOutputValuesAt([{ expression: 'input', position: proof.position }],
    { parameters: new Map([['input', { known: true }]]), mode: 'html' }), false);
});

test('independent printf bulk shares work across elements and keeps callee parameters localOnly', () => {
  const helper = `private String choose(Request request, String input) { int count = 0; ${'count = 1;'.repeat(200)} return "fixed"; }`;
  const proof = outputProof('String selected = choose(request, input);', helper);
  const entry = { expression: 'selected', position: proof.position };
  assert.equal(proof.filter.independentOutputValuesAt([entry]), true);
  assert.equal(proof.filter.independentOutputValuesAt(Array(32).fill(entry)), false, 'no per-element replenishment or safe cache');
  assert.equal(proof.filter.independentOutputValuesAt([entry]), true, 'each new query is fresh');
  for (const body of ['return input;', 'return choose(request, input);', 'return old(input);',
    'request.toString(); return "fixed";', 'field = input; return "fixed";',
    'boolean ignored = ("prefix" + input) == ""; return null;']) {
    const candidate = outputProof('String selected = choose(request, input);',
      `private String choose(Request request, String input) { ${body} } private String old(String input) { return "fixed"; }`);
    assert.equal(candidate.filter.independentOutputValuesAt([{ expression: 'selected', position: candidate.position }]), false, body);
  }
  const parameter = outputProof('', 'private String choose(Request request, String input) { return "fixed"; } private void echo(String value) { consume(); } void caller() { echo("fixed"); }');
  const position = parameter.source.indexOf('consume()');
  assert.equal(parameter.filter.valueAt('value', position), true, 'ordinary parameterFact positive twin');
  assert.equal(parameter.filter.independentOutputValuesAt([{ expression: 'value', position }]), false);
});

test('independent printf internal requests retain method depth mode and return-budget gates', () => {
  const proof = outputProof('String selected = choose(request, input);',
    'private String choose(Request request, String input) { if (true) return "one"; else return "two"; }');
  const context = extra => ({ independentOutputOnly: true, mode: 'constant',
    budget: { left: 10000, methods: new Set() }, stack: [], ...extra });
  const accepts = state => proof.filter.valueAt('selected', proof.position, state);
  assert.equal(accepts(context()), true);
  assert.equal(accepts(context({ stack: ['a', 'b', 'c'] })), true);
  assert.equal(accepts(context({ stack: ['a', 'b', 'c', 'd'] })), false);
  assert.equal(accepts(context({ budget: { left: 10000, methods: new Set(Array.from({ length: 32 }, (_, i) => 'method-' + i)) } })), false);
  assert.equal(accepts(context({ budget: { left: 0, methods: new Set() } })), false);
  assert.equal(accepts(context({ mode: 'html' })), false);
  const state = context();
  assert.equal(accepts(state), true);
  const firstLeft = state.budget.left;
  assert.equal(accepts(state), true);
  assert.ok(state.budget.left < firstLeft, 'shared requests spend work again rather than caching a safe return');
  const contaminated = outputProof('String selected = choose(request, input);',
    'private String choose(Request request, String input) { return input; }');
  assert.equal(contaminated.filter.valueAt('selected', contaminated.position, context({
    parameterMethod: contaminated.filter.index.methods[0].start,
    parameters: new Map([['input', { known: true, dependencies: [], encodings: [] }]]),
  })), false, 'fresh localOnly child discards caller parameter maps');
});

test('independent printf strict checker rejects legacy parser syntax and partial windows', () => {
  const { independentFormat } = require('../src/java-independent-format');
  const { argumentsOf } = require('../src/java-methods');
  const check = (format, options = {}) => {
    const text = `String selected = choose(request, input); Object[] parts = {selected}; response.getWriter().printf(${format}, parts);`;
    const proof = outputProof(text);
    const position = proof.source.indexOf('response.getWriter()');
    const end = proof.source.indexOf(';', position);
    const args = argumentsOf(proof.source.slice(proof.source.indexOf('printf(', position) + 7, end - 1));
    return independentFormat({ index: proof.filter.index, filter: proof.filter,
      call: { kind: 'printf', position, end, args }, windowStart: position, windowEnd: end + 1, ...options });
  };
  assert.equal(check('"%s"'), true);
  for (const format of ['"%1$n"', '"%1$%"', '"%0$s"', '"%2$s"', '"%99$s"', '"%999$s"',
    '"%"', '"%S"', '"%2s"', '"%.1s"', '"%d"', '"%<s"', '"%tY"', '"%s %s"', '"%" + "s"', 'choose(request, input)']) {
    assert.equal(check(format), false, format);
  }
  assert.equal(check('"%s"', { windowEnd: 1 }), false);
  assert.equal(check('"%s"', { windowStart: 100000 }), false);
});

test('independent printf rejects custom String and Formattable conversion callbacks and generic overload traps', async t => {
  for (const [type, extra] of [
    ['String', { 'sample/String.java': `package sample; public class String {
      public java.lang.String toString() { callback(); return "fixed"; }
    }` }],
    ['Payload', { 'sample/Payload.java': `package sample; public class Payload implements java.util.Formattable {
      public void formatTo(java.util.Formatter formatter, int flags, int width, int precision) { callback(); }
    }` }],
  ]) {
    const source = `import javax.servlet.http.*; import sample.${type};
      class Example extends HttpServlet {
        private String choose(HttpServletRequest request, String input) { return "fixed"; }
        protected void doPost(HttpServletRequest request, HttpServletResponse response) {
          String input = request.getParameter("x");
          String selected = choose(request, input);
          ${type} other = new ${type}(input);
          Object[] parts = {selected, other};
          response.getWriter().printf("%1$s %2$s", parts);
        }
      }`;
    assert.ok((await findings(t, '', '', { ...extra, 'Example.java': source })).length, type);
  }
  for (const [header, helper, caller] of [
    ['class Example<T>', 'private String choose(Request request, String input)', 'void run(Request request, String input)'],
    ['class Example', 'private <T> String choose(Request request, String input)', 'void run(Request request, String input)'],
    ['class Example', 'private String choose(Request request, String input)', '<Request extends CharSequence> void run(Request request, String input)'],
  ]) {
    const { constantSinkFilter } = require('../src/java-constants');
    const source = `${header} { ${helper} { return "fixed"; } ${caller} { String selected = choose(request, input); consume(); } }`;
    const filter = constantSinkFilter(source, () => []);
    assert.equal(filter.independentOutputValuesAt([{ expression: 'selected', position: source.indexOf('consume()') }]), false, source);
  }
});

test('independent printf admits only pure opaque scalar carriers in the current HTML call', async t => {
  for (const helper of [independentHelper,
    'private String choose(HttpServletRequest request, String input) { String answer; if (true) answer = "fixed"; else answer = input; return answer; }',
    'private String choose(HttpServletRequest request, String input) { return true ? "fixed" : input; }']) {
    for (const locale of ['', 'java.util.Locale.US, ']) {
      const body = `String selected = choose(request, input);
Object[] parts = {selected};

        ${independentPrintf('"%s"', locale)}`;
      const hits = locale ? await findings(t, '', '', { 'Example.java': independentServletSource(body, helper) }) :
        await findings(t, body, helper);
      assert.deepEqual(hits, [], helper + locale);
    }
  }
  for (const format of ['"%s %2$s %s %% %n"', '"fixed %% %n"', 'format']) {
    assert.deepEqual(await findings(t, `String selected = choose(request, input);
String format = "%2$s";
      Object[] parts = {selected, "[literal]"};
 ${independentPrintf(format)}`, independentHelper), [], format);
  }
  const annotated = `import javax.servlet.http.*;
    @Label("metadata") class Example extends HttpServlet {
      ${independentHelper}
      @Override protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("x");
String selected = choose(request, input);
        Object[] parts = {selected};
 ${independentPrintf()}
      }
    }`;
  assert.deepEqual(await findings(t, '', '', { 'Example.java': annotated }), []);
});

test('independent printf rejects impure helpers, external elements and incomplete statements', async t => {
  const setup = 'String selected = choose(request, input);\nObject[] parts = {selected};\n';
  for (const helper of [
    'private String choose(HttpServletRequest request, String input) { request.toString(); return "fixed"; }',
    'private String choose(HttpServletRequest request, String input) { field = input; return "fixed"; }',
    'private String choose(String input) { sideEffect(input); return "fixed"; }',
    'private String choose(HttpServletRequest request, String input) { return input; }',
  ]) {
    const body = setup.replace('choose(request, input)', helper.includes('choose(String') ? 'choose(input)' : 'choose(request, input)');
    assert.ok((await findings(t, `${body} ${independentPrintf()}`, helper)).length, helper);
  }
  for (const value of ['input', escape('input'), 'old(input)', 'input.charAt(0)', 'new Dangerous()', '(Object) selected']) {
    assert.ok((await findings(t, `String selected = choose(request, input);
String other = ${value};
      Object[] parts = {selected, other};
 ${independentPrintf('"%1$s"')}`,
    independentHelper + ' private String old(String input) { sideEffect(input); return "fixed"; }')).length, value);
  }
  for (const call of [
    'if (condition) ' + independentPrintf(), '{ ' + independentPrintf() + ' }',
    'outer(' + independentPrintf().slice(0, -1) + ', input);',
    independentPrintf().slice(0, -1) + '.append(input);',
    'Object result = ' + independentPrintf(), 'return ' + independentPrintf(),
  ]) assert.ok((await findings(t, `${setup} ${call}`, independentHelper)).length, call);
  for (const format of ['"%"', '"%0$s"', '"%2$s"', '"%999999999999999999999$s"', '"%1$n %s"', '"%1$% %s"',
    '"%S"', '"%d"', '"%02s"', '"%.2s"', '"%<s"', '"%tY"', '"%s %s"', 'choose(request, input)', '"%" + "s"']) {
    assert.ok((await findings(t, `${setup} ${independentPrintf(format)}`, independentHelper)).length, format);
  }
});

test('independent printf keeps ownership, carrier lifetime and stream replay conservative', async t => {
  const setup = 'String selected = choose(request, input);\nObject[] parts = {selected};\n';
  for (const change of ['parts[0] = input;', 'Object[] alias = parts;', 'mutate(parts);',
    'parts = new Object[] {selected};', 'use(parts);']) {
    assert.ok((await findings(t, `${setup} ${change}
 ${independentPrintf()}`, independentHelper)).length, change);
  }
  for (const before of ['helper(response);', 'if (condition) ' + print('"<p>"'), print('"<script>"'), print('"<a href=\\\""'), print('"<!--"')]) {
    assert.ok((await findings(t, `${before}
 ${setup} ${independentPrintf()}`, independentHelper)).length, before);
  }
  for (const sibling of [print('input'), 'other.getWriter().print(input);', 'out.print(input);']) {
    assert.ok((await findings(t, `${setup} ${independentPrintf()} ${sibling}`, independentHelper)).length, sibling);
  }
  for (const separator of [' ', '\n']) {
    assert.ok((await findings(t, `${setup} ${independentPrintf()}${separator}${print(escape('input'))}`,
      independentHelper.replace('"fixed"', '"<script>"'))).length, 'markup must stay unknown during replay');
  }
  for (const extra of [
    { 'java/util/Locale.java': 'package java.util; public class Locale {}' },
    { 'Example.java': `import javax.servlet.http.*; class Example extends HttpServlet {
      Object java; ${independentHelper} protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("x");
 ${setup} ${independentPrintf('"%s"', 'java.util.Locale.US, ')} } }` },
  ]) assert.ok((await findings(t, `${setup} ${independentPrintf('"%s"', 'java.util.Locale.US, ')}`, independentHelper, extra)).length);
});

test('independent opaque-reference helpers cannot hide HTML stream effects or claim encoding', async t => {
  const safe = 'private String choose(HttpServletRequest request, String input) { return "fixed"; }';
  assert.deepEqual(await findings(t, `String clean = choose(request, input); ${print('clean')}`, safe), []);
  for (const method of [
    'private String choose(HttpServletRequest request, String input) { request.startAsync().getResponse().getWriter().write("<script>"); return "fixed"; }',
    'private String choose(HttpServletRequest request, String input) { field = request; return "fixed"; }',
  ]) assert.ok((await findings(t, `String clean = choose(request, input); ${print('clean')}`, method)).length, method);
  assert.ok((await findings(t, `String clean = choose(request, input); ${print('clean')}\n${print(escape('input'))}`,
    'private String choose(HttpServletRequest request, String input) { return "<script>"; }')).length,
  'fixed markup is not an encoding fact for later dynamic output');
  // Existing supported-only encoder helpers still use their established route.
  assert.deepEqual(await findings(t, `String clean = encode(input); ${print('clean')}`,
    `private String encode(String input) { return ${escape('input')}; }`), []);
});

test('class annotation literal metadata cannot hide custom String callbacks or response stream effects', async t => {
  const customString = `package sample; public class String {
    private final java.lang.String data;
    private final javax.servlet.http.HttpServletRequest request;
    public String(java.lang.String data, javax.servlet.http.HttpServletRequest request) { this.data = data; this.request = request; }
    @Override public java.lang.String toString() {
      try { request.startAsync().getResponse().getWriter().write(data); } catch (java.io.IOException error) { }
      return "";
    }
  }`;
  const source = body => `import javax.servlet.http.*;
import sample.String;
@Arbitrary(label = "{ } < > ( ) metadata")
class Example extends HttpServlet {
 private String choose(HttpServletRequest request, String input) { ${body} }
 @Override protected void doPost(HttpServletRequest request, HttpServletResponse response) {
  String input = new String(request.getParameter("x"), request);
  String selected = choose(request, input);
  response.getWriter().print(selected);
 }
}`;
  const hits = async body => findings(t, '', '', { 'sample/String.java': customString, 'Example.java': source(body) });
  assert.deepEqual(await hits('return null;'), [], 'quiet independent null-return twin');
  assert.deepEqual(await hits('String alias = input; boolean ignored = alias == input; return null;'), [], 'reference identity has no conversion');
  for (const body of [
    'input.toString(); return null;',
    'boolean ignored = ("prefix" + input) == ""; return null;',
    'String alias = input; alias = null; boolean ignored = ("prefix" + alias) == ""; return null;',
    'request.startAsync().getResponse().getWriter().write("<script>"); return null;',
  ]) assert.ok((await hits(body)).some(hit => hit.file === 'Example.java' && hit.line === 9), body);
});

test('independent textual String bindings never certify implicit conversion effects across type scopes', async t => {
  const customString = `public class String {
    private final java.lang.String data;
    private final javax.servlet.http.HttpServletRequest request;
    public String(java.lang.String data, javax.servlet.http.HttpServletRequest request) { this.data = data; this.request = request; }
    @Override public java.lang.String toString() {
      try { request.startAsync().getResponse().getWriter().write(data); } catch (java.io.IOException error) { }
      return "";
    }
  }`;
  const shapes = [
    { name: 'single-type import', first: 'import javax.servlet.http.*;', second: 'import sample.String;', parent: 'HttpServlet',
      extra: { 'sample/String.java': `package sample; ${customString}` } },
    { name: 'same package', first: 'package sample;', second: 'import javax.servlet.http.*;', parent: 'HttpServlet',
      extra: { 'sample/String.java': `package sample; ${customString}` } },
    { name: 'inherited member type', first: 'import javax.servlet.http.*;', second: 'import sample.Base;', parent: 'Base',
      extra: { 'sample/Base.java': `package sample; public class Base extends javax.servlet.http.HttpServlet { ${customString.replace('public class String', 'public static class String')} }` } },
    { name: 'unresolved single-type import', first: 'import javax.servlet.http.*;', second: 'import missing.String;', parent: 'HttpServlet' },
    { name: 'unresolved inherited member', first: 'import javax.servlet.http.*;', second: 'import missing.Base;', parent: 'Base' },
    { name: 'wildcard possibility', first: 'import javax.servlet.http.*;', second: 'import sample.*;', parent: 'HttpServlet',
      extra: { 'sample/String.java': `package sample; ${customString}` } },
  ];
  for (const shape of shapes) await t.test(shape.name, async t => {
    const source = body => `${shape.first}
${shape.second}
public class Example extends ${shape.parent} {
 private String choose(HttpServletRequest request, String input) { ${body} }
 protected void doPost(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
  String input = new String(request.getParameter("x"), request);
  String selected = choose(request, input);
  response.getWriter().print(selected);
 }
}`;
    const hits = async body => (await findings(t, '', '', { ...shape.extra, 'Example.java': source(body) }))
      .map(({ ruleId, file, line }) => ({ ruleId, file, line }));
    assert.deepEqual(await hits('return null;'), [], 'safe null-return twin proves route admission');
    assert.deepEqual(await hits('String alias = input; boolean ignored = alias == input; return null;'), [], 'copy and identity comparison have no callback');
    assert.deepEqual(await hits('input.toString(); return null;'), [{ ruleId: 'JAVA-XSS-001', file: 'Example.java', line: 8 }], 'explicit callback twin');
    assert.deepEqual(await hits('boolean ignored = ("prefix" + input) == ""; return null;'),
      [{ ruleId: 'JAVA-XSS-001', file: 'Example.java', line: 8 }], 'implicit conversion must not erase the warning');
  });
  for (const body of [
    'String copy = input; boolean ignored = copy == input; return null;',
    'boolean ignored = ("prefix" + (input == null)) == ""; return null;',
    'String answer = "prefix" + "literal"; return answer;',
  ]) assert.deepEqual(await findings(t, `String selected = choose(request, input); ${print('selected')}`,
    `private String choose(HttpServletRequest request, String input) { ${body} }`, {
      'Example.java': `import javax.servlet.http.*;
import java.lang.String;
class Example extends HttpServlet {
 private String choose(HttpServletRequest request, String input) { ${body} }
 protected void doPost(HttpServletRequest request, HttpServletResponse response) {
  String input = request.getParameter("x");
String selected = choose(request, input);
  response.getWriter().print(selected);
 }
}`,
    }), [], `genuine java.lang.String positive: ${body}`);
});

async function findings(t, body, methods = '', extra = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-java-sanitizers-'));
  t.after(() => {
    const resolved = fs.realpathSync(root);
    assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('appsec-java-sanitizers-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const source = `import javax.servlet.http.*;
  public class Example extends HttpServlet {
    ${methods}
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
      String input = request.getParameter("value");
      ${body}
    }
  }`;
  for (const [file, text] of Object.entries({ 'Example.java': source, ...extra })) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  }
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'JAVA-XSS-001');
}

test('HTML text encoding survives aliases and private helper returns', async t => {
  for (const expression of [escape('input'), 'encode(input)']) {
    const hits = await findings(t, `String clean = ${expression};
      String alias = clean;
      ${print('alias')}`, `private String encode(String value) { return ${escape('value')}; }`);
    assert.equal(hits.length, 0);
  }
});

test('HTML encoding only protects every dynamic value in a known text context', async t => {
  assert.equal((await findings(t, `String clean = ${escape('input')};
    ${print('"<p>" + clean + "</p>"')}`)).length, 0);
  for (const expression of ['clean + input', '"<script>let x=\\\'" + clean + "\\\';</script>"',
    '"<a href=\\\"" + clean + "\\\">link</a>"']) {
    assert.ok((await findings(t, `String clean = ${escape('input')}; ${print(expression)}`)).length, expression);
  }
});

test('earlier script output and unknown response aliases retain context uncertainty', async t => {
  for (const before of [print('"<script>let x=\\\'"'), 'helper(response);']) {
    assert.ok((await findings(t, `${before}
      String clean = ${escape('input')};
      ${print('clean')}`)).length, before);
  }
});

test('reassignment, partial branches and decoding remove encoding guarantees', async t => {
  for (const change of [
    'clean = input;',
    'if (condition) clean = input;',
    'clean = org.springframework.web.util.HtmlUtils.htmlUnescape(clean);',
  ]) assert.ok((await findings(t, `String clean = ${escape('input')};
    ${change}
    ${print('clean')}`)).length, change);
});

test('a sanitizer elsewhere on the same line cannot hide a second unsafe sink', async t => {
  assert.ok((await findings(t, `${print(escape('input'))} ${print('input')}`)).length, 'second raw sink');
});

test('custom safe-looking names and shadowed library classes retain warnings', async t => {
  assert.ok((await findings(t, `String value = safeHtml(input);
    ${print('value')}`, 'private String safeHtml(String input) { return input; }')).length, 'custom sanitizer');
  assert.ok((await findings(t, `${print(escape('input'))}`, '', {
    'HtmlUtils.java': 'package org.springframework.web.util; public class HtmlUtils { public static String htmlEscape(String x) { return x; } }',
  })).length, 'shadowed library');
});

test('printf checks substitutions rather than treating an encoded format as sufficient', async t => {
  assert.equal((await findings(t, `String clean = ${escape('input')};
    response.getWriter().printf(java.util.Locale.US, "<p>%s</p>", clean);`)).length, 0);
  assert.ok((await findings(t, `response.getWriter().printf(${escape('"%s"')}, input);`)).length, 'raw substitution');
});

test('constant XSS output cannot inherit another method taint', async t => {
  assert.equal((await findings(t, `String value = "fixed";
    ${print('value')}`, 'void other(HttpServletRequest request) { String value = request.getParameter("x"); }')).length, 0);
});

test('a response helper needs an established HTML stream context', async t => {
  const ambiguous = `void echo(HttpServletRequest request, HttpServletResponse response) {
    ${print(escape('request.getParameter("x")'))}
  }`;
  assert.ok((await findings(t, '', ambiguous)).length, 'unknown caller output context');
  const fresh = ambiguous.replace('{\n', '{\n response.resetBuffer(); response.setContentType("text/html;charset=UTF-8");\n');
  assert.equal((await findings(t, '', fresh)).length, 0);
});

test('shadowed servlet types do not establish library output contracts', async t => {
  assert.ok((await findings(t, print(escape('input')), '', {
    'javax/servlet/http/HttpServletResponse.java': 'package javax.servlet.http; public class HttpServletResponse {}',
  })).length, 'shadowed servlet contract');
});

test('conditional output cannot close a script context unconditionally', async t => {
  for (const guard of ['if (false)', 'for (; condition; )', 'while (condition)']) {
    assert.ok((await findings(t, `${print('"<script>"')}
      ${guard} ${print('"</script>"')}
      ${print(escape('input'))}`)).length, guard);
  }
});

test('a proved response sink cannot suppress an unproved writer on the same line', async t => {
  assert.ok((await findings(t, `java.io.PrintWriter out = response.getWriter();
    out.print(input); ${print('"fixed"')}`)).length);
});

test('HTML facts cannot hide structural markup in aliases, helpers or parameters', async t => {
  for (const expression of [`"<script>" + ${escape('input')} + "</script>"`, 'wrap(input)', 'join("<script>", input)']) {
    assert.ok((await findings(t, `String clean = ${expression}; ${print('clean')}`,
      `private String wrap(String value) { return "<script>" + ${escape('value')} + "</script>"; }
       private String join(String prefix, String value) { return prefix + ${escape('value')}; }`)).length, expression);
  }
});

test('writer integer overload and different response receivers retain their own context', async t => {
  for (const before of [
    'response.getWriter().write(60); response.getWriter().write("script>");',
    'other.response.getWriter().print("<script>"); response.getWriter().print("</script>");',
  ]) {
    const target = before.startsWith('other') ? 'other.response.getWriter().print' : 'response.getWriter().print';
    const hits = await findings(t, `${before} ${target}(${escape('input')});`);
    assert.ok(hits.length, before);
  }
});

test('explicit servlet imports and direct character copies preserve HTML text encoding', async t => {
  const explicit = 'import javax.servlet.http.HttpServlet; import javax.servlet.http.HttpServletRequest; import javax.servlet.http.HttpServletResponse;';
  const source = `${explicit}
    public class ServletExample extends HttpServlet {
      protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("value");
        String clean = ${escape('input')};
        response.getWriter().write(clean.toCharArray());
      }
    }`;
  assert.equal((await findings(t, '', '', { 'ServletExample.java': source })).length, 0);
});

test('println newline can complete an HTML tag name before a following attribute', async t => {
  const hits = await findings(t, `response.getWriter().println("<script");
    ${print('"x>"')}
    ${print(escape('input'))}`);
  assert.ok(hits.length);
});

test('repeated output cannot borrow the first iteration HTML context', async t => {
  const hits = await findings(t, `while (condition) {
    ${print(escape('input') + ' + "<script>"')}
  }`);
  assert.ok(hits.length);
});

test('unsupported browser comment and raw-text states retain warnings', async t => {
  for (const prefix of ['<!--><script><!-- -->', "<noscript><p title='</noscript><script>'>", '<script><!--<script></script>', "<p a=b'><script>'>"]) {
    // Split --> so the source-level lambda fallback cannot mask this test.
    const expression = prefix.split('-->').map(JSON.stringify).join(' + "--" + ">" + ');
    const hits = await findings(t, `${print(expression)} ${print(escape('input'))}`);
    assert.ok(hits.length, prefix);
  }
});

test('skipped source directories cannot establish encoder ownership', async t => {
  const hits = await findings(t, print(escape('input')), '', {
    'build/HtmlUtils.java': 'package org.springframework.web.util; public class HtmlUtils { public static String htmlEscape(String x) { return x; } }',
  });
  assert.ok(hits.length);
});

test('immutable formatting arrays render each indexed substitution in HTML text', async t => {
  for (const declaration of ['Object[] parts = {"a", clean};', 'String[] parts = {"a", clean};',
    'final Object[] parts = {"a", clean};']) {
    const hits = await findings(t, `String clean = ${escape('input')};
      ${declaration}
      response.getWriter().printf(java.util.Locale.US, "<p>%1$s and %2$s %% %n</p>", parts);`);
    assert.equal(hits.length, 0, declaration);
  }
});

test('formatting arrays cannot hide raw elements, mutation, aliases or object callbacks', async t => {
  for (const [declaration, change] of [
    ['Object[] parts = {"a", input};', ''],
    ['Object[] parts = {"a", clean};', 'parts[1] = input;'],
    ['Object[] parts = {"a", clean};', '(parts)[1] = input;'],
    ['Object[] parts = {"a", clean};', 'parts = new Object[] {"a", input};'],
    ['Object[] parts = {"a", clean};', 'Object[] alias = parts; alias[1] = input;'],
    ['Object[] parts = {"a", clean};', 'mutate(parts, input);'],
    ['Object[] parts = {new Dangerous(), clean};', ''],
    ['Object[] parts = {"a", input};', `input = ${escape('input')};`],
  ]) {
    assert.ok((await findings(t, `String clean = ${escape('input')};
      ${declaration} ${change}
      response.getWriter().printf("%1$s %2$s", parts);`)).length, declaration + change);
  }
});

test('formatting arrays preserve output structure, scope and unsupported contexts', async t => {
  for (const [prefix, declaration, format, suffix] of [
    ['', 'Object[] parts = {"<script>", clean};', '%1$s %2$s', ''],
    ['', 'Object[] parts = {"a", clean};', '<a href="%2$s">', ''],
    ['response.getWriter().print("<script>");', 'Object[] parts = {"a", clean};', '%2$s', ''],
    ['{ Object[] parts = {"a", clean}; }', 'Object[] parts = {"a", input};', '%2$s', ''],
    ['', 'Object[] parts = {"a", clean};', '%2$s', 'mutate(parts, input);'],
    ['', 'Object[] parts = {"a", clean};', '%3$s', ''],
  ]) {
    assert.ok((await findings(t, `String clean = ${escape('input')};
      ${prefix} ${declaration}
      response.getWriter().printf(${JSON.stringify(format)}, parts);
      ${suffix}`)).length, prefix + declaration + format + suffix);
  }
});

test('formatting arrays support sequential placeholders and ignore unselected raw values', async t => {
  assert.equal((await findings(t, `String clean = ${escape('input')};
    String[] parts = {"label", clean};
    response.getWriter().printf("<p>%s: %s</p>", parts);`)).length, 0);
  assert.equal((await findings(t, `String clean = ${escape('input')};
    Object[] parts = {input, clean};
    response.getWriter().printf("%2$s", parts);`)).length, 0);
});

test('formatting array budgets and unsupported carriers retain warnings', async t => {
  const values = Array(32).fill('clean').join(', ');
  assert.equal((await findings(t, `String clean = ${escape('input')};
    Object[] parts = {${values}};
    response.getWriter().printf("%32$s", parts);`)).length, 0);
  for (const body of [
    `Object[] parts = {${values}, clean}; response.getWriter().printf("%33$s", parts);`,
    'Object[] parts = new Object[] {"a", clean}; response.getWriter().printf("%2$s", parts);',
    'Object[] parts = {"a", clean}; response.getWriter().printf("%2$s", (Object) parts);',
    'Object[] parts = {"a", clean}; response.getWriter().printf("%2$s", parts); parts[1] = input;',
    'Object value = obtain(input); Object[] parts = {value, clean}; response.getWriter().printf("%1$s %2$s", parts);',
  ]) assert.ok((await findings(t, `String clean = ${escape('input')};
    ${body.replaceAll('; ', ';\n')}`)).length, body);
});

test('unselected array initializers cannot change the output context or invoke callbacks', async t => {
  for (const value of [
    'request.startAsync().getResponse().getWriter().append("<script>")',
    'sideEffect(input)',
    '(clean = input)',
    'new Dangerous()',
  ]) {
    assert.ok((await findings(t, `String clean = ${escape('input')};
      Object[] parts = {${value}, clean};
      response.getWriter().printf("%2$s</script>", parts);`)).length, value);
  }
});
