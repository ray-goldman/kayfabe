'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const { scan } = require('../src/engine');
const { createCSharpConstMemberProof } = require('../src/csharp-const-members');
const { parseCSharp } = require('../src/parsers/csharp/parser');
const project = '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>';
const constants = 'namespace Example.Data; public sealed class QueryText { public const string Columns = "id, name"; }';
const consumer = expression => `using Example.Data;
namespace Example.Web;
public sealed class Reports {
 public void Run(dynamic command, string input) {
  command.CommandText = ${expression};
 }
}`;
async function findings(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-const-members-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [file, text] of Object.entries({ 'Example.csproj': project, 'Data/QueryText.cs': constants, ...files })) {
    const dest = path.join(root, file); fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, text);
  }
  return (await scan(root)).findings.filter(f => f.ruleId === 'CS-SQLI-001');
}
test('cross-file literal const member interpolation is not dynamic SQL', async t => {
  assert.equal((await findings(t, { 'Reports.cs': consumer('$"SELECT {QueryText.Columns} FROM records WHERE id = $id"') })).length, 0);
});
test('raw SQL interpolation proves the complete expression across lines', async t => {
  assert.equal((await findings(t, { 'Reports.cs': consumer('$"""\nSELECT {QueryText.Columns}\nFROM records WHERE id = $id\n"""') })).length, 0);
});
test('literal backslashes in raw SQL do not make a constant interpolation dynamic', async t => {
  const expression = String.raw`$"""
SELECT {QueryText.Columns} FROM records WHERE name LIKE $name ESCAPE '\'
"""`;
  assert.equal((await findings(t, { 'Reports.cs': consumer(expression) })).length, 0);
});
test('a constant member cannot hide an additional attacker-controlled hole', async t => {
  assert.ok((await findings(t, { 'Reports.cs': consumer('$"SELECT {QueryText.Columns} FROM records WHERE name = {input}"') })).length);
});

for (const [label, changes] of Object.entries({
  'mutable static field': { 'Data/QueryText.cs': constants.replace('const string', 'static string') },
  'readonly field': { 'Data/QueryText.cs': constants.replace('const string', 'static readonly string') },
  'property': { 'Data/QueryText.cs': constants.replace('const string Columns = "id, name";', 'static string Columns => ReadInput();') },
  'unresolved member': { 'Data/QueryText.cs': constants.replace('Columns', 'Different') },
  'unknown type': { 'Data/QueryText.cs': constants.replace('QueryText', 'Other') },
  'ambiguous type': { 'Other.cs': constants.replace('Example.Data', 'Other.Data') },
  'generic type': { 'Data/QueryText.cs': constants.replace('class QueryText', 'class QueryText<T>') },
  'partial type': { 'Data/QueryText.cs': constants.replace('sealed class', 'sealed partial class') },
  'conditional source': { 'Data/QueryText.cs': '#if DEBUG\n' + constants + '\n#endif' },
  'malformed source': { 'Other.cs': 'class Unclosed {' },
  'alias': { 'Alias.cs': 'using QueryText = Other.Type; namespace Example.Web; class Alias {}' },
  'global import': { 'Imports.cs': 'global using Other;' },
  'custom build inputs': { 'Directory.Build.props': '<Project />' },
  'unknown project package': { 'Example.csproj': project.replace('</Project>', '<ItemGroup><PackageReference Include="Unknown" Version="1.0.0" /></ItemGroup></Project>') },
  'excluded constant source': { 'Example.csproj': project.replace('</Project>', '<ItemGroup><Compile Remove="Data/QueryText.cs" /></ItemGroup></Project>') },
  'unknown base': { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('class Reports', 'class Reports : ExternalBase') },
  'source base named like framework': { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('class Reports', 'class Reports : ControllerBase'), 'Base.cs': 'namespace Example.Web; class ControllerBase : ExternalBase {}' },
  'parameter shadow': { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('Run(dynamic command, string input)', 'Run(dynamic command, dynamic QueryText, string input)') },
  'escaped parameter shadow': { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('Run(dynamic command, string input)', 'Run(dynamic command, dynamic @QueryText, string input)') },
  'local shadow': { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('command.CommandText', 'dynamic QueryText = ReadInput();\n command.CommandText') },
  'opaque binding in another interpolation': { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('command.CommandText', 'var x = $"{Read(out var QueryText)}";\n command.CommandText') },
})) test(`does not suppress SQL for ${label}`, async t => {
  assert.ok((await findings(t, { 'Reports.cs': consumer('$"SELECT {QueryText.Columns} FROM records"'), ...changes })).length);
});

for (const [label, expr] of Object.entries({
  'format clause': '$"SELECT {QueryText.Columns:x}"',
  'alignment clause': '$"SELECT {QueryText.Columns,10}"',
  'getter call': '$"SELECT {QueryText.Columns.ToString()}"',
  'unknown suffix after raw string': '$"""\nSELECT {QueryText.Columns}\n""" +\n input',
  'two sinks on one line': '$"SELECT {QueryText.Columns}"; other.CommandText = $"SELECT {input}"',
})) test(`retains dynamic warning for ${label}`, async t => {
  assert.ok((await findings(t, { 'Reports.cs': consumer(expr) })).length);
});

test('complete input and project budgets are required for the proof', () => {
  const { createCSharpConstMemberProof } = require('../src/csharp-const-members');
  const sources = [{ file:'Reports.cs', raw:consumer('$"SELECT {QueryText.Columns}"') }, { file:'Data/QueryText.cs', raw:constants }];
  const options = { projects:[{file:'Example.csproj',raw:project}] };
  assert.equal(createCSharpConstMemberProof(sources,options)('Reports.cs',5),true);
  for(const extra of [{complete:false},{projectComplete:false},{projects:[]},{projects:[...options.projects,...options.projects]}])
    assert.equal(createCSharpConstMemberProof(sources,{...options,...extra})('Reports.cs',5),false);
});

for(const [base, receiver, member] of [['Controller','ViewBag','Columns'],['ControllerBase','Request','Method']])
test(`inherited ${receiver} is a value even when an imported source type has the same name`, async t => {
  const source=`using Microsoft.AspNetCore.Mvc;
using Example.Data;
namespace Example.Web;
public class Reports : ${base} {
 public void Run(dynamic command, string input) {
  ${receiver}.${member} = input;
  command.CommandText = $"SELECT {${receiver}.${member}} FROM records";
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'Data/Receiver.cs':`namespace Example.Data; public class ${receiver} { public const string ${member} = "id"; }`})).length);
});

test('imports from another block namespace cannot redirect expression binding', async t => {
  const source=`using System;
namespace Other { using Example.Data; public class Marker {} }
namespace Example.Web {
 public class Reports {
  public void Run(dynamic command, string input) {
   Console.Title = input;
   command.CommandText = $"SELECT {Console.Title} FROM records";
  }
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'Data/Console.cs':'namespace Example.Data; public class Console { public const string Title = "id"; }'})).length);
});

for(const directory of ['obj','bin','.hidden','node_modules','bower_components','jspm_packages','packages','vendor'])
test(`default-excluded ${directory} source cannot contribute a constant binding`, async t => {
  const source=`using System;
namespace Example.Web;
public class Reports {
 public void Run(dynamic command, string input) {
  Console.Title = input;
  command.CommandText = $"SELECT {Console.Title} FROM records";
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,[directory+'/Console.cs']:'namespace Example.Web; public class Console { public const string Title = "id"; }'})).length);
});

for(const [label, body] of [
  ['switch guard', 'switch(holder) { case var QueryText when true:\n command.CommandText = $"SELECT {QueryText.Columns}"; break; }'],
  ['pattern conjunction', 'if(holder is var QueryText and not null) {\n command.CommandText = $"SELECT {QueryText.Columns}"; }'],
]) test(`pattern binding in a ${label} cannot be mistaken for a type`, async t => {
  const source=`using Example.Data;
namespace Example.Web;
public class Holder { public string Columns = "id"; }
public class Reports {
 public void Run(dynamic command, string input) {
  var holder = new Holder(); holder.Columns = input;
  ${body}
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source})).length);
});

for(const [label, decoy] of [
  ['unimported','namespace Example.Decoy; public interface Controller {}'],
  ['generic','namespace Example.Web; public interface Controller<T> {}'],
  ['nested','namespace Example.Web; public class Container { public interface Controller {} }'],
]) test(`an ${label} source interface cannot establish a framework base binding`, async t => {
  const source=`using Microsoft.AspNetCore.Mvc;
using Example.Data;
namespace Example.Web;
public class Reports : Controller {
 public void Run(dynamic command, string input) {
  Request.Method = input;
  command.CommandText = $"SELECT {Request.Method} FROM records";
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'Decoy.cs':decoy,'Data/Request.cs':'namespace Example.Data; public class Request { public const string Method = "id"; }'})).length);
});

test('LINQ continuation variables cannot masquerade as type declarations', async t => {
  const source=`using System;
using System.Linq;
using Example.Data;
namespace Example.Web;
public class Holder { public string Columns = "id"; }
public class Reports {
 public void Run(dynamic command, string input) {
  var holder = new Holder(); holder.Columns = input;
  var actions = from x in new[] { holder } select x into QueryText
   select ((Func<string>)(() => {
    command.CommandText = $"SELECT {QueryText.Columns}";
    return "";
   }));
  actions.Single()();
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source})).length);
});

test('file-local const types cannot supply cross-file expression bindings', async t => {
  const source=`using System;
namespace Example.Web;
public class Reports {
 public void Run(dynamic command, string input) {
  Console.Title = input;
  command.CommandText = $"SELECT {Console.Title}";
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'FileLocal.cs':'namespace Example.Web; file class Console { public const string Title = "id"; }'})).length);
});

test('file-local interfaces cannot establish a base binding in another file', async t => {
  const source=`using Microsoft.AspNetCore.Mvc;
using Example.Data;
namespace Example.Web;
public class Reports : Controller {
 public void Run(dynamic command, string input) {
  Request.Method = input;
  command.CommandText = $"SELECT {Request.Method}";
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'FileLocal.cs':'namespace Example.Web; file interface Controller {}','Data/Request.cs':'namespace Example.Data; public class Request { public const string Method="id"; }'})).length);
});

test('the this receiver does not resolve an escaped keyword type', async t => {
  const source=`using Example.Data;
namespace Example.Web;
public class Reports {
 public string Columns = "id";
 public void Run(dynamic command, string input) {
  this.Columns = input;
  command.CommandText = $"SELECT {this.Columns}";
 }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'Keyword.cs':'namespace Example.Data; public class @this { public const string Columns="id"; }'})).length);
});

test('namespace components cannot be mistaken for independent interface bases', async t => {
  const source=`using Microsoft.AspNetCore.Mvc;
using Example.Data;
namespace Example.Web;
public class Reports : global::Microsoft.AspNetCore.Mvc.Controller {
 public void Run(dynamic command, string input) {
  Request.Method = input;
  command.CommandText = $"SELECT {Request.Method}";
 }
}`;
  const decoys='namespace Example.Web; public interface @global {} public interface Microsoft {} public interface AspNetCore {} public interface Mvc {} public interface Controller {}';
  assert.ok((await findings(t, {'Reports.cs':source,'Decoys.cs':decoys,'Data/Request.cs':'namespace Example.Data; public class Request { public const string Method="id"; }'})).length);
});

test('implicit setter value cannot resolve an unrelated contextual-keyword type', async t => {
  const source=`using Example.Data;
namespace Example.Web;
public class Holder { public string Columns = "id"; }
public class Reports {
 private dynamic command;
 public Holder Input { set {
  command.CommandText = $"SELECT {value.Columns}";
 } }
 public void Run(dynamic cmd, string input) { command=cmd; Input=new Holder { Columns=input }; }
}`;
  assert.ok((await findings(t, {'Reports.cs':source,'Value.cs':'namespace Example.Data; public class value { public const string Columns="id"; }'})).length);
});

test('default interface methods cannot prove an inherited mutable receiver is a const type', async t => {
  const source=`using Microsoft.AspNetCore.Http;
using Example.Data;
namespace Example.Web;
public interface ISource : IHttpContextAccessor {}
public interface IReports : ISource {
 public void Run(dynamic command, string input) {
  HttpContext.TraceIdentifier = input;
  command.CommandText = $"SELECT {HttpContext.TraceIdentifier} FROM records";
 }
}
public class Reports : HttpContextAccessor, IReports {}
public class Program { public static void Main() {} }
`;
  assert.ok((await findings(t, {'Reports.cs':source,'Data/HttpContext.cs':'namespace Example.Data; public class HttpContext { public const string TraceIdentifier="id"; }'})).length);
});

for (const kind of ['interface', 'struct', 'record', 'record class', 'record struct'])
test(`a ${kind} sink owner is outside the ordinary-class binding proof`, async t => {
  const source=consumer('$"SELECT {QueryText.Columns}"').replace('sealed class Reports', `${kind} Reports`);
  assert.ok((await findings(t, {'Reports.cs':source})).length);
});

test('a positional record sink owner is outside the ordinary-class binding proof', async t => {
  const source=consumer('$"SELECT {QueryText.Columns}"').replace('sealed class Reports', 'record Reports(int Id)');
  assert.ok((await findings(t, {'Reports.cs':source})).length);
});

const initializer = 'namespace Example.Auth; class Other : Base { public Other(string input) : base(input) {} }';
function initializerProof(other, overrides = {}, factory = createCSharpConstMemberProof) {
  const files = { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"'), 'Data/QueryText.cs': constants,
    'Other.cs': other, ...overrides };
  return factory(Object.entries(files).map(([file, raw]) => ({ file, raw })),
    { projects: [{ file: 'Example.csproj', raw: project }] })('Reports.cs', 5);
}

for (const eol of ['\n', '\r\n']) test(`unrelated explicit initializer preserves a closed const-member proof (${JSON.stringify(eol)})`, async t => {
  const other = initializer.replace(' : base', `${eol} : base`);
  const parsed = parseCSharp(other);
  assert.equal(parsed.complete, false);
  assert.equal(parsed.coverage.parsedMethods, 0);
  assert.equal(parsed.errors[0].code, 'unsupported-constructor-header');
  assert.equal(initializerProof(other), true);
  assert.equal((await findings(t, { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"'), 'Other.cs': other })).length, 0);
  // Same file, disjoint owners: the known unsupported owner is still excluded.
  assert.equal(initializerProof('', { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"') + '\n' +
    initializer.replace('namespace Example.Auth; ', '') }), true);
});

for (const [label, other, overrides] of [
  ['same sink owner', '', { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace(' public void Run', ' public Reports() : this(1) {}\n public void Run') }],
  ['constant owner', initializer, { 'Data/QueryText.cs': constants.replace('public const', 'public QueryText() : this(1) {} public const') }],
  ['primary parameter in sink owner', initializer, { 'Reports.cs': consumer('$"SELECT {QueryText.Columns}"').replace('class Reports', 'class Reports(dynamic QueryText)') }],
  ['primary default header', 'class Other(string input = "x") {}', {}],
  ['primary base header', 'class Other(string input) : Base(input) {}', {}],
  ['initializer parameter shadow', initializer.replace('string input', 'dynamic QueryText'), {}],
  ['initializer out binding shadow', initializer.replace('base(input)', 'base(Read(out var QueryText))'), {}],
  ['initializer pattern shadow', initializer.replace('base(input)', 'base(input is var QueryText)'), {}],
  ['duplicate type in unsupported owner', initializer.replace(' {} }', ' {} class QueryText {} }'), {}],
  ['duplicate type beside unsupported owner', initializer + ' class QueryText {}', {}],
  ['unknown parser diagnostic', initializer.replace('{}', '{ goto done; done: return; }'), {}],
  ['unclosed delimiter', initializer + ' class Broken {', {}],
  ['mismatched delimiter', initializer.replace('base(input)', 'base(input]'), {}],
  ['lexical diagnostic', initializer + ' "unterminated', {}],
  ['conditional declaration', '#if DEBUG\n' + initializer + '\n#endif', {}],
  ['global alias', initializer + ' using QueryText = Other.Type;', {}],
]) test(`explicit initializer compatibility retains warning for ${label}`, () => {
  assert.equal(initializerProof(other, overrides), false);
});

test('initializer diagnostic exceptions require exact known diagnostics and independent owner bounds', t => {
  const parser = require('../src/parsers/csharp/parser');
  const modulePath = require.resolve('../src/csharp-const-members'), cached = require.cache[modulePath];
  t.after(() => { require.cache[modulePath] = cached; });
  for (const mutate of [
    p => { p.errors[0].code = 'future-header-error'; },
    p => { p.errors[0].message = 'future constructor error'; },
    p => { p.errors[0].ownerStart++; },
    p => { p.errors[0].ownerEnd--; },
    p => { p.errors[0].ownerEnd = Infinity; },
    p => { p.errors[0].start = p.errors[0].ownerStart; },
    p => { p.errors = []; },
    p => { p.errors.push({ message: 'unrecognized', start: 0 }); },
  ]) {
    const mock = t.mock.method(parser, 'parseCSharp', raw => {
      const parsed = parseCSharp(raw);
      if (raw === initializer) mutate(parsed);
      return parsed;
    });
    delete require.cache[modulePath];
    const factory = require('../src/csharp-const-members').createCSharpConstMemberProof;
    assert.equal(initializerProof(initializer, {}, factory), false);
    mock.mock.restore();
  }
});
