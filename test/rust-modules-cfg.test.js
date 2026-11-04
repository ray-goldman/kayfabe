'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {lexRust}=require('../src/parsers/rust/lexer');
const {evaluatePredicate}=require('../src/parsers/rust/cfg');
const {analyzeRustProject}=require('../src/parsers/rust/analysis');
const manifest='[package]\nname="module-fixture"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nreqwest="0.12"';
const chain='reqwest::Client::builder().danger_accept_invalid_certs(true).build()';
const run=(files,opts={})=>analyzeRustProject(Object.entries(files).map(([file,raw])=>({file,raw})),[{rel:'Cargo.toml',raw:manifest}],true,opts);
test('cfg predicates use three states and validate every operand',()=>{
 for(const [source,value]of [['all()',true],['any()',false],['not(any())',true],['all(windows,any())',false],['any(unix,all())',true],['feature="x"',null],['windows',null],['not(windows)',null],['all(any(),unsupported())',null],['not(any(),)',null],['all(,)',null]]) {
  const parsed=lexRust(source);assert.equal(evaluatePredicate(parsed.tokens).value,value,source);
 }
 assert.equal(evaluatePredicate(lexRust('test').tokens).value,false);
 assert.equal(evaluatePredicate(lexRust('test').tokens,{includeTests:true}).value,null);
});
test('inline and external modules retain unsafe evidence and keep fixed clients quiet',()=>{
 const r=run({'src/main.rs':`mod inline { fn f() { ${chain}; } } mod client;`,'src/client.rs':`fn f() { ${chain}; }`});
 assert.equal(r.findings.length,2);assert.deepEqual(r.findings.map(f=>f.file).sort(),['src/client.rs','src/main.rs']);
 const safe=run({'src/main.rs':`mod client;`,'src/client.rs':`fn f() { ${chain.replace('(true)','(false)')}; }`});assert.equal(safe.findings.length,0);
});
test('known cfg includes/excludes while target and feature branches stay unresolved',()=>{
 for(const [cfg,n]of [['all()',1],['any()',0],['test',0],['windows',0],['feature="danger"',0]]) {
  assert.equal(run({'src/main.rs':`#[cfg(${cfg})] mod client;`,'src/client.rs':`fn f() { ${chain}; }`}).findings.length,n,cfg);
 }
 assert.equal(run({'src/main.rs':`#![cfg(any())]\nfn a() {} fn b(){${chain};}`}).findings.length,0);
 assert.equal(run({'src/main.rs':`#[cfg(all())] fn a(){${chain};} #[cfg(windows)] fn b(){${chain};}`}).findings.length,1);
});
test('cfg_attr handles disabled macro effects, active cfg and unknown inert attributes',()=>{
 assert.equal(run({'src/main.rs':`#[cfg_attr(any(),rewrite_items)] struct Marker; fn f(){${chain};}`}).findings.length,1);
 assert.equal(run({'src/main.rs':`#[cfg_attr(all(),cfg(any()))] fn f(){${chain};}`}).findings.length,0);
 assert.equal(run({'src/main.rs':`#![cfg_attr(windows,windows_subsystem="windows")] fn f(){${chain};}`}).findings.length,1);
 assert.equal(run({'src/main.rs':`#[cfg_attr(windows,rewrite_items)] struct Marker; fn f(){${chain};}`}).findings.length,0);
});
test('module bindings and macro uncertainty stay scoped and disabled shadows stay absent',()=>{
 const r=run({'src/main.rs':`mod noise { #[rewrite_items] struct Marker; } mod client { use reqwest::Client; fn f(){Client::builder().danger_accept_invalid_certs(true).build();} }`});assert.equal(r.findings.length,1);
 assert.equal(run({'src/main.rs':`#[cfg(any())] mod reqwest {} fn f(){${chain};}`}).findings.length,1);
 assert.equal(run({'src/main.rs':`#[cfg(windows)] mod reqwest {} fn f(){${chain};}`}).findings.length,0);
 assert.equal(run({'src/main.rs':`use reqwest::Client; mod client { fn f(){Client::builder().danger_accept_invalid_certs(true).build();} }`}).findings.length,0);
});
test('module lookup refuses ambiguous, cyclic, custom and absent paths without filesystem reads',()=>{
 for(const files of [
  {'src/main.rs':`mod client;`,'src/client.rs':`fn f(){${chain};}`,'src/client/mod.rs':`fn f(){${chain};}`},
  {'src/main.rs':`mod main; fn f(){${chain};}`},
  {'src/main.rs':`#[path="../outside.rs"] mod client;`,'outside.rs':`fn f(){${chain};}`},
  {'src/main.rs':'mod client;','src/orphan.rs':`fn f(){${chain};}`},
 ])assert.equal(run(files).findings.length,0);
});
test('nested module directories follow Rust defaults and do not promote unreachable source',()=>{
 const r=run({'src/main.rs':'mod outer;','src/outer.rs':`mod inner;`,'src/outer/inner.rs':`fn f(){${chain};}`,'src/orphan.rs':`fn f(){${chain};}`});
 assert.equal(r.findings.length,1);assert.equal(r.findings[0].file,'src/outer/inner.rs');
});
test('inactive cfg effects do not block live siblings or known-safe module controls',()=>{
 assert.equal(run({'src/main.rs':`#[cfg(any())] #[rewrite_items] fn dormant() {} fn f(){${chain};}`}).findings.length,1);
 assert.equal(run({'src/main.rs':`#[cfg(windows)] use safe_http as reqwest; fn f(){${chain};}`}).findings.length,0);
 assert.equal(run({'src/main.rs':`#[cfg(any())] use safe_http as reqwest; fn f(){${chain};}`}).findings.length,1);
});
test('duplicate module/import declarations are unresolved without crashes or inflated function counts',()=>{
 for(const source of [`use reqwest::{Client,Client}; fn f(){${chain};}`,`use reqwest::{Client @}; fn f(){${chain};}`,`mod foo {fn f(){${chain};}} mod foo {}`,`mod foo {fn f(){${chain};}} #[cfg(windows)] mod foo {}`]) {
  assert.doesNotThrow(()=>run({'src/main.rs':source}));assert.equal(run({'src/main.rs':source}).findings.length,0,source);
 }
 const r=run({'src/main.rs':'mod lib;','src/lib.rs':`fn f(){${chain};}`});
 assert.equal(r.findings.length,1);const coverage=r.files.find(f=>f.file==='src/lib.rs').coverage;
 assert.equal(coverage.discoveredFunctions,1);assert.equal(coverage.analyzedFunctions,1);
});
test('explicit Cargo required features cannot be bypassed by automatic root discovery',()=>{
 const files=[{file:'src/main.rs',raw:`fn f(){${chain};}`}];
 const r=analyzeRustProject(files,[{rel:'Cargo.toml',raw:manifest+'\n[[bin]]\nname="app"\npath="src/main.rs"\nrequired-features=["risky"]'}]);
 assert.equal(r.findings.length,0);assert.equal(r.files[0].coverage.moduleStatus,'conditional');
});
test('anonymous imports do not shadow and repeated module contexts obey a shared token budget',()=>{
 assert.equal(run({'src/main.rs':`use reqwest::{Client as _,ClientBuilder as _}; fn f(){${chain};}`}).findings.length,1);
 const files={'src/bin/common.rs':`fn f(){${'let x=0;'.repeat(5000)} ${chain};}`};
 for(let i=0;i<60;i++)files['src/bin/a'+i+'.rs']='mod common;';
 const r=run(files);assert.equal(r.findings.length,0);assert.ok(r.files.some(f=>f.coverage.diagnostics.some(d=>d.code==='rust-analysis-budget')));
});

test('unconditional libraries stay active when a feature-gated binary shares their source',()=>{
 for(const file of ['src/lib.rs','src/shared.rs']) {
  const lib=file==='src/shared.rs'?'\n[lib]\npath="src/shared.rs"':'';
  const r=analyzeRustProject([{file,raw:`pub fn main(){${chain};}`}],[{rel:'Cargo.toml',raw:manifest+lib+`\n[[bin]]\nname="gated"\npath="${file}"\nrequired-features=["risky"]`}]);
  assert.equal(r.findings.length,1,file);assert.equal(r.files[0].coverage.moduleStatus,'reachable');
  assert.equal(r.files[0].coverage.analyzedFunctions,1);
 }
});

test('explicit targets cannot borrow a nested package dependency identity',()=>{
 const r=analyzeRustProject([
  {file:'child/entry.rs',raw:`mod harmless {} fn f(){${chain};}`},
  {file:'child/src/lib.rs',raw:''},
 ],[
  {rel:'Cargo.toml',raw:'[package]\nname="outer"\nversion="0.0.0"\n[dependencies]\nreqwest={package="safe-http",version="1"}\n[[bin]]\nname="outer"\npath="child/entry.rs"'},
  {rel:'child/Cargo.toml',raw:manifest},
 ]);
 assert.equal(r.findings.length,0);
 assert.ok(r.files.find(f=>f.file==='child/entry.rs').coverage.diagnostics.some(d=>d.code==='rust-target-owner-unresolved'));
});

test('explicit binary names replace conventional source paths without losing active targets',()=>{
 for(const [name,file]of [['module-fixture','src/main.rs'],['extra','src/bin/extra.rs'],['extra','src/bin/extra/main.rs']]) {
  const inputs=[{file,raw:`mod harmless {} fn f(){${chain};}`},{file:'entry.rs',raw:'fn main() {}'}];
  const cargo=[{rel:'Cargo.toml',raw:manifest+`\n[[bin]]\nname="${name}"\npath="entry.rs"`}];
  assert.equal(analyzeRustProject(inputs,cargo).findings.length,0,file);
  inputs[1].raw=`fn main(){${chain};}`;const r=analyzeRustProject(inputs,cargo);
  assert.equal(r.findings.length,1,file);assert.equal(r.findings[0].file,'entry.rs');
 }
});

test('2015 target auto-discovery is disabled by manual targets unless explicitly enabled',()=>{
 const inputs=[{file:'src/bin/extra.rs',raw:`fn main(){${chain};}`},{file:'entry.rs',raw:'fn main() {}'}];
 for(const edition of ['2015','2021']) {
  const base=manifest.replace('edition="2021"',`edition="${edition}"`);
  const r=analyzeRustProject(inputs,[{rel:'Cargo.toml',raw:base+'\n[[bin]]\nname="manual"\npath="entry.rs"'}]);
  assert.equal(r.findings.length,edition==='2015'?0:1);
 }
 const explicit=manifest.replace('edition="2021"','edition="2015"\nautobins=true');
 assert.equal(analyzeRustProject(inputs,[{rel:'Cargo.toml',raw:explicit+'\n[[bin]]\nname="manual"\npath="entry.rs"'}]).findings.length,1);
});

test('module budget diagnostics survive saturated namespace diagnostics',()=>{
 const r=run({'src/main.rs':`${'mod sibling {}'.repeat(4100)} fn f(){${chain};}`});
 assert.equal(r.findings.length,0);const diagnostics=r.files[0].coverage.diagnostics;
 assert.ok(diagnostics.some(d=>d.code==='rust-module-budget'));assert.ok(diagnostics.length<=260);
});

test('manual example/test/bench targets cannot activate a historical standalone fallback',()=>{
 for(const edition of ['2015','2021'])for(const kind of ['example','test','bench']) {
  const r=analyzeRustProject([{file:'main.rs',raw:`mod harmless {} fn main(){${chain};}`},{file:'examples/tool.rs',raw:'fn main() {}'}],
   [{rel:'Cargo.toml',raw:manifest.replace('edition="2021"',`edition="${edition}"`)+`\n[[${kind}]]\nname="tool"\npath="examples/tool.rs"`}]);
  assert.equal(r.findings.length,0,edition+' '+kind);
 }
});
