'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {lexRust}=require('../src/parsers/rust/lexer');
const {analyzeRustProject}=require('../src/parsers/rust/analysis');
const manifest='[dependencies]\nreqwest = "0.12"\n';
function analyze(source, cargo=manifest,extra=[]) { return analyzeRustProject([{file:'src/main.rs',raw:source},...extra],[{rel:'Cargo.toml',raw:cargo}]); }
const chain='reqwest::Client::builder().danger_accept_invalid_certs(true).build()';
const hits=source=>analyze(source).findings;
test('Rust lexer separates nested comments, raw literals, chars, lifetimes and raw identifiers',()=>{
 const r=lexRust('/* outer /* inner */ end */ fn r#type<\'a>() { let s=br##" /* } */ "##; let c=\'x\'; let x: &\'a str = "ok"; }');
 assert.equal(r.complete,true);assert.equal(r.tokens.filter(t=>t.kind==='literal').length,3);
 assert.ok(r.tokens.some(t=>t.kind==='lifetime'&&t.value==="'a"));assert.ok(r.tokens.some(t=>t.value==='type'));
});
test('Rust malformed and excessive inputs have explicit bounded diagnostics',()=>{
 for(const raw of ['/* unclosed','fn f() { "unterminated', 'fn f() { ] }','{'.repeat(129),'a '.repeat(100001),' '.repeat(1048577)]) {
  const r=lexRust(raw);assert.equal(r.complete,false);assert.ok(r.diagnostics.length);
 }
 for(const c of ['`','\\','\0','\x07']){const raw=`fn f() { ${c}; ${chain}; }`;assert.equal(lexRust(raw).complete,false);assert.equal(hits(raw).length,0);}
});
test('resolved reqwest chains require literal unsafe setting and terminal build',()=>{
 assert.equal(hits(`fn f() { let client = ${chain}; }`).length,1);
 assert.equal(hits(`use reqwest::Client as Http; fn f() { let client = Http::builder().use_native_tls().danger_accept_invalid_hostnames(true).build(); }`)[0].ruleId,'RUST-TLS-002');
 assert.equal(hits('use reqwest::{Client, redirect::Policy}; fn f() { let c=Client::builder().redirect(Policy::none()).danger_accept_invalid_certs(true).build(); }').length,1);
 assert.equal(hits('fn f() { reqwest::blocking::ClientBuilder::new().danger_accept_invalid_certs(true).build() }').length,1);
 for(const suffix of ['.danger_accept_invalid_certs(false).build()','.danger_accept_invalid_certs(flag).build()','.custom_reset().build()','']) {
  assert.equal(hits(`fn f() { reqwest::Client::builder().danger_accept_invalid_certs(true)${suffix}; }`).length,0);
 }
});
test('text, macros, unknown APIs, branches and binding collisions do not create TLS findings',()=>{
 const safe=[`fn f() { let s=r#"${chain}"#; }`,`fn f() { /* ${chain} */ }`,`fn f() { println!("x", ${chain}); }`,
  `fn f() { if false { ${chain}; } }`,`fn f<Client>() { ${chain}; }`,`#[cfg(test)] fn f() { ${chain}; }`,
  `use other::Client; fn f() { Client::builder().danger_accept_invalid_certs(true).build(); }`,
  `mod reqwest {} fn f() { ${chain}; }`,`fn f(reqwest: Fake) { ${chain}; }`,
  `fn f() { let reqwest = Fake; ${chain}; }`,`fn f() { return; ${chain}; }`,
  `macro_rules! alias { () => {} } fn f() { ${chain}; }`,
  `fn f() { false && ${chain}.is_ok(); }`,
  `fn f() { std::process::exit(0); ${chain}; }`,
  `fn f() { std::process::abort(); ${chain}; }`,
  `include!("bindings.rs"); fn f() { ${chain}; }`,
  'fn f() { let r#true=false; reqwest::Client::builder().danger_accept_invalid_certs(r#true).build(); }',
  `use other::*; fn f() { ${chain}; }`];
 for(const source of safe) assert.equal(hits(source).length,0,source);
 assert.equal(analyze(`fn f() { ${chain}; }`,'[dependencies]\nreqwest={package="custom-http",version="1"}').findings.length,0);
 assert.equal(analyze(`fn f() { ${chain}; }`,manifest,[{file:'src/other.rs',raw:'mod reqwest {}'}]).findings.length,0);
});
test('hostname settings require an explicitly selected native TLS backend',()=>{
 assert.equal(hits('fn f(){reqwest::Client::builder().danger_accept_invalid_hostnames(true).build();}').length,0);
 assert.equal(hits('fn f(){reqwest::Client::builder().use_native_tls().danger_accept_invalid_hostnames(true).use_rustls_tls().build();}').length,0);
});
test('crate-level cfg and macro attributes cannot leave later functions falsely reachable',()=>{
 for(const prefix of ['#![cfg(any())]','#![cfg_attr(feature="off",cfg(any()))]','#[cfg_attr(feature="rewrite",rewrite_items)]','#[rewrite_items]']) {
  assert.equal(hits(`${prefix} fn first() {} fn second() { ${chain}; }`).length,0,prefix);
 }
});
test('malformed Rust and import token trees never throw or disclose source diagnostics',()=>{
 const parts=['use','::','as','Client','reqwest','fn','(',')','{','}',';','*',',','!','#','[',']','"x"','r#true'];let seed=17;
 for(let n=0;n<600;n++){let raw='';for(let j=0;j<30;j++){seed=(Math.imul(seed,1664525)+1013904223)>>>0;raw+=parts[seed%parts.length]+' ';}assert.doesNotThrow(()=>analyze(raw));}
});
test('Cargo ownership rejects optional/build-only crates, local library identities and normalized alias collisions',()=>{
 const source=`fn f() { ${chain}; }`;
 for(const cargo of [
  '[build-dependencies]\nreqwest="0.12"',
  '[dependencies]\nreqwest={version="0.12",optional=true}',
  '[lib]\nname="reqwest"\n[dependencies]\nreqwest="0.12"',
  '[dependencies]\nhttp-client={package="reqwest",version="0.12"}\n[target.\'cfg(windows)\'.dependencies]\nhttp_client={package="safe-http",version="1"}',
 ])assert.equal(analyze(source.replaceAll('reqwest::',cargo.includes('http-client')?'http_client::':'reqwest::'),cargo).findings.length,0,cargo);
});
test('unsupported module reachability cannot report cfg-excluded external modules',()=>{
 const r=analyze('fn main() {}',manifest,[{file:'src/lib.rs',raw:'#[cfg(any())] mod excluded;'}, {file:'src/excluded.rs',raw:`fn f() { ${chain}; }`}]);
 assert.equal(r.findings.length,0);
});
test('import aliases for known terminating APIs cannot make unreachable chains appear live',()=>{
 for(const name of ['exit','abort'])assert.equal(hits(`use std::process::${name} as terminate; fn f() { terminate(${name==='exit'?'0':''}); ${chain}; }`).length,0);
 for(const imports of ['use std::process as p; use p::exit as terminate;','use std::process::exit as end; use end as terminate;','use a as b; use b as a;']) {
  assert.equal(hits(`${imports} fn f() { terminate(0); ${chain}; }`).length,0,imports);
 }
});
test('nested eagerly evaluated builder arguments retain their own unsafe configuration finding',()=>{
 const r=hits(`fn f() { let _outer=reqwest::Client::builder().user_agent(make_agent(${chain})).build(); }`);
 assert.equal(r.length,1);assert.equal(r[0].ruleId,'RUST-TLS-001');
});
test('excluded tests cannot suppress production Rust checks; visible Cargo config prevents identity claims',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-rust-scope-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,'Cargo.toml'),manifest);fs.writeFileSync(path.join(root,'main.rs'),`fn main() { let c=${chain}; }`);
 fs.mkdirSync(path.join(root,'tests'));fs.writeFileSync(path.join(root,'tests/client.rs'),'mod support;');
 const {scan}=require('../src/engine');let r=await scan(root);
 assert.equal(r.findings.filter(f=>f.ruleId==='RUST-TLS-001').length,1);assert.equal(r.coverage.scope.excludedTests,1);
 fs.mkdirSync(path.join(root,'.cargo'));fs.writeFileSync(path.join(root,'.cargo/config.toml'),'[source.crates-io]\nreplace-with="local"\n[source.local]\ndirectory="local-source"');
 r=await scan(root);assert.equal(r.findings.filter(f=>f.ruleId.startsWith('RUST-')).length,0);
});
test('Rust coverage stays partial and reports measured lexer/function counts without source text',()=>{
 const r=analyze(`fn plain() { let c=${chain}; } fn complex() { loop {} }`);
 assert.equal(r.files[0].coverage.lexed,true);assert.equal(r.files[0].coverage.discoveredFunctions,2);
 assert.equal(r.files[0].coverage.analyzedFunctions,1);assert.equal(r.files[0].coverage.status,'partial');
 assert.ok(!JSON.stringify(r.files[0].coverage).includes(chain));
});
test('engine integrates Rust findings, redaction, partial coverage and excluded test accounting',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-rust-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,'Cargo.toml'),manifest);fs.writeFileSync(path.join(root,'main.rs'),`fn main() { let c=${chain}; }`);
 const r=await require('../src/engine').scan(root);
 assert.equal(r.findings.filter(f=>f.ruleId==='RUST-TLS-001').length,1);
 assert.equal(r.coverage.source.status,'incomplete');assert.equal(r.coverage.source.rust.lexedFiles,1);
 assert.equal(r.coverage.source.rust.analyzedFunctions,1);assert.equal(r.coverage.source.languages.rust.partiallyAnalyzedFiles,1);
 assert.equal(require('../src/coverage').coverageGate(r,true).passed,false);
});
