'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {analyzeRustProject}=require('../src/parsers/rust/analysis');
const cargo='[package]\nname="local-fixture"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nreqwest="0.12"';
const receiver='reqwest::Client::builder()';
const unsafe='.danger_accept_invalid_certs(true)';
const direct=receiver+unsafe+'.build()';
const source=(initial=unsafe,final='',terminal='?',prefix='',header='fn f() -> Result<(), reqwest::Error>')=>`${prefix} ${header} { let builder=${receiver}${initial}; let _client=builder${final}.build()${terminal}; Ok(()) }`;
const run=(raw,manifest=cargo)=>analyzeRustProject([{file:'src/main.rs',raw}],[{rel:'Cargo.toml',raw:manifest}]);
function supported(raw,want=1,manifest=cargo) {
 const r=run(raw,manifest),c=r.files[0].coverage;
 assert.equal(r.findings.length,want,raw);assert.equal(c.analyzedFunctions,1,raw);assert.equal(c.resolvedBuilderChains,1,raw);assert.equal(c.discoveredFunctions,1);assert.equal(c.status,'partial');return r;
}
function rejected(raw,manifest=cargo) {
 const r=run(raw,manifest),c=r.files[0].coverage;
 assert.equal(r.findings.length,0,raw);assert.equal(c.resolvedBuilderChains,0,raw);
 // Legacy non-question functions retain their existing admission accounting.
 if(raw.includes('?'))assert.equal(c.analyzedFunctions,0,raw);
 return r;
}

// Break caught: constructor state is discarded at the declaration semicolon.
test('one immutable local handoff resolves one physical builder chain',()=>{
 for(const terminal of ['?','','.unwrap()','.expect("client")'])supported(source(unsafe,'',terminal));
 supported(source('',unsafe));supported(source('.danger_accept_invalid_certs(false)'),0);
 for(const [prefix,from,to,manifest]of [
  ['use reqwest::Client;','reqwest::Client::builder()','Client::builder()',cargo],
  ['use reqwest::Client as Http;','reqwest::Client::builder()','Http::builder()',cargo],
  ['use reqwest::{blocking::ClientBuilder as Http};','reqwest::Client::builder()','Http::new()',cargo],
  ['',receiver,'reqwest::blocking::Client::builder()',cargo],
  ['',receiver,'http_client::ClientBuilder::new()',cargo.replace('reqwest="0.12"','http-client={package="reqwest",version="0.12"}')],
 ])supported(source(unsafe,'','?',prefix).replace(from,to),1,manifest);
 supported(source(unsafe,'','?','','fn f()')); // no Result/type identity is inferred
});

// Break caught: earlier true survives a false reset, or later true/backend is ignored.
test('local state uses final literal flags and final selected backend across both segments',()=>{
 for(const [initial,final,want]of [
  [unsafe,'.danger_accept_invalid_certs(false)',0],['.danger_accept_invalid_certs(false)',unsafe,1],
  [unsafe,unsafe,1],[unsafe,'.danger_accept_invalid_certs(flag)',0],[unsafe,'.danger_accept_invalid_certs(r#true)',0],
  [unsafe+'.use_native_tls()','.use_rustls_tls()',1],
 ])supported(source(initial,final),want);
 for(const [initial,final,want]of [
  ['.use_native_tls().danger_accept_invalid_hostnames(true)','',1],
  ['.danger_accept_invalid_hostnames(true)','.use_native_tls()',1],
  ['.use_native_tls().danger_accept_invalid_hostnames(true)','.use_rustls_tls()',0],
  ['.use_rustls_tls().danger_accept_invalid_hostnames(true)','.use_native_tls()',1],
  ['.use_native_tls().danger_accept_invalid_hostnames(true)','.danger_accept_invalid_hostnames(false)',0],
 ]){const r=supported(source(initial,final),want);if(want)assert.equal(r.findings[0].ruleId,'RUST-TLS-002');}
 const r=supported(source('.use_native_tls()'+unsafe+'.danger_accept_invalid_hostnames(false)','.danger_accept_invalid_certs(false).danger_accept_invalid_hostnames(true)'));
 assert.equal(r.findings[0].ruleId,'RUST-TLS-002');
 for(const selector of ['.use_native_tls(true)','.use_rustls_tls(flag)'])rejected(source(selector+unsafe));
});

// Break caught: initial flags lose their source location or reset evidence points at first true.
test('local evidence points at the effective dangerous setter in either segment',()=>{
 for(const nl of ['\n','\r\n'])for(const reset of [false,true]) {
  const raw=['fn f() -> Result<(), reqwest::Error> {',' let builder=reqwest::Client::builder()', '  .danger_accept_invalid_certs(true);', ' let _client=builder', reset?'  .danger_accept_invalid_certs(true)':'  .timeout(5)', '  .build()?;', ' Ok(())','}'].join(nl);
  const r=supported(raw);assert.equal(r.findings[0].line,reset?5:3);assert.equal(r.findings[0].col,4);
 }
});

// Break caught: calls are accepted by spelling, or Duration effects lose their identity checks.
test('local timeout arguments allow only bounded resolved standard Duration constructors',()=>{
 for(const [prefix,arg]of [
  ['use std::time::Duration;','Duration::from_secs(5)'],['use std::time::Duration as Delay;','Delay::from_secs(5)'],
  ['use std::time as clock;','clock::Duration::from_secs(5)'],['','std::time::Duration::from_secs(5)'],
 ])for(const [initial,final]of [[unsafe+`.timeout(${arg})`, ''],[unsafe,`.timeout(${arg},)`]])supported(source(initial,final,'?',prefix));
 for(const [prefix,arg]of [
  ['use other::Duration;','Duration::from_secs(5)'],['','Duration::from_secs(5)'],
  ['use std::time::Duration; use other::Duration;','Duration::from_secs(5)'],
  ['use std::time::Duration;','Duration::from_secs(helper())'],['','std::time::Duration::from_secs(flag)'],
  ['','std::time::Duration::from_secs(5, 6)'],['','std::time::Duration::from_secs(5).unknown()'],
  ['','helper()'],['','builder'],['','&builder'],['','helper(builder)'],
 ])rejected(source(unsafe,`.timeout(${arg})`,'?',prefix));
 for(const header of ['fn f(Duration: Fake) -> Result<(), reqwest::Error>','fn f(std: Fake) -> Result<(), reqwest::Error>']) {
  const arg=header.includes('Duration:')?'Duration::from_secs(5)':'std::time::Duration::from_secs(5)';
  rejected(source(unsafe,`.timeout(${arg})`,'?','use std::time::Duration;',header));
 }
 rejected('mod std {} '+source(unsafe,'.timeout(std::time::Duration::from_secs(5))'));
 rejected(source(unsafe,'.timeout(Duration::from_secs(5))','?','use std::time::Duration;').replace('let builder=', 'let Duration=0; let builder='));
});

// Break caught: a Cargo crate/library named std mints standard Duration authority.
test('local Duration identity rejects Cargo declarations that shadow std',()=>{
 const raw=source(unsafe,'.timeout(std::time::Duration::from_secs(5))');
 for(const manifest of [cargo.replace('name="local-fixture"','name="std"'),cargo+'\n[lib]\nname="std"',
  cargo+'\nstd={package="other-time",version="1"}',cargo+'\nstd={package="reqwest",version="0.12"}'])rejected(raw,manifest);
});

// Break caught: alias/reference/reassignment or an extra owner occurrence is ignored.
test('local ownership proof rejects escapes aliases duplicate uses and unsupported bindings',()=>{
 const baseline=source();
 for(const statement of ['let alias=builder;','let alias=&builder;','let alias=builder.clone();','consume(builder);',
  'let moved=builder;','builder=other;','builder+=other;','let builder=other;','let list=[builder];','let x=builder.field;','let x=builder[0];']) {
  rejected(baseline.replace('let _client=',statement+' let _client='));
  rejected(baseline.replace('Ok(())',statement+' Ok(())'));
 }
 for(const binding of ['mut builder','r#builder','(builder)','builder: ClientBuilder','[builder]'])rejected(baseline.replace('let builder=',`let ${binding}=`));
 for(const header of ['fn f(builder: Fake) -> Result<(), reqwest::Error>','fn f(reqwest: Fake) -> Result<(), reqwest::Error>'])rejected(source(unsafe,'','?','',header));
 rejected(baseline.replace('let _client=builder','let _client=builder.timeout(builder)'));
 rejected(baseline.replace('Ok(())','builder.build(); Ok(())'));
 rejected(baseline.replace('let _client=',`let second=${receiver}${unsafe}; let _client=`));
 rejected(baseline.replace('let _client=builder.build()?;','let alias=builder;'));
 rejected(`fn f(){let builder=${receiver}${unsafe};}`);
});

// Break caught: a local build legitimizes unrelated questions, calls or terminal suffixes.
test('local propagation validates the complete function before committing candidates',()=>{
 for(const statement of ['fallible()?;','unknown();','let x=unknown();']) {
  rejected(source().replace('let builder=',statement+' let builder='));
  rejected(source().replace('let _client=',statement+' let _client='));
  rejected(source().replace('Ok(())',statement+' Ok(())'));
 }
 for(const terminal of ['??','?.unknown()','.unwrap()?','.expect(helper())','.unwrap(unknown())'])rejected(source(unsafe,'',terminal));
 rejected(source().replace('Ok(())',direct+'?; Ok(())'));
 rejected(source().replace('let _client=builder.build()?;', 'wrapper(builder.build()?);'));
 supported(source().replace('let builder=','let attempts=1; let label="client"; let mut flag=false; let builder='));
});

// Break caught: new local-mode rejection suppresses old admitted direct chains in the same function.
test('unsupported local state preserves independent legacy direct and nested findings',()=>{
 for(const invalid of [`let b=${receiver}${unsafe}; let alias=b;`, `let b=${receiver}${unsafe}; b.unknown().build();`, `let b=${receiver}${unsafe}; consume(b);`]) {
  const raw=`fn f(){${direct}; ${invalid} ${receiver}.user_agent(make_agent(${direct})).build();}`;
  const r=run(raw);assert.equal(r.findings.length,2,raw);assert.equal(r.files[0].coverage.resolvedBuilderChains,3);assert.equal(r.files[0].coverage.analyzedFunctions,1);
 }
 const r=run(source()+` fn old(){${direct}.unwrap();}`);assert.equal(r.findings.length,2);assert.equal(r.files[0].coverage.analyzedFunctions,2);assert.equal(r.files[0].coverage.resolvedBuilderChains,2);
});

// Break caught: a local receiver bypasses Cargo/import/cfg or global control-flow guards.
test('local mode retains identity function parameter control flow and macro exclusions',()=>{
 for(const prefix of ['use other::*;','#[cfg(windows)]','#[cfg(any())]','#[rewrite_items]','mod reqwest {}','fn stop() -> ! {loop {}}'])rejected(prefix+' '+source());
 for(const extra of ['if true {}','loop {}','return;','std::process::exit(0);','std::future::pending::<()>().await;','let x=|| 0;','false && unknown();','println!("x");'])rejected(source().replace('let builder=',extra+' let builder='));
 for(const manifest of [cargo.replace('[dependencies]','[build-dependencies]'),cargo.replace('[dependencies]','[dev-dependencies]'),
  cargo.replace('reqwest="0.12"','reqwest={version="0.12",optional=true}'),cargo.replace('reqwest="0.12"','reqwest={version="0.12",path="../reqwest"}'),
  cargo.replace('reqwest="0.12"','reqwest={version="0.12",git="https://example.invalid/reqwest"}'),cargo.replace('reqwest="0.12"','reqwest={workspace=true}')])rejected(source(),manifest);
 rejected(source().replace('reqwest::Client::builder()', 'Fake::builder()'));
 rejected(source(unsafe,'','?','','fn f<T>() -> Result<(), reqwest::Error>'));
});

// Break caught: the two segments/multiple contexts inflate physical counters or exhaust work after a partial commit.
test('local chain counts remain physical and shared work exhaustion clears all candidates',()=>{
 const files=[{file:'src/main.rs',raw:'mod lib;'},{file:'src/lib.rs',raw:source()}];
 let r=analyzeRustProject(files,[{rel:'Cargo.toml',raw:cargo}]);const c=r.files.find(f=>f.file==='src/lib.rs').coverage;
 assert.equal(r.findings.length,1);assert.equal(c.discoveredFunctions,1);assert.equal(c.analyzedFunctions,1);assert.equal(c.resolvedBuilderChains,1);
 const many=[{file:'src/bin/common.rs',raw:source().replace('let builder=','let x=0;'.repeat(5000)+'let builder=')}];
 for(let i=0;i<60;i++)many.push({file:`src/bin/a${i}.rs`,raw:'mod common;'});
 r=analyzeRustProject(many,[{rel:'Cargo.toml',raw:cargo}]);assert.equal(r.findings.length,0);
 assert.ok(r.files.some(f=>f.coverage.diagnostics.some(d=>d.code==='rust-analysis-budget')));
 assert.ok(r.files.every(f=>!f.coverage.analyzedFunctions&&!f.coverage.resolvedBuilderChains));
});
