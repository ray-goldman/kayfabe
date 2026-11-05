'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {analyzeRustProject}=require('../src/parsers/rust/analysis');
const cargo='[package]\nname="result-fixture"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nreqwest="0.12"';
const chain='reqwest::Client::builder().danger_accept_invalid_certs(true).build()';
const run=(source,manifest=cargo,extra=[])=>analyzeRustProject([{file:'src/main.rs',raw:source},...extra],[{rel:'Cargo.toml',raw:manifest}]);
const result=(body,header='fn f() -> Result<(), reqwest::Error>')=>`${header} { ${body} }`;
function supported(source,want=1,manifest=cargo) {
 const r=run(source,manifest),c=r.files[0].coverage;
 assert.equal(r.findings.length,want,source);assert.equal(c.analyzedFunctions,1,source);assert.equal(c.resolvedBuilderChains,1,source);assert.equal(c.status,'partial');
 if(want)assert.equal(r.findings[0].ruleId,'RUST-TLS-001');return r;
}
function rejected(source,manifest=cargo) {
 const r=run(source,manifest),c=r.files[0].coverage;
 assert.equal(r.findings.length,0,source);assert.equal(c.analyzedFunctions,0,source);assert.equal(c.resolvedBuilderChains,0,source);assert.equal(c.status,'partial');
}

// Break caught: treating every header angle as a function generic, or every ? as unknown.
test('return generics and build propagation have independent positive controls',()=>{
 supported(result(`${chain}; Ok(())`));
 supported(result(`${chain}?;`,'fn f()'));
 supported(result(`let _client=${chain}?; Ok(())`));
 supported(result(`${chain}?; Ok(())`,'async fn f() -> std::result::Result<(), reqwest::Error>'));
});

// Break caught: return annotations enter the binding set, or create trusted identities.
test('return paths do not shadow separately resolved constructors or establish ownership',()=>{
 for(const [prefix,receiver,header,manifest]of [
  ['use reqwest::Client;','Client::builder()', 'fn f() -> Result<Client, reqwest::Error>',cargo],
  ['use reqwest::Client as Http;','Http::builder()', 'fn f() -> Result<Http, reqwest::Error>',cargo],
  ['', 'reqwest::blocking::ClientBuilder::new()', 'fn f() -> Result<(), reqwest::Error>',cargo],
  ['', 'http_client::Client::builder()', 'fn f() -> Result<(), http_client::Error>',cargo.replace('reqwest="0.12"','http-client={package="reqwest",version="0.12"}')],
 ])supported(`${prefix} ${result(`${receiver}.danger_accept_invalid_certs(true).build()?; Ok(())`,header)}`,1,manifest);
 rejected(result('Client::builder().danger_accept_invalid_certs(true).build()?; Ok(())','fn f() -> Result<reqwest::Client, reqwest::Error>'));
 rejected(result(`${chain}?; Ok(())`),cargo.replace('reqwest="0.12"','reqwest={package="other",version="1"}'));
});

// Break caught: function generics, parameter/local names or malformed headers bypass identity guards.
test('function generic parameters and real receiver collisions remain unsupported',()=>{
 for(const header of ['fn f<T>()','fn f<reqwest>()','fn f<\'a>()','fn f<const N: usize>()','fn f() -> Result<Vec<()>, reqwest::Error>','fn f() -> Result<(), reqwest::Error> where X: Y',
  'fn f(reqwest: Fake) -> Result<(), reqwest::Error>','fn f(r#reqwest: Fake) -> Result<(), reqwest::Error>', 'fn f() -> Result<(), reqwest::Error', 'fn f() -> impl Trait<()>'])rejected(result(`${chain}?; Ok(())`,header));
 for(const declaration of ['let reqwest=0;','let r#reqwest=0;'])rejected(result(`${declaration} ${chain}?; Ok(())`));
 rejected('use reqwest::Client; '+result('Client::builder().danger_accept_invalid_certs(true).build()?; Ok(())','fn f(Client: Fake) -> Result<(), reqwest::Error>'));
});

// Break caught: ignored last setting, raw boolean, or last backend.
test('propagating chains preserve literal settings and native backend ordering',()=>{
 for(const [settings,want]of [
  ['.danger_accept_invalid_certs(true)',1],['.danger_accept_invalid_certs(false)',0],
  ['.danger_accept_invalid_certs(true).danger_accept_invalid_certs(false)',0],['.danger_accept_invalid_certs(false).danger_accept_invalid_certs(true)',1],
  ['.danger_accept_invalid_certs(flag)',0],['.danger_accept_invalid_certs(r#true)',0],
 ])supported(result(`let flag=false; reqwest::Client::builder()${settings}.build()?; Ok(())`),want);
 for(const [settings,want]of [
  ['.use_native_tls().danger_accept_invalid_hostnames(true)',1],['.use_native_tls().danger_accept_invalid_hostnames(false)',0],
  ['.danger_accept_invalid_hostnames(true)',0],['.use_native_tls().danger_accept_invalid_hostnames(true).use_rustls_tls()',0],
  ['.use_rustls_tls().danger_accept_invalid_hostnames(true).use_native_tls()',1],
 ]) {const r=run(result(`reqwest::Client::builder()${settings}.build()?; Ok(())`));assert.equal(r.findings.length,want,settings);assert.equal(r.files[0].coverage.resolvedBuilderChains,1);if(want)assert.equal(r.findings[0].ruleId,'RUST-TLS-002');}
});

// Break caught: partial commits before a later question/unsupported token, or trusting textual build calls.
test('only the single direct resolved terminal build question is admitted',()=>{
 for(const body of [
  `fallible()?; ${chain}?; Ok(())`,`${chain}?; fallible()?; Ok(())`, `unknown(); ${chain}?; Ok(())`,
  `let x=unknown(); ${chain}?; Ok(())`,`${chain}.unwrap()?; Ok(())`,`${chain}??; Ok(())`,`${chain}?.unknown(); Ok(())`,
  `${chain}?; ${chain}?; Ok(())`,`wrapper(${chain}?); Ok(())`,`${chain.replace('reqwest::','other::')}?; Ok(())`,
  'unknown.build()?; Ok(())',`${chain.replace('.build()', '.custom_reset().build()')}?; Ok(())`,
  `${chain.replace('.build()', '.timeout(unknown()).build()')}?; Ok(())`, `${chain}?; unknown(); Ok(())`,
  `${chain}?; Ok(()); unsupported!()`,
 ])rejected(result(body));
 supported(result(`let attempts=1; let label="client"; let mut flag=false; let _client=${chain}?; Ok(())`));
});

// Break caught: a named backend method with unsupported arguments becomes backend evidence.
test('propagating backend selectors require their known zero argument call shape',()=>{
 for(const selector of ['use_native_tls(true)','use_rustls_tls(flag)'])rejected(result(`reqwest::Client::builder().${selector}.danger_accept_invalid_certs(true).build()?; Ok(())`));
});

// Break caught: new mode loses old control-flow/termination or macro exclusions.
test('await branches early termination and rewriting remain excluded',()=>{
 for(const body of [`return; ${chain}?; Ok(())`,`if true { ${chain}?; } Ok(())`,`loop {} ${chain}?; Ok(())`,
  `std::future::pending::<()>().await; ${chain}?; Ok(())`,`false && ${chain}?; Ok(())`,
  `std::process::exit(0); ${chain}?; Ok(())`,`std::panic::panic_any(0); ${chain}?; Ok(())`,
  `let x=|| 1; ${chain}?; Ok(())`])rejected(result(body));
 for(const prefix of ['#[cfg(windows)]','#[cfg(any())]','#[rewrite_items]','#![rewrite_items]','#[cfg_attr(windows,rewrite_items)]','use other::*;',
  'mod reqwest {}','#[cfg(windows)] mod reqwest {}','fn stop() -> ! { loop {} }'])rejected(prefix+' '+result(`${chain}?; Ok(())`));
 rejected('use reqwest::Client; use other::Client; '+result('Client::builder().danger_accept_invalid_certs(true).build()?; Ok(())'));
 rejected('use std::process::exit as stop; '+result(`stop(0); ${chain}?; Ok(())`));
 supported('#[cfg(all())] '+result(`${chain}?; Ok(())`));
 supported('#[cfg(any())] fn stop() -> ! { loop {} } '+result(`${chain}?; Ok(())`));
});

// Break caught: cargo/module identity is inferred from return spelling instead of existing ownership.
test('propagation retains Cargo and module ownership exclusions',()=>{
 for(const manifest of [
  cargo.replace('[dependencies]','[build-dependencies]'),cargo.replace('[dependencies]','[dev-dependencies]'),
  cargo.replace('reqwest="0.12"','reqwest={version="0.12",optional=true}'),cargo.replace('reqwest="0.12"','reqwest={version="0.12",path="../reqwest"}'),
  cargo.replace('reqwest="0.12"','reqwest={workspace=true}'),cargo.replace('name="result-fixture"','name="reqwest"'),
  cargo+'\n[[bin]]\nname="result-fixture"\npath="src/main.rs"\nrequired-features=["special"]',
 ])rejected(result(`${chain}?; Ok(())`),manifest);
 const r=run('mod client;',cargo,[{file:'src/client.rs',raw:result(`${chain}?; Ok(())`)}]);assert.equal(r.findings.length,1);
 for(const declaration of ['#[cfg(windows)] mod client;','#[path="client.rs"] mod client;'])assert.equal(run(declaration,cargo,[{file:'src/client.rs',raw:result(`${chain}?; Ok(())`)}]).findings.length,0);
});

// Break caught: new-mode rejection erases independent old findings or commits phantom counts.
test('rejected propagation preserves independent legacy direct unwrap and nested findings',()=>{
 const source=result(`${chain}?; fallible()?; Ok(())`)+` fn old(){${chain}.unwrap();} fn nested(){reqwest::Client::builder().user_agent(make_agent(${chain})).build();}`;
 const r=run(source);assert.equal(r.findings.length,2);assert.equal(r.files[0].coverage.analyzedFunctions,2);assert.equal(r.files[0].coverage.resolvedBuilderChains,3);
});

// Break caught: newline/position changes move evidence, or incomplete/budgeted work leaks positives.
test('Result chain evidence has stable LF and CRLF locations and bounded failure',()=>{
 for(const newline of ['\n','\r\n']) {
  const r=run(['fn f() -> Result<(), reqwest::Error> {','    let c=reqwest::Client::builder()','        .danger_accept_invalid_certs(true)','        .build()?;','    Ok(())','}'].join(newline));
  assert.equal(r.findings.length,1);assert.equal(r.findings[0].line,3);assert.equal(r.findings[0].col,10);
 }
 for(const source of [result(`${chain}?; Ok(())`)+' /*',`fn f() -> Result<${'X,'.repeat(51000)}()> { ${chain}?; }`]) {const r=run(source);assert.equal(r.findings.length,0);assert.equal(r.files[0].coverage.analyzedFunctions,0);assert.ok(r.files[0].coverage.diagnostics.length);}
 const inputs=[{file:'src/bin/common.rs',raw:result('let x=0;'.repeat(5000)+`${chain}?; Ok(())`)}];
 for(let i=0;i<60;i++)inputs.push({file:`src/bin/a${i}.rs`,raw:'mod common;'});
 const r=analyzeRustProject(inputs,[{rel:'Cargo.toml',raw:cargo}]);assert.equal(r.findings.length,0);assert.ok(r.files.some(f=>f.coverage.diagnostics.some(d=>d.code==='rust-analysis-budget')));
 assert.ok(r.files.every(f=>f.coverage.analyzedFunctions===0&&f.coverage.resolvedBuilderChains===0));
});
