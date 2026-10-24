'use strict';
const path=require('node:path').posix;
const {lexRust}=require('./lexer');
const {parseCargo}=require('../../supply/cargo');
const PROJECT_LIMITS=Object.freeze({files:4096,bytes:32*1024*1024,manifests:4096,tokens:400000});
const METHODS=new Set(['redirect','timeout','connect_timeout','read_timeout','user_agent','https_only','pool_idle_timeout','pool_max_idle_per_host','use_rustls_tls','use_native_tls','add_root_certificate','no_proxy','proxy','default_headers','danger_accept_invalid_certs','danger_accept_invalid_hostnames']);
const UNSUPPORTED=new Set(['if','else','match','loop','while','for','return','break','continue','yield','async','await','move','unsafe','use','fn','const','static','type','struct','enum','impl','trait','mod','exit','abort','panic_any','resume_unwind','handle_alloc_error']);
const TERMINATING_PATHS=new Set(['std::process::exit','std::process::abort','std::panic::panic_any','std::panic::resume_unwind','std::alloc::handle_alloc_error','alloc::alloc::handle_alloc_error']);
const INERT_ATTRIBUTES=new Set(['cfg','cfg_attr','allow','warn','deny','forbid','doc','inline','cold','must_use','deprecated','repr','non_exhaustive','no_mangle','export_name','link','link_name','path','windows_subsystem','test','ignore','should_panic']);
function imports(tokens,start,end,aliases) {
 let i=start,glob=false;
 function tree(prefix,stop) {
  while(i<stop) {
   if(tokens[i].value===','){i++;continue;}
   if(tokens[i].value==='::')i++;
   const parts=[...prefix];
   while(i<stop&&tokens[i].kind==='identifier') {
    parts.push(tokens[i++].value);
    if(tokens[i]?.value!=='::')break;i++;
   }
   if(tokens[i]?.value==='{'){const close=tokens.pairs.get(i);i++;tree(parts,close);i=close+1;}
   else if(tokens[i]?.value==='*'){glob=true;i++;}
   else {
    let alias=parts.at(-1);if(tokens[i]?.value==='as'){i++;alias=tokens[i++]?.value;}
    if(!alias)return false;
    const key=parts.join('::');aliases.set(alias,aliases.has(alias)?null:key);
   }
   if(i<stop&&tokens[i].value!==',')return false;
  }return true;
 }
 return {complete:tree([],end),glob};
}
function analyzeFile(input,parsed,crates,projectBlocked,projectComplete) {
 const {tokens:t,pairs}=parsed;Object.defineProperty(t,'pairs',{value:pairs});
 const coverage={status:'partial',lexed:parsed.complete,discoveredFunctions:0,analyzedFunctions:0,resolvedBuilderChains:0,diagnostics:parsed.diagnostics.map(d=>({...d}))};
 const findings=[];if(!parsed.complete)return {file:input.file,coverage,findings};
 const aliases=new Map(),terminators=new Set(),functions=[];let ownership=projectComplete&&crates.size>0,depth=0,itemStart=0;
 for(let i=0;i<t.length;i++) {
  const v=t[i].value;
  if(v==='macro_rules'||v==='extern'&&t[i+1]?.value==='crate'||v==='*'&&t[i-1]?.value==='::')ownership=false;
  if(depth===0&&v==='use') {
   let end=i+1;while(end<t.length&&t[end].value!==';')end++;
   if(end===t.length)ownership=false;
   const attributed=t.slice(itemStart,i).some(x=>x.value==='#'),imported=new Map();
   const result=imports(t,i+1,end,imported);if(!result.complete||result.glob)ownership=false;
   for(const [alias,key]of imported){aliases.set(alias,attributed||aliases.has(alias)?null:key);if(TERMINATING_PATHS.has(key))terminators.add(alias);}
   i=end;itemStart=end+1;continue;
  }
  if(v==='fn'&&t[i+1]?.kind==='identifier') {
   coverage.discoveredFunctions++;
   let j=i+2;while(j<t.length&&!['{',';'].includes(t[j].value)) {if(t[j].value==='('||t[j].value==='[')j=pairs.get(j);j++;}
   if(t[j]?.value==='{') {
    const end=pairs.get(j),header=t.slice(i+2,j),prefix=t.slice(itemStart,i),body=t.slice(j+1,end);
    const supported=depth===0&&!header.some(x=>x.value==='<')&&!prefix.some(x=>['#','unsafe','extern'].includes(x.value))&&
     !body.some(x=>UNSUPPORTED.has(x.value)||['!','#','{','}','|','||','&&','?'].includes(x.value));
    functions.push({start:j+1,end,header,supported});i=end;itemStart=end+1;continue;
   }
  }
  if(v==='{')depth++;else if(v==='}') {depth--;if(!depth)itemStart=i+1;}else if(v===';'&&!depth)itemStart=i+1;
 }
 // Import-through-import resolution and cycles are outside this phase. They
 // can hide a terminating API or change constructor ownership; decline both.
 for(const key of aliases.values())if(key&&aliases.has(key.split('::',1)[0]))ownership=false;
 const resolve=parts=>{
  let root=parts[0],rest=parts.slice(1);if(aliases.has(root)){const key=aliases.get(root);if(!key)return null;const p=key.split('::');root=p[0];rest=p.slice(1).concat(rest);}
  if(!crates.has(root)||projectBlocked.has(root))return null;
  const identity=rest.join('::');return ['Client::builder','blocking::Client::builder','ClientBuilder::new','blocking::ClientBuilder::new'].includes(identity)?identity:null;
 };
 for(const fn of functions) {
  if(!fn.supported||!ownership||t.slice(fn.start,fn.end).some(token=>terminators.has(token.value)))continue;
  const localBlocked=new Set(fn.header.filter(x=>x.kind==='identifier').map(x=>x.value));
  for(let i=fn.start;i<fn.end;i++)if(t[i].value==='let') {
   let j=i+1;while(j<fn.end&&!['=',';'].includes(t[j].value)){if(t[j].kind==='identifier')localBlocked.add(t[j].value);j++;}
  }
  coverage.analyzedFunctions++;
  for(let i=fn.start;i<fn.end;i++) {
   if(t[i].kind!=='identifier'||['::','.'].includes(t[i-1]?.value))continue;
   let j=i,parts=[t[j++].value];while(t[j]?.value==='::'&&t[j+1]?.kind==='identifier'){parts.push(t[j+1].value);j+=2;}
   if(localBlocked.has(parts[0])||projectBlocked.has(parts[0])||!resolve(parts)||t[j]?.value!=='('||pairs.get(j)!==j+1)continue;
   j+=2;const settings=new Map();let built=false,valid=true,backend=null;
   while(j<fn.end&&t[j]?.value==='.'&&t[j+1]?.kind==='identifier'&&t[j+2]?.value==='(') {
    const method=t[j+1].value,open=j+2,end=pairs.get(open);
    if(method==='build'){if(end!==open+1)valid=false;built=true;j=end+1;break;}
    if(!METHODS.has(method)){valid=false;break;}
    if(method==='use_native_tls')backend='native';
    if(method==='use_rustls_tls')backend='rustls';
    if(method.startsWith('danger_accept_invalid_')) {
     const args=t.slice(open+1,end);if(args.at(-1)?.value===',')args.pop();
     settings.set(method,args.length===1&&!args[0].raw&&['true','false'].includes(args[0].value)?{unsafe:args[0].value==='true',token:t[j+1]}:null);
    }
    j=end+1;
   }
   if(!valid||!built)continue;
   // After build, only ordinary result unwrapping is allowed by this proof.
   while(t[j]?.value==='.'&&['unwrap','expect'].includes(t[j+1]?.value)&&t[j+2]?.value==='(')j=pairs.get(j+2)+1;
   if(t[j]&&![';',')',','].includes(t[j].value)&&j!==fn.end)continue;
   coverage.resolvedBuilderChains++;
   for(const [method,setting]of settings)if(setting?.unsafe&&(method.endsWith('_certs')||backend==='native'))findings.push({ruleId:method.endsWith('_certs')?'RUST-TLS-001':'RUST-TLS-002',file:input.file,line:setting.token.line,col:setting.token.col,source:'sast',confidence:'high'});
   // Continue through argument tokens: eagerly evaluated nested builders carry
   // independent configuration evidence even when the outer chain is safe.
  }
 }
 if(!ownership)coverage.diagnostics.push({code:'rust-unresolved-crate-or-import',line:1,col:1});
 if(coverage.analyzedFunctions<coverage.discoveredFunctions)coverage.diagnostics.push({code:'rust-unsupported-function',line:1,col:1});
 return {file:input.file,coverage,findings};
}
function analyzeRustProject(inputs,manifests,complete=true) {
 let bytes=0,manifestBytes=0,totalTokens=0;const rows=[],blocked=new Set(),cargo=new Map();
 for(const m of manifests)if(path.basename(m.rel)==='Cargo.toml') {
  manifestBytes+=Buffer.byteLength(m.raw);if(cargo.size>=PROJECT_LIMITS.manifests||manifestBytes>PROJECT_LIMITS.bytes){complete=false;break;}
  const p=parseCargo(m.rel,m.raw),aliases=new Set(),root=p.cargoDocument.root;
  if(p.diagnostics.length)complete=false;
  const normalized=s=>typeof s==='string'?s.replaceAll('-','_'):null;
  const ownLibrary=normalized(root?.lib?.name||root?.package?.name);
  const trustedAliases=new Map();
  for(const d of p.deps) {
   const key=normalized(d.alias),trusted=d.name==='reqwest'&&d.origin==='registry'&&!d.source&&!d.workspace;
   trustedAliases.set(key,trusted&&(trustedAliases.get(key)??true));
  }
  if(!p.diagnostics.length)for(const d of p.deps) {
   const declared=root?.dependencies?.[d.alias],alias=normalized(d.alias);
   if(declared==null||typeof declared==='object'&&declared.optional===true||alias===ownLibrary)continue;
   if(trustedAliases.get(alias)&&!d.dev)aliases.add(alias);
  }
  cargo.set(path.dirname(m.rel),aliases);
 }
 for(const [index,input]of inputs.entries()) {
  bytes+=Buffer.byteLength(input.raw);const parsed=index<PROJECT_LIMITS.files&&bytes<=PROJECT_LIMITS.bytes&&totalTokens<PROJECT_LIMITS.tokens?lexRust(input.raw):{tokens:[],pairs:new Map(),complete:false,diagnostics:[{code:'rust-project-budget',line:1,col:1}]};
  totalTokens+=parsed.tokens.length;
  if(totalTokens>PROJECT_LIMITS.tokens){parsed.complete=false;parsed.diagnostics.push({code:'rust-project-token-budget',line:1,col:1});complete=false;}
  if(!parsed.complete)complete=false;
  for(let i=0;i<parsed.tokens.length-1;i++)if(['mod','struct','enum','union','trait','type'].includes(parsed.tokens[i].value))blocked.add(parsed.tokens[i+1].value);
  // Macro expansion and extern-crate rebinding can alter ownership across files.
  if(parsed.tokens.some((t,i)=>t.value==='macro_rules'||t.value==='extern'&&parsed.tokens[i+1]?.value==='crate'))complete=false;
  // Module reachability (including cfg and #[path]) is not resolved in this phase.
  // Suppress semantic proofs rather than treating excluded/orphan module code as live.
  if(parsed.tokens.some(t=>t.value==='mod'))complete=false;
  if(parsed.tokens.some((t,i)=>t.value==='!'&&parsed.tokens[i-1]?.value==='->'))complete=false;
  let depth=0;
  for(let i=0;i<parsed.tokens.length;i++){const token=parsed.tokens[i];if(token.value==='!'&&!depth&&parsed.tokens[i-1]?.value!=='#')complete=false;if('([{'.includes(token.value))depth++;else if(')]}'.includes(token.value))depth--;}
  for(let i=0;i<parsed.tokens.length;i++)if(parsed.tokens[i].value==='#') {
   const inner=parsed.tokens[i+1]?.value==='!',start=i+(inner?2:1);
   if(parsed.tokens[start]?.value!=='['){complete=false;continue;}
   const attribute=parsed.tokens[start+1]?.value;
   if(!INERT_ATTRIBUTES.has(attribute)||attribute==='cfg_attr'||inner&&attribute==='cfg')complete=false;
  }
  rows.push({input,parsed});
 }
 const files=rows.map(({input,parsed})=>{
  let dir=path.dirname(input.file);while(!cargo.has(dir)&&dir!=='.'){dir=path.dirname(dir);}
  return analyzeFile(input,parsed,cargo.get(dir)||new Set(),blocked,complete);
 });
 return {files,findings:files.flatMap(f=>f.findings)};
}
module.exports={analyzeRustProject,PROJECT_LIMITS};
