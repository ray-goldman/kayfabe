'use strict';
const path=require('node:path').posix;
const {lexRust}=require('./lexer');
const {parseCargo}=require('../../supply/cargo');
const {structure}=require('./structure');
const {moduleGraph}=require('./modules');
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
   if(tokens[i]?.value==='{'){const close=tokens.pairs.get(i);i++;if(!tree(parts,close))return false;i=close+1;}
   else if(tokens[i]?.value==='*'){glob=true;i++;}
   else {
    let alias=parts.at(-1);if(tokens[i]?.value==='as'){i++;alias=tokens[i++]?.value;}
    if(!alias)return false;
    const key=parts.join('::');if(alias!=='_')aliases.set(alias,aliases.has(alias)?null:key);
   }
   if(i<stop&&tokens[i].value!==',')return false;
  }return true;
 }
 return {complete:tree([],end),glob};
}
function analyzeContext(ctx,crates,complete,record,budget) {
 const {tokens:t,pairs}=ctx.row.parsed,findings=record.findings,analyzed=record.analyzed,chains=record.chains;
 if(!Object.hasOwn(t,'pairs'))Object.defineProperty(t,'pairs',{value:pairs});
 const aliases=new Map(),terminators=new Set();let ownership=complete&&crates.size>0;
 const isBlocked=name=>{for(let scope=ctx;scope;scope=scope.parent)if(scope.blocked.has(name))return true;return false;};
 for(let scope=ctx;scope;scope=scope.parent)if(scope.hazard||scope.state!==true)ownership=false;
 for(const {item,state}of ctx.items)if(item.kind==='use'&&state!==false) {
  const imported=new Map(),result=imports(t,item.keyword+1,item.end-1,imported);
  if(!result.complete||result.glob)ownership=false;
  for(const [alias,key]of imported){aliases.set(alias,state!==true||aliases.has(alias)?null:key);if(TERMINATING_PATHS.has(key))terminators.add(alias);if(key===null||['self','super','crate'].includes(key?.split('::',1)[0]))ownership=false;}
 }
 for(const key of aliases.values())if(key&&aliases.has(key.split('::',1)[0]))ownership=false;
 const resolve=parts=>{
  let root=parts[0],rest=parts.slice(1);if(aliases.has(root)){const key=aliases.get(root);if(!key)return null;const p=key.split('::');root=p[0];rest=p.slice(1).concat(rest);}
  if(!crates.has(root)||isBlocked(root))return null;
  return ['Client::builder','blocking::Client::builder','ClientBuilder::new','blocking::ClientBuilder::new'].includes(rest.join('::'));
 };
 const input=ctx.row.input;
 for(const {item,state}of ctx.items) {
  if(item.kind!=='fn'||item.functionStart===null||state!==true)continue;
  const fn={start:item.functionStart,end:item.functionEnd,header:item.header};
  budget.tokens+=fn.end-fn.start;if(budget.tokens>1000000){budget.exceeded=true;return;}
  const body=t.slice(fn.start,fn.end);
  const supported=!fn.header.some(x=>x.value==='<')&&!item.qualifiers.some(x=>['unsafe','extern'].includes(x))&&!item.effects.hazard&&
   !body.some(x=>UNSUPPORTED.has(x.value)||['!','#','{','}','|','||','&&','?'].includes(x.value));
  if(!supported||!ownership||body.some(token=>terminators.has(token.value)))continue;
  const localBlocked=new Set(fn.header.filter(x=>x.kind==='identifier').map(x=>x.value));
  for(let i=fn.start;i<fn.end;i++)if(t[i].value==='let') {
   let j=i+1;while(j<fn.end&&!['=',';'].includes(t[j].value)){if(t[j].kind==='identifier')localBlocked.add(t[j].value);j++;}
  }
  analyzed.add(item);
  for(let i=fn.start;i<fn.end;i++) {
   if(t[i].kind!=='identifier'||['::','.'].includes(t[i-1]?.value))continue;
   let j=i,parts=[t[j++].value];while(t[j]?.value==='::'&&t[j+1]?.kind==='identifier'){parts.push(t[j+1].value);j+=2;}
   if(localBlocked.has(parts[0])||isBlocked(parts[0])||!resolve(parts)||t[j]?.value!=='('||pairs.get(j)!==j+1)continue;
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
   chains.add(t[i].start);
   for(const [method,setting]of settings)if(setting?.unsafe&&(method.endsWith('_certs')||backend==='native'))findings.push({ruleId:method.endsWith('_certs')?'RUST-TLS-001':'RUST-TLS-002',file:input.file,line:setting.token.line,col:setting.token.col,source:'sast',confidence:'high'});
   // Continue through argument tokens: eagerly evaluated nested builders carry
   // independent configuration evidence even when the outer chain is safe.
  }
 }
 if(!ownership)record.codes.add('rust-unresolved-crate-or-import');
}
function analyzeRustProject(inputs,manifests,complete=true,options={}) {
 let bytes=0,manifestBytes=0,totalTokens=0;const rows=[],cargo=new Map();
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
  cargo.set(path.dirname(m.rel),{aliases,document:root});
 }
 for(const [index,input]of inputs.entries()) {
  bytes+=Buffer.byteLength(input.raw);const parsed=index<PROJECT_LIMITS.files&&bytes<=PROJECT_LIMITS.bytes&&totalTokens<PROJECT_LIMITS.tokens?lexRust(input.raw):{tokens:[],pairs:new Map(),complete:false,diagnostics:[{code:'rust-project-budget',line:1,col:1}]};
  totalTokens+=parsed.tokens.length;
  if(totalTokens>PROJECT_LIMITS.tokens){parsed.complete=false;parsed.diagnostics.push({code:'rust-project-token-budget',line:1,col:1});complete=false;}
  if(!parsed.complete)complete=false;
  const tree=parsed.complete?structure(parsed,options):{root:{start:0,end:0,items:[],inner:{gate:null,hazard:true},valid:false},functions:[]};
  rows.push({input,parsed,tree});
 }
 const graph=moduleGraph(rows,cargo,options),records=new Map(rows.map(row=>[row.input.file,{row,findings:[],analyzed:new Set(),chains:new Set(),codes:new Set()}]));
 const budget={tokens:0,exceeded:false};
 // Keep the prior conservative never-returning helper guard, but ignore items
 // which conditional compilation has proven absent.
 let never=false;const checkedNever=new Set();
 for(const ctx of graph.contexts)for(const {item,state}of ctx.items)if(state!==false&&item.kind!=='mod') {
  if(checkedNever.has(item))continue;checkedNever.add(item);
  const tokens=ctx.row.parsed.tokens;
  for(let i=item.keyword;i<item.end;i++)if(tokens[i].value==='!'&&tokens[i-1]?.value==='->')never=true;
 }
 for(const ctx of graph.contexts)if(ctx.state===true) {
  budget.tokens+=ctx.node.end-ctx.node.start;if(budget.tokens>1000000){budget.exceeded=true;break;}
  let dir=path.dirname(ctx.row.input.file);while(!cargo.has(dir)&&dir!=='.')dir=path.dirname(dir);
  analyzeContext(ctx,cargo.get(dir)?.aliases||new Set(),complete&&!never&&!graph.budget,records.get(ctx.row.input.file),budget);
 }
 const files=rows.map(row=>{
  const record=records.get(row.input.file),states=graph.states.get(row.input.file),active=states?.has(true),unknown=states?.has(null),excluded=states?.has(false);
  const contexts=graph.contexts.filter(c=>c.row===row);
  const cfgItems=contexts.flatMap(c=>c.items),diagnostics=[...row.parsed.diagnostics,...(graph.diagnostics.get(row.input.file)||[])];
  if(record.analyzed.size<row.tree.functions.length)record.codes.add('rust-unsupported-function');
  if(budget.exceeded)record.codes.add('rust-analysis-budget');
  if(never)record.codes.add('rust-never-type-unresolved');
  for(const code of record.codes)diagnostics.push({code,line:1,col:1});
  const coverage={status:'partial',lexed:row.parsed.complete,discoveredFunctions:row.tree.functions.length,analyzedFunctions:budget.exceeded?0:record.analyzed.size,resolvedBuilderChains:budget.exceeded?0:record.chains.size,
   moduleStatus:active?'reachable':unknown?'conditional':excluded?'excluded':'unreachable',moduleScopes:contexts.length,
   cfgExcludedItems:cfgItems.filter(x=>x.state===false).length+Number(excluded&&!active),cfgUnknownItems:cfgItems.filter(x=>x.state===null).length+Number(unknown&&!active),cfgUnknownConditions:contexts.reduce((n,c)=>n+(c.node.inner.unknownConditions||0),0)+cfgItems.reduce((n,x)=>n+(x.item.effects.unknownConditions||0),0),diagnostics};
  const seen=new Set();const findings=budget.exceeded?[]:record.findings.filter(f=>{const key=[f.ruleId,f.file,f.line,f.col].join('|');if(seen.has(key))return false;seen.add(key);return true;});
  return {file:row.input.file,coverage,findings};
 });
 return {files,findings:files.flatMap(f=>f.findings)};
}

module.exports={analyzeRustProject,PROJECT_LIMITS};
