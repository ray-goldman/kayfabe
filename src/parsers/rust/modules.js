'use strict';
const path=require('node:path').posix;
const {and}=require('./cfg');
const LIMITS=Object.freeze({scopes:4096,depth:64});
function moduleGraph(rows,cargo,options={}) {
 const byFile=new Map(rows.map(r=>[r.input.file,r])),contexts=[],diagnostics=new Map(),states=new Map(),owners=new Map();let budget=false,work=0;
 const diagnose=(file,code,line=1)=>{const list=diagnostics.get(file)||[];
  // Repeated namespace errors cannot conceal the reason analysis stopped.
  if(list.length>=256&&code.endsWith('-budget')&&!list.some(d=>d.code===code)){
   const index=list.findLastIndex(d=>!d.code.endsWith('-budget'));if(index>=0)list.splice(index,1);
  }
  if(list.length<256)list.push({code,line,col:1});diagnostics.set(file,list);};
 for(const row of rows){let dir=path.dirname(row.input.file);while(!cargo.has(dir)&&dir!=='.')dir=path.dirname(dir);owners.set(row.input.file,cargo.has(dir)?dir:null);}
 function visit(row,node,parent,state,directory,ancestry,depth=0) {
  const file=row.input.file;
  if(contexts.length>=LIMITS.scopes||depth>LIMITS.depth){budget=true;diagnose(file,'rust-module-budget');return null;}
  state=and(state,node.inner.gate);const ctx={row,node,parent,state,directory,items:[],blocked:new Set(),hazard:!row.parsed.complete||!node.valid||node.inner.hazard||node.opaque,children:[]};
  contexts.push(ctx);const seen=states.get(file)||new Set();seen.add(state);states.set(file,seen);
  if(state===false)return ctx;
  if(!node.valid)diagnose(file,'rust-module-syntax-unresolved');
  if(node.inner.hazard)diagnose(file,'rust-macro-attribute-unresolved');
  const moduleNames=new Set();
  const bind=name=>{if(moduleNames.has(name)){ctx.hazard=true;diagnose(file,'rust-module-duplicate');}moduleNames.add(name);ctx.blocked.add(name);};
  for(const item of node.items) {
   if(++work>200000){budget=true;ctx.hazard=true;diagnose(file,'rust-module-work-budget');break;}
   const gate=and(state,item.effects.gate);ctx.items.push({item,state:gate});
   if(gate===false)continue;
   if(item.effects.hazard)diagnose(file,'rust-macro-attribute-unresolved',row.parsed.tokens[item.keyword].line);
   ctx.hazard ||= item.effects.hazard;
   if(item.kind==='mod') {
    if(!item.name||item.qualifiers.length||item.effects.customPath){bind(item.name);diagnose(file,'rust-module-unresolved',row.parsed.tokens[item.keyword].line);continue;}
    let child;
    if(item.scope)child=visit(row,item.scope,ctx,gate,path.join(directory,item.name),ancestry,depth+1);
    else {
     const candidates=[path.join(directory,item.name+'.rs'),path.join(directory,item.name,'mod.rs')].filter(f=>byFile.has(f)&&owners.get(f)===owners.get(file));
     if(candidates.length!==1){ctx.hazard=true;bind(item.name);diagnose(file,'rust-module-missing-or-ambiguous');continue;}
     if(ancestry.has(candidates[0])){ctx.hazard=true;bind(item.name);diagnose(file,'rust-module-cycle');continue;}
     const next=byFile.get(candidates[0]),nextAncestors=new Set(ancestry);nextAncestors.add(candidates[0]);
     child=visit(next,next.tree.root,ctx,gate,path.join(directory,item.name),nextAncestors,depth+1);
    }
    if(child){ctx.children.push(child);if(child.state!==false)bind(item.name);}else ctx.hazard=true;
   }else if(['struct','enum','union','trait','type'].includes(item.kind)&&item.name)ctx.blocked.add(item.name);
   else if(!['use','fn','const','static','impl'].includes(item.kind))ctx.hazard=true;
  }
  return ctx;
 }
 const roots=new Map();
 for(const [dir,entry]of cargo) {
  const ownRows=rows.filter(r=>owners.get(r.input.file)===dir),root=entry.document||{},pkg=root.package||{};
  const manualTargets=['lib','bin','example','test','bench'].some(k=>root[k]!=null);
  const defaultAuto=!manualTargets||['2018','2021','2024'].includes(pkg.edition);
  const declaredBins=new Map(),declaredBinNames=new Set();
  for(const bin of Array.isArray(root.bin)?root.bin:[]) {
   if(typeof bin.name==='string')declaredBinNames.add(bin.name);
   const paths=typeof bin.path==='string'?[bin.path]:typeof bin.name==='string'?['src/bin/'+bin.name+'.rs','src/bin/'+bin.name+'/main.rs',...(bin.name===pkg.name?['src/main.rs']:[])]:[];
   const state=bin['required-features']==null||Array.isArray(bin['required-features'])&&!bin['required-features'].length?true:null;
   for(const rel of paths){const f=path.normalize(path.join(dir,rel));declaredBins.set(f,declaredBins.get(f)===true||state===true?true:null);}
  }
  const add=(rel,kind='bin')=>{if(typeof rel!=='string'||rel.includes('\\')||path.isAbsolute(rel)||/^[A-Za-z]:/.test(rel))return;
   const f=path.normalize(path.join(dir,rel));if((dir==='.'?!f.startsWith('../'):f.startsWith(dir+'/'))&&byFile.has(f)){
    if(owners.get(f)!==dir){diagnose(f,'rust-target-owner-unresolved');return;}
    const state=kind==='lib'?true:declaredBins.has(f)?declaredBins.get(f):true;
    roots.set(f,roots.get(f)===true||state===true?true:null);
   }};
  if(root.lib?.path)add(root.lib.path,'lib');else if(root.lib||pkg.autolib===true||pkg.autolib!==false&&defaultAuto)add('src/lib.rs','lib');
  const autoBin=(rel,name)=>{const f=path.normalize(path.join(dir,rel));if(!declaredBinNames.has(name)||declaredBins.has(f))add(rel);};
  if(pkg.autobins===true||pkg.autobins!==false&&defaultAuto){autoBin('src/main.rs',pkg.name);for(const r of ownRows){const local=path.relative(dir,r.input.file),match=local.match(/^src\/bin\/([^/]+)\.rs$/)||local.match(/^src\/bin\/([^/]+)\/main\.rs$/);if(match)autoBin(local,match[1]);}}
  for(const f of declaredBins.keys())add(path.relative(dir,f));
  // Historical standalone/flat source inputs remain supported, without promoting
  // every orphan next to an existing Cargo root into a separately compiled crate.
  const explicit=manualTargets||pkg.autobins===false||pkg.autolib===false;
  if(![...roots.keys()].some(f=>owners.get(f)===dir)&&!explicit){add('main.rs');add('lib.rs','lib');if(![...roots.keys()].some(f=>owners.get(f)===dir)&&ownRows.length===1)roots.set(ownRows[0].input.file,true);}
 }
 for(const [file,state]of roots){const row=byFile.get(file);if(state===null)diagnose(file,'rust-target-features-unresolved');visit(row,row.tree.root,null,state,path.dirname(file),new Set([file]));}
 if(budget)for(const ctx of contexts)ctx.hazard=true;
 for(const row of rows)if(!states.has(row.input.file))diagnose(row.input.file,'rust-module-unreachable');
 return {contexts,diagnostics,states,budget};
}
module.exports={moduleGraph,LIMITS};
