'use strict';
const {evaluateAttributes}=require('./cfg');
// Structural item boundaries only; expression bodies remain the existing subset.
function structure(parsed,options={}) {
 const {tokens:t,pairs}=parsed;let work=0;const functions=[];
 function attributes(i,end,inner) {
  const attrs=[];
  while(i<end&&t[i].value==='#') {
   const isInner=t[i+1]?.value==='!';if(isInner!==inner)break;
   const open=i+(isInner?2:1);if(t[open]?.value!=='['||!pairs.has(open))return {attrs,i,valid:false};
   const close=pairs.get(open);attrs.push(t.slice(open+1,close));i=close+1;
  }return {attrs,i,valid:true};
 }
 function scope(start,end,depth=0,opaque=false) {
  const inner=attributes(start,end,true),node={start,end,items:[],inner:evaluateAttributes(inner.attrs,options),valid:inner.valid,opaque};
  if(depth>64){node.valid=false;return node;}let i=inner.i;
  while(i<end&&node.valid) {
   if(++work>100000){node.valid=false;break;}
   if(t[i].value===';'){i++;continue;}
   const outer=attributes(i,end,false);if(!outer.valid){node.valid=false;break;}
   const first=i;let j=outer.i;const effects=evaluateAttributes(outer.attrs,options),qualifiers=[];
   if(t[j]?.value==='pub'){j++;if(t[j]?.value==='(')j=pairs.get(j)+1;}
   while(['async','unsafe','const','extern'].includes(t[j]?.value)) {
    // const before a name is a constant item, not a function qualifier.
    if(t[j].value==='const'&&t[j+1]?.value!=='fn'&&t[j+1]?.value!=='unsafe')break;
    qualifiers.push(t[j++].value);if(qualifiers.at(-1)==='extern'&&t[j]?.kind==='literal')j++;
   }
   const kind=t[j]?.raw?'unknown':t[j]?.value,name=t[j+1]?.kind==='identifier'?t[j+1].value:null;
   if(!kind){node.valid=false;break;}
   let cursor=j+1,body=null,last=null;
   while(cursor<end) {
    const v=t[cursor].value;
    if(v===';'){last=cursor+1;break;}
    if(v==='{'){body=cursor;last=pairs.get(cursor)+1;if(t[last]?.value===';')last++;break;}
    if(v==='('||v==='['){cursor=pairs.get(cursor)+1;continue;}cursor++;
   }
   if(last===null||!Number.isInteger(last)||last<=first||last>end){node.valid=false;break;}
   const item={kind,name,start:first,keyword:j,end:last,body,effects,qualifiers};
   if(kind==='fn') {
    item.header=t.slice(j+2,body??last);item.functionStart=body===null?null:body+1;item.functionEnd=body===null?null:pairs.get(body);
    functions.push(item);
   }else if(kind==='mod'&&body!==null)item.scope=scope(body+1,pairs.get(body),depth+1,opaque);
   else if(['impl','trait','extern'].includes(kind)&&body!==null)item.scope=scope(body+1,pairs.get(body),depth+1,true);
   node.items.push(item);i=last;
  }
  return node;
 }
 const root=scope(0,t.length);
 return {root,functions};
}
module.exports={structure};
