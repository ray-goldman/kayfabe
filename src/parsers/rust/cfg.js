'use strict';
const LIMITS=Object.freeze({tokens:4096,depth:32,attributes:256});
const and=(a,b)=>a===false||b===false?false:a===true&&b===true?true:null;
const join=(a,b)=>a===b?a:null;
const stringToken=t=>t?.kind==='literal'&&(/^"/.test(t.value)||/^r#{0,255}"/.test(t.value));
function evaluatePredicate(tokens,options={}) {
 let i=0,valid=tokens.length<=LIMITS.tokens;
 function expression(depth) {
  if(depth>LIMITS.depth||i>=tokens.length){valid=false;return null;}
  const t=tokens[i++];if(t.kind!=='identifier'||t.raw){valid=false;return null;}
  const name=t.value;
  if(tokens[i]?.value==='(') {
   if(!['all','any','not'].includes(name)){valid=false;return null;}i++;
   const values=[];let trailing=false;
   while(i<tokens.length&&tokens[i].value!==')') {
    const before=i;values.push(expression(depth+1));if(!valid||i===before)break;
    if(tokens[i]?.value===','){i++;trailing=true;if(tokens[i]?.value===')')break;}else{trailing=false;break;}
   }
   if(tokens[i]?.value!==')'){valid=false;return null;}i++;
   if(name==='not'){if(values.length!==1||trailing){valid=false;return null;}return values[0]===null?null:!values[0];}
   if(name==='all')return values.reduce(and,true);
   return values.some(v=>v===true)?true:values.every(v=>v===false)?false:null;
  }
  if(tokens[i]?.value==='=') {
   i++;if(!stringToken(tokens[i++]))valid=false;return null;
  }
  if(name==='true')return true;if(name==='false')return false;
  if(name==='test')return options.includeTests?null:false;
  return null;
 }
 const value=valid?expression(0):null;valid=valid&&i===tokens.length;
 return {value:valid?value:null,complete:valid};
}
function splitArguments(tokens) {
 const out=[];let depth=0,start=0;
 for(let i=0;i<tokens.length;i++) {
  const v=tokens[i].value;
  if(['(','[','{'].includes(v))depth++;else if([')',']','}'].includes(v))depth--;
  if(depth<0)return null;
  if(v===','&&!depth){if(i===start)return null;out.push(tokens.slice(start,i));start=i+1;}
 }
 if(depth)return null;if(start<tokens.length)out.push(tokens.slice(start));return out;
}
const INERT=new Set(['allow','warn','deny','forbid','doc','inline','cold','must_use','deprecated','repr','non_exhaustive','no_mangle','export_name','link','link_name','windows_subsystem','ignore','should_panic']);
function evaluateAttributes(attributes,options={},depth=0) {
 const result={gate:true,hazard:false,customPath:false,unknownConditions:0};
 if(depth>LIMITS.depth||attributes.length>LIMITS.attributes){result.gate=null;result.hazard=true;return result;}
 for(const tokens of attributes) {
  if(!tokens.length||tokens.length>LIMITS.tokens||tokens[0].kind!=='identifier'||tokens[0].raw){result.gate=null;result.hazard=true;continue;}
  const name=tokens[0].value;
  if(name==='cfg'||name==='cfg_attr') {
   if(tokens[1]?.value!=='('||tokens.at(-1)?.value!==')'){result.gate=and(result.gate,null);result.hazard=true;continue;}
   const args=splitArguments(tokens.slice(2,-1));
   if(!args||name==='cfg'&&args.length!==1||name==='cfg_attr'&&args.length<2){result.gate=and(result.gate,null);result.hazard=true;continue;}
   const predicate=evaluatePredicate(args[0],options);
   if(predicate.value===null)result.unknownConditions++;
   if(!predicate.complete){result.gate=and(result.gate,null);result.hazard=true;continue;}
   if(name==='cfg'){result.gate=and(result.gate,predicate.value);continue;}
   if(predicate.value===false)continue;
   const nested=evaluateAttributes(args.slice(1),options,depth+1);
   result.gate=and(result.gate,predicate.value===true?nested.gate:join(true,nested.gate));
   result.hazard ||= nested.hazard;result.customPath ||= nested.customPath;result.unknownConditions+=nested.unknownConditions;
  }else if(name==='test'){result.gate=and(result.gate,options.includeTests?null:false);}
  else if(name==='path')result.customPath=true;
  else if(!INERT.has(name)||tokens[1]?.value==='::'||tokens.length>1&&!['(','='].includes(tokens[1].value))result.hazard=true;
 }
 // Attribute expansion on an item removed by cfg cannot inject names.
 if(result.gate===false){result.hazard=false;result.customPath=false;}
 return result;
}
module.exports={evaluatePredicate,evaluateAttributes,and,LIMITS};
