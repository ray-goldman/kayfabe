'use strict';
// A bounded token reader, not rustc. Detected lexical errors never feed rules.
const LIMITS=Object.freeze({bytes:1024*1024,tokens:100000,depth:128,commentDepth:128,rawHashes:255});
const identStart=c=>!!c&&/[A-Za-z_]/.test(c),identPart=c=>!!c&&/[A-Za-z0-9_]/.test(c);
function lexRust(source) {
 const tokens=[],pairs=new Map(),diagnostics=[],stack=[];let i=0,line=1,col=1;
 const fail=code=>{diagnostics.push({code,line,col});};
 const advance=end=>{while(i<end){if(source[i++]==='\n'){line++;col=1;}else col++;}};
 const emit=(kind,start,ln,cl,value)=>{tokens.push({kind,value:value??source.slice(start,i),start,end:i,line:ln,col:cl});};
 if(typeof source!=='string'||Buffer.byteLength(source)>LIMITS.bytes)return {tokens,pairs,complete:false,diagnostics:[{code:'rust-byte-budget',line:1,col:1}]};
 while(i<source.length&&!diagnostics.length) {
  if(tokens.length>=LIMITS.tokens){fail('rust-token-budget');break;}
  const start=i,ln=line,cl=col,c=source[i],next=source[i+1];
  if(/\s/.test(c)){advance(i+1);continue;}
  if(c==='/'&&next==='/'){const end=source.indexOf('\n',i+2);advance(end<0?source.length:end);continue;}
  if(c==='/'&&next==='*') {
   let depth=1;advance(i+2);
   while(i<source.length&&depth){if(source.startsWith('/*',i)){if(++depth>LIMITS.commentDepth){fail('rust-comment-depth');break;}advance(i+2);}else if(source.startsWith('*/',i)){depth--;advance(i+2);}else advance(i+1);}
   if(!depth)continue;if(!diagnostics.length)fail('rust-unclosed-comment');break;
  }
  let prefix=0;
  if(c==='r')prefix=1;else if((c==='b'||c==='c')&&next==='r')prefix=2;
  if(prefix) {
   let j=i+prefix;while(source[j]==='#')j++;
   if(source[j]==='"') {
    const hashes=j-i-prefix;if(hashes>LIMITS.rawHashes){fail('rust-raw-hash-budget');break;}
    const close='"'+'#'.repeat(hashes),end=source.indexOf(close,j+1);
    if(end<0){fail('rust-unclosed-raw-string');break;}
    advance(end+close.length);emit('literal',start,ln,cl);continue;
   }
  }
  let quote=c==='"'?i:((c==='b'||c==='c')&&next==='"'?i+1:-1);
  if(quote>=0) {
   advance(quote+1);let closed=false;
   while(i<source.length){if(source[i]==='\\'){advance(Math.min(source.length,i+2));}else if(source[i]==='"'){advance(i+1);closed=true;break;}else advance(i+1);}
   if(!closed){fail('rust-unclosed-string');break;}emit('literal',start,ln,cl);continue;
  }
  if(c==="'"||(c==='b'&&next==="'")) {
   const q=c==="'"?i:i+1;let j=q+1;
   if(source[j]==='\\') {
    j+=2;if(source[j-1]==='u'&&source[j]==='{'){j++;while(j<source.length&&j<q+12&&source[j]!=='}')j++;if(source[j]==='}')j++;}
    else if(source[j-1]==='x')j+=2;
   }else if(j<source.length)j+=source.codePointAt(j)>0xffff?2:1;
   if(source[j]==="'"){advance(j+1);emit('literal',start,ln,cl);continue;}
   if(c==="'"&&identStart(next)){advance(i+2);while(identPart(source[i]))advance(i+1);emit('lifetime',start,ln,cl);continue;}
   fail('rust-invalid-character');break;
  }
  if(identStart(c)) {
   const raw=c==='r'&&next==='#'&&identStart(source[i+2]);advance(i+(raw?3:1));while(identPart(source[i]))advance(i+1);
   emit('identifier',start,ln,cl,source.slice(start+(raw?2:0),i));if(raw)tokens.at(-1).raw=true;continue;
  }
  if(/[0-9]/.test(c)){advance(i+1);while(identPart(source[i]))advance(i+1);emit('number',start,ln,cl);continue;}
  if(c.charCodeAt(0)>127){fail('rust-unsupported-identifier');break;}
  if(!'()[]{}+-*/%^!&|=<>.,;:#$?@~'.includes(c)){fail('rust-invalid-token');break;}
  const p=source.slice(i,i+2);advance(i+(['::','->','=>','&&','||','==','!=','<=','>='].includes(p)?2:1));
  emit('punctuation',start,ln,cl);
  if('([{'.includes(c)) {
   if(stack.length>=LIMITS.depth){fail('rust-delimiter-depth');break;}stack.push(tokens.length-1);
  }else if(')]}'.includes(c)) {
   const open=stack.pop();if(open===undefined||'([{'.indexOf(tokens[open].value)!==')]}'.indexOf(c)){fail('rust-unbalanced-delimiter');break;}
   pairs.set(open,tokens.length-1);pairs.set(tokens.length-1,open);
  }
 }
 if(!diagnostics.length&&stack.length)fail('rust-unclosed-delimiter');
 return {tokens,pairs,complete:!diagnostics.length,diagnostics};
}
module.exports={lexRust,LIMITS};
