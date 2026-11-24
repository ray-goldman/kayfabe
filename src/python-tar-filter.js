'use strict';

// Only a top-level literal filter on the extraction call proves it safe.
// A nested helper's filter keyword or a conditional expression does not.
function topLevelArguments(source, open) {
  const stack = ['('];
  const pairs = { ')': '(', ']': '[', '}': '{' };
  const args = [];
  let start = open + 1;
  let quote = null;
  let escaped = false;
  for (let i = start; i < source.length; i += 1) {
    const ch = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { stack.push(ch); continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      if (stack.pop() !== pairs[ch]) return null;
      if (stack.length === 0) {
        args.push(source.slice(start, i).trim());
        return args;
      }
      continue;
    }
    if (ch === ',' && stack.length === 1) {
      args.push(source.slice(start, i).trim());
      start = i + 1;
    }
  }
  return null;
}

function pythonTarLiteralFilterSafe(window) {
  if (window.length > 14000 || window.includes("'''") || window.includes('"""')) return false;
  const calls = [...window.matchAll(/\.(?:extractall|extract)\s*\(/g)];
  if (calls.length === 0 || calls.length > 20) return false;
  return calls.every(call => {
    const open = call.index + call[0].lastIndexOf('(');
    const args = topLevelArguments(window, open);
    return !!args && args.some(arg => /^filter\s*=\s*(?:"(?:data|tar)"|'(?:data|tar)')$/.test(arg));
  });
}

module.exports = { pythonTarLiteralFilterSafe };
