'use strict';

const MAX_TOKENS = 20000;
const WRITES = new Set(['=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '>>>=', '??=', '++', '--']);

// Return the identifiers inside wrapped write targets/ref operands. This is
// deliberately an invalidation inventory, not an alias or lvalue inference.
// Pair once, then charge every examined token against a fixed linear budget.
// Null means malformed/over-budget syntax and callers must decline the proof.
function parenthesizedMutationTokens(tokens) {
  if (tokens.length > MAX_TOKENS) return null;
  const stack = [], pairs = [], affected = new Set();
  let work = 0;
  for (let i = 0; i < tokens.length; i++) {
    work++;
    if (tokens[i].text === '(') stack.push(i);
    else if (tokens[i].text === ')') {
      if (!stack.length) return null;
      pairs.push([stack.pop(), i]);
    }
  }
  if (stack.length) return null;
  for (const [open, close] of pairs) {
    if (++work > MAX_TOKENS * 4) return null;
    let operator = '', write = false;
    for (let j = close + 1; j < Math.min(tokens.length, close + 4); j++) {
      if (++work > MAX_TOKENS * 4) return null;
      operator += tokens[j].text;
      if (WRITES.has(operator)) { write = true; break; }
    }
    if (!write && !['ref', 'out', '++', '--'].includes(tokens[open - 1]?.text)) continue;
    for (let j = open + 1; j < close; j++) {
      if (++work > MAX_TOKENS * 4) return null;
      if (tokens[j].kind === 'identifier') affected.add(tokens[j]);
    }
  }
  return [...affected];
}

module.exports = { parenthesizedMutationTokens };
