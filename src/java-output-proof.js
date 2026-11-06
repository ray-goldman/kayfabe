'use strict';

// Shared current-call boundary proof. This grants no render or replay facts.
function completeOutputStatement({ index, call, windowStart, windowEnd }) {
  const method = index.at(call.position);
  const limit = Math.min(method?.end ?? 0, windowEnd);
  if (!method || call.position < windowStart || call.end > limit ||
      call.end - call.position > 4000 || method.end - method.start > 50000) return false;
  // The prefix must begin at a complete OUTER statement boundary. Brace depth
  // and typed delimiters exclude wrappers, unbraced guards and sibling calls.
  const stack = [];
  let boundary = method.start;
  for (let i = method.start; i < call.position; i++) {
    const c = index.mask[i];
    if ('([{'.includes(c)) { if (stack.length >= 64) return false; stack.push(c); }
    else if (')]}'.includes(c)) {
      if (stack.pop() !== ({ ')': '(', ']': '[', '}': '{' })[c]) return false;
      if (!stack.length && c === '}') boundary = i + 1;
    } else if (c === ';' && !stack.length) boundary = i + 1;
  }
  if (stack.length || index.mask.slice(boundary, call.position).trim()) return false;
  let after = call.end;
  while (after < limit && /\s/.test(index.mask[after])) after++;
  if (after >= limit || index.mask[after] !== ';') return false;
  return true;
}

module.exports = { completeOutputStatement };
