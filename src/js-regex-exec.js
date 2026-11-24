'use strict';

// Recognize a regex literal immediately owning the only .exec call on a line.
// Other method receivers, including renamed child_process bindings, keep alerting.
function regexLiteralExecSafe(line) {
  if (line.includes('\n') || line.length > 2000) return false;
  const calls = [...line.matchAll(/\.exec\s*\(/g)];
  if (calls.length !== 1) return false;
  const dot = calls[0].index;
  for (let start = 0; start < dot; start += 1) {
    if (line[start] !== '/') continue;
    const before = line.slice(0, start).trimEnd().slice(-1);
    if (before && !/[=(\[:,!?]/.test(before) && !/\breturn$/.test(line.slice(0, start).trimEnd())) continue;
    let inClass = false, escaped = false;
    for (let end = start + 1; end < dot; end += 1) {
      const char = line[end];
      if (escaped) { escaped = false; continue; }
      if (char === '\\') { escaped = true; continue; }
      if (char === '[') { inClass = true; continue; }
      if (char === ']') { inClass = false; continue; }
      if (char === '/' && !inClass && /^[dgimsuvy]*$/.test(line.slice(end + 1, dot))) return true;
    }
  }
  return false;
}

module.exports = { regexLiteralExecSafe };
