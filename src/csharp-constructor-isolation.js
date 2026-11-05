'use strict';
const { tokenFile, name } = require('./csharp-proof-index');

// Permission to use independently inventoried declarations, never evidence that
// executable parsing is complete. Callers keep fallback coverage and exclude
// these owners from method/value proofs. Every source token remains visible.
function isolatedConstructorOwners(parsed, source, owners) {
  if (parsed.complete) return [];
  if (source.length > 100000 || !Array.isArray(parsed.errors) || !parsed.errors.length || parsed.errors.length > 512) return null;
  const lex = tokenFile(source); if (!lex) return null;
  const { ts, pairs } = lex, positions = new Map(ts.map((token, i) => [token.start, i]));
  const byBounds = new Map();
  for (const owner of owners) {
    const key = owner.start + ':' + owner.end;
    if (byBounds.has(key)) return null;
    byBounds.set(key, owner);
  }
  const result = [];
  for (const error of parsed.errors) {
    if (error.code !== 'unsupported-constructor-header' || error.message !== 'unsupported constructor initializer' ||
      !Number.isInteger(error.start) || !Number.isInteger(error.ownerStart) || !Number.isInteger(error.ownerEnd) ||
      error.ownerStart < 0 || error.start <= error.ownerStart || error.start >= error.ownerEnd || error.ownerEnd > source.length) return null;
    const owner = byBounds.get(error.ownerStart + ':' + error.ownerEnd), at = positions.get(error.start);
    if (!owner || at === undefined || error.start <= owner.bodyStart || ts[at]?.text !== ':' ||
      !['base', 'this'].includes(ts[at+1]?.text) || ts[at+2]?.text !== '(' || !pairs.has(at+2) ||
      ts[at-1]?.text !== ')' || !pairs.has(at-1) || name(ts[pairs.get(at-1)-1]) !== owner.name) return null;
    const body = pairs.get(at+2)+1, end = pairs.get(body);
    if (ts[body]?.text !== '{' || end === undefined || ts[end].end >= owner.end) return null;
    result.push({ start: owner.start, end: owner.end });
  }
  return result;
}
module.exports = { isolatedConstructorOwners };
