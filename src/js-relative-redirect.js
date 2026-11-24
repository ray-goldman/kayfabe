'use strict';

// Prove the target is a fixed local path whose only variable portions are
// percent-encoded. Only the simple response.redirect wrapper is admitted.
function encodedRelativeRedirectSafe(code, lineIndex) {
  if (code.length > 100000 || /\bglobalThis\b|\bReflect\b|Object\s*\.\s*defineProperty/.test(code)) return false;
  const wrapper = /function\s+redirect\s*\(\s*response(?:\s*:\s*Response)?\s*,\s*path(?:\s*:\s*string)?\s*\)(?:\s*:\s*void)?\s*\{\s*response\.redirect\(\s*303\s*,\s*path\s*\)\s*;\s*\}/g;
  if ([...code.matchAll(wrapper)].length !== 1 || [...code.matchAll(/\bfunction\s+redirect\s*\(/g)].length !== 1 ||
      /\b(?:const|let|var|class)\s+redirect\b|\bredirect\s*=/.test(code)) return false;
  if (/\b(?:const|let|var|function|class)\s+encodeURIComponent\b|\bencodeURIComponent\s*=/.test(code)) return false;
  const line = code.split('\n')[lineIndex] || '';
  const call = line.match(/^\s*redirect\(\s*response\s*,\s*(`[^`\\\r\n]+`)\s*\)\s*;?\s*$/);
  if (!call) return false;
  const template = call[1].slice(1, -1);
  const expression = /\$\{encodeURIComponent\([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\)\}/g;
  const matches = [...template.matchAll(expression)];
  if (matches.length === 0) return false;
  const reduced = template.replace(expression, 'x');
  return reduced.startsWith('/') && !reduced.startsWith('//') &&
    !reduced.includes('${') && !/[\\\r\n]/.test(reduced);
}

module.exports = { encodedRelativeRedirectSafe };
