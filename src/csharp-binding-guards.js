'use strict';

// The lexer deliberately does not normalize C# identifier escapes or ignored
// formatting characters. A strict proof cannot compare those raw spellings.
// Walk physical source once: comments and literal tokens are inert, while gaps
// must still be inspected because JS whitespace consumes embedded U+FEFF.
function hasUnsupportedIdentifierSpelling(source, tokens) {
  let offset = 0, tokenIndex = 0;
  while (offset < source.length) {
    while (tokenIndex < tokens.length && tokens[tokenIndex].end <= offset) tokenIndex++;
    const token = tokens[tokenIndex];
    if (token?.start === offset && ['string', 'char', 'interpolated-string'].includes(token.kind)) {
      offset = token.end;
      continue;
    }
    if (source.startsWith('//', offset)) {
      let end = offset + 2;
      for (; end < source.length && source[end] !== '\n'; end++) {
        // C# also terminates line comments at CR/NEL/LS/PS. The lexer has
        // already swallowed those spans, including possible ordinary writes;
        // scanning only for alternative names after them cannot repair that.
        // CR immediately before LF is the supported CRLF ending.
        if (/[\r\u0085\u2028\u2029]/.test(source[end]) && !(source[end] === '\r' && source[end + 1] === '\n')) return true;
      }
      offset = end;
      continue;
    }
    if (source.startsWith('/*', offset)) {
      const end = source.indexOf('*/', offset + 2);
      if (end < 0) return true;
      offset = end + 2;
      continue;
    }
    const character = String.fromCodePoint(source.codePointAt(offset));
    if (character === '\\' || /\p{Cf}/u.test(character) && !(offset === 0 && character === '\ufeff')) return true;
    offset += character.length;
  }
  return false;
}

// Query range variables need binding scopes this bounded proof does not model.
// Exact spelling keeps escaped identifiers, comments and strings inert.
function hasQueryBindings(tokens, method) {
  const typePunctuation = new Set(['.', '::', '<', '>', '>>', '[', ']', '?', ',', '(', ')']);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].start <= method.bodyStart || tokens[i].end >= method.bodyEnd || tokens[i].text !== 'from') continue;
    for (let j = i + 1; j < tokens.length && tokens[j].end < method.bodyEnd; j++) {
      if (tokens[j].text === 'in' && tokens[j - 1].kind === 'identifier') return true;
      if (tokens[j].kind !== 'identifier' && !typePunctuation.has(tokens[j].text)) break;
      if (j - i >= 256) return true;
    }
  }
  return false;
}

module.exports = { hasQueryBindings, hasUnsupportedIdentifierSpelling };
