'use strict';

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

module.exports = { hasQueryBindings };
