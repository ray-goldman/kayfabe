'use strict';

// JLS 15.8.2: a class literal has a type name (or primitive type), optional
// array dimensions, and .class. It evaluates no receiver/call or initializer
// (JLS 12.4.1). This is auxiliary SQL metadata only, never a String fact.
function classLiteralMetadata(expression) {
  if (expression.length > 4000) return false;
  const tokens = expression.match(/[A-Za-z_$][\w$]*|\S/g) || [];
  if (tokens.pop() !== 'class' || tokens.pop() !== '.' || !tokens.length) return false;
  if (tokens[0] === 'void') return tokens.length === 1;
  const typeName = name => /^[A-Za-z_$][\w$]*$/.test(name || '') &&
    !/^(?:_|abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|extends|final|finally|float|for|goto|if|implements|import|instanceof|int|interface|long|native|new|package|private|protected|public|return|short|static|strictfp|super|switch|synchronized|this|throw|throws|transient|try|void|volatile|while|true|false|null|var|yield|record|sealed|permits)$/.test(name);
  let index = 1;
  if (!/^(?:boolean|byte|short|int|long|char|float|double)$/.test(tokens[0])) {
    if (!typeName(tokens[0])) return false;
    while (tokens[index] === '.') {
      if (!typeName(tokens[index + 1])) return false;
      index += 2;
    }
  }
  while (index < tokens.length) {
    if (tokens[index++] !== '[' || tokens[index++] !== ']') return false;
  }
  return true;
}

// Only this exact constructor form is auxiliary metadata. It is never a
// String/return fact, and populated, aliased or wrapped arrays remain unknown.
const emptyObjectArray = /new\s+(?:java\s*\.\s*lang\s*\.\s*)?Object\s*\[\s*\]\s*\{\s*\}/;

function sqlAuxiliaryMetadata(expression) {
  if (expression.length > 4000) return false;
  return classLiteralMetadata(expression) ||
    new RegExp('^\\s*(?:' + emptyObjectArray.source + ')\\s*$').test(expression);
}

// These inputs share offsets. Check the original code as well as the string
// mask: a populated literal/char initializer must never appear empty here.
// This mask is used only by the constructor declaration guard, not as facts or
// as the method's scope map. Preserve positions and newlines for both users.
function maskEmptyObjectArrayInitializers(code, masked) {
  const spans = [];
  for (const match of code.matchAll(new RegExp('\\b' + emptyObjectArray.source, 'g'))) {
    if (match[0].length > 4000 || masked.slice(match.index, match.index + match[0].length) !== match[0]) continue;
    // A member/qualified lookalike is not the exact supported constructor.
    let before = match.index - 1;
    while (before >= 0 && /\s/.test(code[before])) before--;
    if (code[before] === '.' || /[\w$]/.test(code[before] || '')) continue;
    spans.push([match.index, match.index + match[0].length]);
  }
  let result = '', last = 0;
  for (const [start, end] of spans) {
    result += masked.slice(last, start) + masked.slice(start, end).replace(/[^\r\n]/g, ' ');
    last = end;
  }
  return result + masked.slice(last);
}

module.exports = { sqlAuxiliaryMetadata, maskEmptyObjectArrayInitializers };
