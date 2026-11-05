'use strict';

const { parseCSharp } = require('./parsers/csharp/parser');
const { tokenizeCSharp } = require('./parsers/csharp/lexer');
const { createCSharpValueProof } = require('./csharp-values');

const CONSTANT_TYPES = new Set(['string', 'String', 'char', 'int', 'long', 'short', 'byte', 'bool', 'float', 'double', 'decimal', 'var']);
const MAX_METHOD = 50000;

function splitAtTopLevel(tokens, delimiter) {
  const parts = []; let start = 0, depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const text = tokens[i].text;
    if (['(', '[', '{'].includes(text)) depth++;
    else if ([')', ']', '}'].includes(text)) depth--;
    else if (text === delimiter && depth === 0) { parts.push(tokens.slice(start, i)); start = i + 1; }
  }
  parts.push(tokens.slice(start));
  return parts;
}

// Expression reads are confined to one bounded method. A line selects sink starts, not
// expression ends: never prove a prefix that omits a later argument or operand.
function completeExpression(tokens, start, call = false, methodEnd = Infinity) {
  const stack = [], closes = { ')': '(', ']': '[', '}': '{' };
  for (let i = start; i < tokens.length && tokens[i].end <= methodEnd; i++) {
    const text = tokens[i].text;
    if (['(', '[', '{'].includes(text)) stack.push(text);
    else if (closes[text]) {
      if (!stack.length) return call && text === ')' ? { tokens: tokens.slice(start, i), end: tokens[i].end } : null;
      if (stack.pop() !== closes[text]) return null;
    } else if (text === ';') {
      if (stack.length || call) return null;
      return { tokens: tokens.slice(start, i), end: tokens[i].end };
    }
  }
  return null;
}

function sqlCallOpen(tokens, start) {
  if (tokens[start]?.text === '(') return start;
  if (tokens[start]?.text !== '<') return -1;
  // Only a bounded type-argument list may intervene before the call. Expand
  // the lexer's shift token locally for nested generic closing delimiters.
  const types = tokens.slice(start, start + 256).flatMap((token, offset) =>
    (token.text === '>>' ? ['>', '>'] : [token.text]).map(text => ({ ...token, text, index: start + offset })));
  let cursor = 0;
  function argumentsAt(depth) {
    if (depth > 24 || types[cursor++]?.text !== '<' || !typeAt(depth)) return false;
    while (types[cursor]?.text === ',') { cursor++; if (!typeAt(depth)) return false; }
    return types[cursor++]?.text === '>';
  }
  function typeAt(depth) {
    if (types[cursor++]?.kind !== 'identifier') return false;
    if (types[cursor]?.text === '<' && !argumentsAt(depth + 1)) return false;
    while (['.', '::'].includes(types[cursor]?.text)) {
      cursor++;
      if (types[cursor++]?.kind !== 'identifier') return false;
      if (types[cursor]?.text === '<' && !argumentsAt(depth + 1)) return false;
    }
    if (types[cursor]?.text === '?') cursor++;
    while (types[cursor]?.text === '[' && types[cursor + 1]?.text === ']') cursor += 2;
    return true;
  }
  return argumentsAt(0) && types[cursor]?.text === '(' ? types[cursor].index : -1;
}

function sinkExpression(tokens, ruleId, lineStart, lineEnd, methodStart = 0, methodEnd = Infinity) {
  const expressions = [];
  let multiline = false;
  const command = ruleId === 'CS-CMDI-001';
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].start >= lineEnd) break;
    if (tokens[i].start < lineStart) continue;
    const property = command ? 'Arguments' : 'CommandText';
    const assignment = tokens[i].text === '.' && tokens[i + 1]?.text === property && tokens[i + 2]?.text === '=';
    const processCall = command && tokens[i].text === 'Process' && tokens[i + 1]?.text === '.' &&
      tokens[i + 2]?.text === 'Start' && tokens[i + 3]?.text === '(';
    const methodCall = !command && ['FromSqlRaw', 'ExecuteSqlRaw', 'ExecuteSqlRawAsync', 'SqlQueryRaw'].includes(tokens[i].text) &&
      ['(', '<'].includes(tokens[i + 1]?.text);
    // The scanner's constructor candidate starts at new, which can precede
    // SqlCommand on another line (including inside another call's arguments).
    const constructor = !command && tokens[i].text === 'new' && tokens[i + 1]?.text === 'SqlCommand';
    if (!assignment && !processCall && !methodCall && !constructor) continue;
    // Check all selected-line anchors before narrowing expression reads. A
    // field initializer sharing a method's line cannot inherit its proof.
    if (tokens[i].start < methodStart || tokens[i].end > methodEnd) return null;
    if (assignment) {
      const value = completeExpression(tokens, i + 3, false, methodEnd);
      if (!value?.tokens.length) return null;
      expressions.push(value.tokens);
      multiline ||= value.end > lineEnd;
      continue;
    }
    const open = processCall ? i + 3 : constructor ? i + 2 : sqlCallOpen(tokens, i + 1);
    if (open < 0 || tokens[open]?.text !== '(' || tokens[open].end > methodEnd) return null;
    const value = completeExpression(tokens, open + 1, true, methodEnd);
    if (!value?.tokens.length) return null;
    multiline ||= value.end > lineEnd;
    const args = splitAtTopLevel(value.tokens, ',');
    if (args.some(arg => !arg.length) || command && args.length > 2) return null;
    // SQL's first argument is command text; later arguments are connection or
    // parameter values, rather than executable SQL. Process.Start needs both.
    expressions.push(...(command ? args : [args[0]]));
  }
  return expressions.length ? { expressions, multiline } : null;
}

function parseLocalDeclarations(tokens) {
  const declarations = new Map();
  for (let i = 1; i < tokens.length; i++) {
    const name = tokens[i];
    if (name.kind !== 'identifier' || !['=', ';'].includes(tokens[i + 1]?.text)) continue;
    let previous = i - 1;
    while (previous >= 0 && ['?', ']', '['].includes(tokens[previous].text)) previous--;
    if (!CONSTANT_TYPES.has(tokens[previous]?.text)) continue;
    const key = name.text.replace(/^@/, '');
    if (!declarations.has(key)) declarations.set(key, []);
    declarations.get(key).push({ tokenIndex: i, nameIndex: i, type: tokens[previous].text });
  }
  return declarations;
}

function proveExpression(tokens, declarations, assignments, parameters, visiting = new Set(), depth = 0) {
  if (!tokens.length || tokens.length > 256 || depth > 24) return false;
  while (tokens[0]?.text === '(' && tokens.at(-1)?.text === ')') {
    let level = 0, wraps = true;
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].text === '(') level++;
      else if (tokens[i].text === ')' && --level === 0 && i !== tokens.length - 1) { wraps = false; break; }
    }
    if (!wraps) break;
    tokens = tokens.slice(1, -1);
  }
  const plus = splitAtTopLevel(tokens, '+');
  if (plus.length > 1) return plus.every(part => proveExpression(part, declarations, assignments, parameters, visiting, depth + 1));
  if (tokens.length === 1) {
    const token = tokens[0];
    if (['string', 'char', 'number'].includes(token.kind) || ['true', 'false', 'null'].includes(token.text)) return true;
    if (token.kind !== 'identifier') return false;
    const name = token.text.replace(/^@/, '');
    if (parameters.has(name) || visiting.has(name) || declarations.get(name)?.length !== 1) return false;
    const writes = assignments.get(name) || [];
    if (!writes.length) return false;
    const next = new Set(visiting); next.add(name);
    return writes.every(rhs => proveExpression(rhs, declarations, assignments, parameters, next, depth + 1));
  }
  return false;
}

function directConstantSink({ code, line, ruleId, parsed: suppliedParse }) {
  if (typeof code !== 'string' || !Number.isInteger(line) || line < 0 || code.length > 2 * 1024 * 1024 ||
      !['CS-CMDI-001', 'CS-SQLI-001'].includes(ruleId)) return false;
  if (/\busing\s+(?:String|var)\s*=/.test(code)) return false;
  // Keep CR characters in line widths so offsets remain source/token offsets.
  const lines = code.split('\n');
  if (line >= lines.length) return false;
  const lineStart = lines.slice(0, line).reduce((sum, value) => sum + value.length + 1, 0);
  const lineEnd = lineStart + lines[line].length;
  const parsed = suppliedParse || parseCSharp(code);
  if (!parsed.complete) return false;
  const methods = parsed.methods.filter(method => method.start <= lineStart && method.end >= lineEnd);
  if (methods.length !== 1) return false;
  const method = methods[0];
  if (method.end - method.start > MAX_METHOD) return false;
  const lexed = tokenizeCSharp(code.slice(method.start, method.end));
  if (lexed.errors.length || lexed.tokens.some(token => token.kind === 'interpolated-string')) return false;
  const tokens = lexed.tokens;
  const methodParams = new Set((method.parameters || []).map(parameter => parameter.name));
  const declarations = parseLocalDeclarations(tokens);
  const assignments = new Map();
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i], name = token.text.replace(/^@/, '');
    if (token.kind !== 'identifier' || tokens[i - 1]?.text === '.') continue;
    if (tokens[i + 1]?.text !== '=' || tokens[i + 2]?.text === '=') continue;
    if (!declarations.has(name)) continue;
    let end = i + 2, nesting = 0;
    for (; end < tokens.length; end++) {
      if (['(', '[', '{'].includes(tokens[end].text)) nesting++;
      else if ([')', ']', '}'].includes(tokens[end].text)) { if (nesting === 0) break; nesting--; }
      else if (tokens[end].text === ';' && nesting === 0) break;
    }
    if (end >= tokens.length || tokens[end].text !== ';') return false;
    if (!assignments.has(name)) assignments.set(name, []);
    assignments.get(name).push(tokens.slice(i + 2, end));
  }
  const sink = sinkExpression(tokens, ruleId, lineStart - method.start, lineEnd - method.start);
  if (!sink) return false;
  // The legacy collector is unscoped and does not model these bindings. Do
  // not extend it to newly complete expressions in such methods: a sibling
  // literal with the same spelling is not evidence about the actual binding.
  // The scoped value proof can still establish safety within its own subset.
  if (sink.multiline && tokens.some(token => ['foreach', 'catch', '=>', 'delegate', 'out', 'is', 'switch', 'fixed'].includes(token.text))) return false;
  const expression = sink.expressions;
  // Newly supported overloads/multiple sinks use the stricter scoped proof;
  // do not expand the legacy proof's acceptance of unresolved named types.
  if (expression.length > 1) return false;
  const relevant = new Set();
  const pending = expression.flat().filter(token => token.kind === 'identifier').map(token => token.text.replace(/^@/, ''));
  while (pending.length) {
    const name = pending.pop();
    if (relevant.has(name)) continue;
    relevant.add(name);
    for (const rhs of assignments.get(name) || []) for (const token of rhs) {
      if (token.kind === 'identifier') pending.push(token.text.replace(/^@/, ''));
    }
  }
  for (let i = 0; i < tokens.length; i++) {
    const name = tokens[i].kind === 'identifier' ? tokens[i].text.replace(/^@/, '') : null;
    if (!name || !relevant.has(name)) continue;
    if (['++', '--', '+=', '-=', '*=', '/=', '%='].includes(tokens[i + 1]?.text) || ['++', '--'].includes(tokens[i - 1]?.text) ||
        ['ref', 'out'].includes(tokens[i - 1]?.text)) return false;
    if (tokens[i + 1]?.text === '=>' && tokens.slice(i + 2).some(token => token.kind === 'identifier' && relevant.has(token.text.replace(/^@/, '')))) return false;
  }
  const opens=[];
  for(let i=0;i<tokens.length;i++) {
    if(tokens[i].text==='(')opens.push(i);
    else if(tokens[i].text===')') {
      const open=opens.pop();
      if(open!==undefined&&tokens[i+1]?.text==='='&&tokens.slice(open+1,i).some(token=>token.kind==='identifier'&&relevant.has(token.text.replace(/^@/,''))))return false;
    }
  }
  return expression.every(value => proveExpression(value, declarations, assignments, methodParams));
}

function createCSharpConstantSinkProof(code) {
  let parsed, tokens, proveValue;
  return (line, ruleId) => {
    if (typeof code !== 'string' || code.length > 2 * 1024 * 1024 || !Number.isInteger(line) || line < 0 ||
        !['CS-CMDI-001', 'CS-SQLI-001'].includes(ruleId)) return false;
    parsed ||= parseCSharp(code);
    if (!parsed.complete) return false;
    const lines = code.split('\n');
    if (line >= lines.length) return false;
    const start = lines.slice(0, line).reduce((sum, text) => sum + text.length + 1, 0);
    const end = start + lines[line].length;
    const methods = parsed.methods.filter(method => method.start < end && method.end > start);
    if (methods.length !== 1 || methods[0].end - methods[0].start > MAX_METHOD) return false;
    const method = methods[0];
    // Both proof paths need the same unique ownership gate. Whole-line
    // containment alone can miss a local function starting on that line.
    if (directConstantSink({ code, line, ruleId, parsed })) return true;
    tokens ||= tokenizeCSharp(code).tokens;
    const sink = sinkExpression(tokens, ruleId, start, end, method.start, method.end);
    if (!sink?.expressions.length) return false;
    proveValue ||= createCSharpValueProof(code, parsed);
    return sink.expressions.every(value => proveValue(value));
  };
}

function isConstantCSharpSink({ code, line, ruleId }) {
  return createCSharpConstantSinkProof(code)(line, ruleId);
}

module.exports = { isConstantCSharpSink, createCSharpConstantSinkProof };
