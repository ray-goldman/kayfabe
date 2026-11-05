'use strict';

const { tokenizeCSharp } = require('./lexer');
const CONTROL = new Set(['if', 'while', 'for', 'foreach', 'switch', 'catch', 'using', 'lock', 'fixed', 'nameof', 'typeof', 'checked', 'unchecked']);
const TYPE = new Set(['class', 'struct', 'interface', 'record']);

function parseCSharp(source) {
  const lexed = tokenizeCSharp(source), { tokens } = lexed, errors = [...lexed.errors], declarations = [], methods = [];
  const stack = [], pairs = new Map();
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (['(', '{', '['].includes(t.text)) stack.push(i);
    else if ([')', '}', ']'].includes(t.text)) {
      const open = stack.pop();
      if (open === undefined || !({ ')': '(', '}': '{', ']': '[' })[t.text] || tokens[open].text !== ({ ')': '(', '}': '{', ']': '[' })[t.text]) {
        errors.push({ message: 'unbalanced delimiter', start: t.start }); continue;
      }
      pairs.set(open, i); pairs.set(i, open);
    }
  }
  for (const open of stack) errors.push({ message: 'unclosed delimiter', start: tokens[open].start });
  const isId = t => t && t.kind === 'identifier';
  for (let i = 0; i < tokens.length - 1; i++) {
    if (TYPE.has(tokens[i].text) && isId(tokens[i + 1])) declarations.push({ kind: tokens[i].text, name: tokens[i + 1].text.replace(/^@/, ''), start: tokens[i].start, end: tokens[i + 1].end });
    if (tokens[i].text === 'unsafe' || tokens[i].text === 'goto') errors.push({ message: `unsupported ${tokens[i].text}`, start: tokens[i].start });
  }
  // A primary constructor belongs to a type header, not to a method whose
  // executable body spans every member. Keep header ranges and input names so
  // removing the false method cannot turn its parameters into unbound locals.
  const typeHeaders = [];
  for (let i = 0; i < tokens.length - 1; i++) {
    if (!TYPE.has(tokens[i].text) || !isId(tokens[i + 1]) ||
        tokens[i].text === 'record' && ['class', 'struct'].includes(tokens[i + 1].text)) continue;
    let end = i + 2;
    for (; end < tokens.length; end++) {
      if (['{', ';'].includes(tokens[end].text)) break;
      if (['(', '['].includes(tokens[end].text) && pairs.has(end)) end = pairs.get(end);
    }
    if (!tokens[end]) continue;
    let primary = i + 2;
    // Generic owners are indexed only to exclude their header from methods;
    // they do not gain a constant-value ownership proof.
    if (tokens[primary]?.text === '<') {
      let depth = 0;
      while (primary < end) {
        const text = tokens[primary++].text;
        if (text === '<') depth++;
        else if (text === '>') depth--;
        else if (text === '>>') depth -= 2;
        if (depth <= 0) break;
      }
    }
    const hasPrimary = tokens[primary]?.text === '(' && pairs.has(primary), parameters = [];
    let unsupported = false;
    if (hasPrimary) {
      const close = pairs.get(primary);
      let start = primary + 1;
      for (let j = start; j <= close; j++) {
        if (j < close && ['(', '['].includes(tokens[j].text) && pairs.has(j)) { j = pairs.get(j); continue; }
        if (j !== close && tokens[j].text !== ',') continue;
        const part = tokens.slice(start, j);
        // Only a plain, non-defaulted type/name pair is a supported primary
        // binding. Reject rather than guessing a name inside richer syntax.
        if (part.length === 2 && part.every(isId)) parameters.push({ name: part[1].text.replace(/^@/, ''), type: part[0].text, start: part[0].start, end: part[1].end });
        else if (part.length) unsupported = true;
        start = j + 1;
      }
      const executableHeader = tokens.slice(primary + 1, close).some(t => t.text === '=') || tokens.slice(close + 1, end).some(t => t.text === ':');
      if (executableHeader) errors.push({ message: 'unsupported primary constructor executable header', start: tokens[primary].start,
        code: 'unsupported-constructor-header', ownerStart: tokens[i].start,
        ownerEnd: tokens[end].text === '{' && pairs.has(end) ? tokens[pairs.get(end)].end : tokens[end].end });
      let prefix = i - 1;
      while (prefix >= 0 && ![';', '{', '}'].includes(tokens[prefix].text)) prefix--;
      unsupported ||= tokens[i + 2]?.text === '<' || tokens.slice(prefix + 1, i).some(t => t.text === 'partial') || close + 1 !== end;
    }
    typeHeaders.push({ start: tokens[i].start, headerEnd: tokens[end].start, bodyStart: tokens[end].text === '{' ? tokens[end].start : null,
      bodyEnd: tokens[end].text === '{' && pairs.has(end) ? tokens[pairs.get(end)].end : null, hasPrimary, parameters, unsupported });
  }
  const lineAt = offset => source.slice(0, offset).split(/\r?\n/).length;
  const addStatement = (list, kind, index, endIndex = index) => {
    const a = tokens[index], b = tokens[endIndex];
    if (a && b) list.push({ kind, start: a.start, end: b.end, startLine: lineAt(a.start), endLine: lineAt(b.end) });
  };
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== '(' || !pairs.has(i)) continue;
    const close = pairs.get(i), nameToken = tokens[i - 1], name = nameToken?.text?.replace(/^@/, '');
    if (typeHeaders.some(type => tokens[i].start >= type.start && tokens[i].start < type.headerEnd)) continue;
    if (!isId(nameToken) || CONTROL.has(name) || tokens[close + 1]?.text === '=>' || tokens[close + 1]?.text === '.') continue;
    let body = close + 1;
    const constructorInitializer = tokens[body]?.text === ':' && ['base', 'this'].includes(tokens[body + 1]?.text) &&
      tokens[body + 2]?.text === '(' && pairs.has(body + 2) && declarations.some(d => d.name === name);
    if (constructorInitializer) body = pairs.get(body + 2) + 1;
    while (['where'].includes(tokens[body]?.text)) body++;
    if (tokens[body]?.text !== '{' || !pairs.has(body)) continue;
    // A declaration has a type/member prefix and is not a call expression or control construct.
    const prefix = tokens.slice(Math.max(0, i - 7), i).map(t => t.text);
    if (!prefix.some(x => ['public','private','protected','internal','static','virtual','override','async','partial','new','sealed','abstract','void','string','int','bool','Task','var'].includes(x)) &&
        !declarations.some(d => d.name === name)) continue;
    if (constructorInitializer) {
      const owner = typeHeaders.filter(type => type.bodyStart < nameToken.start && type.bodyEnd >= tokens[pairs.get(body)].end).at(-1);
      errors.push({ message: 'unsupported constructor initializer', start: tokens[close + 1].start,
        code: 'unsupported-constructor-header', ownerStart: owner?.start, ownerEnd: owner?.bodyEnd });
    }
    const endIndex = pairs.get(body), statements = [];
    const parameters = [];
    let paramDepth = 0, paramStart = i + 1;
    for (let j = i + 1; j <= close; j++) {
      const txt = tokens[j]?.text;
      if (['(', '[', '<'].includes(txt)) paramDepth++;
      else if ([')', ']', '>'].includes(txt)) paramDepth--;
      if ((txt === ',' && paramDepth === 0) || j === close) {
        const part = tokens.slice(paramStart, j), last = [...part].reverse().find(t => t.kind === 'identifier');
        if (last) parameters.push({ name: last.text.replace(/^@/, ''), type: part.slice(0, part.indexOf(last)).map(t => t.text).join('') || null, start: part[0].start, end: part.at(-1).end });
        paramStart = j + 1;
      }
    }
    let depth = 0;
    for (let j = body + 1; j < endIndex; j++) {
      const tok = tokens[j];
      if (['if','switch','try','catch','finally','for','foreach','while','using','return','throw','break','continue'].includes(tok.text)) {
        addStatement(statements, tok.text, j);
      }
      if (tok.text === '=' && depth === 0) addStatement(statements, 'assignment', j - 1, j);
      if (['{','(' ,'['].includes(tok.text)) depth++;
      else if (['}',')',']'].includes(tok.text)) depth--;
    }
    const declarationStart = Math.max(0, tokens[Math.max(0, i - 8)]?.start ?? nameToken.start);
    const prefixText = tokens.slice(Math.max(0, i - 8), i).map(t => t.text);
    const visibility = ['public','protected','internal','private'].find(v => prefixText.includes(v)) || 'private';
    const owners = typeHeaders.filter(type => type.bodyStart < nameToken.start && type.bodyEnd >= tokens[endIndex].end);
    const primaryOwners = owners.filter(type => type.hasPrimary);
    methods.push({ name, start: nameToken.start, end: tokens[endIndex].end, declarationStart, startLine: lineAt(nameToken.start), endLine: lineAt(tokens[endIndex].end), bodyStart: tokens[body].start, bodyEnd: tokens[endIndex].end, parameters, visibility, statements,
      primaryConstructorParameters: primaryOwners.flatMap(type => type.parameters),
      hasPrimaryConstructor: primaryOwners.length > 0,
      primaryConstructorUnsupported: primaryOwners.some(type => type.unsupported) || primaryOwners.length > 0 && owners.length !== 1 });
    i = body;
  }
  return {
    complete: errors.length === 0,
    declarations,
    methods,
    regions: lexed.regions,
    errors,
    coverage: { discoveredMethods: methods.length, parsedMethods: errors.length ? 0 : methods.length, methodRatio: methods.length ? (errors.length ? 0 : 1) : null,
      unsupportedPrimaryConstructors: typeHeaders.filter(type => type.hasPrimary && type.unsupported).length },
  };
}

module.exports = { parseCSharp };
