'use strict';

// This grammar belongs only to the opaque-reference route. Existing supported
// summaries deliberately retain their original eligibility and budgets.
const supportedTypes = new Set(['String', 'int', 'boolean', 'char', 'long']);
const primitiveTypes = new Set(['byte', 'short', 'int', 'long', 'float', 'double', 'boolean', 'char', 'void']);
const keywords = new Set(('abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null record sealed permits var yield').split(' '));
const identifier = value => /^[A-Za-z_]\w*$/.test(value || '') && !keywords.has(value);
function referenceType(type) {
  return typeof type === 'string' && !primitiveTypes.has(type) && type.split('.').every(identifier);
}

function headerTokens(text) {
  if (text.length > 4000) return null;
  const tokens = text.match(/[A-Za-z_]\w*|[^\s]/g) || [];
  return tokens.length <= 256 ? tokens : null;
}
function headerReader(tokens) {
  let at = 0;
  const peek = () => tokens[at];
  const take = value => tokens[at] === value && (++at, true);
  function name() {
    if (!identifier(peek())) return null;
    let result = tokens[at++];
    while (take('.')) {
      if (!identifier(peek())) return null;
      result += '.' + tokens[at++];
    }
    return result;
  }
  function modifiers(allowed) {
    const found = new Set();
    let annotations = 0;
    while (take('@')) {
      if (++annotations > 16 || !name()) return null;
    }
    // Only leading declaration markers are understood. An annotation after a
    // modifier can be a return-type annotation and stays outside this grammar.
    while (allowed.has(peek())) {
      const modifier = tokens[at++];
      if (found.has(modifier)) return null;
      found.add(modifier);
    }
    if (['public', 'protected', 'private'].filter(value => found.has(value)).length > 1) return null;
    return found;
  }
  return { peek, take, name, modifiers, done: () => at === tokens.length };
}

function classHeader(index, open) {
  const tokens = headerTokens(index.mask.slice(0, open));
  if (!tokens) return false;
  const r = headerReader(tokens);
  if (r.take('package') && (!r.name() || !r.take(';'))) return false;
  while (r.take('import')) {
    r.take('static');
    // Imports may have a wildcard; they establish no new type equivalence.
    let parts = 0;
    if (!identifier(r.peek())) return false;
    r.take(r.peek());
    while (r.take('.')) {
      if (++parts > 32) return false;
      if (r.take('*')) break;
      if (!identifier(r.peek())) return false;
      r.take(r.peek());
    }
    if (!r.take(';')) return false;
  }
  if (!r.modifiers(new Set(['public', 'final', 'abstract', 'strictfp'])) ||
      !r.take('class') || !r.take(index.className)) return false;
  if (r.take('extends') && !r.name()) return false;
  if (r.take('implements')) {
    do { if (!r.name()) return false; } while (r.take(','));
  }
  return r.done();
}

// Locate the member header without treating annotation-array braces as method
// boundaries. The index's single-class and balanced-body checks still apply.
function callerHeader(index, caller, budget) {
  const open = index.mask.indexOf('{');
  if (open < 0 || !classHeader(index, open)) return null;
  let start = open + 1, braces = 1;
  const delimiters = [];
  let header = null;
  for (let i = open + 1; i < caller.start; i++) {
    if (i % 64 === 0 && --budget.left < 0) return null;
    const c = index.mask[i];
    if (c === '(' || c === '[') {
      if (delimiters.length >= 64) return null;
      delimiters.push(c);
    } else if (c === ')' || c === ']') {
      if (delimiters.pop() !== (c === ')' ? '(' : '[')) return null;
    } else if (c === '{') {
      if (braces === 1 && !delimiters.length && i === caller.start - 1) header = index.mask.slice(start, i);
      braces++;
    } else if (c === '}') {
      if (--braces < 1) return null;
      if (braces === 1 && !delimiters.length) start = i + 1;
    } else if (c === ';' && braces === 1 && !delimiters.length) start = i + 1;
  }
  if (!header || braces !== 2 || delimiters.length) return null;
  const tokens = headerTokens(header);
  if (!tokens) return null;
  const r = headerReader(tokens);
  const modifiers = r.modifiers(new Set(['public', 'private', 'protected', 'static', 'final', 'synchronized', 'strictfp']));
  if (!modifiers || !r.take(caller.type) || !r.take(caller.name) || !r.take('(')) return null;
  const parameters = [];
  if (!r.take(')')) {
    do {
      r.take('final');
      let type;
      if (primitiveTypes.has(r.peek()) && r.peek() !== 'void') { type = r.peek(); r.take(type); }
      else type = r.name();
      const name = r.peek();
      if (!type || !identifier(name) || parameters.length >= 16 || parameters.some(p => p.name === name)) return null;
      r.take(name);
      parameters.push({ type, name });
    } while (r.take(','));
    if (!r.take(')')) return null;
  }
  if (r.take('throws')) {
    do { if (!r.name()) return null; } while (r.take(','));
  }
  if (!r.done() || parameters.length !== caller.parameters.length ||
      parameters.some((p, i) => p.name !== caller.parameters[i]?.name || p.type !== caller.parameters[i]?.type)) return null;
  return { parameters, static: modifiers.has('static') };
}

// Recognize an effect-free subset rather than assume a constant return means a
// pure invocation. Calls, member/index access, allocation and unknown syntax all
// fail. This also protects constant-mode consumers of HTML output facts.
function localBody(index, method, budget) {
  const body = index.code.slice(method.start, method.end);
  if (body.length > 50000) return false;
  const tokens = [];
  const token = /\s+|"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)'|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[lL]?|\d+[lL]?|>>>|>>|<<|==|!=|<=|>=|&&|\|\||\+\+|--|[{}();?:=+\-*/%<>&|^!~]/gy;
  for (let end = 0; end < body.length;) {
    token.lastIndex = end;
    const match = token.exec(body);
    if (!match || tokens.length >= 4096 || --budget.left < 0) return false;
    if (match[0].trim()) tokens.push(match[0]);
    end = token.lastIndex;
  }
  const parameters = new Map(method.parameters.map(p => [p.name, p.type]));
  if (parameters.size !== method.parameters.length || method.parameters.some(p => !identifier(p.name))) return false;
  const scopes = [parameters];
  const bound = name => scopes.some(scope => scope.has(name));
  const scalar = name => supportedTypes.has(scopes.findLast(scope => scope.has(name))?.get(name));
  let locals = 0;
  const precedence = new Map([['||', 1], ['&&', 2], ['|', 3], ['^', 4], ['&', 5],
    ['==', 6], ['!=', 6], ['<', 7], ['>', 7], ['<=', 7], ['>=', 7],
    ['<<', 8], ['>>', 8], ['>>>', 8], ['+', 9], ['-', 9], ['*', 10], ['/', 10], ['%', 10]]);
  let at = 0;
  const take = value => tokens[at] === value && (++at, true);
  function expression(min = 0, depth = 0) {
    if (--budget.left < 0 || depth >= 64) return false;
    const value = tokens[at++];
    if (['!', '~', '+', '-'].includes(value)) {
      if (!expression(11, depth + 1)) return false;
    } else if (value === '(') {
      if (!expression(0, depth + 1) || !take(')')) return false;
    } else if (!(scalar(value) || /^(?:"|'|\d)/.test(value || '') || ['true', 'false', 'null'].includes(value))) return false;
    while (precedence.has(tokens[at]) && precedence.get(tokens[at]) >= min) {
      const power = precedence.get(tokens[at++]);
      if (!expression(power + 1, depth + 1)) return false;
    }
    if (min === 0 && take('?') && (!expression(0, depth + 1) || !take(':') || !expression(0, depth + 1))) return false;
    return true;
  }
  function statement(depth = 0, inSwitch = false, declarations = true) {
    if (--budget.left < 0 || depth >= 64) return false;
    if (take(';')) return true;
    if (take('{')) {
      scopes.push(new Map());
      while (at < tokens.length && tokens[at] !== '}') if (!statement(depth + 1, inSwitch)) return false;
      scopes.pop();
      return !!take('}');
    }
    if (take('if')) {
      if (!take('(') || !expression() || !take(')') || !statement(depth + 1, inSwitch, false)) return false;
      return !take('else') || statement(depth + 1, inSwitch, false);
    }
    if (take('switch')) {
      if (!take('(') || !expression() || !take(')') || !take('{')) return false;
      scopes.push(new Map());
      while (at < tokens.length && tokens[at] !== '}') {
        if (take('case')) { if (!expression() || !take(':')) return false; }
        else if (take('default')) { if (!take(':')) return false; }
        else if (!statement(depth + 1, true)) return false;
      }
      scopes.pop();
      return !!take('}');
    }
    if (take('break')) return inSwitch && !!take(';');
    if (take('return')) return expression() && !!take(';');
    const final = take('final');
    if (supportedTypes.has(tokens[at])) {
      if (!declarations) return false;
      const type = tokens[at++];
      const name = tokens[at++];
      if (!identifier(name) || bound(name) || ++locals > 64) return false;
      // No forward/self binding; the local exists only after its initializer.
      if (take('=') && !expression()) return false;
      scopes[scopes.length - 1].set(name, type);
      return !!take(';');
    }
    if (final || !scalar(tokens[at++]) || !take('=')) return false;
    return expression() && !!take(';');
  }
  while (at < tokens.length) if (!statement()) return false;
  return true;
}

function independentReturnEligible({ index, target, method, call, position, filter, budget }) {
  if (target.index !== index || !method.private || !filter) return false;
  const caller = index.at(position);
  const header = caller && callerHeader(index, caller, budget);
  if (!header || header.static && (!method.static || call.owner === 'this') ||
      call.owner && call.owner !== 'this' && !method.static) return false;
  for (let i = 0; i < method.parameters.length; i++) {
    const parameter = method.parameters[i], argument = call.args[i].trim();
    if (supportedTypes.has(parameter.type)) {
      // typeAt resolves lexical locals/formals and validates exact literal
      // types; bare bindings may intentionally carry untrusted values.
      if (!identifier(argument) && !/^(?:"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)'|true|false|[0-9]+[lL]?)$/.test(argument)) return false;
    } else {
      if (!referenceType(parameter.type) || !identifier(argument) ||
          header.parameters.filter(p => p.name === argument && p.type === parameter.type).length !== 1) return false;
    }
    if (filter.typeAt(argument, position) !== parameter.type) return false;
  }
  return localBody(index, method, budget);
}

module.exports = { independentReturnEligible };
