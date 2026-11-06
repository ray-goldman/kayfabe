'use strict';
const { evaluate } = require('./java-branches');

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
// Class metadata alone may contain literal tokens. Read the comment-stripped
// source at the mask's offsets: masked whitespace is never evidence of a value.
// Ordinary String escapes admitted here are b, t, n, f, r, ", ' and backslash.
// Octal, Unicode preprocessing, text blocks and line continuations stay unknown.
function classHeaderTokens(index, open, budget) {
  if (open > 4000) return null;
  const text = index.code.slice(0, open), mask = index.mask.slice(0, open);
  if (text.length !== mask.length || (budget.left -= text.length) < 0) return null;
  const tokens = [];
  const token = /\s+|[A-Za-z_]\w*|[^\s]/gy;
  for (let at = 0; at < text.length;) {
    if (text[at] === '"') {
      if (mask[at] !== '"' || text.startsWith('"""', at)) return null;
      let end = at + 1;
      for (; end < text.length && text[end] !== '"'; end++) {
        if (text[end] === '\r' || text[end] === '\n' || mask[end] !== ' ') return null;
        if (text[end] === '\\') {
          if (!'btnfr"\'\\'.includes(text[end + 1] || '\0') || mask[++end] !== ' ') return null;
        }
      }
      if (end >= text.length || mask[end] !== '"') return null;
      tokens.push({ kind: 'string' });
      at = end + 1;
    } else {
      token.lastIndex = at;
      const match = token.exec(text);
      if (!match || mask.slice(at, token.lastIndex) !== match[0]) return null;
      if (match[0].trim()) tokens.push(match[0]);
      at = token.lastIndex;
    }
    if (tokens.length > 256) return null;
  }
  return tokens;
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
  const literal = () => tokens[at]?.kind === 'string' && (++at, true);
  function annotationArguments() {
    if (!take('(') || take(')')) return true;
    if (literal()) return !!take(')');
    const elements = new Set();
    do {
      const element = peek();
      if (!identifier(element) || elements.has(element)) return false;
      elements.add(element);
      take(element);
      if (!take('=') || !literal()) return false;
    } while (take(','));
    return !!take(')');
  }
  function modifiers(allowed, { classAnnotations = false } = {}) {
    const found = new Set();
    let annotations = 0;
    while (take('@')) {
      if (++annotations > 16 || !name()) return null;
      if (classAnnotations && !annotationArguments()) return null;
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

function classHeader(index, open, budget) {
  const tokens = classHeaderTokens(index, open, budget);
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
  if (!r.modifiers(new Set(['public', 'final', 'abstract', 'strictfp']), { classAnnotations: true }) ||
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
  if (open < 0 || !classHeader(index, open, budget)) return null;
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
// pure invocation. Only the separately certified local String.charAt atom may
// call a method; all other calls/member/index access and unknown effects fail.
function localBody(index, method, budget, project) {
  const body = index.code.slice(method.start, method.end);
  if (body.length > 50000 || index.code.length !== index.mask.length) return false;
  const tokens = [];
  const token = /\s+|"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)'|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[lL]?|\d+[lL]?|>>>|>>|<<|==|!=|<=|>=|&&|\|\||\+\+|--|[{}();.?:=+\-*/%<>&|^!~]/gy;
  for (let end = 0; end < body.length;) {
    token.lastIndex = end;
    const match = token.exec(body);
    if (!match || tokens.length >= 4096 || --budget.left < 0) return false;
    if (match[0].trim()) tokens.push({ text: match[0], start: method.start + match.index, end: method.start + token.lastIndex });
    end = token.lastIndex;
  }
  const parameters = new Map(method.parameters.map(p => [p.name, { name: p.name, type: p.type, origin: 'parameter' }]));
  if (parameters.size !== method.parameters.length || method.parameters.some(p => !identifier(p.name))) return false;
  const scopes = [parameters];
  const bound = name => scopes.some(scope => scope.has(name));
  const binding = name => scopes.findLast(scope => scope.has(name))?.get(name);
  const bindingType = name => binding(name)?.type;
  const scalar = name => supportedTypes.has(bindingType(name));
  let locals = 0;
  const precedence = new Map([['||', 1], ['&&', 2], ['|', 3], ['^', 4], ['&', 5],
    ['==', 6], ['!=', 6], ['<', 7], ['>', 7], ['<=', 7], ['>=', 7],
    ['<<', 8], ['>>', 8], ['>>>', 8], ['+', 9], ['-', 9], ['*', 10], ['/', 10], ['%', 10]]);
  let at = 0;
  const text = (offset = 0) => tokens[at + offset]?.text;
  const take = value => text() === value && (++at, true);
  const pending = [];
  function expression(min = 0, depth = 0) {
    if (--budget.left < 0 || depth >= 64) return false;
    const atom = tokens[at++], value = atom?.text;
    let reference = false;
    if (['!', '~', '+', '-'].includes(value)) {
      const operand = expression(11, depth + 1);
      if (!operand || operand.reference) return false;
    } else if (value === '(') {
      const inner = expression(0, depth + 1);
      if (!inner || !take(')')) return false;
      reference = inner.reference;
    } else if (scalar(value)) {
      // The spelling String may denote a user type. Copying/comparing its
      // reference is effect-free; implicit conversion may call user toString.
      // Keep the declared uncertainty even after a literal/null assignment.
      reference = bindingType(value) === 'String';
      if (take('.')) {
        const receiver = binding(value), close = tokens[at + 3];
        if (!receiver || receiver.origin !== 'local' || !receiver.root || receiver.type !== 'String' ||
            receiver.literalStart === undefined || receiver.initializedAfter > atom.start ||
            !take('charAt') || !take('(') || !/^(?:0|[1-9][0-9]*)$/.test(text() || '')) return false;
        at++;
        if (!take(')') || --budget.left < 0) return false;
        pending.push({ receiver, start: atom.start, end: close.end });
        reference = false;
      }
    } else if (!/^(?:"|'|\d)/.test(value || '') && !['true', 'false', 'null'].includes(value)) return false;
    while (precedence.has(text()) && precedence.get(text()) >= min) {
      const operator = tokens[at++].text, power = precedence.get(operator);
      const right = expression(power + 1, depth + 1);
      if (!right || (reference || right.reference) && !['==', '!='].includes(operator)) return false;
      reference = false; // Equality compares references without conversion.
    }
    if (min === 0 && take('?')) {
      if (reference) return false;
      const yes = expression(0, depth + 1);
      if (!yes || !take(':')) return false;
      const no = expression(0, depth + 1);
      if (!no) return false;
      reference = yes.reference || no.reference;
    }
    return { reference };
  }
  function statement(depth = 0, inSwitch = false, declarations = true) {
    if (--budget.left < 0 || depth >= 64) return false;
    if (take(';')) return true;
    if (take('{')) {
      scopes.push(new Map());
      while (at < tokens.length && text() !== '}') if (!statement(depth + 1, inSwitch)) return false;
      scopes.pop();
      return !!take('}');
    }
    if (take('if')) {
      if (!take('(')) return false;
      const condition = expression();
      if (!condition || condition.reference || !take(')') || !statement(depth + 1, inSwitch, false)) return false;
      return !take('else') || statement(depth + 1, inSwitch, false);
    }
    if (take('switch')) {
      if (!take('(')) return false;
      const selector = expression();
      if (!selector || selector.reference || !take(')') || !take('{')) return false;
      scopes.push(new Map());
      while (at < tokens.length && text() !== '}') {
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
    if (supportedTypes.has(text())) {
      if (!declarations) return false;
      const type = tokens[at++].text;
      const nameToken = tokens[at++], name = nameToken?.text;
      if (!identifier(name) || bound(name) || ++locals > 64) return false;
      // No forward/self binding; the local exists only after its initializer.
      const initialized = take('='), begin = at;
      if (initialized && !expression()) return false;
      const literal = initialized && at === begin + 1 && /^"/.test(tokens[begin].text) ? tokens[begin] : null;
      const semicolon = tokens[at];
      if (!take(';')) return false;
      const scope = scopes[scopes.length - 1];
      scope.set(name, { name, type, origin: 'local', scope, declaration: nameToken.start,
        root: scopes.length === 1 && depth === 0, initializedAfter: semicolon.end,
        literalStart: literal?.start, literalEnd: literal?.end, writes: 0 });
      return true;
    }
    const assigned = binding(tokens[at++]?.text);
    if (final || !supportedTypes.has(assigned?.type) || !take('=')) return false;
    assigned.writes++;
    return expression() && !!take(';');
  }
  while (at < tokens.length) if (!statement()) return false;
  // All arms and even statements after return have now contributed writes.
  // Certificates remain local to this invocation and never grant return facts.
  let intrinsicLeft = 512, canonical;
  function intrinsic(source, resolve) {
    const allowance = Math.min(intrinsicLeft, budget.left);
    if (allowance <= 0) return null;
    const meter = { left: allowance }, result = evaluate(source, resolve, meter);
    const spent = allowance - meter.left;
    intrinsicLeft -= spent;
    budget.left -= spent;
    return meter.left < 0 || intrinsicLeft < 0 || budget.left < 0 ? null : result;
  }
  for (const use of pending) {
    if (--budget.left < 0 || use.receiver.writes) return false;
    canonical ??= canonicalStringScope({ index, position: use.start, project, budget });
    if (!canonical) return false;
    const receiver = use.receiver;
    if (!receiver.decoded) {
      receiver.decoded = intrinsic(index.code.slice(receiver.literalStart, receiver.literalEnd), () => null);
      if (receiver.decoded?.type !== 'String') return false;
    }
    // Decimal syntax alone does not establish int range; the existing evaluator
    // supplies the int type/range and exact UTF-16 charAt bounds on this slice.
    const result = intrinsic(index.code.slice(use.start, use.end), name => name === receiver.name ? receiver.decoded : null);
    if (result?.type !== 'char') return false;
  }
  return true;
}

function independentReturnEligible({ index, target, method, call, position, filter, budget, project }) {
  if (target.index !== index || !method.private || !filter) return false;
  // A dotted owner may resolve through an imported type/value rather than the
  // apparent package. Added opaque proofs accept only local owner syntax.
  if (call.owner && call.owner !== 'this' && call.owner !== index.className) return false;
  // Static imports can expose a value with the same spelling as our class.
  if (call.owner === index.className && /\bimport\s+static\b/.test(index.mask)) return false;
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
  return localBody(index, method, budget, project);
}

// Nominal ownership is required only by new String intrinsic/copy consumers.
// Existing helper summaries keep their original header eligibility unchanged.
function canonicalStringScope({ index, position, project, budget }) {
  if (!index?.complete || !project?.complete || !budget || !Number.isFinite(budget.left) || budget.left <= 0) return false;
  const caller = index.at(position);
  if (!caller || !callerHeader(index, caller, budget)) return false;
  const tokens = classHeaderTokens(index, index.mask.indexOf('{'), budget);
  if (!tokens) return false;
  const r = headerReader(tokens), imports = new Map();
  let packageName = '';
  if (r.take('package')) {
    packageName = r.name();
    if (!packageName || !r.take(';')) return false;
  }
  // The new reader normalizes dotted names, but legacy inventory keys do not.
  // Decline this certificate rather than search a different package's types.
  if (packageName !== index.package) return false;
  while (r.take('import')) {
    // Unknown classpaths, member-type imports and malformed declarations cannot
    // establish that an unqualified String denotes java.lang.String.
    const name = r.name();
    if (!name || !name.includes('.') || !r.take(';')) return false;
    const short = name.split('.').pop();
    if (imports.has(short) || short === 'String' && name !== 'java.lang.String' || short === 'java') return false;
    imports.set(short, name);
  }
  if (!r.modifiers(new Set(['public', 'final', 'abstract', 'strictfp']), { classAnnotations: true }) ||
      !r.take('class') || !r.take(index.className)) return false;
  const parent = r.take('extends') ? r.name() : null;
  // Nongeneric headers with no interfaces exclude inherited unknown member
  // types; the bounded caller reader also excludes method type variables.
  if (!r.done()) return false;
  const sourceType = name => project.classes.has(name) ||
    project.classes.has([packageName, name].filter(Boolean).join('.'));
  if (sourceType('String') || sourceType('java') || project.classes.has('java.lang.String')) return false;
  // Fresh response output needs no servlet superclass. Its qualified response
  // spelling can still resolve through a source/imported namespace type, so
  // certify these roots before implicit or explicit Object can return success.
  if (['javax', 'jakarta'].some(root => sourceType(root) || imports.has(root))) return false;
  if (!parent) return !project.classes.has('java.lang.Object');
  if (!parent.includes('.') && sourceType(parent)) return false;
  const qualified = parent.includes('.') ? parent : imports.get(parent) || (parent === 'Object' ? 'java.lang.Object' : null);
  const root = qualified?.split('.')[0];
  // A dotted framework spelling can instead name members of a source/imported
  // root type. Exact full-name absence alone cannot establish package ownership.
  return ['java.lang.Object', 'javax.servlet.http.HttpServlet', 'jakarta.servlet.http.HttpServlet'].includes(qualified) &&
    !sourceType(root) && !imports.has(root) && !project.classes.has(qualified);
}

module.exports = { independentReturnEligible, canonicalStringScope };
