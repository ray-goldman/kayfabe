'use strict';

const { buildDotnetProjectIndex } = require('./dotnet/project-index');
const { tokenizeCSharp } = require('./parsers/csharp/lexer');
const { parenthesizedMutationTokens } = require('./csharp-mutations');
const { hasQueryBindings, hasUnsupportedIdentifierSpelling } = require('./csharp-binding-guards');
const SCALARS = new Set(['string', 'char', 'int', 'long', 'short', 'byte', 'bool', 'float', 'double', 'decimal']);
const RESERVED = new Set(('abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while').split(' '));
const MAX_QUERY_WORK = 65536;
const id = token => token?.text.replace(/^@/, '');
const identifier = token => token?.kind === 'identifier' && (token.text.startsWith('@') || !RESERVED.has(token.text));

// One context belongs to one value query, including every recursive alternative.
// Charging expressions, bindings and call-site scans bounds branching expansion;
// a new helper invocation must never receive a fresh budget.
function charge(context, amount = 1) {
  context.remaining -= amount;
  return context.remaining >= 0;
}

function split(tokens, separator) {
  const result = []; let start = 0, depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    if (['(', '[', '{'].includes(tokens[i].text)) depth++;
    else if ([')', ']', '}'].includes(tokens[i].text)) depth--;
    else if (!depth && tokens[i].text === separator) { result.push(tokens.slice(start, i)); start = i + 1; }
  }
  result.push(tokens.slice(start));
  return result;
}

// An invalid label (such as a missing name) must not fall through to the
// positional path, where an unused actual is not necessarily expanded.
function argumentLabel(tokens) {
  let depth = 0, required = 0, possible = 0, label = false;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (['(', '[', '{'].includes(token.text)) depth++;
    else if ([')', ']', '}'].includes(token.text)) depth--;
    else if (!depth && token.text === '?') {
      // ? [ can be null-conditional indexing or a ternary collection arm.
      // Track the interval of possible pending counts, without binding types or
      // selecting a value. Ordinary ternaries are mandatory in every reading.
      if (tokens[i + 1]?.text !== '[') required++;
      possible++;
    }
    else if (!depth && token.text === ':') {
      if (possible) {
        possible--;
        required = Math.max(0, required - 1);
      }
      else label = true;
    }
  }
  // A matched ternary colon is not a label. Keep examining the rest of the
  // actual: an extra colon or unmatched question must not enter positional proof.
  return label || required > 0;
}

// This proof deliberately accepts a small subset. All syntactic writes count,
// including branches not selected by the current caller or build configuration.
function createCSharpValueProof(code, ast, { strictBindings = false } = {}) {
  const lex = tokenizeCSharp(code);
  if (!ast.complete || lex.errors.length || lex.tokens.length > 20000) return () => false;
  const tokens = lex.tokens, pairs = new Map(), stack = [];
  // Check the complete file for strict contexts: a field writer or recursive
  // helper can change a binding under a spelling outside the selected method.
  const unsupportedIdentity = (strictBindings || ast.methods.some(method => method.hasPrimaryConstructor)) &&
    hasUnsupportedIdentifierSpelling(code, tokens);
  if (strictBindings && unsupportedIdentity) return () => false;
  const positions = new Map(tokens.map((token, i) => [token.start, i]));
  for (let i = 0; i < tokens.length; i++) {
    if (['(', '[', '{'].includes(tokens[i].text)) stack.push(i);
    else if ([')', ']', '}'].includes(tokens[i].text)) {
      const open = stack.pop(); pairs.set(open, i); pairs.set(i, open);
    }
  }
  const index = buildDotnetProjectIndex([{ file: 'proof.cs', source: code, ast }]);
  // Partial, nested and multiple types need a project-wide ownership proof.
  if (index.types.length !== 1 || index.types[0].partial || index.methods.length > 256 || index.diagnostics.truncated) return () => false;
  const owner = index.types[0], methods = index.methods;
  // An exact keyword alias avoids guessing what an imported String denotes.
  // Keep its scope closed: namespaces, bases and generic owners can shadow it.
  const stringAliases = tokens.filter((t,i) => t.text === 'using' && id(tokens[i+1]) === 'String' && tokens[i+2]?.text === '=');
  const aliasIndex = stringAliases.length === 1 ? positions.get(stringAliases[0].start) : -1;
  const ownerStart = positions.get(owner.declarations[0]?.start);
  const ownerOpen = ownerStart === undefined ? -1 : tokens.findIndex((t,i) => i > ownerStart && t.text === '{');
  // The project index can omit unsupported base names; inspect the raw header.
  const closedOwner = ownerOpen > ownerStart && !tokens.slice(ownerStart, ownerOpen).some(t => t.text === ':');
  const keywordStringAlias = aliasIndex >= 0 && tokens[aliasIndex+3]?.text === 'string' && tokens[aliasIndex+4]?.text === ';' &&
    closedOwner && !tokens.some(t => ['namespace', '<'].includes(t.text));
  const scalar = type => SCALARS.has(type) || type === 'String' && keywordStringAlias;
  const models = new Map(), fields = new Map();
  for (const field of owner.fields) {
    const position = tokens.findIndex((token, i) => id(token) === field.name && tokens[i + 1]?.text === ';');
    if (position < 0 || !scalar(field.type)) continue;
    let start = position - 1;
    while (start >= 0 && ![';', '{', '}'].includes(tokens[start].text)) start--;
    const prefix = tokens.slice(start + 1, position).map(t => t.text);
    if (!prefix.includes('private') || prefix.includes('volatile')) continue;
    fields.set(field.name, { key: 'field:' + field.name, name: field.name, declaration:tokens[position].start, field: true, writes: [], invalid: false });
  }
  function buildModel(method) {
    if (models.has(method.id)) return models.get(method.id);
    const ts = tokens.filter(t => t.start > method.bodyStart && t.end < method.bodyEnd);
    const root = { parent: null, bindings: new Map() }, scopes = new Map(), allBindings = [], parameterBindings = [];
    for (const parameter of method.primaryConstructorParameters || []) {
      const binding = { key: method.id + ':primary:' + parameter.name, name: parameter.name, writes: [], invalid: true };
      root.bindings.set(parameter.name, binding); allBindings.push(binding);
    }
    for (const [n, parameter] of method.parameters.entries()) {
      const binding = { key: method.id + ':param:' + n, name: parameter.name, parameter: n, method, writes: [], invalid: false };
      root.bindings.set(parameter.name, binding); allBindings.push(binding);
      parameterBindings.push(binding);
    }
    let scope = root;
    const shadowedFields = new Set(ts.filter((t, i) => fields.has(id(t)) && ts[i - 1]?.kind === 'identifier' &&
      !['return','throw','await','yield'].includes(ts[i - 1].text) && !['=',';'].includes(ts[i + 1]?.text)).map(id));
    for (let i=0;i<ts.length;i++) if(ts[i].text==='catch'&&ts[i+1]?.text==='(') {
      const close=pairs.get(positions.get(ts[i+1].start)),name=close===undefined?null:id(tokens[close-1]);
      if(fields.has(name))shadowedFields.add(name);
    }
    for(const name of shadowedFields)fields.get(name).invalid=true;
    const strict = strictBindings || method.hasPrimaryConstructor;
    const wrappedWrites = strict ? parenthesizedMutationTokens(ts) : [];
    const invalid = !wrappedWrites || strict && (unsupportedIdentity || hasQueryBindings(ts, method)) || method.primaryConstructorUnsupported || method.end - method.start > 50000 || ts.some((t, i) => t.kind === 'interpolated-string' ||
      ['=>', 'ref', 'out', 'foreach', 'fixed', 'unsafe', 'goto', 'is', 'switch'].includes(t.text) ||
      t.text === '(' && pairs.has(positions.get(t.start)) && tokens[pairs.get(positions.get(t.start)) + 1]?.text === '{' &&
      !['if','while','for','switch','catch','using','lock'].includes(ts[i - 1]?.text));
    for (let i = 0; i < ts.length; i++) {
      const token = ts[i];
      if (token.text === '{') scope = { parent: scope, bindings: new Map() };
      scopes.set(token.start, scope);
      const previous=ts[i-1];
      const declaration=previous?.kind==='identifier'&&!['return','throw','await','yield'].includes(previous.text)||['>','?',']'].includes(previous?.text);
      if (token.kind === 'identifier' && declaration && ['=', ';'].includes(ts[i + 1]?.text)) {
        const name = id(token), duplicate = scope.bindings.has(name);
        const binding = { key: method.id + ':' + token.start, name, writes: [], invalid: duplicate || !scalar(previous.text) };
        if (duplicate) scope.bindings.get(name).invalid = true;
        scope.bindings.set(name, binding); allBindings.push(binding);
      }
      if (token.text === '}') scope = scope.parent || root;
    }
    function bindingAt(token) {
      const offset = positions.get(token.start), previous = tokens[offset - 1];
      if (previous?.text === '.') {
        if (tokens[offset - 2]?.text === 'this') return fields.get(id(token));
        return null;
      }
      let current = scopes.get(token.start);
      while (current) { if (current.bindings.has(id(token))) return current.bindings.get(id(token)); current = current.parent; }
      return shadowedFields.has(id(token)) ? null : fields.get(id(token));
    }
    const model = { method, ts, invalid, bindingAt, parameterBindings, returns: [] };
    models.set(method.id, model);
    for (const token of wrappedWrites || []) {
      const binding = bindingAt(token);
      if (binding) binding.invalid = true;
    }
    for (const token of ts) {
      const open = positions.get(token.start), close = pairs.get(open);
      if (token.text !== '(' || tokens[close + 1]?.text !== '=') continue;
      for (const item of tokens.slice(open + 1, close)) {
        const binding = item.kind === 'identifier' && bindingAt(item);
        if (binding) binding.invalid = true;
      }
    }
    for (let i = 0; i < ts.length; i++) {
      const token = ts[i];
      if (token.kind !== 'identifier') continue;
      const binding = bindingAt(token);
      if (binding && (['++','--','+=','-=','*=','/=','%=','??='].includes(ts[i + 1]?.text) ||
          ['++','--','ref','out'].includes(ts[i - 1]?.text) ||
          strict && ['<<','>>'].includes(ts[i + 1]?.text) && ts[i + 2]?.text === '=' ||
          ['&','|','^','%','<','>'].includes(ts[i + 1]?.text) && ts[i + 2]?.text === '=')) binding.invalid = true;
      if (binding && ts[i + 1]?.text === '=') {
        if (binding.parameter !== undefined) binding.invalid = true;
        let end = i + 2, depth = 0;
        for (; end < ts.length; end++) {
          const text = ts[end].text;
          if (['(', '[', '{'].includes(text)) depth++;
          else if ([')', ']', '}'].includes(text)) { if (!depth) break; depth--; }
          else if (text === ';' && !depth) break;
        }
        if (ts[end]?.text !== ';') binding.invalid = true;
        else binding.writes.push({ expression: ts.slice(i + 2, end), model });
      }
      if (token.text === 'return') {
        let end = i + 1;
        while (end < ts.length && ts[end].text !== ';') end++;
        model.returns.push(ts.slice(i + 1, end));
      }
    }
    // An unsupported body can write a private field through syntax we don't model.
    if (invalid) for (const field of fields.values()) field.invalid = true;
    return model;
  }
  for (const method of methods) buildModel(method);
  const modelAt = token => token && [...models.values()].find(m => token.start > m.method.bodyStart && token.end < m.method.bodyEnd);
  for (const field of fields.values()) {
    // Explicit member access through any receiver other than this is unresolved.
    if (tokens.some((t, i) => id(t) === field.name && tokens[i - 1]?.text === '.' && tokens[i - 2]?.text !== 'this')) field.invalid = true;
    if (tokens.some(t => id(t) === field.name && t.start !== field.declaration && !modelAt(t))) field.invalid = true;
    if (tokens.some(t => t.kind === 'interpolated-string' || ['GetField','GetFields','SetValue','DynamicInvoke'].includes(t.text))) field.invalid = true;
  }
  const targets = name => methods.filter(m => m.name === name);
  const shadowedName = name => methods.some(method => [...method.parameters, ...(method.primaryConstructorParameters || [])].some(parameter => parameter.name === name)) ||
    tokens.some((t, i) => id(t) === name && tokens[i - 1]?.text !== '.' && ['=', ';'].includes(tokens[i + 1]?.text));
  function helper(name) {
    const matches = targets(name);
    if (matches.length !== 1 || matches[0].unsupported || matches[0].ambiguous || matches[0].visibility !== 'private') return null;
    // A same-spelled local/delegate makes ownership uncertain.
    if (shadowedName(name)) return null;
    return models.get(matches[0].id);
  }
  // This is deliberately separate from the legacy all-callers parameter proof.
  // Every actual is an exact built-in string literal, even if it is not returned:
  // no ignored conversion, getter, call or condition may execute along this path.
  function proveNamed(args, callee, caller, prefix, visiting, depth, context) {
    if (!charge(context, callee.ts.length + caller.ts.length + args.length + ownerOpen - ownerStart) || callee.invalid || !callee.method.static ||
        prefix.length === 3 && (!closedOwner || prefix[0].text === 'this') ||
        caller.ts.some((t, i) => ['catch', 'delegate', 'from'].includes(t.text) ||
          id(t) === callee.method.name && caller.ts[i + 1]?.text !== '(' ||
          prefix.length === 3 && id(t) === id(prefix[0]) && caller.ts[i + 1]?.text !== '.')) return false;
    const nameIndex = positions.get(callee.method.start);
    let start = nameIndex - 1;
    while (start >= 0 && ![';', '{', '}'].includes(tokens[start].text)) start--;
    const declaration = tokens.slice(start + 1, nameIndex).map(t => t.text);
    if (declaration.length !== 3 || declaration[2] !== 'string' ||
        !declaration.slice(0, 2).includes('private') || !declaration.slice(0, 2).includes('static')) return false;
    if (!identifier(tokens[nameIndex]) || prefix.length === 3 && !identifier(prefix[0])) return false;
    // A qualified type spelling needs a closed owner: an unknown inherited field
    // or getter can supply that receiver. For unqualified calls, exact string
    // identity conversions make the known private member applicable at this owner.
    // No framework/base spelling establishes member or receiver identity.
    if (tokens.slice(ownerStart, ownerOpen).some(t => t.text === '<')) return false;
    const open = nameIndex + 1, close = pairs.get(open);
    if (tokens[open]?.text !== '(' || tokens[close + 1]?.start !== callee.method.bodyStart) return false;
    const parameters = split(tokens.slice(open + 1, close), ',');
    if (parameters.length !== args.length || parameters.length !== callee.parameterBindings.length) return false;
    const byName = new Map();
    for (let n = 0; n < parameters.length; n++) {
      const part = parameters[n], binding = callee.parameterBindings[n];
      if (part.length !== 2 || part[0].text !== 'string' || !identifier(part[1]) ||
          byName.has(id(part[1])) || binding.invalid || binding.writes.length ||
          binding.name !== id(part[1]) || callee.method.parameterTypes[n] !== 'string') return false;
      byName.set(binding.name, binding);
    }
    const frame = new Map();
    for (const arg of args) {
      if (!charge(context, arg.length) || arg.length !== 3 || !identifier(arg[0]) || arg[1].text !== ':' ||
          arg[2].kind !== 'string' || arg[2].text.endsWith('u8')) return false;
      const binding = byName.get(id(arg[0]));
      if (!binding || frame.has(binding.key)) return false;
      frame.set(binding.key, { expression: arg.slice(2), model: caller });
    }
    const body = callee.ts;
    if (body.length !== 3 || body[0].text !== 'return' || !identifier(body[1]) || body[2].text !== ';') return false;
    const returned = callee.bindingAt(body[1]);
    if (!returned || returned.invalid || returned.parameter === undefined || returned.writes.length) return false;
    const actual = frame.get(returned.key);
    return !!actual && prove(actual.expression, actual.model, visiting, depth + 1, context);
  }
  function proveBinding(binding, visiting, depth, context) {
    if (!charge(context) || !binding || binding.invalid || visiting.has(binding.key)) return false;
    const next = new Set(visiting); next.add(binding.key);
    if (binding.parameter !== undefined) {
      if (!scalar(binding.method.parameterTypes[binding.parameter])) return false;
      const target = helper(binding.method.name);
      if (!target) return false;
      let sites = 0;
      for (let i = 0; i < tokens.length; i++) {
        if (!charge(context)) return false;
        if (id(tokens[i]) !== target.method.name || tokens[i].start === target.method.start) continue;
        if (tokens[i + 1]?.text !== '(' || !pairs.has(i + 1) ||
            tokens[i - 1]?.text === '.' && !['this', owner.name].includes(id(tokens[i - 2]))) return false;
        if (tokens[i - 1]?.text === '.' && id(tokens[i - 2]) === owner.name && shadowedName(owner.name)) return false;
        const caller = modelAt(tokens[i]);
        if (!caller || caller.invalid) return false;
        const args = split(tokens.slice(i + 2, pairs.get(i + 1)), ',');
        if (args.length !== target.method.arity || args.some(arg => !arg.length || argumentLabel(arg)) || !prove(args[binding.parameter], caller, next, depth + 1, context)) return false;
        sites++;
      }
      return sites > 0;
    }
    return (binding.field || binding.writes.length > 0) && binding.writes.every(write => charge(context) && !write.model.invalid && prove(write.expression, write.model, next, depth + 1, context));
  }
  function prove(expression, model, visiting, depth, context) {
    if (!charge(context, 1 + (expression?.length || 0)) || !model || model.invalid || !expression?.length || expression.length > 256 || depth > 24) return false;
    while (expression[0]?.text === '(' && expression.at(-1)?.text === ')' &&
        pairs.get(positions.get(expression[0].start)) === positions.get(expression.at(-1).start)) expression = expression.slice(1, -1);
    // The condition may be unknown; both possible values must be proved safe.
    let level = 0, question = -1, nested = 0;
    for (let i = 0; i < expression.length; i++) {
      const text = expression[i].text;
      if (['(', '[', '{'].includes(text)) level++;
      else if ([')', ']', '}'].includes(text)) level--;
      else if (!level && text === '?') { if (question < 0) question = i; else nested++; }
      else if (!level && text === ':' && question >= 0) {
        if (nested) { nested--; continue; }
        return question > 0 && prove(expression.slice(question + 1, i), model, visiting, depth + 1, context) &&
          prove(expression.slice(i + 1), model, visiting, depth + 1, context);
      }
    }
    if (question >= 0) return false;
    const coalesced = split(expression, '??');
    if (coalesced.length > 1) return coalesced.every(part => prove(part, model, visiting, depth + 1, context));
    const parts = split(expression, '+');
    if (parts.length > 1) return parts.every(part => prove(part, model, visiting, depth + 1, context));
    if (expression.length === 1) {
      const token = expression[0];
      if (['string','char','number'].includes(token.kind) || ['true','false','null'].includes(token.text)) return true;
      return token.kind === 'identifier' && proveBinding(model.bindingAt(token), visiting, depth + 1, context);
    }
    if (expression.length === 3 && expression[0].text === 'this' && expression[1].text === '.') return proveBinding(fields.get(id(expression[2])), visiting, depth + 1, context);
    let open = expression.findIndex(t => t.text === '(');
    if (open < 1 || pairs.get(positions.get(expression[open].start)) !== positions.get(expression.at(-1).start)) return false;
    const prefix = expression.slice(0, open);
    if (!(prefix.length === 1 || prefix.length === 3 && prefix[1].text === '.' && ['this', owner.name].includes(id(prefix[0])))) return false;
    if (prefix.length === 3 && id(prefix[0]) !== 'this' && shadowedName(id(prefix[0]))) return false;
    const callee = helper(id(prefix.at(-1)));
    const args = expression.length === open + 2 ? [] : split(expression.slice(open + 1, -1), ',');
    if (!charge(context) || !callee || callee.method.arity !== args.length || args.some(arg => !arg.length) || !callee.returns.length || visiting.has(callee.method.id)) return false;
    const nameIndex=positions.get(callee.method.start);
    if (!scalar(tokens[nameIndex-1]?.text)) return false;
    const next = new Set(visiting); next.add(callee.method.id);
    if (args.some(argumentLabel)) return proveNamed(args, callee, model, prefix, next, depth + 1, context);
    return callee.returns.every(result => charge(context) && prove(result, callee, next, depth + 1, context));
  }
  return expression => prove(expression, modelAt(expression?.[0]), new Set(), 0, { remaining: MAX_QUERY_WORK });
}

module.exports = { createCSharpValueProof };

