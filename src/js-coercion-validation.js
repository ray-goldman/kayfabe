'use strict';
// Bounded, positive-evidence check. Unsupported syntax yields no new finding.
const { maskStrings } = require('./languages');
const path = require('node:path');
const ID = '[A-Za-z_$][\\w$]*';
const ident = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function matching(text, open, left, right) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === left) depth++;
    if (text[i] === right && --depth === 0) return i;
  }
  return -1;
}

function functions(file) {
  const code = file.code;
  if (code.length > 120000 || /\\u[0-9a-fA-F]{4}/.test(code)) return [];
  const mask = maskStrings(code, file.lang);
  const result = [];
  const re = new RegExp('\\bfunction\\s+(' + ID + ')\\s*\\(', 'g');
  for (const m of mask.matchAll(re)) {
    const paren = mask.indexOf('(', m.index), end = matching(mask, paren, '(', ')');
    if (end < 0 || end - paren > 600) continue;
    const brace = mask.indexOf('{', end + 1);
    if (brace < 0 || brace - end > 120) continue;
    const close = matching(mask, brace, '{', '}');
    if (close < 0 || close - brace > 16000) continue;
    const params = code.slice(paren + 1, end);
    if (/[(){}]/.test(params.replace(/=\s*new\s+Date\s*\(\s*\)/g, ''))) continue;
    result.push({ name: m[1], file: file.rel, params, body: code.slice(brace + 1, close), start: brace + 1,
      code, mask: mask.slice(brace + 1, close) });
    if (result.length > 250) break;
  }
  return result;
}

function acceptsMissing(validator, name) {
  const n = ident(name);
  // Only certify the complete, simple validator shape. Extra branches abstain.
  const shape = new RegExp('^\\s*if\\s*\\(\\s*typeof\\s+' + n + '\\s*!==\\s*[\'\"]string[\'\"]\\s*\\|\\|\\s*!\\s*/(\\^[^/\\n]{1,100}\\$)/([i]?)\\s*\\.test\\(\\s*' + n + '\\s*\\)\\s*\\)\\s*(?:\\{\\s*throw\\s+[^;]{1,300};\\s*\\}|throw\\s+[^;]{1,300};)\\s*return\\s+' + n + '\\s*;\\s*$');
  const m = shape.exec(validator.body);
  if (!m || !/^[\^$A-Za-z0-9\[\]{}.,_+*?\-]+$/.test(m[1])) return false;
  try { return new RegExp(m[1], m[2]).test('undefined'); } catch { return false; }
}

function argumentsOf(text) {
  const args = [];
  let depth = 0, start = 0;
  for (let i = 0; i < text.length; i++) {
    if ('([{'.includes(text[i])) depth++;
    else if (')]}'.includes(text[i])) depth--;
    else if (text[i] === ',' && depth === 0) { args.push(text.slice(start, i).trim()); start = i + 1; }
    if (depth < 0) return [];
  }
  if (depth !== 0) return [];
  args.push(text.slice(start).trim());
  return args;
}

function importResolves(caller, callee) {
  const from = caller.file || caller.rel;
  if (from === callee.file) return true;
  const imports = caller.code.matchAll(/\bimport\s*\{([^}]{0,1000})\}\s*from\s*['"]([^'"]+)['"]/g);
  for (const m of imports) {
    if (!m[2].startsWith('.') || !new RegExp('(?:^|,)\\s*' + ident(callee.name) + '\\s*(?:,|$)').test(m[1])) continue;
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(from), m[2])).replace(/\.(?:js|ts)$/, '');
    if (resolved === callee.file.replace(/\.(?:js|ts)$/, '')) return true;
  }
  return false;
}

function handlerStart(mask, at) {
  const stack = [];
  for (let i = 0; i < at; i++) {
    if (mask[i] === '{') stack.push(i);
    else if (mask[i] === '}') stack.pop();
  }
  for (const open of stack.reverse()) {
    const prefix = mask.slice(Math.max(0, open - 160), open);
    if (/=>\s*$/.test(prefix) || /\bfunction\s+[\w$]+\s*\([^)]{0,100}\)\s*$/.test(prefix)) return open + 1;
  }
  return -1;
}

function routeSource(files, entry, name) {
  const position = entry.params.split(',').findIndex(p => new RegExp('^\\s*' + ident(name) + '\\s*:').test(p));
  if (position < 0) return false;
  const call = new RegExp('(?<![.\\w$])' + ident(entry.name) + '\\s*\\(', 'g');
  return files.some(f => {
    const mask = f.mask;
    for (const m of mask.matchAll(call)) {
      const open = mask.indexOf('(', m.index), close = matching(mask, open, '(', ')');
      if (close < 0 || close - open > 800) continue;
      const arg = argumentsOf(mask.slice(open + 1, close))[position];
      if (!arg) continue;
      const direct = new RegExp('^(?:(?:req|request)\\.body|requestBody\\([^)]{0,80}\\))\\.' + ident(name) + '$');
      const local = new RegExp('^body\\.' + ident(name) + '$');
      const start = handlerStart(mask, m.index);
      if (start < 0 || !importResolves(f, entry)) continue;
      const before = f.code.slice(Math.max(start, m.index - 700), m.index);
      if (!direct.test(arg) && !(local.test(arg) && /\b(?:const|let)\s+body\s*=\s*requestBody\s*\(/.test(before))) continue;
      const source = '(?:(?:req|request)\\.body|body|requestBody\\([^)]*\\))\\.' + ident(name);
      const guard = new RegExp('\\bif\\s*\\(\\s*typeof\\s+' + source + '\\s*!==\\s*[\'\"]string[\'\"]\\s*\\)\\s*(?:\\{\\s*)?(?:throw|return)\\b');
      const absentGuard = new RegExp('\\bif\\s*\\(\\s*' + source + '\\s*(?:==\\s*null|===\\s*undefined)\\s*\\)\\s*(?:\\{\\s*)?(?:throw|return)\\b');
      const falsyGuard = new RegExp('\\bif\\s*\\(\\s*!\\s*' + source + '\\s*\\)\\s*(?:\\{\\s*)?(?:throw|return)\\b');
      if (guard.test(before) || absentGuard.test(before) || falsyGuard.test(before)) continue;
      return true;
    }
    return false;
  });
}

function callBindings(body, methods, expression, caller, at = -1) {
  const re = new RegExp('(?<![.\\w$])(' + ID + ')\\s*\\(', 'g');
  const out = [];
  for (const m of body.matchAll(re)) {
    const callee = methods.get(m[1]);
    if (!callee || !importResolves(caller, callee)) continue;
    const open = body.indexOf('(', m.index), close = matching(body, open, '(', ')');
    if (close < 0 || close - open > 800) continue;
    const args = argumentsOf(body.slice(open + 1, close));
    const params = argumentsOf(callee.params);
    for (let i = 0; i < args.length; i++) {
      if (args[i] !== expression) continue;
      const param = new RegExp('^\\s*(' + ID + ')(?=\\s*(?::|=|$))').exec(params[i] || '')?.[1];
      if (!param) continue;
      if (at >= 0) {
        const raw = body.slice(open + 1, close);
        const first = raw.indexOf(expression);
        if (first < 0 || at !== open + 1 + first) continue;
      }
      out.push({ method: callee, param });
    }
  }
  return out;
}

function guardedWrite(method, methods, name) {
  for (const { method: validator, param } of callBindings(method.mask, methods, name, method)) {
    if (!acceptsMissing(validator, param)) continue;
    const guardCall = new RegExp('(?<![.\\w$])(?:const|let)\\s+(' + ID + ')\\s*=\\s*' + ident(validator.name) + '\\s*\\(\\s*' + ident(name) + '\\s*\\)');
    const guard = guardCall.exec(method.mask);
    if (!guard) continue;
    const insert = /\bdb\.prepare\s*\(\s*(['"`])INSERT\s+INTO\b[^'"`]{0,600}\1\s*\)\s*\.run\s*\(/gi;
    for (const m of method.body.matchAll(insert)) {
      if (m.index <= guard.index) continue;
      const between = method.body.slice(guard.index + guard[0].length, m.index);
      if (new RegExp('\\b' + ident(guard[1]) + '\\s*=(?!=)').test(between)) continue;
      if (new RegExp('\\bif\\s*\\([^)]{0,160}\\b(?:' + ident(name) + '|' + ident(guard[1]) + ')\\b[^)]{0,160}\\)\\s*(?:\\{\\s*)?(?:throw|return)\\b').test(between)) continue;
      const runOpen = m.index + m[0].length - 1;
      const runClose = matching(method.mask, runOpen, '(', ')');
      if (runClose < 0 || runClose - runOpen > 500) continue;
      if (new RegExp('(?:^|,)\\s*' + ident(guard[1]) + '\\s*(?:,|$)').test(method.mask.slice(runOpen + 1, runClose))) return true;
    }
  }
  return false;
}

function reachesWrite(method, methods, name, depth, seen = new Set()) {
  if (!method || depth > 3 || seen.has(method.name + ':' + name)) return false;
  if (guardedWrite(method, methods, name)) return true;
  seen.add(method.name + ':' + name);
  return callBindings(method.mask, methods, name, method).some(edge => reachesWrite(edge.method, methods, edge.param, depth + 1, seen));
}

function coercionFindings(ctx) {
  const files = ctx.files.filter(f => ['javascript', 'typescript'].includes(f.lang));
  if (files.length > 2000 || files.reduce((n, f) => n + f.code.length, 0) > 2000000) return [];
  const all = files.flatMap(functions), methods = new Map();
  if (all.length > 750) return [];
  const sourceFiles = files.map(f => ({ ...f, mask: maskStrings(f.code, f.lang) }));
  for (const f of all) methods.set(f.name, methods.has(f.name) ? null : f);
  const findings = [];
  const globalStringShadow = /\b(?:globalThis|global|window)\.String\s*=/.test(files.map(x => x.code).join('\n'));
  for (const f of all) {
    if (!methods.get(f.name) || /\b(?:const|let|var|function|class|import)\s+(?:\{[^}]*\b)?String\b/.test(f.code) ||
      globalStringShadow) continue;
    const param = [...f.params.matchAll(new RegExp('(?:^|,)\\s*(' + ID + ')\\s*:\\s*unknown\\b', 'g'))];
    for (const p of param) {
      const name = p[1];
      if (!routeSource(sourceFiles, f, name)) continue;
      const re = new RegExp('\\bString\\s*\\(\\s*' + ident(name) + '\\s*\\)', 'g');
      for (const m of f.mask.matchAll(re)) {
        const prefix = f.body.slice(0, m.index);
        if (new RegExp('\\b' + ident(name) + '\\s*=(?!=)').test(prefix)) continue;
        // An explicit missing-value default is an API decision, not a bypass of a required value.
        if (new RegExp('\\b' + ident(name) + '\\s*===?\\s*undefined\\s*\\?[^;]{0,80}:\\s*$').test(prefix)) continue;
        if (new RegExp('\\bif\\s*\\(\\s*typeof\\s+' + ident(name) + '\\s*!==?\\s*[\'\"]string[\'\"]\\s*\\)\\s*(?:\\{\\s*)?(?:throw|return)\\b').test(prefix)) continue;
        const edges = callBindings(f.mask, methods, 'String(' + name + ')', f, m.index);
        if (!edges.some(edge => reachesWrite(edge.method, methods, edge.param, 0))) continue;
        const line = f.code.slice(0, f.start + m.index).split('\n').length;
        findings.push({ file: f.file, line, detail: 'An absent request field becomes a string accepted by a downstream validator before a visible insert.' });
      }
    }
  }
  return findings.slice(0, 20);
}

module.exports = { coercionFindings };
