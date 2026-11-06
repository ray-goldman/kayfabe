'use strict';
const { shadowsType } = require('./java-methods');
const { formattingArray } = require('./java-format-arrays');
const { completeOutputStatement } = require('./java-output-proof');

function localeImportsKnown(index) {
  for (const hit of index.mask.matchAll(/\bimport\b/g)) {
    const end = index.mask.indexOf(';', hit.index);
    if (end < 0 || end - hit.index > 4000) return false;
    const declaration = index.mask.slice(hit.index, end + 1).match(
      /^import\s+(static\s+)?((?:[A-Za-z_]\w*\s*\.\s*)+(?:[A-Za-z_]\w*|\*))\s*;$/);
    if (!declaration || declaration[1]) return false;
    const name = declaration[2].replace(/\s/g, '');
    // Source inventory completeness says nothing about dependency classpaths.
    if (name.endsWith('.*') || name.split('.').pop() === 'java') return false;
  }
  return true;
}

// A Boolean proof for this complete current call only. It never renders bytes
// or creates a fact that a later output-context reconstruction could reuse.
function independentFormat({ index, filter, project, call, windowStart, windowEnd }) {
  if (!index?.complete || call.kind !== 'printf' || !filter.independentOutputValuesAt) return false;
  if (!completeOutputStatement({ index, call, windowStart, windowEnd })) return false;
  let args = call.args;
  if (/^java\.util\.Locale\.(?:ROOT|US|UK|ENGLISH)$/.test(args[0]?.trim())) {
    if (!project?.complete || !localeImportsKnown(index) || shadowsType(index, 'java', project) || index.imports.has('java') ||
        index.className === 'java' || project.classes.has([index.package, 'java'].filter(Boolean).join('.')) ||
        project.classes.has('java.util.Locale')) return false;
    args = args.slice(1);
  }
  if (args.length !== 2) return false;
  const source = args[0].trim();
  if (!/^(?:"(?:[^"\\\r\n]|\\[btnfr"'\\])*"|[A-Za-z_]\w*)$/.test(source)) return false;
  const format = filter.literalAt(source, call.position);
  if (format?.type !== 'String' || format.value.length > 4000) return false;
  const values = formattingArray(index, args[1], call, filter);
  if (!values || !filter.independentOutputValuesAt(values)) return false;
  let next = 1, estimatedWork = format.value.length;
  for (let i = 0; i < format.value.length; i++) {
    if (format.value[i] !== '%') continue;
    const tail = format.value.slice(++i);
    if (/^[%n]/.test(tail)) continue;
    if (tail[0] === 's') {
      if (next++ > values.length) return false;
    } else {
      const explicit = tail.match(/^([1-9]\d{0,1})\$s/);
      if (!explicit || Number(explicit[1]) > values.length) return false;
      i += explicit[0].length - 1;
    }
    // Admission/work estimate only: alias/helper composition may produce more
    // actual bytes. This checker never renders them or bounds their length.
    if ((estimatedWork += 4000) > 16000) return false;
  }
  return true;
}

module.exports = { independentFormat };
