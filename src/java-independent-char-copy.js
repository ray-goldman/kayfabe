'use strict';
const { canonicalStringScope } = require('./java-independent-return');
const { completeOutputStatement } = require('./java-output-proof');

// Boolean proof for this call only; copying does not establish an HTML encoding
// or expose helper-produced bytes to prior-output reconstruction.
function independentCharCopy({ index, filter, project, call, windowStart, windowEnd }) {
  if (!index?.complete || !['print', 'println'].includes(call.kind) || call.args.length !== 1 ||
      !filter.independentOutputValuesAt || !completeOutputStatement({ index, call, windowStart, windowEnd })) return false;
  const copy = call.args[0].match(/^\s*([A-Za-z_]\w*)\s*\.\s*toCharArray\s*\(\s*\)\s*$/);
  if (!copy || !canonicalStringScope({ index, position: call.position, project, budget: { left: 10000 } }) ||
      filter.typeAt(copy[1], call.position) !== 'String') return false;
  return filter.independentOutputValuesAt([{ expression: copy[1], position: call.position }]);
}

module.exports = { independentCharCopy };
