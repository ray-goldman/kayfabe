'use strict';

// A narrow lexical proof for a closed basename array mapped to local files.
// It does not treat arbitrary .map callbacks or mutable arrays as sanitizers.
function closedLiteralArrayPathSafe(code, lineIndex) {
  if (code.length > 100000) return false;
  const lines = code.split('\n');
  const line = lines[lineIndex] || '';
  const mapped = line.match(/^\s*const\s+[A-Za-z_$][\w$]*\s*=\s*new Map\(\s*([A-Za-z_$][\w$]*)\.map\(\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*=>\s*\[\s*([A-Za-z_$][\w$]*)\s*,\s*readFileSync\(\s*new URL\(\s*`([^`\\\n]+)`\s*,\s*import\.meta\.url\s*\)\s*\)\s*\]\s*\)\s*\)\s*;?\s*$/);
  if (!mapped || mapped[2] !== mapped[3]) return false;
  const [, arrayName, itemName, , template] = mapped;
  const marker = '${' + itemName + '}';
  if (!template.endsWith(marker)) return false;
  const prefix = template.slice(0, -marker.length);
  if (!/^[./A-Za-z0-9_-]+\/$/.test(prefix)) return false;
  const references = code.match(new RegExp(`\\b${arrayName}\\b`, 'g')) || [];
  if (references.length !== 2) return false;
  const declaration = new RegExp(`(?:^|\\n)\\s*const\\s+${arrayName}\\s*=\\s*\\[([\\s\\S]{0,1000}?)\\]\\s*;`, 'g');
  const matches = [...code.matchAll(declaration)];
  if (matches.length !== 1 || matches[0].index >= lines.slice(0, lineIndex).join('\n').length) return false;
  const entries = matches[0][1].split(',').map(value => value.trim()).filter(Boolean);
  if (entries.length === 0 || entries.length > 100) return false;
  return entries.every(value => {
    const literal = value.match(/^(['"])([A-Za-z0-9][A-Za-z0-9._-]{0,100})\1$/);
    return literal && !literal[2].includes('..');
  });
}

module.exports = { closedLiteralArrayPathSafe };
