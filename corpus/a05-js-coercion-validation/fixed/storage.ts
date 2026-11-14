export function createRecord(db, label: unknown) {
  const clean = validate(label);
  return db.prepare('INSERT INTO chains(label) VALUES (?)').run(clean);
}
function validate(label: unknown) {
  if (typeof label !== 'string' || !/^[A-Za-z0-9_.-]{1,80}$/.test(label)) throw new Error('validation_error');
  return label;
}
