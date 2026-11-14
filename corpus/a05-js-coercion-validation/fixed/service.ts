import { createRecord } from './storage';
export function createChain(db, label: unknown) {
  return issue(db, label);
}
function issue(db, label: unknown) {
  return createRecord(db, label);
}
