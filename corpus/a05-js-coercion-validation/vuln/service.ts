import { createRecord } from './storage';
export function createChain(db, label: unknown) {
  return issue(db, String(label));
}
function issue(db, label: string) {
  return createRecord(db, label);
}
