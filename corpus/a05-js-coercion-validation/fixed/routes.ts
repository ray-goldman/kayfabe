import { createChain } from './service';
export function endpoint(req, db) {
  return createChain(db, req.body.label);
}
