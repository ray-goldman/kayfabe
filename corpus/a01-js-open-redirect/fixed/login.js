const express = require('express');
const router = express.Router();
function safeRedirectPath(p) { return typeof p === 'string' && /^\/[^/\\]/.test(p) ? p : '/'; }
router.get('/after-login', (req, res) => {
  res.redirect(safeRedirectPath(req.query.next));
});
module.exports = router;
function redirect(response, path) { response.redirect(303, path); }
router.get('/agent/:id', (request, response) => {
  redirect(response, `/admin/agents?agent=${encodeURIComponent(request.params.id)}`);
});
