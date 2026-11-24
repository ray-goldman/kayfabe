const { execFile } = require('node:child_process');

function route(req) {
  const match = /^x/.exec(req.query.x);
  const host = req.query.host;
  if (typeof host !== 'string' || !/^[a-z0-9.-]{1,253}$/i.test(host)) return match;
  execFile('ping', ['-c', '1', host], { shell: false });
  return match;
}
