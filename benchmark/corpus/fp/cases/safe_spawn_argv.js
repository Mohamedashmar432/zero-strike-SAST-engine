// spawn/spawnSync with a fixed, non-shell program and an argv array: no shell
// parses the request-supplied value, so this is not command injection
// (ZS-JS-029/075, ZS-TS-027/073). A tainted argv element to a fixed program is
// at most argument injection, which these CWE-78 rules do not claim.
const { spawn, spawnSync } = require('child_process');

app.post('/ping', (req, res) => {
  spawn('ping', ['-c', '2', req.body.host]);
});

app.post('/label', (req, res) => {
  spawnSync('lp', ['-d', 'label-printer', req.body.form], { shell: false });
});
