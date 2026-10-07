// ZS-JS-029: command injection — spawn() with shell: true, so the shell parses
// the request-supplied host and `; rm -rf /` runs as a second command.
const { spawn } = require('child_process');
app.post('/ping', (req, res) => {
  spawn('ping', ['-c', '2', req.body.host], { shell: true });
});
