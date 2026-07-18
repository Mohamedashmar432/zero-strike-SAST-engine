// ZS-JS-045: command injection — execSync() with a shell string built from req.body
const { execSync } = require('child_process');
function runPing(req, res) {
  const host = req.body.host;
  const cmd = 'ping -c 2 ' + host;
  execSync(cmd);
}
