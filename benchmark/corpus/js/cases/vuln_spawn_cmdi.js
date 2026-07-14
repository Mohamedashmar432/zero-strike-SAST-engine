// ZS-JS-029: command injection — spawn() with the command argument sourced
// directly inline from req.body (no intermediate variable)
const { spawn } = require('child_process');
function ping(req, res) {
  spawn('ping', ['-c', '2', req.body.host]);
}
