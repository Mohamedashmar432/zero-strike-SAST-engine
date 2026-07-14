// ZS-JS-031: arbitrary code execution — fork() with the module path sourced
// directly inline from req.body (no intermediate variable)
const { fork } = require('child_process');
function runWorker(req, res) {
  fork(req.body.modulePath);
}
