// ZS-JS-030: command injection — execFile() with the executable path sourced
// directly inline from req.body (no intermediate variable)
const { execFile } = require('child_process');
function convert(req, res) {
  execFile(req.body.tool, ['--input', 'in.txt']);
}
