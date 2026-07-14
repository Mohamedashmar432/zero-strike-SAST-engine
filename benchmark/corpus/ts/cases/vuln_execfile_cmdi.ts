// ZS-TS-028: command injection — execFile() with the executable path sourced
// directly inline from req.body (no intermediate variable)
import { execFile } from 'child_process';
function convert(req: any, res: any) {
  execFile(req.body.tool, ['--input', 'in.txt']);
}
