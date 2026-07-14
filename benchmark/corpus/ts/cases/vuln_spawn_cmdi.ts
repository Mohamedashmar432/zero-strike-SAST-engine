// ZS-TS-027: command injection — spawn() with the command argument sourced
// directly inline from req.body (no intermediate variable)
import { spawn } from 'child_process';
function ping(req: any, res: any) {
  spawn('ping', ['-c', '2', req.body.host]);
}
