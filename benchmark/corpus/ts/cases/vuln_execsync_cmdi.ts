// ZS-TS-043: command injection — execSync() with a shell string built from req.body
import { execSync } from 'child_process';
function runPing(req: any, res: any) {
  const host: string = req.body.host;
  const cmd: string = 'ping -c 2 ' + host;
  execSync(cmd);
}
