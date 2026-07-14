// ZS-TS-029: arbitrary code execution — fork() with the module path sourced
// directly inline from req.body (no intermediate variable)
import { fork } from 'child_process';
function runWorker(req: any, res: any) {
  fork(req.body.modulePath);
}
