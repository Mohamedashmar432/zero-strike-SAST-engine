// ZS-TS-027: command injection — spawn() runs a program chosen by the request.
import { spawn } from 'child_process';
app.post('/run', (req: any, res: any) => {
  spawn(req.body.tool, ['--version']);
});
