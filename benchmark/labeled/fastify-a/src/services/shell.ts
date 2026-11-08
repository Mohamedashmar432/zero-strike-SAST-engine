import { exec } from 'child_process';

/** Runs a maintenance command. Every caller in this service passes a literal. */
export function runCmd(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    exec(cmd, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

export const diskFree = () => runCmd('df -h /var/data');
export const uptime = () => runCmd('uptime');
