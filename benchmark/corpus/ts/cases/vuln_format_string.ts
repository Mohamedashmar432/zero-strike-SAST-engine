// ZS-TS-032: tainted format string — util.format() template built directly
// from req.query (the real vulnerable shape: the template itself, not just a
// substituted value, is attacker-controlled)
import * as util from 'util';
function log(req: any) {
  const message = util.format('User: ' + req.query.name);
  return message;
}
