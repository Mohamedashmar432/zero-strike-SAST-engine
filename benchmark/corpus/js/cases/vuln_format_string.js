// ZS-JS-034: tainted format string — util.format() template built directly
// from req.query (the real vulnerable shape: the template itself, not just a
// substituted value, is attacker-controlled)
const util = require('util');
function log(req) {
  console.log(util.format('User: ' + req.query.name));
}
