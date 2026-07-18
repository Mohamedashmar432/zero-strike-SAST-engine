// ZS-JS-043: dynamic code execution — vm.runInNewContext() with request-derived code
const vm = require('vm');
function run(req, res) {
  const code = req.query.expr;
  vm.runInNewContext(code, {});
}
