// ZS-JS-173: vm in a request handler
function handler(req, res) {
  log(req.method);
  const sandbox = { lines: loadLines() };
  vm.createContext(sandbox);
  vm.runInContext('run(lines)', sandbox);
}
