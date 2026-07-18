// ZS-TS-041: dynamic code execution — vm.runInNewContext() with request-derived code
import vm from 'vm';
function run(req: any, res: any) {
  const code: string = req.query.expr;
  vm.runInNewContext(code, {});
}
