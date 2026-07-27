// ZS-TS-076: vm.runInContext() executing tainted code
const code = req.body.code;
vm.runInContext(code, sandbox);
