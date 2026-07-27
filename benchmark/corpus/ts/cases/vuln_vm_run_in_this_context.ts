// ZS-TS-075: vm.runInThisContext() executing tainted code
const code = req.body.code;
vm.runInThisContext(code);
