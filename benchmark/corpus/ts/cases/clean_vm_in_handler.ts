function compute() {
  const sandbox = { n: 2 };
  vm.createContext(sandbox);
  vm.runInContext('n * 2', sandbox);
}
