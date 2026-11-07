function parse(data) {
  return vm.runInContext('libxml.parseXml(data, { noblanks: true })', ctx);
}
