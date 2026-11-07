// ZS-TS-176: noent inside an evaluated script string
function parse(data) {
  return vm.runInContext('libxml.parseXml(data, { noent: true })', ctx);
}
