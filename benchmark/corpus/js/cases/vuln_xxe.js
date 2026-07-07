// ZS-JS-013: XXE — libxmljs configured with noent:true resolves external entities
const libxmljs = require('libxmljs');
function parse(xml) {
  return libxmljs.parseXmlString(xml, { noent: true, noblanks: true });
}
