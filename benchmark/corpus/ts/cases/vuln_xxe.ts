// ZS-TS-017: XXE — libxmljs configured with noent:true resolves external entities
function parse(xml: string) {
  return libxmljs.parseXmlString(xml, { noent: true, noblanks: true });
}
