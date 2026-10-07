// ZS-JS-129: CWE-643: XPath expression concatenated with request data
const xpath = require('xpath');
function find(req, res, doc) {
  const release = decodeURI(req.params.release);
  const nodes = xpath.select("//note[release='" + release + "']", doc);
  res.json(nodes.length);
}
