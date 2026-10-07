// ZS-JS-131: CWE-22: res.download with a request-controlled path
const path = require('path');
function fetchFile(req, res) {
  const filename = path.resolve(process.cwd() + '/public/uploads/' + req.body.filename);
  res.download(filename);
}
