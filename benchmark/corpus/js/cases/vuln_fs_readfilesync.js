// ZS-JS-025: path traversal — fs.readFileSync() with a path traced back to req.params
const fs = require('fs');

function download(req, res) {
  const filename = req.params.filename;
  const data = fs.readFileSync(filename, 'utf8');
  res.send(data);
}
