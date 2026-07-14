// ZS-JS-024: path traversal — fs.readFile() with a path traced back to req.query
const fs = require('fs');

function download(req, res) {
  const filename = req.query.filename;
  fs.readFile(filename, 'utf8', function (err, data) {
    res.send(data);
  });
}
