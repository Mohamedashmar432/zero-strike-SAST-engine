// ZS-JS-134: CWE-22: directory listing of a request-controlled path
const fs = require('fs');
function list(req, res) {
  const dir = './uploads/' + req.query.user;
  fs.readdir(dir, function (err, files) {
    res.json(files || []);
  });
}
