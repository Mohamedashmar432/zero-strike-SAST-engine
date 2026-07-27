// ZS-JS-065: path traversal via fs.createReadStream() with a tainted path
const fs = require('fs');
const p = req.query.path;
fs.createReadStream(p);
