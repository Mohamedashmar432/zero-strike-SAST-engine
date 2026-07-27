// ZS-TS-063: path traversal via fs.createReadStream() with a tainted path
const fs = require('fs');
const p = req.query.path;
fs.createReadStream(p);
