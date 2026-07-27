// ZS-JS-063: arbitrary file write via fs.writeFileSync() with a tainted path
const fs = require('fs');
const p = req.query.path;
fs.writeFileSync(p, "data");
