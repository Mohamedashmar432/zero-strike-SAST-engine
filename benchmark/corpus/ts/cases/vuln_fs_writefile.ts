// ZS-TS-060: arbitrary file write via fs.writeFile() with a tainted path
const fs = require('fs');
const p = req.query.path;
fs.writeFile(p, "data", () => {});
