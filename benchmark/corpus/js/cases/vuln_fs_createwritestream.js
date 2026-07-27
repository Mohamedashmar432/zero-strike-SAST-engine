// ZS-JS-064: arbitrary file write via fs.createWriteStream() with a tainted path
const fs = require('fs');
const p = req.query.path;
fs.createWriteStream(p);
