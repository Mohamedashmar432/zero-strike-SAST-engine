// ZS-TS-022: path traversal — fs.readFile() with a tainted path (source: req.query)
import fs from 'fs';
const filename: string = req.query.filename;
fs.readFile(filename, 'utf8', (err, data) => {});
