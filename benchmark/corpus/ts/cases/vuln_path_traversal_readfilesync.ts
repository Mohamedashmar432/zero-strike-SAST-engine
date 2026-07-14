// ZS-TS-023: path traversal — fs.readFileSync() with a tainted path (source: req.query)
import fs from 'fs';
const filename: string = req.query.filename;
const data: string = fs.readFileSync(filename, 'utf8');
