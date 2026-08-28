// ZS-JS-091: path.join path traversal
const path = require('path');
const userInput = req.query.file;
const target = path.join('/var/www/uploads', userInput);
