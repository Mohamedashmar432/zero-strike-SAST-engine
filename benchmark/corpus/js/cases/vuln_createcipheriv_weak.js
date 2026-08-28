// ZS-JS-044: crypto.createCipheriv weak cipher algorithm
const crypto = require('crypto');
const cipher = crypto.createCipheriv('des', key, iv);
