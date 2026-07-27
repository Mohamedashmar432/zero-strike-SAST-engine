// ZS-JS-069: weak HMAC algorithm — crypto.createHmac('md5', ...)
const crypto = require('crypto');
const mac = crypto.createHmac('md5', key);
