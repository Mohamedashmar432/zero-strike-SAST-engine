// ZS-JS-026: weak cryptographic hash — crypto.createHash('md5')
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}
