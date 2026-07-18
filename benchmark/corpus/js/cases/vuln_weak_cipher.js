// ZS-JS-044: weak symmetric cipher — crypto.createCipheriv('des-ede3')
const crypto = require('crypto');
function encrypt(data, key, iv) {
  const cipher = crypto.createCipheriv('des-ede3', key, iv);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
