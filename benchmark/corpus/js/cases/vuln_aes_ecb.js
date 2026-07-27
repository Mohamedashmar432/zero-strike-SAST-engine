// ZS-JS-068: AES in ECB mode leaks plaintext structure (insecure mode)
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-128-ecb', key, iv);
