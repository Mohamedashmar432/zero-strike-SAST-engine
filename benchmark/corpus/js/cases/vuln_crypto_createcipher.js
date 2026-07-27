// ZS-JS-066: deprecated crypto.createCipher() — weak KDF, no random IV
const crypto = require('crypto');
const cipher = crypto.createCipher('aes192', 'password');
