// ZS-TS-065: deprecated crypto.createDecipher() — weak KDF, no random IV
const crypto = require('crypto');
const decipher = crypto.createDecipher('aes192', 'password');
