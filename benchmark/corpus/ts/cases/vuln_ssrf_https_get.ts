// ZS-TS-080: SSRF — https.get() to a tainted URL
const https = require('https');
const url = req.query.url;
https.get(url);
