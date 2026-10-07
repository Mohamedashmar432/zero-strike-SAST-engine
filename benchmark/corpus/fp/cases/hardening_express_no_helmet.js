// Hardening tier (ZS-CFG-002, missing helmet): excluded from default output
// and counted in Stats.TierExcluded instead.
const express = require('express');
const app = express();

app.get('/', (req, res) => res.send('ok'));

app.listen(3000);
