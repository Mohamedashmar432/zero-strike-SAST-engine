const express = require('express');
// const helmet = require("helmet");
const app = express();

/*
 * Fix: app.use(helmet()) once the header audit lands
 */
app.get('/', (req, res) => res.send('http://example.test/ok'));

app.listen(3000);
