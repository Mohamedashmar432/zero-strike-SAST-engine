// ZS-JS-012: command injection — exec() with a tainted argument (source: req.body)
const { exec } = require('child_process');
const address = req.body.address;
exec('ping -c 2 ' + address, function (err, stdout) {});
