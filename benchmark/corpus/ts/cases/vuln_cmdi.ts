// ZS-TS-016: command injection — exec() with a tainted argument (source: req.body)
const address: string = req.body.address;
exec('ping -c 2 ' + address, function (err, stdout) {});
