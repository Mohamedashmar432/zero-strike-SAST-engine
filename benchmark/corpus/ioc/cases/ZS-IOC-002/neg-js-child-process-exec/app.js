const cp = require('child_process');
cp.exec('ls -la', (e, out) => console.log(out));
