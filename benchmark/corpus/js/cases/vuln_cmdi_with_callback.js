// ZS-JS-012: a tainted command still fires when exec() also takes a callback.
const { exec } = require('child_process');
const dir = req.query.dir;
exec('ls ' + dir, (error, stdout, stderr) => {
  console.log(stdout);
});
