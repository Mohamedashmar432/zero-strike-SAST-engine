'use strict';

const { exec } = require('child_process');

// Runs a maintenance command. The only callers (routes/admin.js) pass string literals.
function run(command) {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

module.exports = { run };
