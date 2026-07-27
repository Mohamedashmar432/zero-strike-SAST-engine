// ZS-JS-075: spawnSync() with a tainted command
const cmd = req.query.cmd;
spawnSync('sh', ['-c', cmd]);
