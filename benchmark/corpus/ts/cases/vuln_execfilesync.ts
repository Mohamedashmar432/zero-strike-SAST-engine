// ZS-TS-074: execFileSync() with a tainted executable path
const tool = req.query.tool;
execFileSync(tool);
