// ZS-JS-076: execFileSync() with a tainted executable path
const tool = req.query.tool;
execFileSync(tool);
