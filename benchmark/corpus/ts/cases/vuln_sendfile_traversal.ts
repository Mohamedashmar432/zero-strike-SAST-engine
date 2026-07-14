// ZS-TS-030: path traversal — res.sendFile() with a path traced directly
// from req.query (inline, no intermediate variable)
function download(req: any, res: any) {
  res.sendFile(req.query.filename);
}
