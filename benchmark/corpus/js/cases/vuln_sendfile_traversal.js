// ZS-JS-032: path traversal — res.sendFile() with a path traced directly
// from req.query (inline, no intermediate variable)
function download(req, res) {
  res.sendFile(req.query.filename);
}
