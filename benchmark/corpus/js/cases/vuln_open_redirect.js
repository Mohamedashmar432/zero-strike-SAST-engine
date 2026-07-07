// ZS-JS-015: open redirect — target traces back to req.query (untrusted input)
function redirect(req, res) {
  const target = req.query.url;
  if (target) {
    res.redirect(target);
  }
}
