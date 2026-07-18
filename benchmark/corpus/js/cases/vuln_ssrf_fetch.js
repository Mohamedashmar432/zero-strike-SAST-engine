// ZS-JS-037: SSRF — global fetch() with a URL taken from the request
function proxy(req, res) {
  const target = req.query.url;
  fetch(target);
}
