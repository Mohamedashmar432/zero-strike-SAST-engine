// ZS-JS-038: SSRF — http.get() with a URL taken from the request
const http = require('http');
function pull(req, res) {
  const target = req.query.target;
  http.get(target);
}
