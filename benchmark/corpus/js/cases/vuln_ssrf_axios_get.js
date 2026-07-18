// ZS-JS-035: SSRF — axios.get() with a URL taken from the request
const axios = require('axios');
function fetchRemote(req, res) {
  const target = req.query.url;
  axios.get(target);
}
