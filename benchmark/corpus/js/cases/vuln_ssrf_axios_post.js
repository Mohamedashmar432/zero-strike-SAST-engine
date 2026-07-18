// ZS-JS-036: SSRF — axios.post() with the endpoint sourced inline from req.body
const axios = require('axios');
function postRemote(req, res) {
  axios.post(req.body.endpoint, { ok: true });
}
