// ZS-JS-035 / ZS-JS-036 still fire when the part the request controls is the
// host: a tainted first operand, a scheme with a tainted host, or a fixed
// host immediately followed by a tainted suffix.
const axios = require('axios');
function proxy(req, res) {
  const host = req.query.host;
  axios.get(host + '/status');
  axios.post('https://api.service.invalid' + req.body.suffix, { ok: true });
}
