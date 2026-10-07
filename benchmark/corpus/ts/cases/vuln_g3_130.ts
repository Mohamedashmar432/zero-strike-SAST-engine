// ZS-TS-130: CWE-918: needle request to a URL taken from the request
const needle = require('needle');
function check(req, res) {
  const target = req.query.url;
  needle.get(target, function (error, response) {
    res.json({ up: !error });
  });
}
