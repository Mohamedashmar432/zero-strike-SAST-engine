// ZS-TS-120: CWE-209: caught error objects returned to the client
const fs = require('fs');
function load(req, res) {
  try {
    res.json(JSON.parse(fs.readFileSync('/etc/app.json', 'utf8')));
  } catch (err) {
    res.status(500).send(err.message);
  }
}
function save(req, res) {
  fs.writeFile('/tmp/out', 'x', function (err) {
    if (err) {
      return res.json({ error: err });
    }
    res.json({ ok: true });
  });
}
