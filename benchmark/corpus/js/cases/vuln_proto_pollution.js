// ZS-JS-040: prototype pollution — __proto__ assigned from request input
function applySettings(req, res) {
  const payload = req.body.data;
  const settings = {};
  settings.__proto__ = payload;
}
