// ZS-JS-137: CWE-915: model created from the entire request body
const User = require('./models/user');
function register(req, res) {
  const user = new User(req.body);
  user.save();
  res.json({ ok: true });
}
