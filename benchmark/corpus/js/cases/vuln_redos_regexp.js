// ZS-JS-033: ReDoS — RegExp constructed directly from req.query (attacker-
// controlled pattern, inline, no intermediate variable)
function search(req) {
  const re = new RegExp(req.query.pattern);
  return re.test('some input');
}
