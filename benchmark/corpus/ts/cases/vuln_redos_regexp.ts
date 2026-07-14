// ZS-TS-031: ReDoS — RegExp constructed directly from req.query (attacker-
// controlled pattern, inline, no intermediate variable)
function search(req: any) {
  const re: RegExp = new RegExp(req.query.pattern);
  return re.test('some input');
}
