// ZS-TS-121: CWE-209: a stack trace returned in the response body
function report(req, res, lastFailure) {
  res.status(500).json({ message: 'failed', stack: lastFailure.stack });
}
