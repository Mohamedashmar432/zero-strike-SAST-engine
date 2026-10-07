// ZS-TS-123: CWE-614: session cookie without the secure flag (Express default is false)
function login(req, res, sid) {
  res.cookie('session_id', sid, { httpOnly: true });
}
