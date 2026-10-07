// ZS-JS-122: CWE-1004: session token cookie without httpOnly (Express default is false)
function login(req, res, token) {
  res.cookie('token', token);
}
