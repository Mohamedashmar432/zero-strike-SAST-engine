// ZS-JS-124: CWE-614: hand-written Set-Cookie header without Secure
function login(req, res, token) {
  res.setHeader('Set-Cookie', `auth_token=${token}; Path=/; HttpOnly; SameSite=Strict`);
}
