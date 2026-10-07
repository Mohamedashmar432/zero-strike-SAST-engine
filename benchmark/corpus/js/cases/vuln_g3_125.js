// ZS-JS-125: CWE-1275: hand-written Set-Cookie header without SameSite
function login(req, res, token) {
  res.setHeader('Set-Cookie', `auth_token=${token}; Path=/; HttpOnly; Secure`);
}
