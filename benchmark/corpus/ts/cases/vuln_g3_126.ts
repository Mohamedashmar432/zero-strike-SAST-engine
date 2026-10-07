// ZS-TS-126: CWE-1004: hand-written Set-Cookie header without HttpOnly
function login(req, res, token) {
  res.header('Set-Cookie', 'session=' + token + '; Path=/; Secure; SameSite=Lax');
}
