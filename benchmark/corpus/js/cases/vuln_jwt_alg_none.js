// ZS-JS-048: JWT verification accepting the unsigned 'none' algorithm
const jwt = require('jsonwebtoken');
function verifyRequest(req, res, signingKey) {
  return jwt.verify(req.body.jwt, signingKey, { algorithms: ['none'] });
}
