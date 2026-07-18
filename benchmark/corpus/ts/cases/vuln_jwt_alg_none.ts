// ZS-TS-046: JWT verification accepting the unsigned 'none' algorithm
import jwt from 'jsonwebtoken';
function verifyRequest(req: any, res: any, signingKey: string) {
  return jwt.verify(req.body.jwt, signingKey, { algorithms: ['none'] });
}
