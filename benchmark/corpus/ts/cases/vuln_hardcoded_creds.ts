import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const dbConfig = { host: 'db.internal', password: 'Tr0ub4dor-fixture-pw' };
const apiSecret = process.env.API_SECRET || 'fixture-fallback-secret-value';
const dbPass = process.env.DB_PASSWORD || 'fixture-fallback-db-pass';

function login(req: any) {
  if (req.body.password === 'fixture-admin-pass-1') {
    return jwt.sign({ user: 'admin' }, 'fixture-jwt-signing-key');
  }
  return null;
}

const mac = crypto.createHmac('sha256', 'fixture-hmac-key-value');
const hash = bcrypt.hash('fixture-user-pass-1', 10);
export { dbConfig, apiSecret, dbPass, login, mac, hash };

import Hashids from 'hashids';
const hashids = new Hashids('fixture hashids salt value');
const signingKey = process.env.SIGNING_KEY || 'fixture-signing-fallback-key';
const sig = crypto.createHmac('sha256', signingKey).update('m').digest('hex');
