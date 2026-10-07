import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const dbConfig = { host: 'db.internal', password: process.env.DB_PASSWORD };
const templ = { password: '${DB_PASSWORD}' };
const placeholder = { password: 'changeme' };
const apiSecret = process.env.API_SECRET;

function login(req: any, stored: string) {
  if (!process.env.JWT_KEY) throw new Error('JWT_KEY required');
  if (crypto.timingSafeEqual(Buffer.from(req.body.password), Buffer.from(stored))) {
    return jwt.sign({ user: 'u' }, process.env.JWT_KEY);
  }
  return null;
}
export { dbConfig, templ, placeholder, apiSecret, login };
