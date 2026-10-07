const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const dbConfig = { host: 'db.internal', password: process.env.DB_PASSWORD };
const templ = { password: '${DB_PASSWORD}' };
const placeholder = { password: 'changeme' };
const apiSecret = process.env.API_SECRET;

function login(req, stored) {
  if (!process.env.JWT_KEY) throw new Error('JWT_KEY required');
  if (crypto.timingSafeEqual(Buffer.from(req.body.password), Buffer.from(stored))) {
    return jwt.sign({ user: 'u' }, process.env.JWT_KEY);
  }
  return null;
}
module.exports = { dbConfig, templ, placeholder, apiSecret, login };
