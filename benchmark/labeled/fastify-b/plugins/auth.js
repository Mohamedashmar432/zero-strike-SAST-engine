'use strict';

const fp = require('fastify-plugin');
const crypto = require('crypto');

async function authPlugin(fastify) {
  fastify.decorate('hashPassword', (password) => crypto.createHash('sha1').update(password).digest('hex'));

  fastify.decorate('hashPasswordStrong', (password, salt) => crypto.scryptSync(password, salt, 64).toString('hex'));

  fastify.decorate('newSessionId', () => Math.random().toString(16).slice(2));

  fastify.decorate('newSessionIdStrong', () => crypto.randomBytes(24).toString('hex'));

  fastify.decorate('encryptLegacy', (text, key) => {
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  });

  fastify.decorate('encryptStrong', (text, key) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return Buffer.concat([iv, cipher.update(text, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  });

  fastify.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/admin') && request.headers['x-admin-token'] !== process.env.ADMIN_TOKEN) {
      reply.code(401).send({ error: 'unauthorized' });
    }
  });

  fastify.post('/login', async (request, reply) => {
    const sid = fastify.newSessionId();
    reply.setCookie('sid', sid, { path: '/', httpOnly: false, secure: false });
    return { ok: true };
  });

  fastify.post('/login-secure', async (request, reply) => {
    const sid = fastify.newSessionIdStrong();
    reply.setCookie('sid', sid, { path: '/', httpOnly: true, secure: true, sameSite: 'strict' });
    return { ok: true };
  });
}

module.exports = fp(authPlugin);
