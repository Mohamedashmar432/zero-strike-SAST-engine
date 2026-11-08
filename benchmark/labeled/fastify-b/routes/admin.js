'use strict';

const { exec, execFile } = require('child_process');
const serialize = require('node-serialize');
const shell = require('../lib/shell');

const ALLOWED_RETURN = ['/admin', '/orders', '/reports'];

module.exports = async function adminRoutes(fastify) {
  fastify.get('/ping', async (request) => {
    exec('ping -c 1 ' + request.query.host, () => {});
    return { queued: true };
  });

  fastify.get('/ping-safe', async (request) => {
    return new Promise((resolve) => {
      execFile('ping', ['-c', '1', request.query.host], (err, stdout) => resolve({ stdout }));
    });
  });

  fastify.get('/status', async () => ({
    uptime: await shell.run('uptime'),
    disk: await shell.run('df -h /var/data'),
  }));

  fastify.post('/import', async (request) => {
    return serialize.unserialize(request.cookies.prefs);
  });

  fastify.post('/import-safe', async (request) => {
    return JSON.parse(request.cookies.prefs);
  });

  fastify.get('/back', async (request, reply) => {
    return reply.redirect(request.query.to);
  });

  fastify.get('/back-safe', async (request, reply) => {
    const to = ALLOWED_RETURN.includes(request.query.to) ? request.query.to : '/admin';
    return reply.redirect(to);
  });
};
