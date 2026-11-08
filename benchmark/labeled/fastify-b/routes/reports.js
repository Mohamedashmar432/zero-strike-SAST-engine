'use strict';

const fs = require('fs');
const path = require('path');

const REPORT_ROOT = path.resolve(__dirname, '..', 'reports');

module.exports = async function reportsRoutes(fastify) {
  fastify.get('/download', async (request, reply) => {
    const body = fs.readFileSync(path.join(REPORT_ROOT, request.query.name), 'utf8');
    return reply.type('text/csv').send(body);
  });

  fastify.get('/raw/:file', async (request, reply) => {
    return reply.sendFile(request.params.file, REPORT_ROOT + '/archive');
  });

  fastify.get('/download-safe', async (request, reply) => {
    const target = path.resolve(REPORT_ROOT, path.basename(request.query.name));
    if (!target.startsWith(REPORT_ROOT + path.sep)) {
      return reply.code(400).send({ error: 'invalid name' });
    }
    return reply.type('text/csv').send(fs.readFileSync(target, 'utf8'));
  });
};
