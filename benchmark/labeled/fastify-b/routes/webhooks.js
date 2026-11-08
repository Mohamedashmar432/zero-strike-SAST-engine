'use strict';

const axios = require('axios');

const ALLOWED_HOSTS = new Set(['hooks.example.com', 'api.example.com']);

module.exports = async function webhooksRoutes(fastify) {
  fastify.get('/preview', async (request) => {
    const res = await axios.get(request.query.target);
    return res.data;
  });

  fastify.post('/deliver', async (request) => {
    const res = await axios.post(request.body.url, { event: 'order.created' });
    return { status: res.status };
  });

  fastify.get('/carrier/:code', async (request) => {
    const res = await axios.get('https://api.example.com/carriers/' + encodeURIComponent(request.params.code));
    return res.data;
  });

  fastify.post('/deliver-allowed', async (request, reply) => {
    const target = new URL(request.body.url);
    if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
      return reply.code(400).send({ error: 'host not allowed' });
    }
    const res = await axios.post(target.href, { event: 'order.created' });
    return { status: res.status };
  });
};
