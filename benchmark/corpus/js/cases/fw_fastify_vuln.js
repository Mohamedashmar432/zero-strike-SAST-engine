// ZS-JS-012: command injection — request.query reaches exec() in a Fastify handler.
const fastify = require('fastify')();
const { exec } = require('child_process');

fastify.get('/ping', async (request, reply) => {
  const host = request.query.host;
  exec('ping -c 2 ' + host);
  return 'ok';
});
