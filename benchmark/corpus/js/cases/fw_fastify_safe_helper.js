// The helper's parameter only ever receives a constant from the handler: no finding.
const fastify = require('fastify')();
const { exec } = require('child_process');

function runTool(flag) {
  exec('tool ' + flag);
}

fastify.get('/version', async (request, reply) => {
  runTool('--version');
  return 'ok';
});
