'use strict';

const Fastify = require('fastify');
const cors = require('@fastify/cors');
const cookie = require('@fastify/cookie');
const view = require('@fastify/view');
const handlebars = require('handlebars');

const PAYMENT_TOKEN = 'EXAMPLE-NOT-REAL-payment-token-abc123';
const SESSION_SECRET = process.env.SESSION_SECRET;

const app = Fastify({ logger: true });

app.register(cors, { origin: '*', credentials: true });
app.register(cookie, { secret: SESSION_SECRET });
app.register(view, { engine: { handlebars }, root: 'views', layout: 'layout.hbs' });

app.register(require('./plugins/db'));
app.register(require('./plugins/auth'));
app.register(require('./routes/orders'), { prefix: '/orders' });
app.register(require('./routes/reports'), { prefix: '/reports' });
app.register(require('./routes/admin'), { prefix: '/admin' });
app.register(require('./routes/webhooks'), { prefix: '/webhooks' });

app.setErrorHandler((error, request, reply) => {
  request.log.error(error);
  reply.status(500).send({ error: error.message, stack: error.stack });
});

app.listen({ port: Number(process.env.PORT || 3000), host: '0.0.0.0' });

module.exports = { app, PAYMENT_TOKEN };
