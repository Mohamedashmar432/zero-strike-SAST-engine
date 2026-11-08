'use strict';

module.exports = async function ordersRoutes(fastify) {
  fastify.get('/by-customer', async (request) => {
    const result = await fastify.pg.query(`SELECT id, total FROM orders WHERE customer = '${request.query.customer}'`);
    return result.rows;
  });

  fastify.get('/by-customer-safe', async (request) => {
    const result = await fastify.pg.query('SELECT id, total FROM orders WHERE customer = $1', [request.query.customer]);
    return result.rows;
  });

  fastify.get('/search', async (request) => {
    const sql = 'SELECT id, total FROM orders WHERE note ILIKE \'%' + request.query.q + '%\' ORDER BY ' + request.query.sort;
    return (await fastify.pg.query(sql)).rows;
  });

  fastify.post('/lookup', async (request) => {
    return fastify.mongo.collection('orders').find({ $where: `this.ref == '${request.body.ref}'` }).toArray();
  });

  fastify.post('/lookup-safe', async (request) => {
    return fastify.mongo.collection('orders').find({ ref: String(request.body.ref) }).toArray();
  });

  fastify.get('/:id/summary', async (request, reply) => {
    const order = { id: request.params.id, note: request.query.note, customer: request.query.customer };
    return reply.view('order.hbs', { order });
  });

  fastify.get('/:id/banner', async (request, reply) => {
    return reply.type('text/html').send('<div class="banner">Order ' + request.params.id + '</div>');
  });

  fastify.get('/:id/banner-safe', async (request, reply) => {
    const id = String(request.params.id).replace(/[&<>"']/g, (c) => '&#' + c.charCodeAt(0) + ';');
    return reply.type('text/html').send('<div class="banner">Order ' + id + '</div>');
  });
};
