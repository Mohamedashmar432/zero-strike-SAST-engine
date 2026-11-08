import { FastifyInstance } from 'fastify';

export default async function proxyRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { url: string } }>('/fetch', async (request) => {
    const res = await fetch(request.query.url);
    return res.text();
  });

  app.post<{ Body: { callback: string } }>('/notify', async (request) => {
    const res = await fetch(request.body.callback, { method: 'POST', body: '{"done":true}' });
    return { status: res.status };
  });

  app.get<{ Params: { id: string } }>('/resource/:id', async (request) => {
    const res = await fetch('https://api.example.com/v1/resources/' + encodeURIComponent(request.params.id));
    return res.json();
  });
}
