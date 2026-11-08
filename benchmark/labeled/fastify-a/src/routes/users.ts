import { FastifyInstance } from 'fastify';
import { findByEmail, findByEmailSafe, searchByName, searchByNameSafe, login, loginSafe } from '../services/userService';

interface EmailQuery { email: string }
interface NameQuery { name: string }

export default async function usersRoutes(app: FastifyInstance) {
  const emailSchema = { querystring: { type: 'object', properties: { email: { type: 'string' } }, required: ['email'] } };

  app.get<{ Querystring: EmailQuery }>('/by-email', { schema: emailSchema }, async (request) => {
    return findByEmail(request.query.email);
  });

  app.get<{ Querystring: EmailQuery }>('/by-email-safe', { schema: emailSchema }, async (request) => {
    return findByEmailSafe(request.query.email);
  });

  app.get<{ Querystring: NameQuery }>('/search', async (request) => {
    return searchByName(request.query.name);
  });

  app.get<{ Querystring: NameQuery }>('/search-safe', async (request) => {
    return searchByNameSafe(request.query.name);
  });

  app.post<{ Body: { username: string; password: string } }>('/login', async (request) => {
    return login(request.body);
  });

  app.post<{ Body: { username: string; password: string } }>('/login-safe', async (request) => {
    return loginSafe(request.body);
  });

  app.get<{ Params: { id: string } }>('/profile/:id', async (request, reply) => {
    const bio = request.headers['x-bio'] as string;
    return reply.view('profile.ejs', { name: request.params.id, bio, query: (request.query as any).q });
  });

  app.get<{ Querystring: NameQuery }>('/hello', async (request, reply) => {
    return reply.type('text/html').send(`<h1>Hello ${request.query.name}</h1>`);
  });

  app.get<{ Querystring: NameQuery }>('/hello-safe', async (request, reply) => {
    const name = request.query.name.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
    return reply.type('text/html').send(`<h1>Hello ${name}</h1>`);
  });
}
