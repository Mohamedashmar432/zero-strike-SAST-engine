import { FastifyInstance } from 'fastify';
import { sessionToken, sessionTokenStrong } from '../services/crypto';

const ALLOWED_NEXT = new Set(['/dashboard', '/bookings', '/settings']);

export default async function authRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { next: string } }>('/continue', async (request, reply) => {
    return reply.redirect(request.query.next);
  });

  app.get<{ Querystring: { next: string } }>('/continue-safe', async (request, reply) => {
    const next = ALLOWED_NEXT.has(request.query.next) ? request.query.next : '/dashboard';
    return reply.redirect(next);
  });

  app.post('/session', async (_request, reply) => {
    reply.setCookie('sid', sessionToken(), { httpOnly: false, secure: false });
    return { ok: true };
  });

  app.post('/session-secure', async (_request, reply) => {
    reply.setCookie('sid', sessionTokenStrong(), { httpOnly: true, secure: true, sameSite: 'strict' });
    return { ok: true };
  });
}
