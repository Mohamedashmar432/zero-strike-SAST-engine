import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import view from '@fastify/view';
import ejs from 'ejs';
import { config } from './config';
import usersRoutes from './routes/users';
import filesRoutes from './routes/files';
import proxyRoutes from './routes/proxy';
import authRoutes from './routes/auth';
import toolsRoutes from './routes/tools';

const app = Fastify({ logger: true });

app.register(cors, { origin: true, credentials: true });
app.register(cookie);
app.register(view, { engine: { ejs }, root: 'views' });

app.setErrorHandler((err, _request, reply) => {
  reply.status(500).send({ message: err.message, stack: err.stack });
});

app.register(usersRoutes, { prefix: '/users' });
app.register(filesRoutes, { prefix: '/files' });
app.register(proxyRoutes, { prefix: '/proxy' });
app.register(authRoutes, { prefix: '/auth' });
app.register(toolsRoutes, { prefix: '/tools' });

app.listen({ port: config.port, host: '0.0.0.0' });
