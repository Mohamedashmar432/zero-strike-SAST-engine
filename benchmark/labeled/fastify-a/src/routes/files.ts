import { FastifyInstance } from 'fastify';
import fs from 'fs';
import path from 'path';
import { config } from '../config';

export default async function filesRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { name: string } }>('/read', async (request, reply) => {
    const data = await fs.promises.readFile(path.join(config.uploadRoot, request.query.name), 'utf8');
    return reply.send(data);
  });

  app.get<{ Params: { file: string } }>('/stream/:file', async (request, reply) => {
    const stream = fs.createReadStream(config.uploadRoot + '/' + request.params.file);
    return reply.send(stream);
  });

  app.get<{ Querystring: { name: string } }>('/read-confined', async (request, reply) => {
    const root = path.resolve(config.uploadRoot);
    const target = path.resolve(root, path.basename(request.query.name));
    if (!target.startsWith(root + path.sep)) {
      return reply.code(400).send({ error: 'bad name' });
    }
    return reply.send(await fs.promises.readFile(target, 'utf8'));
  });
}
