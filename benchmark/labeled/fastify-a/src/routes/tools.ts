import { FastifyInstance } from 'fastify';
import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import serialize from 'node-serialize';
import { diskFree, uptime } from '../services/shell';

const execFileAsync = promisify(execFile);

export default async function toolsRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { host: string } }>('/ping', async (request) => {
    exec('ping -c 1 ' + request.query.host, () => undefined);
    return { queued: true };
  });

  app.get<{ Querystring: { host: string } }>('/ping-safe', async (request) => {
    const { stdout } = await execFileAsync('ping', ['-c', '1', request.query.host]);
    return { stdout };
  });

  app.get('/health', async () => ({ disk: await diskFree(), uptime: await uptime() }));

  app.post<{ Body: { data: string } }>('/restore', async (request) => {
    return serialize.unserialize(request.body.data);
  });

  app.post<{ Body: { data: string } }>('/restore-safe', async (request) => {
    return JSON.parse(request.body.data);
  });
}
