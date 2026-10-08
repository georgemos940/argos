import { request, type RequestOptions } from 'node:http';

// docker engine api over the unix socket, or over http through the argos docker proxy
export type DockerTarget = { socketPath: string } | { url: string; token: string };

export function dockerRequest(target: DockerTarget, method: string, path: string, body?: unknown): Promise<{ status: number; data: Buffer }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const opts: RequestOptions = { method, path, headers };
    if ('socketPath' in target) opts.socketPath = target.socketPath;
    else {
      const u = new URL(target.url);
      opts.host = u.hostname;
      opts.port = u.port || 80;
      opts.path = u.pathname.replace(/\/$/, '') + path;
      headers.Authorization = `Bearer ${target.token}`;
    }
    const req = request(opts, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, data: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.setTimeout(90_000, () => req.destroy(new Error('docker timeout')));
    if (body !== undefined) req.write(JSON.stringify(body));
    req.end();
  });
}
