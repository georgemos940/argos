import { request, type RequestOptions } from 'node:http';

// docker engine api over the unix socket, or over http through the argos docker proxy
export type DockerTarget = { socketPath: string } | { url: string; token: string };

// the only files argos may write in the crowdsec container
export const CONFIG_DIR = (process.env.CROWDSEC_CONFIG_DIR ?? '/etc/crowdsec').replace(/\/+$/, '');
export const FILES = {
  profiles: { dir: CONFIG_DIR, name: 'profiles.yaml' },
  whitelists: { dir: `${CONFIG_DIR}/parsers/s02-enrich`, name: 'zz-argos-whitelists.yaml' },
} as const;
export type FileKind = keyof typeof FILES;
export const isFileKind = (k: string): k is FileKind => k in FILES;

export function checkContent(content: unknown): string {
  if (typeof content !== 'string') throw new Error('content must be text');
  if (Buffer.byteLength(content) > 64 * 1024) throw new Error('file larger than 64 KB');
  if (content.includes('\0')) throw new Error('binary content');
  return content;
}

// a one-file ustar archive, what the docker archive api takes
export function tarOne(name: string, content: string): Buffer {
  const data = Buffer.from(content, 'utf8');
  const h = Buffer.alloc(512);
  const put = (s: string, off: number, len: number) => h.write(s.slice(0, len), off, 'ascii');
  const oct = (n: number, len: number) => n.toString(8).padStart(len - 1, '0');
  put(name, 0, 100);
  put(oct(0o644, 8), 100, 8);
  put(oct(0, 8), 108, 8);
  put(oct(0, 8), 116, 8);
  put(oct(data.length, 12), 124, 12);
  put(oct(Math.floor(Date.now() / 1000), 12), 136, 12);
  h.fill(' ', 148, 156);
  put('0', 156, 1);
  put('ustar', 257, 6);
  put('00', 263, 2);
  let sum = 0;
  for (const b of h) sum += b;
  put(`${oct(sum, 7)}\0 `, 148, 8);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([h, data, pad, Buffer.alloc(1024)]);
}

// first regular file in a tar stream
export function untarFirst(buf: Buffer): string | null {
  for (let off = 0; off + 512 <= buf.length;) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) return null;
    const size = parseInt(h.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim() || '0', 8);
    const type = String.fromCharCode(h[156]);
    if (type === '0' || type === '\0') return buf.subarray(off + 512, off + 512 + size).toString('utf8');
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return null;
}

export async function readContainerFile(target: DockerTarget, container: string, kind: FileKind): Promise<string | null> {
  const f = FILES[kind];
  const r = await dockerRaw(target, 'GET', `/containers/${encodeURIComponent(container)}/archive?path=${encodeURIComponent(`${f.dir}/${f.name}`)}`);
  if (r.status === 404) return null;
  if (r.status !== 200) throw new Error(`read ${f.name}: docker ${r.status}`);
  return untarFirst(r.data);
}

export async function writeContainerFile(target: DockerTarget, container: string, kind: FileKind, content: string): Promise<void> {
  const f = FILES[kind];
  const r = await dockerRaw(target, 'PUT', `/containers/${encodeURIComponent(container)}/archive?path=${encodeURIComponent(f.dir)}`, tarOne(f.name, checkContent(content)), 'application/x-tar');
  if (r.status !== 200) throw new Error(`write ${f.name}: docker ${r.status} ${r.data.toString().slice(0, 200)}`);
}

function dockerRaw(target: DockerTarget, method: string, path: string, body?: Buffer, type = 'application/json') {
  return dockerRequest(target, method, path, body, type);
}

export function dockerRequest(target: DockerTarget, method: string, path: string, body?: unknown, type = 'application/json'): Promise<{ status: number; data: Buffer }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { 'Content-Type': type };
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
    if (body !== undefined) req.write(Buffer.isBuffer(body) ? body : JSON.stringify(body));
    req.end();
  });
}
