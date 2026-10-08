import { createServer, type IncomingMessage } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { argvAllowed } from './argv.js';
import { dockerRequest } from './docker.js';

// the only thing that holds the docker socket. argos reaches docker through here and gets exactly:
// exec of an allowed cscli argv in the crowdsec container, reading that exec back, restarting crowdsec

const TOKEN = process.env.PROXY_TOKEN ?? '';
const CONTAINER = process.env.CROWDSEC_CONTAINER ?? 'crowdsec';
const SOCKET = process.env.DOCKER_SOCKET ?? '/var/run/docker.sock';
const PORT = Number(process.env.PORT ?? 2375);

if (TOKEN.length < 32) {
  console.error('[proxy] PROXY_TOKEN must be set, 32+ chars');
  process.exit(1);
}

const target = { socketPath: SOCKET };
const execs = new Map<string, number>();   // exec ids we created, so nobody reads or starts another one
// whatever container argos names, the proxy only ever acts on its own
const EXEC_CREATE = /^\/(v[\d.]+\/)?containers\/[^/]+\/exec$/;
const RESTART = /^\/(v[\d.]+\/)?containers\/[^/]+\/restart$/;
const forContainer = (op: 'exec' | 'restart') => `/containers/${encodeURIComponent(CONTAINER)}/${op}`;
const EXEC_START = /^\/(v[\d.]+\/)?exec\/([0-9a-f]{64})\/start$/;
const EXEC_JSON = /^\/(v[\d.]+\/)?exec\/([0-9a-f]{64})\/json$/;

function authorized(req: IncomingMessage): boolean {
  const got = Buffer.from(req.headers.authorization ?? '');
  const want = Buffer.from(`Bearer ${TOKEN}`);
  return got.length === want.length && timingSafeEqual(got, want);
}

async function readJson(req: IncomingMessage): Promise<any> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 64 * 1024) throw new Error('body too large');
    chunks.push(c as Buffer);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
}

createServer(async (req, res) => {
  const send = (status: number, data: Buffer | string, json = true) => {
    res.writeHead(status, { 'Content-Type': json ? 'application/json' : 'text/plain' });
    res.end(data);
  };
  const deny = (why: string) => { console.warn(`[proxy] refused ${req.method} ${req.url}: ${why}`); send(403, JSON.stringify({ message: `argos proxy: ${why}` })); };

  try {
    if (req.method === 'GET' && req.url === '/_health') return send(200, 'ok', false);
    if (!authorized(req)) return deny('bad token');
    const url = new URL(req.url ?? '/', 'http://proxy');
    const path = url.pathname;
    let m: RegExpExecArray | null;

    if (req.method === 'POST' && EXEC_CREATE.test(path)) {
      const body = await readJson(req);
      if (!argvAllowed(body.Cmd)) return deny(`command not allowed: ${JSON.stringify(body.Cmd).slice(0, 200)}`);
      // only the fields argos needs, never a user, env, privileges or a working dir
      const r = await dockerRequest(target, 'POST', forContainer('exec'), { AttachStdout: true, AttachStderr: true, Tty: !!body.Tty, Cmd: body.Cmd });
      if (r.status === 201) {
        const id = JSON.parse(r.data.toString()).Id as string;
        execs.set(id, Date.now() + 5 * 60_000);
      }
      return send(r.status, r.data);
    }
    if (req.method === 'POST' && (m = EXEC_START.exec(path))) {
      if (!execs.has(m[2])) return deny('unknown exec');
      await readJson(req);
      const r = await dockerRequest(target, 'POST', path, { Detach: false, Tty: true });
      return send(r.status, r.data, false);
    }
    if (req.method === 'GET' && (m = EXEC_JSON.exec(path))) {
      if (!execs.has(m[2])) return deny('unknown exec');
      const r = await dockerRequest(target, 'GET', path);
      return send(r.status, r.data);
    }
    if (req.method === 'POST' && RESTART.test(path)) {
      const t = Math.min(60, Math.max(0, Number(url.searchParams.get('t') ?? 20)));
      console.log(`[proxy] restarting ${CONTAINER}`);
      const r = await dockerRequest(target, 'POST', `${forContainer('restart')}?t=${t}`);
      return send(r.status, r.data);
    }
    return deny('not an allowed endpoint');
  } catch (e: any) {
    send(500, JSON.stringify({ message: `argos proxy: ${e.message}` }));
  }
}).listen(PORT, '0.0.0.0', () => console.log(`[proxy] docker proxy for ${CONTAINER} on :${PORT}`));

setInterval(() => { const now = Date.now(); for (const [id, until] of execs) if (until < now) execs.delete(id); }, 60_000).unref();
