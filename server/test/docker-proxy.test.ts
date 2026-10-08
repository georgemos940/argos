import './setup.js';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { argvAllowed } from '../src/argv.js';

const c = (...a: string[]) => ['cscli', ...a, '--color', 'no'];

test('argv: what argos really runs', () => {
  for (const cmd of [c('hub', 'list', '-o', 'json'), c('bouncers', 'list', '-o', 'json'), c('hub', 'upgrade', '--dry-run'),
    c('collections', 'install', 'crowdsecurity/nginx'), c('simulation', 'enable', '--global'),
    c('allowlists', 'add', 'trusted', '1.2.3.4', '--comment', 'office, 2nd floor; ask bob'),
    c('explain', '--log', '{"ClientHost":"1.2.3.4","RequestPath":"/.env"}', '--type', 'traefik'),
    c('machines', 'add', 'argos', '--password', 'a'.repeat(32), '-f', '/dev/null', '--force')])
    assert.equal(argvAllowed(cmd), true, cmd.join(' '));
});

test('argv: refuses anything else', () => {
  for (const cmd of [
    ['sh', '-c', 'id'], ['cscli', 'hub', 'list'], c('machines', 'delete', 'localhost'), c('decisions', 'delete', '--all'),
    c('hub list'), c('allowlists', 'add', 'trusted', '1.2.3.4', '--comment', 'x', '-c', '/tmp/evil.yaml'),
    c('allowlists', 'add', 'trusted', '1.2.3.4 --machine x'), c('explain', '--file', '/etc/shadow', '--type', 'syslog'),
    c('explain', '--log', 'a\nb', '--type', 'syslog'), c('machines', 'add', 'argos', '--password', 'short', '-f', '/dev/null', '--force'),
    c('machines', 'add', 'argos', '--password', 'a'.repeat(32), '-f', '/etc/crowdsec/local_api_credentials.yaml', '--force'),
    'cscli hub list' as unknown as string[], [], ['cscli']])
    assert.equal(argvAllowed(cmd), false, JSON.stringify(cmd));
});

// the real proxy process in front of a fake docker engine
const SOCK = process.platform === 'win32' ? `\\\\.\\pipe\\argos-fake-docker-${process.pid}` : join(tmpdir(), `argos-fake-docker-${process.pid}.sock`);
const TOKEN = 't'.repeat(40);
const ID = 'a'.repeat(64);
const seen: string[] = [];
const fake = createServer((req, res) => {
  seen.push(`${req.method} ${req.url}`);
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    if (req.url?.endsWith('/exec')) { res.writeHead(201); res.end(JSON.stringify({ Id: ID })); return; }
    if (req.url?.endsWith('/start')) { res.writeHead(200); res.end('ok'); return; }
    if (req.url?.endsWith('/json')) { res.writeHead(200); res.end('{"ExitCode":0}'); return; }
    res.writeHead(204); res.end();
  });
}).listen(SOCK);
const PORT = 23000 + (process.pid % 1000);
const proxy = spawn(process.execPath, ['--import', 'tsx', 'server/src/docker-proxy.ts'], {
  env: { ...process.env, PROXY_TOKEN: TOKEN, CROWDSEC_CONTAINER: 'crowdsec', DOCKER_SOCKET: SOCK, PORT: String(PORT) }, stdio: 'ignore',
});
after(() => { proxy.kill(); fake.close(); });

const call = async (method: string, path: string, body?: unknown, token = TOKEN) => {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}${path}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
      return r.status;
    } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  throw new Error('proxy did not start');
};

test('proxy: only the allowed calls reach docker', async () => {
  assert.equal(await call('POST', '/containers/crowdsec/exec', { Cmd: c('hub', 'list', '-o', 'json') }, 'wrong'.repeat(8)), 403, 'bad token');
  assert.equal(await call('POST', '/containers/crowdsec/exec', { Cmd: c('hub', 'list', '-o', 'json'), Privileged: true, User: 'root' }), 201);
  assert.equal(await call('POST', `/exec/${ID}/start`, { Detach: false, Tty: true }), 200);
  assert.equal(await call('GET', `/exec/${ID}/json`), 200);
  assert.equal(await call('POST', '/containers/crowdsec/restart?t=20'), 204);

  const before = seen.length;
  assert.equal(await call('POST', '/containers/crowdsec/exec', { Cmd: ['sh', '-c', 'id'] }), 403);
  assert.equal(await call('POST', `/exec/${'b'.repeat(64)}/start`, {}), 403);
  assert.equal(await call('GET', '/containers/json'), 403);
  assert.equal(await call('POST', '/containers/create', { Image: 'alpine' }), 403);
  assert.equal(await call('DELETE', '/containers/crowdsec'), 403);
  assert.equal(seen.length, before, 'nothing refused reached docker');

  // naming another container still only ever touches crowdsec
  await call('POST', '/containers/traefik/exec', { Cmd: c('hub', 'list', '-o', 'json') });
  await call('POST', '/containers/traefik/restart');
  assert.deepEqual(seen.slice(before).map((s) => s.replace(/\?.*$/, '')), ['POST /containers/crowdsec/exec', 'POST /containers/crowdsec/restart']);
});
