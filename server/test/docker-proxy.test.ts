import './setup.js';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CONFIG_TEST, argvAllowed } from '../src/argv.js';
import { tarOne, untarFirst } from '../src/docker.js';

const c = (...a: string[]) => ['cscli', ...a, '--color', 'no'];

test('argv: what argos really runs', () => {
  for (const cmd of [c('hub', 'list', '-o', 'json'), c('bouncers', 'list', '-o', 'json'), c('hub', 'upgrade', '--dry-run'),
    c('collections', 'install', 'crowdsecurity/nginx'), c('simulation', 'enable', '--global'),
    c('allowlists', 'add', 'trusted', '1.2.3.4', '--comment', 'office, 2nd floor; ask bob'),
    c('explain', '--log', '{"ClientHost":"1.2.3.4","RequestPath":"/.env"}', '--type', 'traefik'),
    c('machines', 'add', 'argos', '--password', 'a'.repeat(32), '-f', '/dev/null', '--force'), CONFIG_TEST])
    assert.equal(argvAllowed(cmd), true, cmd.join(' '));
});

test('argv: refuses anything else', () => {
  for (const cmd of [
    ['sh', '-c', 'id'], ['cscli', 'hub', 'list'], c('machines', 'delete', 'localhost'), c('decisions', 'delete', '--all'),
    c('hub list'), c('allowlists', 'add', 'trusted', '1.2.3.4', '--comment', 'x', '-c', '/tmp/evil.yaml'),
    c('allowlists', 'add', 'trusted', '1.2.3.4 --machine x'), c('explain', '--file', '/etc/shadow', '--type', 'syslog'),
    c('explain', '--log', 'a\nb', '--type', 'syslog'), c('machines', 'add', 'argos', '--password', 'short', '-f', '/dev/null', '--force'),
    c('machines', 'add', 'argos', '--password', 'a'.repeat(32), '-f', '/etc/crowdsec/local_api_credentials.yaml', '--force'),
    'cscli hub list' as unknown as string[], [], ['cscli'], ['crowdsec', '-c', '/tmp/evil.yaml', '-t'], [...CONFIG_TEST, '-debug'], ['crowdsec', '-t']])
    assert.equal(argvAllowed(cmd), false, JSON.stringify(cmd));
});

// the real proxy process in front of a fake docker engine
const SOCK = process.platform === 'win32' ? `\\\\.\\pipe\\argos-fake-docker-${process.pid}` : join(tmpdir(), `argos-fake-docker-${process.pid}.sock`);
const TOKEN = 't'.repeat(40);
const ID = 'a'.repeat(64);
const seen: string[] = [];
let written: Buffer | null = null;
const fake = createServer((req, res) => {
  seen.push(`${req.method} ${req.url}`);
  const chunks: Buffer[] = [];
  req.on('data', (d) => chunks.push(d));
  req.on('end', () => {
    if (req.url?.includes('/archive') && req.method === 'GET') { res.writeHead(200); res.end(tarOne('profiles.yaml', 'name: stock\n')); return; }
    if (req.url?.includes('/archive') && req.method === 'PUT') { written = Buffer.concat(chunks); res.writeHead(200); res.end(); return; }
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

const call = async (method: string, path: string, body?: unknown, token = TOKEN, out?: { json?: any }) => {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}${path}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
      if (out) out.json = await r.json().catch(() => null);
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

test('proxy: only argos own two config files', async () => {
  const got: { json?: any } = {};
  assert.equal(await call('GET', '/argos/files/profiles', undefined, TOKEN, got), 200);
  assert.equal(got.json.content, 'name: stock\n');
  assert.equal(await call('PUT', '/argos/files/whitelists', { content: 'name: argos/ignore-rules\n' }), 200);
  assert.equal(untarFirst(written!), 'name: argos/ignore-rules\n');
  assert.ok(seen.includes('PUT /containers/crowdsec/archive?path=%2Fetc%2Fcrowdsec%2Fparsers%2Fs02-enrich'));

  const before = seen.length;
  assert.equal(await call('GET', '/argos/files/acquis'), 403);
  assert.equal(await call('PUT', '/argos/files/profiles', { content: 'x' }, 'wrong'.repeat(8)), 403);
  assert.equal(await call('PUT', '/argos/files/profiles', { content: 'a\0b' }), 500);
  assert.equal(await call('PUT', '/argos/files/profiles', { content: 'x'.repeat(70 * 1024) }), 500);
  assert.equal(seen.length, before, 'nothing refused reached docker');
});
