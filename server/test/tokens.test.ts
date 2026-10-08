import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Hono } from 'hono';
import { createToken, requireRole } from '../src/auth.js';
import { db } from '../src/db.js';

const app = new Hono<{ Variables: { user: any } }>();
app.get('/api/read', requireRole('viewer'), (c) => c.json({ who: c.get('user').username }));
app.post('/api/ban', requireRole('operator'), (c) => c.json({ who: c.get('user').username }));
app.get('/api/users', requireRole('admin'), (c) => c.json({}));
app.post('/api/auth/password', requireRole('viewer', { enrolling: true }), (c) => c.json({}));

const call = (method: string, path: string, token?: string, ip = '198.51.100.1') =>
  app.request(path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), 'X-Real-IP': ip } });

test('tokens: role is the ceiling', async () => {
  const v = createToken('ci', 'viewer', 'admin');
  const o = createToken('bot', 'operator', 'admin');
  assert.match(v, /^argos_[\w-]{43}$/);
  assert.equal((await call('GET', '/api/read', v)).status, 200);
  assert.deepEqual(await (await call('GET', '/api/read', v)).json(), { who: 'token:ci' });
  assert.equal((await call('POST', '/api/ban', v)).status, 403);
  assert.equal((await call('POST', '/api/ban', o)).status, 200);
  assert.equal((await call('GET', '/api/users', o)).status, 403);
  assert.equal((await call('POST', '/api/auth/password', o)).status, 403);
});

test('tokens: only the hash is stored, expired and unknown ones refused', async () => {
  const t = createToken('old', 'viewer', 'admin', 1);
  const row = db.prepare('SELECT hash, prefix FROM tokens WHERE name = ?').get('old') as any;
  assert.notEqual(row.hash, t);
  assert.equal(row.prefix, t.slice(0, 12));
  db.prepare('UPDATE tokens SET expires_at = ? WHERE name = ?').run(Date.now() - 1, 'old');
  assert.equal((await call('GET', '/api/read', t, '198.51.100.2')).status, 401);
  assert.equal((await call('GET', '/api/read', 'argos_nope', '198.51.100.2')).status, 401);
  assert.equal((await call('GET', '/api/read', undefined, '198.51.100.2')).status, 401);
});
