import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import { db, setSetting } from '../src/db.js';
import {
  checkPassword, checkTotp, clearFailures, hashPassword, newTotpSecret, recordFailure, requireRole, tooManyFailures,
} from '../src/auth.js';

const COOKIE = '__Host-argos_session';

function user(role: string, totp: string | null = null) {
  const r = db.prepare('INSERT INTO users (username, pass_hash, role, totp_secret, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(`u${randomBytes(4).toString('hex')}`, hashPassword('long enough pw'), role, totp, Date.now());
  const sid = randomBytes(16).toString('hex');
  db.prepare('INSERT INTO sessions (id, user_id, totp_ok, ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(sid, Number(r.lastInsertRowid), totp ? 0 : 1, 'test', Date.now(), Date.now() + 3600_000);
  return sid;
}

const app = new Hono();
app.get('/viewer', requireRole('viewer'), (c) => c.text('ok'));
app.get('/operator', requireRole('operator'), (c) => c.text('ok'));
app.get('/admin', requireRole('admin'), (c) => c.text('ok'));
const get = (path: string, sid?: string) => app.request(path, { headers: sid ? { Cookie: `${COOKIE}=${sid}` } : {} });

test('roles: each level reaches its own routes and nothing above', async () => {
  const v = user('viewer'), o = user('operator'), a = user('admin');
  const expect: [string, string, number][] = [
    ['/viewer', v, 200], ['/operator', v, 403], ['/admin', v, 403],
    ['/viewer', o, 200], ['/operator', o, 200], ['/admin', o, 403],
    ['/viewer', a, 200], ['/operator', a, 200], ['/admin', a, 200],
  ];
  for (const [path, sid, status] of expect) assert.equal((await get(path, sid)).status, status, `${path}`);
  assert.equal((await get('/viewer')).status, 401);
  assert.equal((await get('/viewer', 'not-a-session')).status, 401);
});

test('a session that has not passed 2fa gets nothing', async () => {
  const sid = user('admin', newTotpSecret());
  assert.equal((await get('/viewer', sid)).status, 401);
});

test('require 2fa for everyone blocks accounts without it', async () => {
  const sid = user('admin');
  setSetting('auth.require2fa', true);
  assert.equal((await get('/viewer', sid)).status, 403);
  setSetting('auth.require2fa', false);
  assert.equal((await get('/viewer', sid)).status, 200);
});

test('passwords', () => {
  const h = hashPassword('correct horse');
  assert.equal(checkPassword('correct horse', h), true);
  assert.equal(checkPassword('wrong horse', h), false);
});

test('totp code works once', () => {
  const secret = newTotpSecret();
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secret) bits += B32.indexOf(ch).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const code = ((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
  assert.equal(checkTotp(secret, code), true);
  assert.equal(checkTotp(secret, code), false, 'replay');
  assert.equal(checkTotp(secret, '000000') && code !== '000000', false);
});

test('login limits per ip and per username', () => {
  for (let i = 0; i < 10; i++) recordFailure('203.0.113.1', 'alice');
  assert.equal(tooManyFailures('203.0.113.1'), true);
  assert.equal(tooManyFailures('203.0.113.2'), false);
  // the same username from many addresses
  for (let i = 0; i < 20; i++) recordFailure(`198.51.100.${i}`, 'bob');
  assert.equal(tooManyFailures('198.51.100.200', 'bob'), true);
  assert.equal(tooManyFailures('198.51.100.200', 'carol'), false);
  clearFailures('203.0.113.1', 'alice');
  assert.equal(tooManyFailures('203.0.113.1', 'alice'), false);
});
