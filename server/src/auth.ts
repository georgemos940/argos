import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { db } from './db.js';
import { config } from './config.js';

export type Role = 'admin' | 'operator' | 'viewer';
export interface User { id: number; username: string; role: Role; totp_secret: string | null }

const SESSION_TTL = 12 * 3600 * 1000;
const COOKIE = 'argos_session';

export function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  return `${salt.toString('hex')}:${scryptSync(pw, salt, 64).toString('hex')}`;
}

export function checkPassword(pw: string, stored: string): boolean {
  const [salt, hash] = stored.split(':');
  const got = scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  return timingSafeEqual(got, Buffer.from(hash, 'hex'));
}

// totp, rfc 6238, +-1 step
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function newTotpSecret(): string {
  return [...randomBytes(20)].map((b) => B32[b & 31]).join('');
}

function base32Decode(s: string): Buffer {
  let bits = '';
  for (const ch of s.replace(/=+$/, '').toUpperCase()) bits += B32.indexOf(ch).toString(2).padStart(5, '0');
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function hotp(secret: string, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const code = ((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).toString();
  return code.padStart(6, '0');
}

export function checkTotp(secret: string, code: string): boolean {
  const step = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some((d) => hotp(secret, step + d) === code.trim());
}

export function createSession(c: Context, userId: number, totpOk: boolean): void {
  const id = randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (id, user_id, totp_ok, ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, userId, totpOk ? 1 : 0, c.req.header('x-forwarded-for') ?? null, now, now + SESSION_TTL);
  setCookie(c, COOKIE, id, { httpOnly: true, secure: config.cookieSecure, sameSite: 'Strict', path: '/', maxAge: SESSION_TTL / 1000 });
}

export function destroySession(c: Context): void {
  const id = getCookie(c, COOKIE);
  if (id) db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
  deleteCookie(c, COOKIE, { path: '/' });
}

export function sessionFor(c: Context): { sid: string; user: User; totpOk: boolean } | null {
  const id = getCookie(c, COOKIE);
  if (!id) return null;
  const row = db.prepare(
    `SELECT s.id sid, s.totp_ok, s.expires_at, u.id, u.username, u.role, u.totp_secret
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`,
  ).get(id) as any;
  if (!row || row.expires_at < Date.now()) return null;
  return {
    sid: row.sid,
    user: { id: row.id, username: row.username, role: row.role, totp_secret: row.totp_secret },
    totpOk: !!row.totp_ok,
  };
}

export function markTotpOk(sid: string): void {
  db.prepare('UPDATE sessions SET totp_ok = 1 WHERE id = ?').run(sid);
}

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

// signed in, 2fa passed, role >= min
export const requireRole = (min: Role): MiddlewareHandler => async (c, next) => {
  const s = sessionFor(c);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (s.user.totp_secret && !s.totpOk) return c.json({ error: '2fa required' }, 401);
  if (RANK[s.user.role] < RANK[min]) return c.json({ error: 'forbidden' }, 403);
  c.set('user', s.user);
  await next();
};

export function userCount(): number {
  return (db.prepare('SELECT COUNT(*) n FROM users').get() as { n: number }).n;
}

// 10 failures per ip per 15 min
const fails = new Map<string, { n: number; until: number }>();
export function tooManyFailures(ip: string): boolean {
  const f = fails.get(ip);
  return !!f && f.n >= 10 && f.until > Date.now();
}
export function recordFailure(ip: string): void {
  const f = fails.get(ip);
  if (!f || f.until < Date.now()) fails.set(ip, { n: 1, until: Date.now() + 15 * 60_000 });
  else f.n++;
}
export function clearFailures(ip: string): void {
  fails.delete(ip);
}
