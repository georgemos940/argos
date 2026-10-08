import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { getConnInfo } from '@hono/node-server/conninfo';
import { db, getSetting } from './db.js';
import { config } from './config.js';

export type Role = 'admin' | 'operator' | 'viewer';
export interface User { id: number; username: string; role: Role; totp_secret: string | null }

const SESSION_TTL = 12 * 3600 * 1000;
// __Host- keeps a subdomain from planting or reading the cookie
const COOKIE = config.cookieSecure ? '__Host-argos_session' : 'argos_session';

// x-forwarded-for is client controlled, only a proxy we sit behind may set it
export function clientIp(c: Context): string {
  if (config.trustProxy) {
    const real = c.req.header('x-real-ip')?.trim();
    if (real) return real;
    const xff = c.req.header('x-forwarded-for')?.split(',').map((s) => s.trim()).filter(Boolean);
    if (xff?.length) return xff[xff.length - 1];
  }
  try { return getConnInfo(c).remote.address ?? 'unknown'; } catch { return 'unknown'; }
}

export function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  return `${salt.toString('hex')}:${scryptSync(pw, salt, 64).toString('hex')}`;
}

export function checkPassword(pw: string, stored: string): boolean {
  const [salt, hash] = stored.split(':');
  const got = scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  return timingSafeEqual(got, Buffer.from(hash, 'hex'));
}

// same cost as a real check, so an unknown username takes as long as a wrong password
const DUMMY_HASH = hashPassword(randomBytes(16).toString('hex'));
export function burnPasswordCheck(pw: string): void {
  checkPassword(pw, DUMMY_HASH);
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

// a code is good once: remember the last step used per secret
const usedStep = new Map<string, number>();
export function checkTotp(secret: string, code: string): boolean {
  const step = Math.floor(Date.now() / 30000);
  const hit = [-1, 0, 1].map((d) => step + d).find((s) => hotp(secret, s) === code.trim());
  if (hit === undefined || hit <= (usedStep.get(secret) ?? -1)) return false;
  usedStep.set(secret, hit);
  return true;
}

export function createSession(c: Context, userId: number, totpOk: boolean): void {
  const id = randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (id, user_id, totp_ok, ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, userId, totpOk ? 1 : 0, clientIp(c), now, now + SESSION_TTL);
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

// after a password or 2fa change every other session of that user goes
export function endOtherSessions(userId: number, keepSid?: string): void {
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').run(userId, keepSid ?? '');
}

export const require2faForAll = () => getSetting<boolean>('auth.require2fa', false);

export function markTotpOk(sid: string): void {
  db.prepare('UPDATE sessions SET totp_ok = 1 WHERE id = ?').run(sid);
}

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

// signed in, 2fa passed, role >= min. enrolling is the one thing allowed before 2fa when it is required
export const requireRole = (min: Role, opts: { enrolling?: boolean } = {}): MiddlewareHandler => async (c, next) => {
  const s = sessionFor(c);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (s.user.totp_secret && !s.totpOk) return c.json({ error: '2fa required' }, 401);
  if (!s.user.totp_secret && !opts.enrolling && require2faForAll()) return c.json({ error: 'set up 2fa first' }, 403);
  if (RANK[s.user.role] < RANK[min]) return c.json({ error: 'forbidden' }, 403);
  c.set('user', s.user);
  await next();
};

export function userCount(): number {
  return (db.prepare('SELECT COUNT(*) n FROM users').get() as { n: number }).n;
}

// 10 failures per ip, 20 per username, per 15 min
const fails = new Map<string, { n: number; until: number }>();
const LIMIT = { ip: 10, user: 20 };
const key = (kind: 'ip' | 'user', v: string) => `${kind}:${v.toLowerCase().slice(0, 64)}`;
export function tooManyFailures(ip: string, username?: string): boolean {
  const over = (k: string, max: number) => { const f = fails.get(k); return !!f && f.n >= max && f.until > Date.now(); };
  return over(key('ip', ip), LIMIT.ip) || (!!username && over(key('user', username), LIMIT.user));
}
export function recordFailure(ip: string, username?: string): void {
  for (const k of [key('ip', ip), ...(username ? [key('user', username)] : [])]) {
    const f = fails.get(k);
    if (!f || f.until < Date.now()) fails.set(k, { n: 1, until: Date.now() + 15 * 60_000 });
    else f.n++;
  }
}
export function clearFailures(ip: string, username?: string): void {
  fails.delete(key('ip', ip));
  if (username) fails.delete(key('user', username));
}
setInterval(() => { const now = Date.now(); for (const [k, f] of fails) if (f.until < now) fails.delete(k); }, 60_000).unref();
